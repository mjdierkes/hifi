use crate::scan::html;
use crate::scan::{self, ApiMap};

use super::cache::{self, ChunkData};
use bytes::Bytes;
use futures_util::{stream, StreamExt};
use reqwest::Client;
use rustc_hash::{FxHashMap, FxHashSet};
use std::sync::{Arc, RwLock};
use url::Url;

const INLINE_SCAN_MAX: usize = 64 * 1024;
const CHUNK_MEMORY_CACHE_MAX_ENTRIES: usize = 1024;
const MAX_CHUNK_DISCOVERY_ROUNDS: usize = 4;

pub type ChunkMemoryCache = Arc<RwLock<FxHashMap<String, Arc<ChunkData>>>>;

#[derive(Default)]
pub struct ChunkScanStats {
    pub discovered: usize,
    pub scanned: usize,
    pub cache_hits: usize,
    pub memory_hits: usize,
    pub errors: usize,
}

enum ChunkSource {
    Fetched,
    Disk,
    Memory,
}

pub async fn scan_chunks(
    client: Client,
    initial: impl IntoIterator<Item = Url>,
    concurrency: usize,
    use_cache: bool,
    memory: Option<ChunkMemoryCache>,
    apis: &mut ApiMap,
) -> ChunkScanStats {
    let mut stats = ChunkScanStats::default();
    let mut visited: FxHashSet<String> = FxHashSet::default();
    let mut queue: Vec<Url> = initial
        .into_iter()
        .filter(|u| visited.insert(u.as_str().to_string()))
        .collect();

    for _ in 0..MAX_CHUNK_DISCOVERY_ROUNDS {
        if queue.is_empty() {
            break;
        }
        let batch = std::mem::take(&mut queue);
        let mut fetched = stream::iter(batch)
            .map(|url| fetch_scan(client.clone(), url, use_cache, memory.clone()))
            .buffer_unordered(concurrency);

        while let Some(res) = fetched.next().await {
            match res {
                Ok((chunk, source)) => {
                    stats.record(source);
                    scan::merge_refs_into(apis, chunk.apis.iter());
                    enqueue_refs(&chunk.refs, &mut visited, &mut queue);
                }
                Err(()) => stats.errors += 1,
            }
        }
    }

    stats.discovered = visited.len();
    stats
}

impl ChunkScanStats {
    fn record(&mut self, source: ChunkSource) {
        match source {
            ChunkSource::Fetched => self.scanned += 1,
            ChunkSource::Disk => self.cache_hits += 1,
            ChunkSource::Memory => {
                self.cache_hits += 1;
                self.memory_hits += 1;
            }
        }
    }
}

fn enqueue_refs(refs: &[Url], visited: &mut FxHashSet<String>, queue: &mut Vec<Url>) {
    for r in refs {
        if visited.insert(r.as_str().to_string()) {
            queue.push(r.clone());
        }
    }
}

async fn fetch_scan(
    client: Client,
    url: Url,
    use_cache: bool,
    memory: Option<ChunkMemoryCache>,
) -> Result<(Arc<ChunkData>, ChunkSource), ()> {
    if use_cache {
        if let Some(chunk) = read_memory_chunk(memory.as_ref(), &url) {
            return Ok((chunk, ChunkSource::Memory));
        }
        if let Some(chunk) = cache::read_chunk(&url).map(Arc::new) {
            write_memory_chunk(memory.as_ref(), &url, chunk.clone());
            return Ok((chunk, ChunkSource::Disk));
        }
    }

    let response = client
        .get(url.clone())
        .send()
        .await
        .map_err(|_| ())?
        .error_for_status()
        .map_err(|_| ())?;
    let mut apis = ApiMap::default();
    let body = response.bytes().await.map_err(|_| ())?;
    let refs = html::extract_chunk_refs(&body, &url);
    scan_bytes(body, &mut apis).await?;
    let chunk = Arc::new(ChunkData { apis, refs });
    if use_cache {
        cache::write_chunk(&url, &chunk);
        write_memory_chunk(memory.as_ref(), &url, chunk.clone());
    }
    Ok((chunk, ChunkSource::Fetched))
}

fn read_memory_chunk(memory: Option<&ChunkMemoryCache>, url: &Url) -> Option<Arc<ChunkData>> {
    memory?.read().ok()?.get(url.as_str()).cloned()
}

fn write_memory_chunk(memory: Option<&ChunkMemoryCache>, url: &Url, chunk: Arc<ChunkData>) {
    let Some(memory) = memory else {
        return;
    };
    if let Ok(mut entries) = memory.write() {
        entries.insert(url.as_str().to_string(), chunk);
        if entries.len() <= CHUNK_MEMORY_CACHE_MAX_ENTRIES {
            return;
        }
        let overflow = entries.len() - CHUNK_MEMORY_CACHE_MAX_ENTRIES;
        let keys: Vec<_> = entries.keys().take(overflow).cloned().collect();
        for key in keys {
            entries.remove(&key);
        }
    }
}

async fn scan_bytes(bytes: Bytes, apis: &mut ApiMap) -> Result<(), ()> {
    if bytes.len() <= INLINE_SCAN_MAX {
        scan::scan(&bytes, apis);
        return Ok(());
    }

    let chunk_apis = tokio::task::spawn_blocking(move || {
        let mut chunk_apis = ApiMap::default();
        scan::scan(&bytes, &mut chunk_apis);
        chunk_apis
    })
    .await
    .map_err(|_| ())?;
    scan::merge_into(apis, chunk_apis);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    #[tokio::test]
    async fn memory_cached_chunks_keep_recursive_refs() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            for _ in 0..2 {
                let (mut socket, _) = listener.accept().await.unwrap();
                tokio::spawn(async move {
                    let mut buf = [0; 1024];
                    let n = socket.read(&mut buf).await.unwrap();
                    let req = String::from_utf8_lossy(&buf[..n]);
                    let body = if req.starts_with("GET /_next/static/chunks/b.js ") {
                        r#"fetch("/api/b")"#
                    } else {
                        r#"fetch("/api/a");"static/chunks/b.js""#
                    };
                    let response = format!(
                        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                        body.len(),
                        body
                    );
                    socket.write_all(response.as_bytes()).await.unwrap();
                });
            }
        });

        let client = Client::new();
        let memory = Arc::new(RwLock::new(FxHashMap::default()));
        let initial = Url::parse(&format!("http://{addr}/_next/static/chunks/a.js")).unwrap();

        let mut first = ApiMap::default();
        let first_stats = scan_chunks(
            client.clone(),
            [initial.clone()],
            1,
            true,
            Some(memory.clone()),
            &mut first,
        )
        .await;
        assert_eq!(first_stats.discovered, 2);
        assert!(first.contains_key("/api/a"));
        assert!(first.contains_key("/api/b"));

        let mut second = ApiMap::default();
        let second_stats = scan_chunks(client, [initial], 1, true, Some(memory), &mut second).await;
        assert_eq!(second_stats.discovered, 2);
        assert_eq!(second_stats.memory_hits, 2);
        assert!(second.contains_key("/api/a"));
        assert!(second.contains_key("/api/b"));
    }
}
