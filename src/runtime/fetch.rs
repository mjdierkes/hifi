use crate::scan::html;
use crate::scan::{self, ApiMap, CandidateMap};

use super::cache::{self, ChunkData};
use bytes::Bytes;
use futures_util::{stream, StreamExt};
use reqwest::Client;
use rustc_hash::{FxHashMap, FxHashSet};
use std::sync::{Arc, RwLock};
use url::Url;

const CHUNK_MEMORY_CACHE_MAX_ENTRIES: usize = 1024;
const MAX_CHUNK_DISCOVERY_ROUNDS: usize = 4;

pub type ChunkMemoryCache = Arc<RwLock<FxHashMap<String, Arc<ChunkData>>>>;

pub struct ChunkScanOptions {
    pub concurrency: usize,
    pub use_processed_cache: bool,
    pub use_bundle_cache: bool,
    pub memory: Option<ChunkMemoryCache>,
}

#[derive(Default)]
pub struct ChunkScanStats {
    pub discovered: usize,
    pub memory_hits: usize,
}

struct ScannedChunk {
    url: Url,
    chunk: Arc<ChunkData>,
    memory_hit: bool,
    raw_body: Option<Bytes>,
}

pub async fn scan_chunks(
    client: Client,
    initial: impl IntoIterator<Item = Url>,
    opts: ChunkScanOptions,
    apis: &mut ApiMap,
    candidates: &mut CandidateMap,
) -> ChunkScanStats {
    let mut stats = ChunkScanStats::default();
    let mut visited: FxHashSet<Url> = FxHashSet::default();
    let initial: Vec<Url> = initial.into_iter().collect();
    let mut queue: Vec<Url> = initial
        .iter()
        .filter(|&u| visited.insert(u.clone()))
        .cloned()
        .collect();
    let mut pack_entries = Vec::new();
    let mut pack_dirty = false;

    if opts.use_bundle_cache && !opts.use_processed_cache {
        if let Some(entries) = cache::read_bundle_pack(&initial) {
            queue.clear();
            for (url, _) in &entries {
                visited.insert(url.clone());
            }
            pack_entries.extend(
                entries
                    .iter()
                    .map(|(url, body)| (url.clone(), body.clone())),
            );
            let mut scanned = stream::iter(entries)
                .map(|(url, body)| scan_body(Bytes::from(body), url, false, None))
                .buffer_unordered(opts.concurrency);

            while let Some(res) = scanned.next().await {
                if let Ok(result) = res {
                    stats.record(result.memory_hit);
                    let chunk = result.chunk;
                    scan::merge_refs_into(apis, chunk.apis.iter());
                    scan::merge_candidate_refs_into(candidates, chunk.candidates.iter());
                    enqueue_refs(&chunk.refs, &mut visited, &mut queue);
                }
            }
        }
    }

    for _ in 0..MAX_CHUNK_DISCOVERY_ROUNDS {
        if queue.is_empty() {
            break;
        }
        let mut fetched = stream::iter(std::mem::take(&mut queue))
            .map(|url| {
                fetch_scan(
                    client.clone(),
                    url,
                    opts.use_processed_cache,
                    opts.use_bundle_cache,
                    opts.memory.clone(),
                )
            })
            .buffer_unordered(opts.concurrency);

        while let Some(res) = fetched.next().await {
            if let Ok(result) = res {
                if let Some(body) = &result.raw_body {
                    pack_entries.push((result.url.clone(), body.to_vec()));
                    pack_dirty = true;
                }
                stats.record(result.memory_hit);
                let chunk = result.chunk;
                scan::merge_refs_into(apis, chunk.apis.iter());
                scan::merge_candidate_refs_into(candidates, chunk.candidates.iter());
                enqueue_refs(&chunk.refs, &mut visited, &mut queue);
            }
        }
    }

    stats.discovered = visited.len();
    if opts.use_bundle_cache && !opts.use_processed_cache && pack_dirty && !pack_entries.is_empty()
    {
        cache::write_bundle_pack(&initial, &pack_entries);
    }
    stats
}

impl ChunkScanStats {
    fn record(&mut self, memory_hit: bool) {
        if memory_hit {
            self.memory_hits += 1;
        }
    }
}

fn enqueue_refs(refs: &[Url], visited: &mut FxHashSet<Url>, queue: &mut Vec<Url>) {
    for r in refs {
        if visited.insert(r.clone()) {
            queue.push(r.clone());
        }
    }
}

async fn fetch_scan(
    client: Client,
    url: Url,
    use_processed_cache: bool,
    use_bundle_cache: bool,
    memory: Option<ChunkMemoryCache>,
) -> Result<ScannedChunk, ()> {
    if use_processed_cache {
        if let Some(chunk) = read_memory_chunk(memory.as_ref(), &url) {
            return Ok(ScannedChunk {
                url,
                chunk,
                memory_hit: true,
                raw_body: None,
            });
        }
        if let Some(chunk) = cache::read_chunk(&url).map(Arc::new) {
            write_memory_chunk(memory.as_ref(), &url, chunk.clone());
            return Ok(ScannedChunk {
                url,
                chunk,
                memory_hit: false,
                raw_body: None,
            });
        }
    }
    if use_bundle_cache {
        if let Some(body) = cache::read_bundle(&url) {
            return scan_body(Bytes::from(body), url, use_processed_cache, memory).await;
        }
    }

    let response = client
        .get(url.clone())
        .send()
        .await
        .map_err(|_| ())?
        .error_for_status()
        .map_err(|_| ())?;
    let body = response.bytes().await.map_err(|_| ())?;
    cache::write_bundle(&url, &body);
    scan_body(body, url, use_processed_cache, memory).await
}

async fn scan_body(
    body: Bytes,
    url: Url,
    use_cache: bool,
    memory: Option<ChunkMemoryCache>,
) -> Result<ScannedChunk, ()> {
    let mut apis = ApiMap::default();
    let mut candidates = CandidateMap::default();
    let refs = html::extract_chunk_refs(&body, &url);
    let raw_body = body.clone();
    scan_bytes(body, &mut apis, &mut candidates).await?;
    let chunk = Arc::new(ChunkData {
        apis,
        candidates,
        refs,
    });
    if use_cache {
        cache::write_chunk(&url, &chunk);
        write_memory_chunk(memory.as_ref(), &url, chunk.clone());
    }
    Ok(ScannedChunk {
        url,
        chunk,
        memory_hit: false,
        raw_body: Some(raw_body),
    })
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
        cache::prune_overflow(&mut entries, CHUNK_MEMORY_CACHE_MAX_ENTRIES);
    }
}

async fn scan_bytes(
    bytes: Bytes,
    apis: &mut ApiMap,
    candidates: &mut CandidateMap,
) -> Result<(), ()> {
    let (chunk_apis, chunk_candidates) = tokio::task::spawn_blocking(move || {
        let mut chunk_apis = ApiMap::default();
        let mut chunk_candidates = CandidateMap::default();
        scan::scan(&bytes, &mut chunk_apis);
        scan::scan_candidates(&bytes, &mut chunk_candidates);
        (chunk_apis, chunk_candidates)
    })
    .await
    .map_err(|_| ())?;
    scan::merge_into(apis, chunk_apis);
    scan::merge_candidates_into(candidates, chunk_candidates);
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
            ChunkScanOptions {
                concurrency: 1,
                use_processed_cache: true,
                use_bundle_cache: true,
                memory: Some(memory.clone()),
            },
            &mut first,
            &mut CandidateMap::default(),
        )
        .await;
        assert_eq!(first_stats.discovered, 2);
        assert!(first.contains_key("/api/a"));
        assert!(first.contains_key("/api/b"));

        let mut second = ApiMap::default();
        let second_stats = scan_chunks(
            client,
            [initial],
            ChunkScanOptions {
                concurrency: 1,
                use_processed_cache: true,
                use_bundle_cache: true,
                memory: Some(memory),
            },
            &mut second,
            &mut CandidateMap::default(),
        )
        .await;
        assert_eq!(second_stats.discovered, 2);
        assert_eq!(second_stats.memory_hits, 2);
        assert!(second.contains_key("/api/a"));
        assert!(second.contains_key("/api/b"));
    }
}
