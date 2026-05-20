use crate::scan::{self, ScanResult};

use super::cache::{self, ChunkData};
use super::net;
use futures_util::{stream::FuturesUnordered, StreamExt};
use lru::LruCache;
use reqwest::header::{HeaderMap, ETAG, IF_MODIFIED_SINCE, IF_NONE_MATCH, LAST_MODIFIED};
use reqwest::{Client, StatusCode};
use std::{
    collections::VecDeque,
    num::NonZeroUsize,
    sync::atomic::{AtomicBool, Ordering},
    sync::{Arc, RwLock},
    time::Instant,
};
use url::Url;

const CHUNK_MEMORY_CACHE_MAX_ENTRIES: usize = 1024;
const MAX_TOTAL_CHUNKS: usize = 2048;
static FIRST_CHUNK_RESPONSE_TRACED: AtomicBool = AtomicBool::new(false);

pub type ChunkMemoryCache = Arc<RwLock<LruCache<String, (Arc<ChunkData>, Instant)>>>;

pub fn chunk_memory_cache() -> ChunkMemoryCache {
    Arc::new(RwLock::new(LruCache::new(
        NonZeroUsize::new(CHUNK_MEMORY_CACHE_MAX_ENTRIES).expect("nonzero cache size"),
    )))
}

pub struct ChunkScanOptions {
    pub concurrency: usize,
    pub use_processed_cache: bool,
    pub cache_key: Option<String>,
    pub allow_private: bool,
    pub memory: Option<ChunkMemoryCache>,
}

#[derive(Default)]
pub struct ChunkScanStats {
    pub discovered: usize,
    pub memory_hits: usize,
    pub failed: usize,
    pub capped: bool,
}

struct ScannedChunk {
    chunk: Arc<ChunkData>,
    memory_hit: bool,
}

enum FetchedBody {
    Body(ScanResult, cache::ChunkValidators),
    NotModified,
}

pub async fn scan_chunks(
    client: Client,
    initial: impl IntoIterator<Item = Url>,
    opts: ChunkScanOptions,
    out: &mut ScanResult,
) -> ChunkScanStats {
    let mut stats = ChunkScanStats::default();
    let mut visited = initial
        .into_iter()
        .take(MAX_TOTAL_CHUNKS)
        .collect::<rustc_hash::FxHashSet<_>>();
    stats.capped = visited.len() == MAX_TOTAL_CHUNKS;
    let mut queue = visited.iter().cloned().collect::<VecDeque<_>>();
    let mut fetched = FuturesUnordered::new();
    let concurrency = opts.concurrency.max(1);

    loop {
        while fetched.len() < concurrency {
            let Some(url) = queue.pop_front() else {
                break;
            };
            fetched.push(fetch_scan(
                client.clone(),
                url,
                opts.use_processed_cache,
                opts.cache_key.as_deref(),
                opts.allow_private,
                opts.memory.clone(),
            ));
        }

        let Some(res) = fetched.next().await else {
            break;
        };
        match res {
            Ok(result) => {
                if result.memory_hit {
                    stats.memory_hits += 1;
                }
                out.merge_findings(&result.chunk);
                enqueue_refs(&result.chunk.refs, &mut visited, &mut queue, &mut stats);
            }
            Err(()) => stats.failed += 1,
        }
    }

    stats.discovered = visited.len();
    stats
}

fn enqueue_refs(
    refs: &[Url],
    visited: &mut rustc_hash::FxHashSet<Url>,
    queue: &mut VecDeque<Url>,
    stats: &mut ChunkScanStats,
) {
    for url in refs {
        if visited.len() >= MAX_TOTAL_CHUNKS {
            if !visited.contains(url) {
                stats.capped = true;
            }
        } else if visited.insert(url.clone()) {
            queue.push_back(url.clone());
        }
    }
}

async fn fetch_scan(
    client: Client,
    url: Url,
    use_cache: bool,
    cache_key: Option<&str>,
    allow_private: bool,
    memory: Option<ChunkMemoryCache>,
) -> Result<ScannedChunk, ()> {
    let mut cached = None;
    if use_cache {
        if let Some(chunk) = read_memory_chunk(memory.as_ref(), &url, cache_key) {
            return Ok(ScannedChunk {
                chunk,
                memory_hit: true,
            });
        }
        if let Some(chunk) = cache::read_chunk_cached(&url, cache_key) {
            if chunk.age_secs < super::processor::CACHE_FRESH_SECS {
                let chunk = Arc::new(chunk.data);
                write_memory_chunk(memory.as_ref(), &url, cache_key, chunk.clone());
                return Ok(ScannedChunk {
                    chunk,
                    memory_hit: false,
                });
            }
            cached = Some(chunk);
        }
    }

    let validators = cached.as_ref().map(|chunk| &chunk.validators);
    match fetch_chunk_body(&client, url.clone(), allow_private, validators).await? {
        FetchedBody::NotModified => {
            let cached = cached.ok_or(())?;
            cache::write_chunk_with_validators(&url, &cached.data, cache_key, &cached.validators);
            let chunk = Arc::new(cached.data);
            write_memory_chunk(memory.as_ref(), &url, cache_key, chunk.clone());
            Ok(ScannedChunk {
                chunk,
                memory_hit: false,
            })
        }
        FetchedBody::Body(scan, validators) => {
            let chunk = Arc::new(scan);
            if use_cache {
                cache::write_chunk_with_validators(&url, &chunk, cache_key, &validators);
                write_memory_chunk(memory.as_ref(), &url, cache_key, chunk.clone());
            }
            Ok(ScannedChunk {
                chunk,
                memory_hit: false,
            })
        }
    }
}

fn read_memory_chunk(
    memory: Option<&ChunkMemoryCache>,
    url: &Url,
    cache_key: Option<&str>,
) -> Option<Arc<ChunkData>> {
    let memory = memory?;
    let key = memory_key(url, cache_key);
    let mut entries = memory.write().ok()?;
    let (chunk, written) = entries.get(&key).cloned()?;
    if written.elapsed().as_secs() < super::processor::CACHE_FRESH_SECS {
        Some(chunk)
    } else {
        entries.pop(&key);
        None
    }
}

fn write_memory_chunk(
    memory: Option<&ChunkMemoryCache>,
    url: &Url,
    cache_key: Option<&str>,
    chunk: Arc<ChunkData>,
) {
    if let Some(memory) = memory {
        if let Ok(mut entries) = memory.write() {
            entries.put(memory_key(url, cache_key), (chunk, Instant::now()));
        }
    }
}

fn memory_key(url: &Url, cache_key: Option<&str>) -> String {
    cache_key
        .map(|key| format!("{key}\n{}", url.as_str()))
        .unwrap_or_else(|| url.as_str().to_string())
}

async fn fetch_chunk_body(
    client: &Client,
    url: Url,
    allow_private: bool,
    validators: Option<&cache::ChunkValidators>,
) -> Result<FetchedBody, ()> {
    net::validate_url(&url, allow_private).map_err(|_| ())?;
    let mut request = client.get(url.clone());
    if let Some(validators) = validators {
        if let Some(etag) = &validators.etag {
            request = request.header(IF_NONE_MATCH, etag);
        }
        if let Some(last_modified) = &validators.last_modified {
            request = request.header(IF_MODIFIED_SINCE, last_modified);
        }
    }

    let response = request.send().await.map_err(|_| ())?;
    if !FIRST_CHUNK_RESPONSE_TRACED.swap(true, Ordering::Relaxed) {
        net::trace_response_version("chunk", &url, &response);
    }
    if response.status() == StatusCode::NOT_MODIFIED {
        return Ok(FetchedBody::NotModified);
    }

    let response = response.error_for_status().map_err(|_| ())?;
    let validators = chunk_validators(response.headers());
    let body = net::read_limited(response).await.map_err(|_| ())?;
    let scan_url = url.clone();
    let scan = tokio::task::spawn_blocking(move || scan::scan_document(&body, &scan_url))
        .await
        .map_err(|_| ())?;
    Ok(FetchedBody::Body(scan, validators))
}

fn chunk_validators(headers: &HeaderMap) -> cache::ChunkValidators {
    cache::ChunkValidators {
        etag: header_value(headers, ETAG),
        last_modified: header_value(headers, LAST_MODIFIED),
    }
}

fn header_value(headers: &HeaderMap, name: reqwest::header::HeaderName) -> Option<String> {
    headers
        .get(name)
        .and_then(|value| value.to_str().ok())
        .map(str::to_string)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    #[tokio::test]
    async fn memory_cached_chunks_keep_recursive_refs() {
        let addr = serve(2, |req| {
            if req.starts_with("GET /_next/static/chunks/b.js ") {
                r#"fetch("/api/b")"#
            } else {
                r#"fetch("/api/a");"static/chunks/b.js""#
            }
        })
        .await;

        let client = Client::new();
        let memory = chunk_memory_cache();
        let initial = Url::parse(&format!("http://{addr}/_next/static/chunks/a.js")).unwrap();

        let mut first = ScanResult::default();
        let first_stats = scan_chunks(
            client.clone(),
            [initial.clone()],
            ChunkScanOptions {
                concurrency: 1,
                use_processed_cache: true,
                cache_key: Some("b1".into()),
                allow_private: true,
                memory: Some(memory.clone()),
            },
            &mut first,
        )
        .await;
        assert_eq!(first_stats.discovered, 2);
        assert!(first.apis.contains_key("/api/a"));
        assert!(first.apis.contains_key("/api/b"));

        let mut second = ScanResult::default();
        let second_stats = scan_chunks(
            client,
            [initial],
            ChunkScanOptions {
                concurrency: 1,
                use_processed_cache: true,
                cache_key: Some("b1".into()),
                allow_private: true,
                memory: Some(memory),
            },
            &mut second,
        )
        .await;
        assert_eq!(second_stats.discovered, 2);
        assert_eq!(second_stats.memory_hits, 2);
        assert!(second.apis.contains_key("/api/a"));
        assert!(second.apis.contains_key("/api/b"));
    }

    #[tokio::test]
    async fn recursive_discovery_is_not_limited_to_fixed_rounds() {
        let addr = serve(6, |req| {
            if req.starts_with("GET /_next/static/chunks/a.js ") {
                r#"fetch("/api/a");"static/chunks/b.js""#
            } else if req.starts_with("GET /_next/static/chunks/b.js ") {
                r#"fetch("/api/b");"static/chunks/c.js""#
            } else if req.starts_with("GET /_next/static/chunks/c.js ") {
                r#"fetch("/api/c");"static/chunks/d.js""#
            } else if req.starts_with("GET /_next/static/chunks/d.js ") {
                r#"fetch("/api/d");"static/chunks/e.js""#
            } else if req.starts_with("GET /_next/static/chunks/e.js ") {
                r#"fetch("/api/e");"static/chunks/f.js""#
            } else {
                r#"fetch("/api/f")"#
            }
        })
        .await;

        let client = Client::new();
        let initial = Url::parse(&format!("http://{addr}/_next/static/chunks/a.js")).unwrap();
        let mut found = ScanResult::default();
        let stats = scan_chunks(
            client,
            [initial],
            ChunkScanOptions {
                concurrency: 2,
                use_processed_cache: false,
                cache_key: None,
                allow_private: true,
                memory: None,
            },
            &mut found,
        )
        .await;

        assert_eq!(stats.discovered, 6);
        assert!(found.apis.contains_key("/api/f"));
    }

    async fn serve(
        requests: usize,
        handler: impl Fn(&str) -> &'static str + Send + Sync + 'static,
    ) -> std::net::SocketAddr {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let handler = Arc::new(handler);
        tokio::spawn(async move {
            for _ in 0..requests {
                let (mut socket, _) = listener.accept().await.unwrap();
                let handler = handler.clone();
                tokio::spawn(async move {
                    let mut buf = [0; 1024];
                    let n = socket.read(&mut buf).await.unwrap();
                    let body = handler(std::str::from_utf8(&buf[..n]).unwrap());
                    let response = format!(
                        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                        body.len(),
                        body
                    );
                    socket.write_all(response.as_bytes()).await.unwrap();
                });
            }
        });
        addr
    }
}
