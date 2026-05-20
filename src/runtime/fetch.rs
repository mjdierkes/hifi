use crate::scan::html;
use crate::scan::{self, ApiMap, CandidateMap};

use super::cache::{self, ChunkData};
use super::net;
use bytes::Bytes;
use futures_util::stream::{self, FuturesUnordered, StreamExt};
use lru::LruCache;
use reqwest::header::{HeaderMap, ETAG, IF_MODIFIED_SINCE, IF_NONE_MATCH, LAST_MODIFIED};
use reqwest::{Client, StatusCode};
use rustc_hash::FxHashSet;
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
    pub use_bundle_cache: bool,
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
    url: Arc<Url>,
    chunk: Arc<ChunkData>,
    memory_hit: bool,
    raw_body: Option<Bytes>,
}

enum FetchedBody {
    Body(Bytes, cache::ChunkValidators),
    NotModified,
}

pub async fn scan_chunks(
    client: Client,
    initial: impl IntoIterator<Item = Url>,
    opts: ChunkScanOptions,
    apis: &mut ApiMap,
    candidates: &mut CandidateMap,
) -> ChunkScanStats {
    let mut stats = ChunkScanStats::default();
    let mut visited: FxHashSet<Arc<Url>> = FxHashSet::default();
    let initial: Vec<Url> = initial.into_iter().collect();
    let mut queue = VecDeque::new();
    for url in &initial {
        if visited.len() >= MAX_TOTAL_CHUNKS {
            stats.capped = true;
            break;
        }
        let url = Arc::new(url.clone());
        if visited.insert(url.clone()) {
            queue.push_back(url);
        }
    }
    let mut pack_entries = Vec::new();
    let mut pack_dirty = false;
    let concurrency = opts.concurrency.max(1);

    if opts.use_bundle_cache && !opts.use_processed_cache {
        if let Some(mut entries) = cache::read_bundle_pack(&initial, opts.cache_key.as_deref()) {
            queue.clear();
            visited.clear();
            if entries.len() > MAX_TOTAL_CHUNKS {
                entries.truncate(MAX_TOTAL_CHUNKS);
                stats.capped = true;
            }
            for (url, _) in &entries {
                visited.insert(Arc::new(url.clone()));
            }
            pack_entries.extend(
                entries
                    .iter()
                    .map(|(url, body)| (url.clone(), body.clone())),
            );
            let mut scanned = stream::iter(entries)
                .map(|(url, body)| {
                    scan_body(
                        Bytes::from(body),
                        Arc::new(url),
                        false,
                        None,
                        None,
                        cache::ChunkValidators::default(),
                    )
                })
                .buffer_unordered(concurrency);

            while let Some(res) = scanned.next().await {
                match res {
                    Ok(result) => {
                        stats.record(result.memory_hit);
                        let chunk = result.chunk;
                        scan::merge_refs_into(apis, chunk.apis.iter());
                        scan::merge_candidate_refs_into(candidates, chunk.candidates.iter());
                        enqueue_refs(&chunk.refs, &mut visited, &mut queue, &mut stats);
                    }
                    Err(()) => stats.failed += 1,
                }
            }
        }
    }

    let mut fetched = FuturesUnordered::new();
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
                if opts.use_bundle_cache && !opts.use_processed_cache {
                    if let Some(body) = &result.raw_body {
                        pack_entries.push((result.url.as_ref().clone(), body.to_vec()));
                        pack_dirty = true;
                    }
                }
                stats.record(result.memory_hit);
                let chunk = result.chunk;
                scan::merge_refs_into(apis, chunk.apis.iter());
                scan::merge_candidate_refs_into(candidates, chunk.candidates.iter());
                enqueue_refs(&chunk.refs, &mut visited, &mut queue, &mut stats);
            }
            Err(()) => stats.failed += 1,
        }
    }

    stats.discovered = visited.len();
    if opts.use_bundle_cache && !opts.use_processed_cache && pack_dirty && !pack_entries.is_empty()
    {
        cache::write_bundle_pack(&initial, &pack_entries, opts.cache_key.as_deref());
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

fn enqueue_refs(
    refs: &[Url],
    visited: &mut FxHashSet<Arc<Url>>,
    queue: &mut VecDeque<Arc<Url>>,
    stats: &mut ChunkScanStats,
) {
    for r in refs {
        if visited.len() >= MAX_TOTAL_CHUNKS {
            if !visited.contains(r) {
                stats.capped = true;
            }
            continue;
        }
        let url = Arc::new(r.clone());
        if visited.insert(url.clone()) {
            queue.push_back(url);
        }
    }
}

async fn fetch_scan(
    client: Client,
    url: Arc<Url>,
    use_processed_cache: bool,
    cache_key: Option<&str>,
    allow_private: bool,
    memory: Option<ChunkMemoryCache>,
) -> Result<ScannedChunk, ()> {
    let mut cached = None;
    if use_processed_cache {
        if let Some(chunk) = read_memory_chunk(memory.as_ref(), &url, cache_key) {
            return Ok(ScannedChunk {
                url,
                chunk,
                memory_hit: true,
                raw_body: None,
            });
        }
        if let Some(chunk) = cache::read_chunk_cached(&url, cache_key) {
            if chunk.age_secs < super::processor::CACHE_FRESH_SECS {
                let chunk = Arc::new(chunk.data);
                write_memory_chunk(memory.as_ref(), &url, cache_key, chunk.clone());
                return Ok(ScannedChunk {
                    url,
                    chunk,
                    memory_hit: false,
                    raw_body: None,
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
                url,
                chunk,
                memory_hit: false,
                raw_body: None,
            })
        }
        FetchedBody::Body(body, validators) => {
            scan_body(
                body,
                url,
                use_processed_cache,
                cache_key,
                memory,
                validators,
            )
            .await
        }
    }
}

async fn scan_body(
    body: Bytes,
    url: Arc<Url>,
    use_cache: bool,
    cache_key: Option<&str>,
    memory: Option<ChunkMemoryCache>,
    validators: cache::ChunkValidators,
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
        cache::write_chunk_with_validators(&url, &chunk, cache_key, &validators);
        write_memory_chunk(memory.as_ref(), &url, cache_key, chunk.clone());
    }
    Ok(ScannedChunk {
        url,
        chunk,
        memory_hit: false,
        raw_body: Some(raw_body),
    })
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
    let Some(memory) = memory else {
        return;
    };
    if let Ok(mut entries) = memory.write() {
        entries.put(memory_key(url, cache_key), (chunk, Instant::now()));
    }
}

fn memory_key(url: &Url, cache_key: Option<&str>) -> String {
    match cache_key {
        Some(cache_key) => format!("{cache_key}\n{}", url.as_str()),
        None => url.as_str().to_string(),
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

async fn fetch_chunk_body(
    client: &Client,
    url: Arc<Url>,
    allow_private: bool,
    validators: Option<&cache::ChunkValidators>,
) -> Result<FetchedBody, ()> {
    net::validate_url(&url, allow_private).map_err(|_| ())?;
    let mut request = client.get(url.as_ref().clone());
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
    Ok(FetchedBody::Body(body, validators))
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
        let memory = chunk_memory_cache();
        let initial = Url::parse(&format!("http://{addr}/_next/static/chunks/a.js")).unwrap();

        let mut first = ApiMap::default();
        let first_stats = scan_chunks(
            client.clone(),
            [initial.clone()],
            ChunkScanOptions {
                concurrency: 1,
                use_processed_cache: true,
                use_bundle_cache: true,
                cache_key: Some("b1".into()),
                allow_private: true,
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
                cache_key: Some("b1".into()),
                allow_private: true,
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

    #[tokio::test]
    async fn recursive_discovery_is_not_limited_to_fixed_rounds() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            for _ in 0..6 {
                let (mut socket, _) = listener.accept().await.unwrap();
                tokio::spawn(async move {
                    let mut buf = [0; 1024];
                    let n = socket.read(&mut buf).await.unwrap();
                    let req = String::from_utf8_lossy(&buf[..n]);
                    let body = if req.starts_with("GET /_next/static/chunks/a.js ") {
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
        let initial = Url::parse(&format!("http://{addr}/_next/static/chunks/a.js")).unwrap();
        let mut apis = ApiMap::default();
        let stats = scan_chunks(
            client,
            [initial],
            ChunkScanOptions {
                concurrency: 2,
                use_processed_cache: false,
                use_bundle_cache: false,
                cache_key: None,
                allow_private: true,
                memory: None,
            },
            &mut apis,
            &mut CandidateMap::default(),
        )
        .await;

        assert_eq!(stats.discovered, 6);
        assert!(apis.contains_key("/api/f"));
    }
}
