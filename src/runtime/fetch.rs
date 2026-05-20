use crate::scan::html;
use crate::scan::{self, ApiMap, CandidateMap};

use super::cache::{self, ChunkData};
use bytes::Bytes;
use futures_util::{stream, StreamExt};
use reqwest::Client;
use rustc_hash::{FxHashMap, FxHashSet};
use std::{
    sync::{Arc, RwLock},
    time::Instant,
};
use url::Url;

const INLINE_SCAN_MAX: usize = 0;
const CHUNK_MEMORY_CACHE_MAX_ENTRIES: usize = 1024;
const MAX_CHUNK_DISCOVERY_ROUNDS: usize = 4;

pub type ChunkMemoryCache = Arc<RwLock<FxHashMap<String, Arc<ChunkData>>>>;

#[derive(Default)]
pub struct ChunkScanStats {
    pub discovered: usize,
    pub scanned: usize,
    pub cache_hits: usize,
    pub bundle_hits: usize,
    pub bundle_pack_hits: usize,
    pub memory_hits: usize,
    pub errors: usize,
    pub bytes_fetched: u64,
    pub bytes_scanned: u64,
    pub fetch_ms: u128,
    pub scan_ms: u128,
    pub fetch_us: u128,
    pub scan_us: u128,
    pub ref_us: u128,
    pub api_scan_us: u128,
    pub candidate_scan_us: u128,
}

enum ChunkSource {
    Fetched,
    Bundle,
    Disk,
    Memory,
}

struct FetchMetrics {
    bytes_fetched: u64,
    bytes_scanned: u64,
    fetch_ms: u128,
    scan_ms: u128,
    fetch_us: u128,
    scan_us: u128,
    ref_us: u128,
    api_scan_us: u128,
    candidate_scan_us: u128,
}

struct FetchResult {
    url: Url,
    chunk: Arc<ChunkData>,
    source: ChunkSource,
    metrics: FetchMetrics,
    raw_body: Option<Bytes>,
}

pub async fn scan_chunks(
    client: Client,
    initial: impl IntoIterator<Item = Url>,
    concurrency: usize,
    use_processed_cache: bool,
    use_bundle_cache: bool,
    memory: Option<ChunkMemoryCache>,
    apis: &mut ApiMap,
    candidates: &mut CandidateMap,
) -> ChunkScanStats {
    let mut stats = ChunkScanStats::default();
    let mut visited: FxHashSet<Url> = FxHashSet::default();
    let initial: Vec<Url> = initial.into_iter().collect();
    let mut queue: Vec<Url> = initial
        .iter()
        .cloned()
        .filter(|u| visited.insert(u.clone()))
        .collect();
    let mut pack_entries = Vec::new();
    let mut pack_dirty = false;

    if use_bundle_cache && !use_processed_cache {
        if let Some(entries) = cache::read_bundle_pack(&initial) {
            queue.clear();
            for (url, _) in &entries {
                visited.insert(url.clone());
            }
            stats.bundle_pack_hits = entries.len();
            pack_entries.extend(
                entries
                    .iter()
                    .map(|(url, body)| (url.clone(), body.clone())),
            );
            let mut scanned = stream::iter(entries)
                .map(|(url, body)| {
                    scan_body(Bytes::from(body), url, ChunkSource::Bundle, false, None)
                })
                .buffer_unordered(concurrency);

            while let Some(res) = scanned.next().await {
                match res {
                    Ok(result) => {
                        stats.record(result.source, result.metrics);
                        let chunk = result.chunk;
                        scan::merge_refs_into(apis, chunk.apis.iter());
                        scan::merge_candidate_refs_into(candidates, chunk.candidates.iter());
                        enqueue_refs(&chunk.refs, &mut visited, &mut queue);
                    }
                    Err(()) => stats.errors += 1,
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
                    use_processed_cache,
                    use_bundle_cache,
                    memory.clone(),
                )
            })
            .buffer_unordered(concurrency);

        while let Some(res) = fetched.next().await {
            match res {
                Ok(result) => {
                    if let Some(body) = &result.raw_body {
                        pack_entries.push((result.url.clone(), body.to_vec()));
                        pack_dirty = true;
                    }
                    stats.record(result.source, result.metrics);
                    let chunk = result.chunk;
                    scan::merge_refs_into(apis, chunk.apis.iter());
                    scan::merge_candidate_refs_into(candidates, chunk.candidates.iter());
                    enqueue_refs(&chunk.refs, &mut visited, &mut queue);
                }
                Err(()) => stats.errors += 1,
            }
        }
    }

    stats.discovered = visited.len();
    if use_bundle_cache && !use_processed_cache && pack_dirty && !pack_entries.is_empty() {
        cache::write_bundle_pack(&initial, &pack_entries);
    }
    stats
}

impl ChunkScanStats {
    fn record(&mut self, source: ChunkSource, metrics: FetchMetrics) {
        match source {
            ChunkSource::Fetched => self.scanned += 1,
            ChunkSource::Bundle => {
                self.scanned += 1;
                self.bundle_hits += 1;
            }
            ChunkSource::Disk => {
                self.cache_hits += 1;
            }
            ChunkSource::Memory => {
                self.cache_hits += 1;
                self.memory_hits += 1;
            }
        }
        self.bytes_fetched += metrics.bytes_fetched;
        self.bytes_scanned += metrics.bytes_scanned;
        self.fetch_ms += metrics.fetch_ms;
        self.scan_ms += metrics.scan_ms;
        self.fetch_us += metrics.fetch_us;
        self.scan_us += metrics.scan_us;
        self.ref_us += metrics.ref_us;
        self.api_scan_us += metrics.api_scan_us;
        self.candidate_scan_us += metrics.candidate_scan_us;
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
) -> Result<FetchResult, ()> {
    if use_processed_cache {
        if let Some(chunk) = read_memory_chunk(memory.as_ref(), &url) {
            return Ok(fetch_result(
                url,
                chunk,
                ChunkSource::Memory,
                FetchMetrics::empty(),
                None,
            ));
        }
        if let Some(chunk) = cache::read_chunk(&url).map(Arc::new) {
            write_memory_chunk(memory.as_ref(), &url, chunk.clone());
            return Ok(fetch_result(
                url,
                chunk,
                ChunkSource::Disk,
                FetchMetrics::empty(),
                None,
            ));
        }
    }
    if use_bundle_cache {
        if let Some(body) = cache::read_bundle(&url) {
            return scan_body(
                Bytes::from(body),
                url,
                ChunkSource::Bundle,
                use_processed_cache,
                memory,
            )
            .await;
        }
    }

    let fetch_t0 = Instant::now();
    let response = client
        .get(url.clone())
        .send()
        .await
        .map_err(|_| ())?
        .error_for_status()
        .map_err(|_| ())?;
    let body = response.bytes().await.map_err(|_| ())?;
    let fetch_elapsed = fetch_t0.elapsed();
    cache::write_bundle(&url, &body);
    let mut result =
        scan_body(body, url, ChunkSource::Fetched, use_processed_cache, memory).await?;
    result.metrics.fetch_ms = fetch_elapsed.as_millis();
    result.metrics.fetch_us = fetch_elapsed.as_micros();
    result.metrics.bytes_fetched = result.metrics.bytes_scanned;
    Ok(result)
}

async fn scan_body(
    body: Bytes,
    url: Url,
    source: ChunkSource,
    use_cache: bool,
    memory: Option<ChunkMemoryCache>,
) -> Result<FetchResult, ()> {
    let mut apis = ApiMap::default();
    let mut candidates = CandidateMap::default();
    let bytes_scanned = body.len() as u64;
    let refs_t0 = Instant::now();
    let refs = html::extract_chunk_refs(&body, &url);
    let ref_us = refs_t0.elapsed().as_micros();
    let scan_t0 = Instant::now();
    let raw_body = body.clone();
    let breakdown = scan_bytes(body, &mut apis, &mut candidates).await?;
    let scan_elapsed = scan_t0.elapsed();
    let chunk = Arc::new(ChunkData {
        apis,
        candidates,
        refs,
    });
    if use_cache {
        cache::write_chunk(&url, &chunk);
        write_memory_chunk(memory.as_ref(), &url, chunk.clone());
    }
    Ok(fetch_result(
        url,
        chunk,
        source,
        FetchMetrics {
            bytes_fetched: 0,
            bytes_scanned,
            fetch_ms: 0,
            scan_ms: scan_elapsed.as_millis(),
            fetch_us: 0,
            scan_us: scan_elapsed.as_micros(),
            ref_us,
            api_scan_us: breakdown.api_us,
            candidate_scan_us: breakdown.candidate_us,
        },
        Some(raw_body),
    ))
}

fn fetch_result(
    url: Url,
    chunk: Arc<ChunkData>,
    source: ChunkSource,
    metrics: FetchMetrics,
    raw_body: Option<Bytes>,
) -> FetchResult {
    FetchResult {
        url,
        chunk,
        source,
        metrics,
        raw_body,
    }
}

impl FetchMetrics {
    fn empty() -> Self {
        Self {
            bytes_fetched: 0,
            bytes_scanned: 0,
            fetch_ms: 0,
            scan_ms: 0,
            fetch_us: 0,
            scan_us: 0,
            ref_us: 0,
            api_scan_us: 0,
            candidate_scan_us: 0,
        }
    }
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

#[derive(Default)]
struct ScanBreakdown {
    api_us: u128,
    candidate_us: u128,
}

async fn scan_bytes(
    bytes: Bytes,
    apis: &mut ApiMap,
    candidates: &mut CandidateMap,
) -> Result<ScanBreakdown, ()> {
    if bytes.len() <= INLINE_SCAN_MAX {
        let api_t0 = Instant::now();
        scan::scan(&bytes, apis);
        let api_us = api_t0.elapsed().as_micros();
        let candidate_t0 = Instant::now();
        scan::scan_candidates(&bytes, candidates);
        let candidate_us = candidate_t0.elapsed().as_micros();
        return Ok(ScanBreakdown {
            api_us,
            candidate_us,
        });
    }

    let (chunk_apis, chunk_candidates, breakdown) = tokio::task::spawn_blocking(move || {
        let mut chunk_apis = ApiMap::default();
        let mut chunk_candidates = CandidateMap::default();
        let api_t0 = Instant::now();
        scan::scan(&bytes, &mut chunk_apis);
        let api_us = api_t0.elapsed().as_micros();
        let candidate_t0 = Instant::now();
        scan::scan_candidates(&bytes, &mut chunk_candidates);
        let candidate_us = candidate_t0.elapsed().as_micros();
        (
            chunk_apis,
            chunk_candidates,
            ScanBreakdown {
                api_us,
                candidate_us,
            },
        )
    })
    .await
    .map_err(|_| ())?;
    scan::merge_into(apis, chunk_apis);
    scan::merge_candidates_into(candidates, chunk_candidates);
    Ok(breakdown)
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
            true,
            Some(memory.clone()),
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
            1,
            true,
            true,
            Some(memory),
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
