use crate::{
    cache,
    scan::{self, ApiMap},
};
use bytes::Bytes;
use futures_util::{stream, StreamExt};
use reqwest::Client;
use rustc_hash::FxHashMap;
use std::sync::{Arc, RwLock};
use url::Url;

const INLINE_SCAN_MAX: usize = 64 * 1024;
const CHUNK_MEMORY_CACHE_MAX_ENTRIES: usize = 1024;

pub type ChunkMemoryCache = Arc<RwLock<FxHashMap<String, Arc<ApiMap>>>>;

pub async fn scan_chunks(
    client: Client,
    chunks: impl Iterator<Item = Url>,
    concurrency: usize,
    use_cache: bool,
    memory: Option<ChunkMemoryCache>,
    apis: &mut ApiMap,
) -> ChunkScanStats {
    let mut stats = ChunkScanStats::default();

    let mut fetched = stream::iter(chunks)
        .map(|url| fetch_scan(client.clone(), url, use_cache, memory.clone()))
        .buffer_unordered(concurrency);

    while let Some(res) = fetched.next().await {
        match res {
            Ok(ChunkScan::Fetched(chunk_apis)) => {
                stats.scanned += 1;
                scan::merge_into(apis, chunk_apis);
            }
            Ok(ChunkScan::Cached(chunk_apis)) => {
                stats.cache_hits += 1;
                scan::merge_into(apis, chunk_apis);
            }
            Ok(ChunkScan::MemoryCached(chunk_apis)) => {
                stats.cache_hits += 1;
                stats.memory_hits += 1;
                scan::merge_refs_into(apis, chunk_apis.iter());
            }
            _ => stats.errors += 1,
        }
    }

    stats
}

#[derive(Default)]
pub struct ChunkScanStats {
    pub scanned: usize,
    pub cache_hits: usize,
    pub memory_hits: usize,
    pub errors: usize,
}

enum ChunkScan {
    Fetched(ApiMap),
    Cached(ApiMap),
    MemoryCached(Arc<ApiMap>),
}

async fn fetch_scan(
    client: Client,
    url: Url,
    use_cache: bool,
    memory: Option<ChunkMemoryCache>,
) -> Result<ChunkScan, ()> {
    if use_cache {
        if let Some(apis) = read_memory_chunk(memory.as_ref(), &url) {
            return Ok(ChunkScan::MemoryCached(apis));
        }
        if let Some(apis) = cache::read_chunk(&url) {
            write_memory_chunk(memory.as_ref(), &url, &apis);
            return Ok(ChunkScan::Cached(apis));
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
    scan_bytes(body, &mut apis).await?;
    if use_cache {
        cache::write_chunk(&url, &apis);
        write_memory_chunk(memory.as_ref(), &url, &apis);
    }
    Ok(ChunkScan::Fetched(apis))
}

fn read_memory_chunk(memory: Option<&ChunkMemoryCache>, url: &Url) -> Option<Arc<ApiMap>> {
    memory?.read().ok()?.get(url.as_str()).cloned()
}

fn write_memory_chunk(memory: Option<&ChunkMemoryCache>, url: &Url, apis: &ApiMap) {
    let Some(memory) = memory else {
        return;
    };
    if let Ok(mut entries) = memory.write() {
        entries.insert(url.as_str().to_string(), Arc::new(apis.clone()));
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

pub async fn grep_chunks(
    client: Client,
    chunks: impl Iterator<Item = Url>,
    concurrency: usize,
    pattern: &str,
    context: usize,
) -> Vec<GrepHit> {
    let pat = std::sync::Arc::new(pattern.to_string());
    let mut searched = stream::iter(chunks)
        .map(|url| grep_one(client.clone(), url, pat.clone(), context))
        .buffer_unordered(concurrency);

    let mut hits = Vec::new();
    while let Some(mut h) = searched.next().await {
        hits.append(&mut h);
    }
    hits
}

pub struct GrepHit {
    pub url: String,
    pub offset: usize,
    pub snippet: String,
}

async fn grep_one(
    client: Client,
    url: Url,
    pattern: std::sync::Arc<String>,
    context: usize,
) -> Vec<GrepHit> {
    let Ok(resp) = client.get(url.clone()).send().await else {
        return Vec::new();
    };
    let Ok(resp) = resp.error_for_status() else {
        return Vec::new();
    };
    let Ok(body) = resp.bytes().await else {
        return Vec::new();
    };

    let mut hits = Vec::new();
    let bytes = &body[..];
    let pat_bytes = pattern.as_bytes();
    if pat_bytes.is_empty() {
        return hits;
    }
    for abs in memchr::memmem::find_iter(bytes, pat_bytes) {
        let lo = abs.saturating_sub(context);
        let hi = (abs + pat_bytes.len() + context).min(bytes.len());
        let snippet = String::from_utf8_lossy(&bytes[lo..hi]).replace('\n', " ");
        hits.push(GrepHit {
            url: url.to_string(),
            offset: abs,
            snippet,
        });
    }
    hits
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
