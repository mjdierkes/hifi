use crate::scan::ApiMap;
use crate::scan::{self, html};

use super::{cache, fetch};
use reqwest::Client;
use rustc_hash::FxHashMap;
use serde_json::{json, Value};
use std::{
    error::Error,
    path::{Path, PathBuf},
    sync::{Arc, RwLock},
    time::Instant,
};
use url::Url;

pub const CACHE_FRESH_SECS: u64 = 300;
pub const CACHE_STALE_SECS: u64 = 3600;
const MEMORY_CACHE_MAX_ENTRIES: usize = 256;

type Result<T, E = Box<dyn Error>> = std::result::Result<T, E>;
pub type Body = Arc<str>;
pub type MemoryCache = Arc<RwLock<FxHashMap<String, (Body, Instant)>>>;
pub type RedirectMemory = Arc<RwLock<FxHashMap<String, Url>>>;

#[derive(Clone, Default)]
pub struct CacheContext {
    pub memory: Option<MemoryCache>,
    pub chunks: Option<fetch::ChunkMemoryCache>,
    pub redirects: Option<RedirectMemory>,
}

pub struct Processor<'a> {
    client: &'a Client,
    concurrency: usize,
    cache: CacheContext,
}

impl<'a> Processor<'a> {
    pub fn new(client: &'a Client, concurrency: usize, cache: CacheContext) -> Self {
        Self {
            client,
            concurrency,
            cache,
        }
    }

    pub async fn process(&self, url: &str, no_cache: bool, t0: Instant) -> Result<Value> {
        let active_cache = (!no_cache).then(|| self.cache.clone()).unwrap_or_default();
        let (base, cache_path, request_base) = request_parts(url, &active_cache)?;

        if let Some((v, age)) = (!no_cache)
            .then(|| cache::read_any(&cache_path))
            .flatten()
            .filter(|(_, age)| *age < CACHE_STALE_SECS)
        {
            let status = if age < CACHE_FRESH_SECS {
                "fresh"
            } else {
                self.refresh_later(url, active_cache.clone());
                "stale"
            };
            return Ok(annotate(v, t0, status, age));
        }

        let (out, cache_hit) = self
            .collect(
                url,
                &base,
                &request_base,
                (!no_cache).then_some(cache_path.as_path()),
                Some(t0),
                active_cache,
            )
            .await?;

        if !no_cache && !cache_hit {
            write_caches(&cache_path, &out, url, self.cache.memory.clone())?;
        }
        Ok(out)
    }

    pub async fn refresh(&self, url: &str) -> Result<()> {
        let (base, cache_path, request_base) = request_parts(url, &self.cache)?;
        let (out, _) = self
            .collect(
                url,
                &base,
                &request_base,
                Some(cache_path.as_path()),
                None,
                self.cache.clone(),
            )
            .await?;
        write_caches(&cache_path, &out, url, self.cache.memory.clone())
    }

    fn refresh_later(&self, url: &str, cache: CacheContext) {
        spawn_refresh(self.client.clone(), self.concurrency, url, cache);
    }

    async fn collect(
        &self,
        url: &str,
        original_base: &Url,
        request_base: &Url,
        cache_path: Option<&Path>,
        t0: Option<Instant>,
        cache_ctx: CacheContext,
    ) -> Result<(Value, bool)> {
        let response = self.client.get(request_base.clone()).send().await?;
        let final_base = response.url().clone();
        remember_redirect(cache_ctx.redirects.as_ref(), original_base, &final_base);
        let html = response.bytes().await?;
        let chunks = html::extract_chunks(&html, &final_base);
        let build_id = html::extract_build_id(&html).or_else(|| Some(cache::fingerprint(&chunks)));

        if let Some(mut v) = cache_path.and_then(|p| cache::read(p, build_id.as_deref())) {
            if let (Some(obj), Some(t0)) = (v.as_object_mut(), t0) {
                insert_elapsed(obj, t0);
                obj.insert("cache".into(), json!("hit"));
            }
            return Ok((v, true));
        }

        let mut apis = ApiMap::default();
        scan::scan(&html, &mut apis);
        let chunk_stats = fetch::scan_chunks(
            self.client.clone(),
            chunks.iter().cloned(),
            self.concurrency,
            cache_path.is_some(),
            cache_ctx.chunks,
            &mut apis,
        )
        .await;

        let mut out = json!({
            "url": url,
            "build_id": build_id,
            "chunks_discovered": chunk_stats.discovered,
            "initial_chunks_discovered": chunks.len(),
            "chunks_scanned": chunk_stats.scanned,
            "chunk_cache_hits": chunk_stats.cache_hits,
            "chunk_memory_hits": chunk_stats.memory_hits,
            "chunk_fetch_errors": chunk_stats.errors,
            "apis": apis,
            "cache": "miss",
        });
        if let (Some(obj), Some(t0)) = (out.as_object_mut(), t0) {
            insert_elapsed(obj, t0);
        }
        Ok((out, false))
    }
}

pub fn spawn_refresh(client: Client, concurrency: usize, url: &str, cache: CacheContext) {
    let url = url.to_string();
    tokio::spawn(async move {
        let _ = Processor::new(&client, concurrency, cache)
            .refresh(&url)
            .await;
    });
}

pub fn read_memory(memory: &MemoryCache, url: &str) -> Option<(Body, u64)> {
    memory
        .read()
        .ok()?
        .get(url)
        .cloned()
        .map(|(body, t)| (body, t.elapsed().as_secs()))
}

pub fn write_memory(memory: &MemoryCache, url: String, body: Body) {
    if let Ok(mut entries) = memory.write() {
        let now = Instant::now();
        entries.insert(url, (body, now));
        prune_memory(&mut entries, now);
    }
}

fn redirected_base(redirects: Option<&RedirectMemory>, base: &Url) -> Option<Url> {
    let target = redirects?.read().ok()?.get(&origin_key(base)?).cloned()?;
    let mut out = target;
    out.set_path(base.path());
    out.set_query(base.query());
    out.set_fragment(base.fragment());
    Some(out)
}

fn request_parts(url: &str, cache: &CacheContext) -> Result<(Url, PathBuf, Url), url::ParseError> {
    let base = Url::parse(url)?;
    let request_base =
        redirected_base(cache.redirects.as_ref(), &base).unwrap_or_else(|| base.clone());
    let cache_path = cache::path_for(&base);
    Ok((base, cache_path, request_base))
}

fn remember_redirect(redirects: Option<&RedirectMemory>, from: &Url, to: &Url) {
    let (Some(from_key), Some(to_key)) = (origin_key(from), origin_key(to)) else {
        return;
    };
    if from_key == to_key {
        return;
    }
    if let Some(redirects) = redirects {
        if let Ok(mut entries) = redirects.write() {
            if let Ok(to_origin) = Url::parse(&format!("{to_key}/")) {
                entries.insert(from_key, to_origin);
            }
        }
    }
}

fn origin_key(url: &Url) -> Option<String> {
    let host = url.host_str()?;
    match url.port() {
        Some(port) => Some(format!("{}://{}:{}", url.scheme(), host, port)),
        None => Some(format!("{}://{}", url.scheme(), host)),
    }
}

fn write_caches(
    cache_path: &Path,
    out: &Value,
    url: &str,
    memory: Option<MemoryCache>,
) -> Result<()> {
    cache::write(cache_path, out);
    if let Some(memory) = memory {
        let body = Arc::from(serde_json::to_string(out)?);
        write_memory(&memory, url.to_string(), body);
    }
    Ok(())
}

fn prune_memory(entries: &mut FxHashMap<String, (Body, Instant)>, now: Instant) {
    entries.retain(|_, (_, written)| {
        now.saturating_duration_since(*written).as_secs() < CACHE_STALE_SECS
    });
    cache::prune_overflow(entries, MEMORY_CACHE_MAX_ENTRIES);
}

fn annotate(mut v: Value, t0: Instant, status: &str, age_secs: u64) -> Value {
    if let Some(obj) = v.as_object_mut() {
        insert_elapsed(obj, t0);
        obj.insert("cache".into(), json!(status));
        obj.insert("cache_age_secs".into(), json!(age_secs));
    }
    v
}

fn insert_elapsed(obj: &mut serde_json::Map<String, Value>, t0: Instant) {
    let elapsed = t0.elapsed();
    obj.insert("elapsed_ms".into(), json!(elapsed.as_millis()));
    obj.insert("elapsed_us".into(), json!(elapsed.as_micros()));
    obj.insert("elapsed_ns".into(), json!(elapsed.as_nanos()));
}
