use crate::scan::{self, html};
use crate::scan::{ApiMap, CandidateMap};

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

    pub async fn process(&self, url: &str, no_cache: bool, t0: Instant) -> Result<String> {
        let active_cache = (!no_cache).then(|| self.cache.clone()).unwrap_or_default();
        let (base, cache_path, request_base) = request_parts(url, &active_cache)?;

        if let Some((json, age)) = (!no_cache)
            .then(|| cache::read_any_bytes(&cache_path))
            .flatten()
            .filter(|(_, age)| *age < CACHE_STALE_SECS)
        {
            let status = if age < CACHE_FRESH_SECS {
                "fresh"
            } else {
                self.refresh_later(url, active_cache.clone());
                "stale"
            };
            return Ok(annotate_json(&json, t0, status, Some(age))?);
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

        if let Collected::Value(v) = &out {
            if !no_cache && !cache_hit {
                write_caches(&cache_path, v, url, self.cache.memory.clone())?;
            }
        }
        out.into_string()
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
        write_caches(
            &cache_path,
            &out.into_value()?,
            url,
            self.cache.memory.clone(),
        )
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
    ) -> Result<(Collected, bool)> {
        let response = self.client.get(request_base.clone()).send().await?;
        let final_base = response.url().clone();
        remember_redirect(cache_ctx.redirects.as_ref(), original_base, &final_base);
        let html = response.bytes().await?;
        let mut chunks = html::extract_chunks(&html, &final_base);
        let html_build_id = html::extract_build_id(&html);
        let build_id = html_build_id
            .clone()
            .or_else(|| Some(cache::fingerprint(&chunks)));

        if let Some(path) = cache_path {
            if let (Some(bytes), Some(t0)) =
                (cache::read_build_bytes(path, build_id.as_deref()), t0)
            {
                return Ok((
                    Collected::Json(annotate_json(&bytes, t0, "hit", None)?),
                    true,
                ));
            }
            if let Some(v) = cache::read(path, build_id.as_deref()) {
                let v = if let Some(t0) = t0 {
                    annotate(v, t0, "hit", None)
                } else {
                    v
                };
                return Ok((Collected::Value(v), true));
            }
        }

        let mut apis = ApiMap::default();
        let mut candidates = CandidateMap::default();
        scan::scan(&html, &mut apis);
        scan::scan_candidates(&html, &mut candidates);
        let manifest_stats = scan_next_manifests(
            self.client,
            &final_base,
            html_build_id.as_deref(),
            &mut apis,
            &mut candidates,
            &mut chunks,
        )
        .await;
        let chunk_stats = fetch::scan_chunks(
            self.client.clone(),
            chunks.iter().cloned(),
            self.concurrency,
            cache_path.is_some(),
            cache_ctx.chunks,
            &mut apis,
            &mut candidates,
        )
        .await;
        for url in apis.keys() {
            candidates.remove(url);
        }

        let mut out = json!({
            "url": url,
            "build_id": build_id,
            "manifests_scanned": manifest_stats.scanned,
            "manifest_fetch_errors": manifest_stats.errors,
            "chunks_discovered": chunk_stats.discovered,
            "initial_chunks_discovered": chunks.len(),
            "chunks_scanned": chunk_stats.scanned,
            "chunk_cache_hits": chunk_stats.cache_hits,
            "chunk_memory_hits": chunk_stats.memory_hits,
            "chunk_fetch_errors": chunk_stats.errors,
            "apis": apis,
            "candidates": candidates,
            "cache": "miss",
        });
        if let (Some(obj), Some(t0)) = (out.as_object_mut(), t0) {
            insert_elapsed(obj, t0);
        }
        Ok((Collected::Value(out), false))
    }
}

enum Collected {
    Json(String),
    Value(Value),
}

impl Collected {
    fn into_string(self) -> Result<String> {
        match self {
            Self::Json(s) => Ok(s),
            Self::Value(v) => Ok(serde_json::to_string(&v)?),
        }
    }

    fn into_value(self) -> Result<Value> {
        match self {
            Self::Json(s) => Ok(serde_json::from_str(&s)?),
            Self::Value(v) => Ok(v),
        }
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

#[derive(Default)]
struct ManifestStats {
    scanned: usize,
    errors: usize,
}

async fn scan_next_manifests(
    client: &Client,
    base: &Url,
    build_id: Option<&str>,
    apis: &mut ApiMap,
    candidates: &mut CandidateMap,
    chunks: &mut Vec<Url>,
) -> ManifestStats {
    let Some(build_id) = build_id else {
        return ManifestStats::default();
    };

    let mut stats = ManifestStats::default();
    for name in ["_buildManifest.js", "_ssgManifest.js"] {
        let Ok(manifest_url) = base.join(&format!("/_next/static/{build_id}/{name}")) else {
            continue;
        };
        match fetch_manifest(client, manifest_url.clone()).await {
            Some(body) => {
                stats.scanned += 1;
                scan::scan(&body, apis);
                scan::scan_candidates(&body, candidates);
                chunks.extend(html::extract_chunk_refs(&body, &manifest_url));
            }
            None => stats.errors += 1,
        }
    }
    stats
}

async fn fetch_manifest(client: &Client, url: Url) -> Option<bytes::Bytes> {
    client
        .get(url)
        .send()
        .await
        .ok()?
        .error_for_status()
        .ok()?
        .bytes()
        .await
        .ok()
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
    let cached = cache_value(out);
    cache::write(cache_path, &cached);
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

fn annotate(mut v: Value, t0: Instant, status: &str, age_secs: Option<u64>) -> Value {
    if let Some(obj) = v.as_object_mut() {
        insert_elapsed(obj, t0);
        obj.insert("cache".into(), json!(status));
        if let Some(age_secs) = age_secs {
            obj.insert("cache_age_secs".into(), json!(age_secs));
        }
    }
    v
}

fn annotate_json(bytes: &[u8], t0: Instant, status: &str, age_secs: Option<u64>) -> Result<String> {
    let raw = std::str::from_utf8(bytes)?.trim_end();
    let body = raw
        .strip_suffix('}')
        .ok_or("cache entry must be a JSON object")?;
    let elapsed = t0.elapsed();
    let sep = if body.ends_with('{') { "" } else { "," };
    let mut out = format!(
        "{body}{sep}\"elapsed_ms\":{},\"elapsed_us\":{},\"elapsed_ns\":{},\"cache\":\"{status}\"}}",
        elapsed.as_millis(),
        elapsed.as_micros(),
        elapsed.as_nanos()
    );
    if let Some(age_secs) = age_secs {
        out.insert_str(out.len() - 1, &format!(",\"cache_age_secs\":{age_secs}"));
    }
    Ok(out)
}

fn cache_value(out: &Value) -> Value {
    let mut cached = out.clone();
    if let Some(obj) = cached.as_object_mut() {
        for key in [
            "cache",
            "cache_age_secs",
            "elapsed_ms",
            "elapsed_us",
            "elapsed_ns",
        ] {
            obj.remove(key);
        }
    }
    cached
}

fn insert_elapsed(obj: &mut serde_json::Map<String, Value>, t0: Instant) {
    let elapsed = t0.elapsed();
    obj.insert("elapsed_ms".into(), json!(elapsed.as_millis()));
    obj.insert("elapsed_us".into(), json!(elapsed.as_micros()));
    obj.insert("elapsed_ns".into(), json!(elapsed.as_nanos()));
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    #[test]
    fn cache_value_strips_dynamic_fields() {
        let cached = cache_value(&json!({
            "url": "https://example.com",
            "apis": {},
            "cache": "miss",
            "cache_age_secs": 1,
            "elapsed_ms": 1,
            "elapsed_us": 2,
            "elapsed_ns": 3
        }));
        let obj = cached.as_object().unwrap();
        assert!(obj.contains_key("url"));
        assert!(!obj.contains_key("cache"));
        assert!(!obj.contains_key("elapsed_ms"));
    }

    #[test]
    fn annotate_json_appends_valid_status_fields() {
        let out = annotate_json(
            br#"{"url":"https://example.com","apis":{}}"#,
            Instant::now(),
            "hit",
            None,
        )
        .unwrap();
        let v: Value = serde_json::from_str(&out).unwrap();
        assert_eq!(v["cache"], "hit");
        assert!(v.get("cache_age_secs").is_none());
        assert!(v.get("elapsed_ns").is_some());
    }

    #[tokio::test]
    async fn build_manifest_seeds_extra_chunks() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            for _ in 0..4 {
                let (mut socket, _) = listener.accept().await.unwrap();
                tokio::spawn(async move {
                    let mut buf = [0; 2048];
                    let n = socket.read(&mut buf).await.unwrap();
                    let req = String::from_utf8_lossy(&buf[..n]);
                    let (status, body) = if req
                        .starts_with("GET /_next/static/b1/_buildManifest.js ")
                    {
                        (
                            "200 OK",
                            r#"self.__BUILD_MANIFEST={"/extra":["static/chunks/app-extra.js"]};const u="/api/from-manifest";"#,
                        )
                    } else if req.starts_with("GET /_next/static/chunks/app-extra.js ") {
                        ("200 OK", r#"fetch("/api/from-chunk",{method:"POST"})"#)
                    } else if req.starts_with("GET /_next/static/b1/_ssgManifest.js ") {
                        ("404 Not Found", "")
                    } else {
                        (
                            "200 OK",
                            r#"<html><script id="__NEXT_DATA__" type="application/json">{"buildId":"b1"}</script></html>"#,
                        )
                    };
                    let response = format!(
                        "HTTP/1.1 {status}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                        body.len()
                    );
                    socket.write_all(response.as_bytes()).await.unwrap();
                });
            }
        });

        let client = Client::new();
        let out = Processor::new(&client, 2, CacheContext::default())
            .process(&format!("http://{addr}/"), true, Instant::now())
            .await
            .unwrap();
        let v: Value = serde_json::from_str(&out).unwrap();

        assert!(v["apis"].get("/api/from-chunk").is_some());
        assert!(v["candidates"].get("/api/from-manifest").is_some());
        assert_eq!(v["manifests_scanned"], 1);
    }
}
