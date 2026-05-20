use crate::scan::{self, html};
use crate::scan::{ApiMap, CandidateMap};

use super::{cache, fetch, net};
use lru::LruCache;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::{
    num::NonZeroUsize,
    path::{Path, PathBuf},
    sync::{Arc, RwLock},
    time::Instant,
};
use thiserror::Error;
use url::Url;

pub const CACHE_FRESH_SECS: u64 = 300;
pub const CACHE_STALE_SECS: u64 = 3600;
const MEMORY_CACHE_MAX_ENTRIES: usize = 256;

type Result<T, E = RuntimeError> = std::result::Result<T, E>;
pub type Body = Arc<str>;
pub type MemoryCache = Arc<RwLock<LruCache<String, (Body, Instant)>>>;
pub type RedirectMemory = Arc<RwLock<LruCache<String, Url>>>;

#[derive(Debug, Error)]
pub enum RuntimeError {
    #[error(transparent)]
    Net(#[from] net::NetError),
    #[error(transparent)]
    Json(#[from] serde_json::Error),
    #[error(transparent)]
    Url(#[from] url::ParseError),
    #[error(transparent)]
    Join(#[from] tokio::task::JoinError),
}

#[derive(Clone, Serialize, Deserialize)]
pub struct Output {
    pub apis: ApiMap,
    #[serde(default, skip_serializing_if = "CandidateMap::is_empty")]
    pub candidates: CandidateMap,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub build_id: Option<String>,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub cache: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cache_age_secs: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub elapsed_us: Option<u128>,
}

impl Output {
    pub fn to_json_string(&self) -> Result<String> {
        Ok(serde_json::to_string(self)?)
    }

    fn mark(mut self, t0: Option<Instant>, cache: &str, age_secs: Option<u64>) -> Self {
        self.cache.clear();
        self.cache.push_str(cache);
        self.cache_age_secs = age_secs;
        self.elapsed_us = t0.map(|t| t.elapsed().as_micros());
        self
    }
}

#[derive(Clone, Default)]
pub struct CacheContext {
    pub memory: Option<MemoryCache>,
    pub chunks: Option<fetch::ChunkMemoryCache>,
    pub redirects: Option<RedirectMemory>,
    pub allow_private: bool,
}

pub fn memory_cache() -> MemoryCache {
    Arc::new(RwLock::new(LruCache::new(
        NonZeroUsize::new(MEMORY_CACHE_MAX_ENTRIES).expect("nonzero cache size"),
    )))
}

pub fn redirect_cache() -> RedirectMemory {
    Arc::new(RwLock::new(LruCache::new(
        NonZeroUsize::new(MEMORY_CACHE_MAX_ENTRIES).expect("nonzero cache size"),
    )))
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
        self.process_for_display(url, no_cache, t0)
            .await?
            .to_json_string()
    }

    pub async fn process_for_display(
        &self,
        url: &str,
        no_cache: bool,
        t0: Instant,
    ) -> Result<Output> {
        let no_cache_ctx;
        let active_cache = if no_cache {
            no_cache_ctx = CacheContext {
                allow_private: self.cache.allow_private,
                ..CacheContext::default()
            };
            &no_cache_ctx
        } else {
            &self.cache
        };
        let (base, cache_path, request_base) = request_parts(url, active_cache)?;

        if let Some((json, age)) = (!no_cache)
            .then(|| cache::read_any_bytes(&cache_path))
            .flatten()
            .filter(|(_, age)| *age < CACHE_STALE_SECS)
        {
            let status = if age < CACHE_FRESH_SECS {
                "fresh"
            } else {
                spawn_refresh(
                    self.client.clone(),
                    self.concurrency,
                    url,
                    (*active_cache).clone(),
                );
                "stale"
            };
            return Ok(serde_json::from_slice::<Output>(&json)?.mark(Some(t0), status, Some(age)));
        }

        let (out, cache_hit) = self
            .collect(
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
                &base,
                &request_base,
                Some(cache_path.as_path()),
                None,
                &self.cache,
            )
            .await?;
        write_caches(&cache_path, &out, url, self.cache.memory.clone())
    }

    async fn collect(
        &self,
        original_base: &Url,
        request_base: &Url,
        cache_path: Option<&Path>,
        t0: Option<Instant>,
        cache_ctx: &CacheContext,
    ) -> Result<(Output, bool)> {
        let (html, final_base) = if let Some((body, final_base)) = cache_path
            .is_none()
            .then(|| cache::read_page(request_base))
            .flatten()
        {
            (bytes::Bytes::from(body), final_base)
        } else {
            let response =
                net::get_limited(self.client, request_base.clone(), cache_ctx.allow_private)
                    .await?;
            let final_base = response.url().clone();
            remember_redirect(cache_ctx.redirects.as_ref(), original_base, &final_base);
            let html = net::read_limited(response).await?;
            cache::write_page(request_base, &final_base, &html);
            (html, final_base)
        };
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
                    serde_json::from_slice::<Output>(&bytes)?.mark(Some(t0), "hit", None),
                    true,
                ));
            }
        }

        let html_scan_body = html.clone();
        let html_scan_task = tokio::task::spawn_blocking(move || {
            let mut apis = ApiMap::default();
            let mut candidates = CandidateMap::default();
            scan::scan(&html_scan_body, &mut apis);
            scan::scan_candidates(&html_scan_body, &mut candidates);
            (apis, candidates)
        });
        let mut manifest_apis = ApiMap::default();
        let mut manifest_candidates = CandidateMap::default();
        scan_next_manifests(
            self.client,
            &final_base,
            html_build_id.as_deref(),
            cache_ctx.allow_private,
            &mut manifest_apis,
            &mut manifest_candidates,
            &mut chunks,
        )
        .await;
        let mut apis = ApiMap::default();
        let mut candidates = CandidateMap::default();
        fetch::scan_chunks(
            self.client.clone(),
            chunks.iter().cloned(),
            fetch::ChunkScanOptions {
                concurrency: self.concurrency,
                use_processed_cache: cache_path.is_some(),
                use_bundle_cache: true,
                cache_key: build_id.clone(),
                allow_private: cache_ctx.allow_private,
                memory: cache_ctx.chunks.clone(),
            },
            &mut apis,
            &mut candidates,
        )
        .await;
        let (html_apis, html_candidates) = html_scan_task.await?;
        scan::merge_into(&mut apis, html_apis);
        scan::merge_candidates_into(&mut candidates, html_candidates);
        scan::merge_into(&mut apis, manifest_apis);
        scan::merge_candidates_into(&mut candidates, manifest_candidates);
        for url in apis.keys() {
            candidates.remove(url);
        }

        Ok((
            Output {
                apis,
                candidates,
                build_id,
                cache: "miss".into(),
                cache_age_secs: None,
                elapsed_us: t0.map(|t| t.elapsed().as_micros()),
            },
            false,
        ))
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
        .write()
        .ok()?
        .get(url)
        .cloned()
        .map(|(body, t)| (body, t.elapsed().as_secs()))
}

pub fn write_memory(memory: &MemoryCache, url: String, body: Body) {
    if let Ok(mut entries) = memory.write() {
        let now = Instant::now();
        entries.put(url, (body, now));
        prune_memory(&mut entries, now);
    }
}

async fn scan_next_manifests(
    client: &Client,
    base: &Url,
    build_id: Option<&str>,
    allow_private: bool,
    apis: &mut ApiMap,
    candidates: &mut CandidateMap,
    chunks: &mut Vec<Url>,
) {
    let Some(build_id) = build_id else {
        return;
    };

    for name in ["_buildManifest.js", "_ssgManifest.js"] {
        let Ok(manifest_url) = base.join(&format!("/_next/static/{build_id}/{name}")) else {
            continue;
        };
        let Some(body) = fetch_manifest(client, manifest_url.clone(), allow_private).await else {
            continue;
        };
        scan::scan(&body, apis);
        scan::scan_candidates(&body, candidates);
        chunks.extend(html::extract_chunk_refs(&body, &manifest_url));
    }
}

async fn fetch_manifest(client: &Client, url: Url, allow_private: bool) -> Option<bytes::Bytes> {
    net::get_bytes_limited(client, url, allow_private)
        .await
        .ok()
}

fn redirected_base(redirects: Option<&RedirectMemory>, base: &Url) -> Option<Url> {
    let target = redirects?.write().ok()?.get(&origin_key(base)?).cloned()?;
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
                entries.put(from_key, to_origin);
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
    out: &Output,
    url: &str,
    memory: Option<MemoryCache>,
) -> Result<()> {
    let cached = out.clone().mark(None, "", None);
    cache::write_with_build_id(cache_path, &cached, out.build_id.as_deref());
    if let Some(memory) = memory {
        let body = Arc::from(out.to_json_string()?);
        write_memory(&memory, url.to_string(), body);
    }
    Ok(())
}

fn prune_memory(entries: &mut LruCache<String, (Body, Instant)>, now: Instant) {
    let stale = entries
        .iter()
        .filter_map(|(url, (_, written))| {
            (now.saturating_duration_since(*written).as_secs() >= CACHE_STALE_SECS)
                .then(|| url.clone())
        })
        .collect::<Vec<_>>();
    for url in stale {
        entries.pop(&url);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    #[test]
    fn cache_value_strips_dynamic_fields() {
        let cached = Output {
            apis: ApiMap::default(),
            candidates: CandidateMap::default(),
            build_id: Some("b1".into()),
            cache: "miss".into(),
            cache_age_secs: Some(1),
            elapsed_us: Some(1000),
        }
        .mark(None, "", None);
        let v = serde_json::to_value(&cached).unwrap();
        assert!(v.get("apis").is_some());
        assert!(v.get("build_id").is_some());
        assert!(v.get("cache_age_secs").is_none());
        assert!(v.get("elapsed_us").is_none());
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
        let out = Processor::new(
            &client,
            2,
            CacheContext {
                allow_private: true,
                ..CacheContext::default()
            },
        )
        .process(&format!("http://{addr}/"), true, Instant::now())
        .await
        .unwrap();
        let v: Value = serde_json::from_str(&out).unwrap();

        assert!(v["apis"].get("/api/from-chunk").is_some());
        assert!(v["candidates"].get("/api/from-manifest").is_some());
    }
}
