use crate::discover::{self, DocumentKind};
use crate::scan::{ApiMap, CandidateMap, RouteMap};

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
    #[serde(default, skip_serializing_if = "RouteMap::is_empty")]
    pub routes: RouteMap,
    #[serde(default, skip_serializing_if = "CandidateMap::is_empty")]
    pub candidates: CandidateMap,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub revision: Option<String>,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub cache: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cache_age_secs: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub elapsed_us: Option<u128>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub warnings: Vec<String>,
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
    pub assets: Option<fetch::AssetMemoryCache>,
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
            .is_some()
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
            if cache_path.is_some() {
                cache::write_page(request_base, &final_base, &html);
            }
            (html, final_base)
        };
        let scan_base = final_base.clone();
        let root_scan = tokio::task::spawn_blocking(move || {
            discover::scan_document(&html, &scan_base, DocumentKind::Html)
        })
        .await?;
        let mut found = root_scan.findings;
        let mut initial_assets = root_scan.assets;
        let revision = root_scan
            .revision
            .clone()
            .or_else(|| Some(cache::fingerprint_assets(&initial_assets)));

        if let (Some(path), Some(revision), Some(t0)) = (cache_path, revision.as_deref(), t0) {
            if let Some(bytes) = cache::read_revision_bytes(path, Some(revision)) {
                return Ok((
                    serde_json::from_slice::<Output>(&bytes)?.mark(Some(t0), "hit", None),
                    true,
                ));
            }
        }

        let asset_options = || fetch::AssetScanOptions {
            concurrency: self.concurrency,
            use_processed_cache: cache_path.is_some(),
            cache_key: revision.clone(),
            allow_private: cache_ctx.allow_private,
            memory: cache_ctx.assets.clone(),
        };
        let asset_stats = fetch::scan_assets(
            self.client.clone(),
            initial_assets.drain(..),
            asset_options(),
            &mut found,
        )
        .await;
        found.finalize();
        let mut warnings = Vec::new();
        if asset_stats.failed > 0 {
            warnings.push(format!(
                "failed to read {} assets; results may be incomplete",
                asset_stats.failed
            ));
        }
        if asset_stats.capped {
            warnings.push(format!(
                "stopped after {} discovered assets; results may be incomplete",
                asset_stats.discovered
            ));
        }

        Ok((
            Output {
                apis: found.apis,
                routes: found.routes,
                candidates: found.candidates,
                revision,
                cache: "miss".into(),
                cache_age_secs: None,
                elapsed_us: t0.map(|t| t.elapsed().as_micros()),
                warnings,
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
    cache::write_with_revision(cache_path, &cached, out.revision.as_deref());
    if let Some(memory) = memory {
        let body = Arc::from(out.to_json_string()?);
        write_memory(&memory, url.to_string(), body);
    }
    Ok(())
}

fn prune_memory(entries: &mut LruCache<String, (Body, Instant)>, now: Instant) {
    let stale = entries
        .iter()
        .filter(|(_, (_, written))| {
            now.saturating_duration_since(*written).as_secs() >= CACHE_STALE_SECS
        })
        .map(|(url, _)| url.clone())
        .collect::<Vec<_>>();
    for url in stale {
        entries.pop(&url);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    };
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    #[tokio::test]
    async fn build_manifest_seeds_extra_chunks() {
        let addr = serve(4, |req| {
            if req.starts_with("GET /_next/static/b1/_buildManifest.js ") {
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
                    r#"<script id="__NEXT_DATA__" type="application/json">{"buildId":"b1"}</script>"#,
                )
            }
        })
        .await;
        let client = Client::new();
        let out = Processor::new(
            &client,
            2,
            CacheContext {
                allow_private: true,
                ..CacheContext::default()
            },
        )
        .process_for_display(&format!("http://{addr}/"), true, Instant::now())
        .await
        .unwrap();

        assert!(out.apis.contains_key("/api/from-chunk"));
        assert!(out.candidates.contains_key("/api/from-manifest"));
    }

    #[tokio::test]
    async fn generic_html_script_assets_are_scanned() {
        let addr = serve(2, |req| {
            if req.starts_with("GET /assets/app.js ") {
                ("200 OK", r#"fetch("/api/from-generic-script")"#)
            } else {
                (
                    "200 OK",
                    r#"<script type="module" src="/assets/app.js"></script>"#,
                )
            }
        })
        .await;
        let client = Client::new();
        let out = Processor::new(
            &client,
            2,
            CacheContext {
                allow_private: true,
                ..CacheContext::default()
            },
        )
        .process_for_display(&format!("http://{addr}/"), true, Instant::now())
        .await
        .unwrap();

        assert!(out.apis.contains_key("/api/from-generic-script"));
    }

    #[tokio::test]
    async fn asset_fetch_failures_are_reported_as_warnings() {
        let addr = serve(3, |req| {
            if req.starts_with("GET /_next/static/chunks/app/ok.js ") {
                ("200 OK", r#"fetch("/api/ok")"#)
            } else if req.starts_with("GET /_next/static/chunks/app/missing.js ") {
                ("404 Not Found", "")
            } else {
                (
                    "200 OK",
                    r#"<script src="/_next/static/chunks/app/ok.js"></script><script src="/_next/static/chunks/app/missing.js"></script>"#,
                )
            }
        })
        .await;
        let client = Client::new();
        let out = Processor::new(
            &client,
            2,
            CacheContext {
                allow_private: true,
                ..CacheContext::default()
            },
        )
        .process_for_display(&format!("http://{addr}/"), true, Instant::now())
        .await
        .unwrap();

        assert!(out.apis.contains_key("/api/ok"));
        assert_eq!(
            out.warnings,
            vec!["failed to read 1 assets; results may be incomplete"]
        );
    }

    #[tokio::test]
    async fn no_cache_bypasses_page_cache() {
        let count = Arc::new(AtomicUsize::new(0));
        let addr = serve(2, move |_| match count.fetch_add(1, Ordering::Relaxed) {
            0 => ("200 OK", r#"<script>fetch("/api/first")</script>"#),
            _ => ("200 OK", r#"<script>fetch("/api/second")</script>"#),
        })
        .await;
        let client = Client::new();
        let processor = Processor::new(
            &client,
            2,
            CacheContext {
                allow_private: true,
                ..CacheContext::default()
            },
        );
        let url = format!("http://{addr}/");

        let first = processor
            .process_for_display(&url, true, Instant::now())
            .await
            .unwrap();
        let second = processor
            .process_for_display(&url, true, Instant::now())
            .await
            .unwrap();

        assert!(first.apis.contains_key("/api/first"));
        assert!(second.apis.contains_key("/api/second"));
        assert!(!second.apis.contains_key("/api/first"));
    }

    async fn serve(
        requests: usize,
        handler: impl Fn(&str) -> (&'static str, &'static str) + Send + Sync + 'static,
    ) -> std::net::SocketAddr {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let handler = Arc::new(handler);
        tokio::spawn(async move {
            for _ in 0..requests {
                let (mut socket, _) = listener.accept().await.unwrap();
                let handler = handler.clone();
                tokio::spawn(async move {
                    let mut buf = [0; 2048];
                    let n = socket.read(&mut buf).await.unwrap();
                    let (status, body) = handler(std::str::from_utf8(&buf[..n]).unwrap());
                    let response = format!(
                        "HTTP/1.1 {status}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                        body.len()
                    );
                    socket.write_all(response.as_bytes()).await.unwrap();
                });
            }
        });
        addr
    }
}
