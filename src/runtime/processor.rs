//! Scan lifecycle orchestration.
//!
//! `Processor` is the runtime boundary between network/cache concerns and pure
//! scanning. The public flow is intentionally staged: plan the request, check
//! processed cache, load the root page, scan the root document, recursively scan
//! assets, then build display output.

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

struct RequestPlan {
    original_base: Url,
    request_base: Url,
    cache_path: PathBuf,
}

struct LoadedPage {
    html: bytes::Bytes,
    final_base: Url,
}

// A scan may reuse a processed result either before network I/O (`fresh`/`stale`)
// or after reading the root page when the page revision matches (`hit`).
struct ScanOutcome {
    output: Output,
    used_revision_cache: bool,
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
        let active_cache = self.cache_for_request(no_cache);
        let plan = RequestPlan::new(url, &active_cache)?;

        if !no_cache {
            if let Some(output) =
                self.read_processed_cache(&plan.cache_path, url, t0, &active_cache)?
            {
                return Ok(output);
            }
        }

        let outcome = self
            .scan_request(&plan, !no_cache, Some(t0), &active_cache)
            .await?;
        if !no_cache && !outcome.used_revision_cache {
            write_caches(
                &plan.cache_path,
                &outcome.output,
                url,
                active_cache.memory.clone(),
            )?;
        }
        Ok(outcome.output)
    }

    pub async fn refresh(&self, url: &str) -> Result<()> {
        let plan = RequestPlan::new(url, &self.cache)?;
        let outcome = self.scan_request(&plan, true, None, &self.cache).await?;
        write_caches(
            &plan.cache_path,
            &outcome.output,
            url,
            self.cache.memory.clone(),
        )
    }

    fn cache_for_request(&self, no_cache: bool) -> CacheContext {
        if no_cache {
            CacheContext {
                allow_private: self.cache.allow_private,
                ..CacheContext::default()
            }
        } else {
            self.cache.clone()
        }
    }

    fn read_processed_cache(
        &self,
        cache_path: &Path,
        url: &str,
        t0: Instant,
        cache_ctx: &CacheContext,
    ) -> Result<Option<Output>> {
        let Some((json, age)) =
            cache::read_any_bytes(cache_path).filter(|(_, age)| *age < CACHE_STALE_SECS)
        else {
            return Ok(None);
        };

        let status = if age < CACHE_FRESH_SECS {
            "fresh"
        } else {
            spawn_refresh(
                self.client.clone(),
                self.concurrency,
                url,
                cache_ctx.clone(),
            );
            "stale"
        };

        Ok(Some(serde_json::from_slice::<Output>(&json)?.mark(
            Some(t0),
            status,
            Some(age),
        )))
    }

    // This is the canonical scan pipeline. Keep cache lookup, page loading,
    // asset recursion, and output construction as separate steps so each policy
    // can be reasoned about independently.
    async fn scan_request(
        &self,
        plan: &RequestPlan,
        use_cache: bool,
        t0: Option<Instant>,
        cache_ctx: &CacheContext,
    ) -> Result<ScanOutcome> {
        let page = self.load_page(plan, use_cache, cache_ctx).await?;
        let root_scan = scan_root_document(page.html, page.final_base).await?;
        let mut found = root_scan.findings;
        let mut initial_assets = root_scan.assets;
        let revision = root_scan
            .revision
            .clone()
            .or_else(|| Some(cache::fingerprint_assets(&initial_assets)));

        if let (true, Some(revision), Some(t0)) = (use_cache, revision.as_deref(), t0) {
            if let Some(bytes) = cache::read_revision_bytes(&plan.cache_path, Some(revision)) {
                return Ok(ScanOutcome {
                    output: serde_json::from_slice::<Output>(&bytes)?.mark(Some(t0), "hit", None),
                    used_revision_cache: true,
                });
            }
        }

        let asset_stats = fetch::scan_assets(
            self.client.clone(),
            initial_assets.drain(..),
            fetch::AssetScanOptions {
                concurrency: self.concurrency,
                use_processed_cache: use_cache,
                cache_key: revision.clone(),
                allow_private: cache_ctx.allow_private,
                memory: cache_ctx.assets.clone(),
            },
            &mut found,
        )
        .await;
        found.finalize();

        Ok(ScanOutcome {
            output: Output {
                apis: found.apis,
                routes: found.routes,
                candidates: found.candidates,
                revision,
                cache: "miss".into(),
                cache_age_secs: None,
                elapsed_us: t0.map(|t| t.elapsed().as_micros()),
                warnings: warnings_from_assets(&asset_stats),
            },
            used_revision_cache: false,
        })
    }

    async fn load_page(
        &self,
        plan: &RequestPlan,
        use_cache: bool,
        cache_ctx: &CacheContext,
    ) -> Result<LoadedPage> {
        if use_cache {
            if let Some((body, final_base)) = cache::read_page(&plan.request_base) {
                return Ok(LoadedPage {
                    html: bytes::Bytes::from(body),
                    final_base,
                });
            }
        }

        let response = net::get_limited(
            self.client,
            plan.request_base.clone(),
            cache_ctx.allow_private,
        )
        .await?;
        let final_base = response.url().clone();
        remember_redirect(
            cache_ctx.redirects.as_ref(),
            &plan.original_base,
            &final_base,
        );
        let html = net::read_limited(response).await?;
        if use_cache {
            cache::write_page(&plan.request_base, &final_base, &html);
        }
        Ok(LoadedPage { html, final_base })
    }
}

impl RequestPlan {
    fn new(url: &str, cache: &CacheContext) -> Result<Self, url::ParseError> {
        let original_base = Url::parse(url)?;
        let request_base = redirected_base(cache.redirects.as_ref(), &original_base)
            .unwrap_or_else(|| original_base.clone());
        let cache_path = cache::path_for(&original_base);
        Ok(Self {
            original_base,
            request_base,
            cache_path,
        })
    }
}

async fn scan_root_document(html: bytes::Bytes, final_base: Url) -> Result<discover::DocumentScan> {
    tokio::task::spawn_blocking(move || {
        discover::scan_document(&html, &final_base, DocumentKind::Html)
    })
    .await
    .map_err(RuntimeError::from)
}

fn warnings_from_assets(asset_stats: &fetch::AssetScanStats) -> Vec<String> {
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
    warnings
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
