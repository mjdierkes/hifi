//! Scan lifecycle orchestration.
//!
//! `Processor` is the runtime boundary between network/cache concerns and pure
//! scanning. The public flow is intentionally staged: plan the request, check
//! processed cache, load the root page, scan the root document, recursively scan
//! assets, then build display output.

use crate::discover::{self, DocumentKind};
use crate::scan::{Evidence, EvidenceKind, Shape};

use super::{cache, fetch, http::Client, net};
use crate::url::Url;
use std::collections::BTreeMap;
use std::{sync::Arc, time::Instant};
use thiserror::Error;

type Result<T, E = RuntimeError> = std::result::Result<T, E>;

#[derive(Debug, Error)]
pub enum RuntimeError {
    #[error(transparent)]
    Net(#[from] net::NetError),
    #[error(transparent)]
    Url(#[from] crate::url::ParseError),
    #[error(transparent)]
    Join(#[from] tokio::task::JoinError),
}

#[derive(Clone, Debug)]
pub struct Output {
    pub apis: Vec<Api>,
    pub revision: Option<String>,
    pub cache: CacheStatus,
    pub cache_age_secs: Option<u64>,
    pub elapsed_us: Option<u128>,
    pub warnings: Vec<String>,
}

#[derive(Clone, Debug)]
pub struct Api {
    pub path: String,
    pub shape: Shape,
}

impl Output {
    pub(crate) fn mark(
        mut self,
        t0: Option<Instant>,
        status: CacheStatus,
        age_secs: Option<u64>,
    ) -> Self {
        self.cache = status;
        self.cache_age_secs = age_secs;
        self.elapsed_us = t0.map(|t| t.elapsed().as_micros());
        self
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum CacheStatus {
    #[default]
    Stored,
    Fresh,
    RevisionHit,
    Miss,
}

pub struct Processor<'a> {
    client: &'a Client,
    concurrency: usize,
    allow_private: bool,
}

struct RequestPlan {
    original_base: Url,
    cache: cache::ScanCache,
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
    pub fn new(client: &'a Client, concurrency: usize, allow_private: bool) -> Self {
        Self {
            client,
            concurrency,
            allow_private,
        }
    }

    pub async fn process_for_display(
        &self,
        url: &str,
        no_cache: bool,
        t0: Instant,
    ) -> Result<Output> {
        let plan = RequestPlan::new(url)?;
        let outcome = self
            .scan_request(&plan, !no_cache, Some(t0), self.allow_private)
            .await?;
        if !no_cache && !outcome.used_revision_cache {
            write_caches(&plan.cache, &outcome.output)?;
        }
        Ok(outcome.output)
    }

    // This is the canonical scan pipeline. Keep cache lookup, page loading,
    // asset recursion, and output construction as separate steps so each policy
    // can be reasoned about independently.
    async fn scan_request(
        &self,
        plan: &RequestPlan,
        use_cache: bool,
        t0: Option<Instant>,
        allow_private: bool,
    ) -> Result<ScanOutcome> {
        if use_cache {
            if let Some((body, age)) = plan.cache.read_fresh_binary() {
                if let Some(output) = decode_output_binary(&body) {
                    return Ok(ScanOutcome {
                        output: output.mark(t0, CacheStatus::Fresh, Some(age)),
                        used_revision_cache: true,
                    });
                }
            }
        }

        let page = self.load_page(plan, use_cache, allow_private).await?;
        let root_scan = scan_root_document(page.html, page.final_base).await?;
        let mut found = root_scan.findings;
        let mut initial_assets = root_scan.assets;
        let revision = root_scan.revision.clone();

        // Revision hits happen after the page is read. The root HTML may be
        // new enough to validate the asset graph, so we can reuse processed
        // output without rescanning every static asset.
        if let (true, Some(revision), Some(t0)) = (use_cache, revision.as_deref(), t0) {
            if let Some(bytes) = plan.cache.read_stale_binary() {
                if let Some(output) = decode_output_binary(&bytes) {
                    if output.revision.as_deref() == Some(revision) {
                        return Ok(ScanOutcome {
                            output: output.mark(Some(t0), CacheStatus::RevisionHit, None),
                            used_revision_cache: true,
                        });
                    }
                }
            }
        }

        let asset_stats = fetch::scan_assets(
            self.client.clone(),
            initial_assets.drain(..),
            fetch::AssetScanOptions {
                concurrency: self.concurrency,
                use_processed_cache: use_cache,
                cache_key: revision.clone(),
                allow_private,
                framework_config: root_scan.framework_config.clone(),
            },
            &mut found,
        )
        .await;
        let found = found.finish();

        Ok(ScanOutcome {
            output: Output {
                apis: collect_apis(&found.evidence),
                revision,
                cache: CacheStatus::Miss,
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
        allow_private: bool,
    ) -> Result<LoadedPage> {
        let response =
            net::get_limited(self.client, plan.original_base.clone(), allow_private).await?;
        let final_base = response.url().clone();
        let html = net::read_limited(response).await?;
        let _ = use_cache;
        Ok(LoadedPage { html, final_base })
    }
}

impl RequestPlan {
    fn new(url: &str) -> Result<Self, crate::url::ParseError> {
        let original_base = Url::parse(url)?;
        let scan_cache = cache::ScanCache::for_base(&original_base);
        Ok(Self {
            original_base,
            cache: scan_cache,
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
        let total = asset_stats.failed;
        let auth = asset_stats.unauthorized;
        let message = if auth == total {
            format!(
                "{total} assets blocked by auth (401/403); scan limited to public bundle surface"
            )
        } else if auth > 0 {
            let other = total - auth;
            format!(
                "failed to read {total} assets ({auth} auth-gated, {other} other); results may be incomplete"
            )
        } else {
            format!("failed to read {total} assets; results may be incomplete")
        };
        warnings.push(message);
    }
    if asset_stats.capped {
        warnings.push(format!(
            "stopped after {} discovered assets; results may be incomplete",
            asset_stats.discovered
        ));
    }
    warnings
}

fn collect_apis(evidence: &[Evidence]) -> Vec<Api> {
    let mut merged = BTreeMap::<String, Shape>::new();
    for item in evidence {
        if item.kind != EvidenceKind::Api {
            continue;
        }
        let Some(shape) = &item.shape else {
            continue;
        };
        merged
            .entry(prettify_path(&normalize_path(&item.url)))
            .and_modify(|existing| existing.merge(shape))
            .or_insert_with(|| shape.clone());
    }
    merged
        .into_iter()
        .map(|(path, shape)| Api { path, shape })
        .collect()
}

fn normalize_path(url: &str) -> String {
    let raw = Url::parse(url)
        .map(|u| u.path().to_string())
        .unwrap_or_else(|_| url.split(['?', '#']).next().unwrap_or(url).to_string());
    let trimmed = raw.trim_end_matches('/');
    if trimmed.is_empty() {
        "/".to_string()
    } else if trimmed.starts_with('/') {
        trimmed.to_string()
    } else {
        format!("/{trimmed}")
    }
}

fn prettify_path(path: &str) -> String {
    path.replace("{dynamic}", ":id")
}

fn write_caches(cache_store: &cache::ScanCache, out: &Output) -> Result<()> {
    let cached = out.clone().mark(None, CacheStatus::Stored, None);
    cache_store.write_binary_deferred(Arc::from(encode_output_binary(&cached)));
    Ok(())
}

const OUTPUT_BINARY_MAGIC: &[u8; 8] = b"HIFIOU2\0";

pub(crate) fn encode_output_binary(out: &Output) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(out.apis.len().saturating_mul(48) + 128);
    bytes.extend_from_slice(OUTPUT_BINARY_MAGIC);
    put_opt_string(&mut bytes, out.revision.as_deref());
    put_u32(&mut bytes, out.apis.len());
    for api in &out.apis {
        put_string(&mut bytes, &api.path);
        put_shape(&mut bytes, &api.shape);
    }
    put_u32(&mut bytes, out.warnings.len());
    for warning in &out.warnings {
        put_string(&mut bytes, warning);
    }
    bytes
}

pub(crate) fn decode_output_binary(bytes: &[u8]) -> Option<Output> {
    let mut reader = BinaryReader::new(bytes);
    reader
        .take_exact(OUTPUT_BINARY_MAGIC.len())
        .filter(|magic| *magic == OUTPUT_BINARY_MAGIC)?;
    let revision = reader.opt_string()?;
    let api_len = reader.u32()? as usize;
    let mut apis = Vec::with_capacity(api_len);
    for _ in 0..api_len {
        apis.push(Api {
            path: reader.string()?,
            shape: reader.shape()?,
        });
    }
    let warnings_len = reader.u32()? as usize;
    let mut warnings = Vec::with_capacity(warnings_len);
    for _ in 0..warnings_len {
        warnings.push(reader.string()?);
    }
    reader.finish()?;
    Some(Output {
        apis,
        revision,
        cache: CacheStatus::Stored,
        cache_age_secs: None,
        elapsed_us: None,
        warnings,
    })
}

fn put_shape(bytes: &mut Vec<u8>, shape: &Shape) {
    let (methods, has_body, has_headers, content_types, auth, next_server_action, query_params) =
        shape.binary_parts();
    bytes.push(methods);
    bytes.push(has_body as u8);
    bytes.push(has_headers as u8);
    bytes.push(content_types);
    bytes.push(auth as u8);
    bytes.push(next_server_action as u8);
    put_u32(bytes, query_params.len());
    for param in query_params {
        put_string(bytes, param);
    }
}

use super::wire::{put_opt_string, put_string, put_u32, Reader as BinaryReader};

trait ReaderExt {
    fn shape(&mut self) -> Option<Shape>;
}

impl<'a> ReaderExt for BinaryReader<'a> {
    fn shape(&mut self) -> Option<Shape> {
        let methods = self.u8()?;
        let has_body = self.bool()?;
        let has_headers = self.bool()?;
        let content_types = self.u8()?;
        let auth = self.bool()?;
        let next_server_action = self.bool()?;
        let query_params = self.string_vec()?;
        Some(Shape::from_binary_parts(
            methods,
            has_body,
            has_headers,
            content_types,
            auth,
            next_server_action,
            query_params,
        ))
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
        let addr = serve(6, |req| {
            if req.starts_with("GET /_next/static/b1/_buildManifest.js ") {
                (
                    "200 OK",
                    r#"self.__BUILD_MANIFEST=function(){return{"/extra":["static/chunks/app-extra.js"]}}();const u="/api/from-manifest";"#,
                )
            } else if req.starts_with("GET /_next/static/chunks/app-extra.js ") {
                ("200 OK", r#"fetch("/api/from-chunk",{method:"POST"})"#)
            } else if req.starts_with("GET /_next/static/b1/_ssgManifest.js ")
                || req.starts_with("GET /_next/static/b1/app-build-manifest.json ")
                || req.starts_with("GET /_next/static/b1/_clientReferenceManifest.json ")
            {
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
        let out = Processor::new(&client, 2, true)
            .process_for_display(&format!("http://{addr}/"), true, Instant::now())
            .await
            .unwrap();

        assert!(has_api(&out, "/api/from-chunk"));
    }

    #[tokio::test]
    async fn generic_html_script_assets_are_scanned() {
        let addr = serve(2, |req| {
            if req.starts_with("GET /assets/app.js ") {
                (
                    "200 OK",
                    r#"fetch("/api/from-generic-script"); const hinted="/api/from-html-asset";"#,
                )
            } else {
                (
                    "200 OK",
                    r#"<script type="module" src="/assets/app.js"></script>"#,
                )
            }
        })
        .await;
        let client = Client::new();
        let out = Processor::new(&client, 2, true)
            .process_for_display(&format!("http://{addr}/"), true, Instant::now())
            .await
            .unwrap();

        assert!(has_api(&out, "/api/from-generic-script"));
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
        let out = Processor::new(&client, 2, true)
            .process_for_display(&format!("http://{addr}/"), true, Instant::now())
            .await
            .unwrap();

        assert!(has_api(&out, "/api/ok"));
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
        let processor = Processor::new(&client, 2, true);
        let url = format!("http://{addr}/");

        let first = processor
            .process_for_display(&url, true, Instant::now())
            .await
            .unwrap();
        let second = processor
            .process_for_display(&url, true, Instant::now())
            .await
            .unwrap();

        assert!(has_api(&first, "/api/first"));
        assert!(has_api(&second, "/api/second"));
        assert!(!has_api(&second, "/api/first"));
    }

    #[tokio::test]
    async fn fresh_processed_cache_skips_network() {
        let addr = serve(1, |_| {
            ("200 OK", r#"<script>fetch("/api/cached")</script>"#)
        })
        .await;
        let client = Client::new();
        let processor = Processor::new(&client, 2, true);
        let url = format!("http://{addr}/");

        let first = processor
            .process_for_display(&url, false, Instant::now())
            .await
            .unwrap();
        let second = processor
            .process_for_display(&url, false, Instant::now())
            .await
            .unwrap();

        assert!(has_api(&first, "/api/cached"));
        assert!(has_api(&second, "/api/cached"));
        assert_eq!(second.cache, CacheStatus::Fresh);
    }

    fn has_api(out: &Output, path: &str) -> bool {
        out.apis.iter().any(|api| api.path == path)
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
