//! Site scan orchestration and scan output encoding.

use super::codec::{document, put_opt_string, put_string, put_u32, Reader as BinaryReader};
use super::{cache, fetch, fetch_root, http::Client, net};
use crate::discover::{self, DocumentKind};
use crate::scan::{Evidence, EvidenceKind, Shape};
use crate::url::Url;
use std::collections::BTreeMap;
use std::sync::Arc;
use std::{fmt, time::Instant};

type Result<T, E = RuntimeError> = std::result::Result<T, E>;
pub use fetch::MAX_TOTAL_ASSETS;

#[derive(Debug)]
pub enum RuntimeError {
    Net(net::NetError),
    Url(crate::url::ParseError),
    Join(tokio::task::JoinError),
}

impl fmt::Display for RuntimeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Net(err) => err.fmt(f),
            Self::Url(err) => err.fmt(f),
            Self::Join(err) => err.fmt(f),
        }
    }
}

impl std::error::Error for RuntimeError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Net(err) => Some(err),
            Self::Url(err) => Some(err),
            Self::Join(err) => Some(err),
        }
    }
}

impl From<net::NetError> for RuntimeError {
    fn from(err: net::NetError) -> Self {
        Self::Net(err)
    }
}

impl From<crate::url::ParseError> for RuntimeError {
    fn from(err: crate::url::ParseError) -> Self {
        Self::Url(err)
    }
}

impl From<tokio::task::JoinError> for RuntimeError {
    fn from(err: tokio::task::JoinError) -> Self {
        Self::Join(err)
    }
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

pub async fn scan_site(
    client: &Client,
    url: &str,
    concurrency: usize,
    allow_private: bool,
    no_cache: bool,
    t0: Instant,
) -> Result<Output> {
    let base = Url::parse(url)?;
    let cache_store = cache::ScanCache::for_base(&base);
    let use_cache = !no_cache;

    if use_cache {
        if let Some((body, age)) = cache_store.read_fresh_binary() {
            if let Some(output) = decode_output_binary(&body) {
                return Ok(output.mark(Some(t0), CacheStatus::Fresh, Some(age)));
            }
        }
    }

    let doc = fetch_root::fetch_root_document(client, url, allow_private).await?;
    let final_base = doc.url;
    let html = doc.body;
    let root_scan = tokio::task::spawn_blocking(move || {
        discover::scan_document(&html, &final_base, DocumentKind::Html)
    })
    .await?;
    let mut found = root_scan.findings;
    let mut initial_assets = root_scan.assets;
    let revision = root_scan.revision.clone();

    if let (true, Some(revision)) = (use_cache, revision.as_deref()) {
        if let Some(bytes) = cache_store.read_stale_binary() {
            if let Some(output) = decode_output_binary(&bytes) {
                if output.revision.as_deref() == Some(revision) {
                    return Ok(output.mark(Some(t0), CacheStatus::RevisionHit, None));
                }
            }
        }
    }

    client.backpressure().set_capacity(concurrency);
    let asset_stats = fetch::scan_assets(
        fetch::ScanEnv {
            client: client.clone(),
            concurrency,
            use_cache,
            cache_key: revision.clone(),
            allow_private,
            site: root_scan.site,
        },
        initial_assets.drain(..),
        &mut found,
    )
    .await;
    let found = found.finish();
    let output = Output {
        apis: collect_apis(&found.evidence),
        revision,
        cache: CacheStatus::Miss,
        cache_age_secs: None,
        elapsed_us: Some(t0.elapsed().as_micros()),
        warnings: warnings_from_assets(&asset_stats),
    };
    if use_cache {
        let cached = output.clone().mark(None, CacheStatus::Stored, None);
        cache_store.write_binary_deferred(Arc::from(encode_output_binary(&cached)));
    }
    Ok(output)
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

const OUTPUT_BINARY_MAGIC: &[u8; 8] = b"HIFI3\0\0\0";

pub(crate) fn encode_output_binary(out: &Output) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(out.apis.len().saturating_mul(48) + 128);
    bytes.extend_from_slice(OUTPUT_BINARY_MAGIC);
    put_opt_string(&mut bytes, out.revision.as_deref());
    put_u32(&mut bytes, out.apis.len());
    for api in &out.apis {
        put_string(&mut bytes, &api.path);
        document::put_shape(&mut bytes, &api.shape);
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

trait ReaderExt {
    fn shape(&mut self) -> Option<Shape>;
}

impl<'a> ReaderExt for BinaryReader<'a> {
    fn shape(&mut self) -> Option<Shape> {
        document::read_shape(self)
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
        let out = scan_site(
            &client,
            &format!("http://{addr}/"),
            2,
            true,
            true,
            Instant::now(),
        )
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
        let out = scan_site(
            &client,
            &format!("http://{addr}/"),
            2,
            true,
            true,
            Instant::now(),
        )
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
        let out = scan_site(
            &client,
            &format!("http://{addr}/"),
            2,
            true,
            true,
            Instant::now(),
        )
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
        let url = format!("http://{addr}/");

        let first = scan_site(&client, &url, 2, true, true, Instant::now())
            .await
            .unwrap();
        let second = scan_site(&client, &url, 2, true, true, Instant::now())
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
        let url = format!("http://{addr}/");

        let first = scan_site(&client, &url, 2, true, false, Instant::now())
            .await
            .unwrap();
        let second = scan_site(&client, &url, 2, true, false, Instant::now())
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
