//! Recursive asset fetcher.
//!
//! The processor gives this module initial `AssetRef`s. Fetch keeps a bounded
//! breadth-first queue, reads each static asset, scans it for more references,
//! and merges findings back into the caller's `FindingsBuilder`.
//!
//! Asset caching is revision-aware: the same URL can produce different scanned
//! data across builds, so the processed asset cache is scoped by cache key.

use crate::discover::{self, AssetRef, AssetSource, DocumentScan};
use crate::framework::{self, FrameworkConfig};
use crate::scan::FindingsBuilder;

use super::cache::{self, AssetData};
use super::net;
use futures_util::{stream::FuturesUnordered, StreamExt};
use lru::LruCache;
use reqwest::header::{HeaderMap, ETAG, IF_MODIFIED_SINCE, IF_NONE_MATCH, LAST_MODIFIED};
use reqwest::{Client, StatusCode};
use std::{
    collections::VecDeque,
    num::NonZeroUsize,
    sync::atomic::{AtomicBool, Ordering},
    sync::{Arc, RwLock},
    time::Instant,
};
use url::Url;

const ASSET_MEMORY_CACHE_MAX_ENTRIES: usize = 1024;
pub const MAX_TOTAL_ASSETS: usize = 2048;
static FIRST_ASSET_RESPONSE_TRACED: AtomicBool = AtomicBool::new(false);

pub type AssetMemoryCache = Arc<RwLock<LruCache<String, (Arc<AssetData>, Instant)>>>;

pub fn asset_memory_cache() -> AssetMemoryCache {
    Arc::new(RwLock::new(LruCache::new(
        NonZeroUsize::new(ASSET_MEMORY_CACHE_MAX_ENTRIES).expect("nonzero cache size"),
    )))
}

#[derive(Default)]
pub struct AssetScanOptions {
    pub concurrency: usize,
    pub use_processed_cache: bool,
    pub cache_key: Option<String>,
    pub allow_private: bool,
    pub memory: Option<AssetMemoryCache>,
    /// Framework config extracted from the root HTML document. Sub-resources
    /// can't host their own page config, so this is how payloads reconstruct
    /// framework routes consistently.
    pub framework_config: FrameworkConfig,
}

#[derive(Default)]
pub struct AssetScanStats {
    pub discovered: usize,
    pub memory_hits: usize,
    pub failed: usize,
    pub unauthorized: usize,
    pub capped: bool,
    pub failed_urls: Vec<Url>,
}

#[derive(Clone, Copy, Debug)]
pub(crate) enum FetchFailure {
    Unauthorized,
    Other,
}

struct ScannedAsset {
    asset: Arc<AssetData>,
    memory_hit: bool,
}

enum FetchedBody {
    Body(Box<DocumentScan>, cache::AssetValidators),
    NotModified,
}

pub async fn scan_assets(
    client: Client,
    initial: impl IntoIterator<Item = AssetRef>,
    opts: AssetScanOptions,
    out: &mut FindingsBuilder,
) -> AssetScanStats {
    let mut stats = AssetScanStats::default();
    let mut visited = rustc_hash::FxHashSet::default();
    let mut queue = VecDeque::new();
    enqueue_assets(initial, &mut visited, &mut queue, &mut stats);

    let mut fetched = FuturesUnordered::new();
    let concurrency = opts.concurrency.max(1);

    loop {
        while fetched.len() < concurrency {
            let Some(asset) = queue.pop_front() else {
                break;
            };
            fetched.push(fetch_scan(
                client.clone(),
                asset,
                opts.use_processed_cache,
                opts.cache_key.as_deref(),
                opts.allow_private,
                opts.memory.clone(),
                opts.framework_config.clone(),
            ));
        }

        let Some(res) = fetched.next().await else {
            break;
        };
        match res {
            Ok(result) => {
                if result.memory_hit {
                    stats.memory_hits += 1;
                }
                out.extend(result.asset.findings.clone());
                enqueue_assets(
                    result.asset.assets.iter().cloned(),
                    &mut visited,
                    &mut queue,
                    &mut stats,
                );
            }
            Err((asset, reason)) => {
                stats.failed += 1;
                if matches!(reason, FetchFailure::Unauthorized) {
                    stats.unauthorized += 1;
                }
                stats.failed_urls.push(asset.url);
            }
        }
    }

    stats.discovered = visited.len();
    stats
}

// Keep recursive discovery bounded. The visited set is both a dedupe mechanism
// and the cap counter, so cyclic chunk references cannot grow the queue forever.
fn enqueue_assets(
    assets: impl IntoIterator<Item = AssetRef>,
    visited: &mut rustc_hash::FxHashSet<Url>,
    queue: &mut VecDeque<AssetRef>,
    stats: &mut AssetScanStats,
) {
    let mut pending = Vec::new();
    for asset in assets {
        if visited.len() >= MAX_TOTAL_ASSETS {
            if !visited.contains(&asset.url) {
                stats.capped = true;
            }
        } else if visited.insert(asset.url.clone()) {
            pending.push(asset);
        }
    }
    pending.sort_by_key(asset_priority);
    queue.extend(pending);
}

fn asset_priority(asset: &AssetRef) -> u8 {
    match (asset.source, asset.kind) {
        (AssetSource::NextManifest | AssetSource::FrameworkManifest, _) => 0,
        (_, discover::AssetKind::Manifest) => 1,
        (AssetSource::HtmlScript | AssetSource::HtmlPreload, discover::AssetKind::Script) => 2,
        (_, discover::AssetKind::Payload) => 3,
        (AssetSource::DynamicImport | AssetSource::NewUrl, discover::AssetKind::Script) => 4,
        (_, discover::AssetKind::Script) => {
            let path = asset.url.path();
            if path.contains("app") || path.contains("page") {
                5
            } else if is_low_signal_script_path(path) {
                8
            } else {
                6
            }
        }
    }
}

fn is_low_signal_script_path(path: &str) -> bool {
    [
        "vendor",
        "vendors",
        "framework",
        "runtime",
        "webpack",
        "polyfill",
        "node_modules",
        "analytics",
    ]
    .iter()
    .any(|fragment| path.contains(fragment))
}

async fn fetch_scan(
    client: Client,
    asset: AssetRef,
    use_cache: bool,
    cache_key: Option<&str>,
    allow_private: bool,
    memory: Option<AssetMemoryCache>,
    framework_config: FrameworkConfig,
) -> Result<ScannedAsset, (AssetRef, FetchFailure)> {
    let mut cached = None;
    if use_cache {
        if let Some(asset_data) = read_memory_asset(memory.as_ref(), &asset.url, cache_key) {
            return Ok(ScannedAsset {
                asset: asset_data,
                memory_hit: true,
            });
        }
        if let Some(asset_data) = cache::read_asset_cached(&asset.url, cache_key) {
            if asset_data.age_secs < cache::CACHE_FRESH_SECS {
                let asset_data = Arc::new(asset_data.data);
                write_memory_asset(memory.as_ref(), &asset.url, cache_key, asset_data.clone());
                return Ok(ScannedAsset {
                    asset: asset_data,
                    memory_hit: false,
                });
            }
            cached = Some(asset_data);
        }
    }

    let validators = cached.as_ref().map(|asset_data| &asset_data.validators);
    match fetch_asset_body(
        &client,
        asset.clone(),
        allow_private,
        validators,
        framework_config,
        use_cache,
    )
    .await
    .map_err(|reason| (asset.clone(), reason))?
    {
        FetchedBody::NotModified => {
            let cached = cached.ok_or_else(|| (asset.clone(), FetchFailure::Other))?;
            cache::write_asset_with_validators(
                &asset.url,
                &cached.data,
                cache_key,
                &cached.validators,
            );
            let asset_data = Arc::new(cached.data);
            write_memory_asset(memory.as_ref(), &asset.url, cache_key, asset_data.clone());
            Ok(ScannedAsset {
                asset: asset_data,
                memory_hit: false,
            })
        }
        FetchedBody::Body(scan, validators) => {
            let asset_data = Arc::new(*scan);
            if use_cache {
                cache::write_asset_with_validators(&asset.url, &asset_data, cache_key, &validators);
                write_memory_asset(memory.as_ref(), &asset.url, cache_key, asset_data.clone());
            }
            Ok(ScannedAsset {
                asset: asset_data,
                memory_hit: false,
            })
        }
    }
}

fn read_memory_asset(
    memory: Option<&AssetMemoryCache>,
    url: &Url,
    cache_key: Option<&str>,
) -> Option<Arc<AssetData>> {
    let memory = memory?;
    let key = memory_key(url, cache_key);
    let mut entries = memory.write().ok()?;
    let (asset, written) = entries.get(&key).cloned()?;
    if written.elapsed().as_secs() < cache::CACHE_FRESH_SECS {
        Some(asset)
    } else {
        entries.pop(&key);
        None
    }
}

fn write_memory_asset(
    memory: Option<&AssetMemoryCache>,
    url: &Url,
    cache_key: Option<&str>,
    asset: Arc<AssetData>,
) {
    if let Some(memory) = memory {
        if let Ok(mut entries) = memory.write() {
            entries.put(memory_key(url, cache_key), (asset, Instant::now()));
        }
    }
}

fn memory_key(url: &Url, cache_key: Option<&str>) -> String {
    cache_key
        .map(|key| format!("{key}\n{}", url.as_str()))
        .unwrap_or_else(|| url.as_str().to_string())
}

async fn fetch_asset_body(
    client: &Client,
    asset: AssetRef,
    allow_private: bool,
    validators: Option<&cache::AssetValidators>,
    framework_config: FrameworkConfig,
    use_hash_cache: bool,
) -> Result<FetchedBody, FetchFailure> {
    let mut current_url = asset.url.clone();
    let mut redirects = 0;
    let response = loop {
        net::validate_request_url(&current_url, allow_private)
            .await
            .map_err(|_| FetchFailure::Other)?;
        let mut request = client.get(current_url.clone());
        for (name, value) in framework::request_headers(&current_url) {
            request = request.header(name, value);
        }
        if let Some(validators) = validators {
            if let Some(etag) = &validators.etag {
                request = request.header(IF_NONE_MATCH, etag);
            }
            if let Some(last_modified) = &validators.last_modified {
                request = request.header(IF_MODIFIED_SINCE, last_modified);
            }
        }

        let response = request.send().await.map_err(|_| FetchFailure::Other)?;
        if response.status().is_redirection() {
            if redirects >= net::MAX_REDIRECTS {
                return Err(FetchFailure::Other);
            }
            let Some(next) = net::redirect_target(&response) else {
                break response;
            };
            if current_url == next {
                return Err(FetchFailure::Other);
            }
            redirects += 1;
            current_url = next;
            continue;
        }
        break response;
    };
    if !FIRST_ASSET_RESPONSE_TRACED.swap(true, Ordering::Relaxed) {
        net::trace_response_version("asset", &current_url, &response);
    }
    let status = response.status();
    if status == StatusCode::NOT_MODIFIED {
        // The cached scan result is still valid; callers refresh the validator
        // sidecar timestamp without reparsing the asset body.
        return Ok(FetchedBody::NotModified);
    }
    if !status.is_success() {
        if matches!(
            asset.source,
            AssetSource::NextManifest | AssetSource::FrameworkManifest
        ) {
            // Framework deployments commonly omit optional manifests.
            // Treat that as an empty document so a missing manifest does not
            // make the whole scan look incomplete.
            return Ok(FetchedBody::Body(
                Box::default(),
                cache::AssetValidators::default(),
            ));
        }
        return Err(match status {
            StatusCode::UNAUTHORIZED | StatusCode::FORBIDDEN => FetchFailure::Unauthorized,
            _ => FetchFailure::Other,
        });
    }

    let validators = asset_validators(response.headers());
    let kind = asset.document_kind();
    let body = net::read_limited(response)
        .await
        .map_err(|_| FetchFailure::Other)?;
    let findings_hash =
        (use_hash_cache && kind == discover::DocumentKind::Script).then(|| cache::body_hash(&body));
    let cached_findings = findings_hash.and_then(|hash| cache::read_findings_by_hash(hash, kind));
    let had_cached_findings = cached_findings.is_some();
    let scan_url = current_url;
    let scan = tokio::task::spawn_blocking(move || {
        discover::scan_document_with_config_and_findings(
            &body,
            &scan_url,
            kind,
            framework_config.as_next(),
            cached_findings,
        )
    })
    .await
    .map_err(|_| FetchFailure::Other)?;
    if let Some(hash) = findings_hash {
        if !had_cached_findings {
            cache::write_findings_by_hash(hash, kind, &scan.findings);
        }
    }
    Ok(FetchedBody::Body(Box::new(scan), validators))
}

fn asset_validators(headers: &HeaderMap) -> cache::AssetValidators {
    cache::AssetValidators {
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
    use crate::discover::AssetKind;
    use std::sync::Arc;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    #[tokio::test]
    async fn memory_cached_assets_keep_recursive_refs() {
        let addr = serve(2, |req| {
            if req.starts_with("GET /_next/static/chunks/b.js ") {
                r#"fetch("/api/b")"#
            } else {
                r#"fetch("/api/a");"static/chunks/b.js""#
            }
        })
        .await;

        let client = Client::new();
        let memory = asset_memory_cache();
        let initial = script_asset(format!("http://{addr}/_next/static/chunks/a.js"));

        let mut first = FindingsBuilder::default();
        let first_stats = scan_assets(
            client.clone(),
            [initial.clone()],
            AssetScanOptions {
                concurrency: 1,
                use_processed_cache: true,
                cache_key: Some("b1".into()),
                allow_private: true,
                memory: Some(memory.clone()),
                ..Default::default()
            },
            &mut first,
        )
        .await;
        assert_eq!(first_stats.discovered, 2);
        let first_apis = first.finish().api_map();
        assert!(first_apis.contains_key("/api/a"));
        assert!(first_apis.contains_key("/api/b"));

        let mut second = FindingsBuilder::default();
        let second_stats = scan_assets(
            client,
            [initial],
            AssetScanOptions {
                concurrency: 1,
                use_processed_cache: true,
                cache_key: Some("b1".into()),
                allow_private: true,
                memory: Some(memory),
                ..Default::default()
            },
            &mut second,
        )
        .await;
        assert_eq!(second_stats.discovered, 2);
        assert_eq!(second_stats.memory_hits, 2);
        let second_apis = second.finish().api_map();
        assert!(second_apis.contains_key("/api/a"));
        assert!(second_apis.contains_key("/api/b"));
    }

    #[tokio::test]
    async fn recursive_discovery_is_not_limited_to_fixed_rounds() {
        let addr = serve(6, |req| {
            if req.starts_with("GET /_next/static/chunks/a.js ") {
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
            }
        })
        .await;

        let client = Client::new();
        let initial = script_asset(format!("http://{addr}/_next/static/chunks/a.js"));
        let mut found = FindingsBuilder::default();
        let stats = scan_assets(
            client,
            [initial],
            AssetScanOptions {
                concurrency: 2,
                use_processed_cache: false,
                cache_key: None,
                allow_private: true,
                memory: None,
                ..Default::default()
            },
            &mut found,
        )
        .await;

        assert_eq!(stats.discovered, 6);
        assert!(found.finish().api_map().contains_key("/api/f"));
    }

    fn script_asset(url: String) -> AssetRef {
        AssetRef {
            url: Url::parse(&url).unwrap(),
            kind: AssetKind::Script,
            source: AssetSource::Literal,
        }
    }

    async fn serve(
        requests: usize,
        handler: impl Fn(&str) -> &'static str + Send + Sync + 'static,
    ) -> std::net::SocketAddr {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let handler = Arc::new(handler);
        tokio::spawn(async move {
            for _ in 0..requests {
                let (mut socket, _) = listener.accept().await.unwrap();
                let handler = handler.clone();
                tokio::spawn(async move {
                    let mut buf = [0; 1024];
                    let n = socket.read(&mut buf).await.unwrap();
                    let body = handler(std::str::from_utf8(&buf[..n]).unwrap());
                    let response = format!(
                        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                        body.len(),
                        body
                    );
                    socket.write_all(response.as_bytes()).await.unwrap();
                });
            }
        });
        addr
    }
}
