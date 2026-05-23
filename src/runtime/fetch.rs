//! Recursive asset fetcher.
//!
//! The engine gives this module initial `AssetRef`s. Fetch keeps a bounded
//! breadth-first queue, reads each static asset, scans it for more references,
//! and merges findings back into the caller's `FindingsBuilder`.
//!
//! Asset caching is revision-aware: the same URL can produce different scanned
//! data across builds, so the processed asset cache is scoped by cache key.

use crate::discover::{self, AssetRef, AssetSource, DocumentScan};
use crate::framework::{self, DetectedSite};
use crate::scan::FindingsBuilder;

use super::cache::{self, AssetData};
use super::concurrent::BoundedUnordered;
use super::http::Client;
use super::net;
use crate::url::Url;
use std::{
    collections::VecDeque,
    sync::atomic::{AtomicBool, Ordering},
    sync::{Arc, OnceLock},
};
use tokio::sync::Semaphore;

pub const MAX_TOTAL_ASSETS: usize = 2048;
const MAX_LOW_SIGNAL_ASSETS: usize = 64;
const MAX_PREWARM_HOSTS: usize = 16;
/// Cap on concurrent background revalidations across the whole process. A
/// burst of stale-cache hits must not fan out into thousands of HTTP requests
/// or thousands of in-flight task allocations.
const MAX_REVALIDATIONS_IN_FLIGHT: usize = 32;
static FIRST_ASSET_RESPONSE_TRACED: AtomicBool = AtomicBool::new(false);

fn revalidation_semaphore() -> &'static Arc<Semaphore> {
    static SEM: OnceLock<Arc<Semaphore>> = OnceLock::new();
    SEM.get_or_init(|| Arc::new(Semaphore::new(MAX_REVALIDATIONS_IN_FLIGHT)))
}

#[derive(Default)]
pub struct AssetScanStats {
    pub discovered: usize,
    pub failed: usize,
    pub unauthorized: usize,
    pub capped: bool,
}

#[derive(Clone, Copy, Debug)]
enum FetchFailure {
    Unauthorized,
    Other,
}

enum FetchedBody {
    Body(Box<DocumentScan>, cache::AssetValidators, Option<String>),
    NotModified,
}

pub(super) struct ScanEnv {
    pub client: Client,
    pub concurrency: usize,
    pub use_cache: bool,
    pub cache_key: Option<String>,
    pub allow_private: bool,
    pub site: DetectedSite,
}

pub async fn scan_assets(
    env: ScanEnv,
    initial: impl IntoIterator<Item = AssetRef>,
    out: &mut FindingsBuilder,
) -> AssetScanStats {
    let mut stats = AssetScanStats::default();
    let mut visited = crate::hash::FxHashSet::default();
    let mut queue = VecDeque::new();
    let mut low_signal_enqueued = 0;
    enqueue_assets(
        initial,
        &mut visited,
        &mut queue,
        &mut stats,
        &mut low_signal_enqueued,
    );
    prewarm_asset_hosts(&env.client, &queue, env.allow_private);

    let mut fetched = BoundedUnordered::new();
    let concurrency = env.concurrency.max(1);

    loop {
        while fetched.len() < concurrency {
            let Some(asset) = queue.pop_front() else {
                break;
            };
            fetched.push(fetch_scan(
                env.client.clone(),
                asset,
                env.use_cache,
                env.cache_key.as_deref(),
                env.allow_private,
                env.site.clone(),
            ));
        }

        let Some(res) = fetched.next().await else {
            break;
        };
        match res {
            Ok(asset) => {
                out.extend(asset.findings.clone());
                enqueue_assets(
                    asset.assets.iter().cloned(),
                    &mut visited,
                    &mut queue,
                    &mut stats,
                    &mut low_signal_enqueued,
                );
            }
            Err(reason) => {
                stats.failed += 1;
                if matches!(reason, FetchFailure::Unauthorized) {
                    stats.unauthorized += 1;
                }
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
    visited: &mut crate::hash::FxHashSet<Url>,
    queue: &mut VecDeque<AssetRef>,
    stats: &mut AssetScanStats,
    low_signal_enqueued: &mut usize,
) {
    let mut pending = Vec::new();
    for asset in assets {
        if visited.len() >= MAX_TOTAL_ASSETS {
            if !visited.contains(&asset.url) {
                stats.capped = true;
            }
        } else if visited.contains(&asset.url) {
            continue;
        } else if is_low_signal_asset(&asset) && *low_signal_enqueued >= MAX_LOW_SIGNAL_ASSETS {
            visited.insert(asset.url.clone());
        } else if visited.insert(asset.url.clone()) {
            if is_low_signal_asset(&asset) {
                *low_signal_enqueued += 1;
            }
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

fn is_low_signal_asset(asset: &AssetRef) -> bool {
    asset.kind == discover::AssetKind::Script && is_low_signal_script_path(asset.url.path())
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

fn prewarm_asset_hosts(client: &Client, assets: &VecDeque<AssetRef>, allow_private: bool) {
    let mut seen = crate::hash::FxHashSet::default();
    for url in assets
        .iter()
        .filter(|asset| asset.url.scheme() == "https")
        .filter_map(|asset| prewarm_key(&asset.url).map(|key| (key, asset.url.clone())))
    {
        let (key, url) = url;
        if !seen.insert(key) {
            continue;
        }
        let client = client.clone();
        tokio::spawn(async move {
            if net::validate_request_url(&url, allow_private).await.is_ok() {
                let _ = client.prewarm(&url).await;
            }
        });
        if seen.len() >= MAX_PREWARM_HOSTS {
            break;
        }
    }
}

fn prewarm_key(url: &Url) -> Option<String> {
    let host = url.host_str()?.to_ascii_lowercase();
    let port = url.port_or_known_default()?;
    Some(format!("{}://{host}:{port}", url.scheme()))
}

async fn fetch_scan(
    client: Client,
    asset: AssetRef,
    use_cache: bool,
    cache_key: Option<&str>,
    allow_private: bool,
    site: DetectedSite,
) -> Result<Arc<AssetData>, FetchFailure> {
    let cached = match cache::resolve_asset(&asset, cache_key, use_cache) {
        cache::CacheAction::Hit(data) => return Ok(data),
        cache::CacheAction::StaleRevalidate {
            data,
            validators,
            content_hash,
        } => {
            spawn_revalidate_chunk(
                client.clone(),
                asset.clone(),
                validators,
                content_hash,
                cache_key.map(str::to_owned),
                site.clone(),
                allow_private,
            );
            return Ok(data);
        }
        cache::CacheAction::Revalidate(c) => Some(c),
        cache::CacheAction::Miss => None,
    };

    let validators = cached.as_ref().map(|asset_data| &asset_data.validators);
    match fetch_asset_body(
        &client,
        asset.clone(),
        allow_private,
        validators,
        site,
        use_cache,
    )
    .await?
    {
        FetchedBody::NotModified => {
            let cached = cached.ok_or(FetchFailure::Other)?;
            let asset_data = Arc::new(cached.data);
            cache::persist_asset(
                &asset.url,
                cache_key,
                asset_data.clone(),
                &cached.validators,
                None,
            );
            Ok(asset_data)
        }
        FetchedBody::Body(scan, validators, content_hash) => {
            let asset_data = Arc::new(*scan);
            if use_cache {
                cache::persist_asset(
                    &asset.url,
                    cache_key,
                    asset_data.clone(),
                    &validators,
                    content_hash.as_deref(),
                );
            }
            Ok(asset_data)
        }
    }
}

async fn fetch_asset_body(
    client: &Client,
    asset: AssetRef,
    allow_private: bool,
    validators: Option<&cache::AssetValidators>,
    site: DetectedSite,
    use_hash_cache: bool,
) -> Result<FetchedBody, FetchFailure> {
    let _bp_guard = client.backpressure().enter();
    let headers = framework::request_headers(&asset.url);
    let response = net::fetch(
        client,
        asset.url.clone(),
        net::FetchOptions::asset(allow_private, validators, headers),
    )
    .await
    .map_err(|err| {
        trace_net_error(&asset.url, &err);
        FetchFailure::Other
    })?;
    if !FIRST_ASSET_RESPONSE_TRACED.swap(true, Ordering::Relaxed) {
        net::trace_response_version("asset", response.url(), &response);
    }
    let current_url = response.url().clone();
    let status = response.status();
    if status == 304 {
        // The cached scan result is still valid; callers refresh the validator
        // sidecar timestamp without reparsing the asset body.
        return Ok(FetchedBody::NotModified);
    }
    if !(200..300).contains(&status) {
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
                None,
            ));
        }
        trace_asset_status(&current_url, status);
        return Err(match status {
            401 | 403 => FetchFailure::Unauthorized,
            _ => FetchFailure::Other,
        });
    }

    let kind = asset.document_kind();
    let validators = asset_validators(&response);
    let body = net::read_limited(response).await.map_err(|err| {
        trace_net_error(&current_url, &err);
        FetchFailure::Other
    })?;
    let content_hash = (use_hash_cache && kind == discover::DocumentKind::Script)
        .then(|| crate::hash::hash128_hex(&body));
    let cached_findings = content_hash
        .as_deref()
        .and_then(|hash| cache::CHUNK.read_content_findings(hash));
    let scan_url = current_url.clone();
    let scan = tokio::task::spawn_blocking(move || {
        discover::scan_document_with_config_and_findings(
            &body,
            &scan_url,
            kind,
            site.next.as_ref(),
            cached_findings,
        )
    })
    .await
    .map_err(|err| {
        if std::env::var_os("HIFI_TRACE_HTTP").is_some() {
            eprintln!("hifi: trace: asset scan join error {err}");
        }
        FetchFailure::Other
    })?;
    Ok(FetchedBody::Body(Box::new(scan), validators, content_hash))
}

fn trace_asset_error(url: &Url, err: &net::NetError) {
    if std::env::var_os("HIFI_TRACE_HTTP").is_some() {
        eprintln!("hifi: trace: asset error {} {err}", url.as_str());
    }
}

fn trace_net_error(url: &Url, err: &net::NetError) {
    if std::env::var_os("HIFI_TRACE_HTTP").is_some() {
        eprintln!("hifi: trace: asset read error {} {err}", url.as_str());
    }
}

fn trace_asset_status(url: &Url, status: u16) {
    if std::env::var_os("HIFI_TRACE_HTTP").is_some() {
        eprintln!("hifi: trace: asset status {} {status}", url.as_str());
    }
}

#[allow(clippy::too_many_arguments)]
fn spawn_revalidate_chunk(
    client: Client,
    asset: AssetRef,
    cached_validators: cache::AssetValidators,
    cached_content_hash: String,
    cache_key: Option<String>,
    site: DetectedSite,
    allow_private: bool,
) {
    let sem = revalidation_semaphore().clone();
    // try_acquire instead of acquire: a burst of stale hits should drop excess
    // background work rather than queue it. The disk cache is still valid, so
    // skipping a revalidation just defers freshness until the next scan.
    let Ok(permit) = sem.try_acquire_owned() else {
        return;
    };
    tokio::spawn(async move {
        let _permit = permit;
        let validators = (!cached_validators.is_empty()).then_some(&cached_validators);
        let Ok(body) = fetch_asset_body(
            &client,
            asset.clone(),
            allow_private,
            validators,
            site,
            true,
        )
        .await
        else {
            return;
        };
        match body {
            FetchedBody::NotModified => {
                // Server confirmed bytes unchanged: refresh validator sidecar
                // timestamps so future scans treat the entry as fresh again.
                if let Some(existing) = cache::CHUNK.read_url(&asset.url, cache::CHUNK_URL_STALE_SECS) {
                    cache::CHUNK.write_deferred(
                        &asset.url,
                        &cached_content_hash,
                        existing.data,
                        &cached_validators,
                    );
                }
            }
            FetchedBody::Body(scan, new_validators, content_hash) => {
                cache::persist_asset(
                    &asset.url,
                    cache_key.as_deref(),
                    Arc::new(*scan),
                    &new_validators,
                    content_hash.as_deref(),
                );
            }
        }
    });
}

fn asset_validators(response: &crate::runtime::http::Response) -> cache::AssetValidators {
    cache::AssetValidators {
        etag: response.header("etag").map(str::to_owned),
        last_modified: response.header("last-modified").map(str::to_owned),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::discover::AssetKind;
    use std::sync::Arc;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

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
            ScanEnv {
                client,
                concurrency: 2,
                use_cache: false,
                cache_key: None,
                allow_private: true,
                site: DetectedSite::default(),
            },
            [initial],
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
