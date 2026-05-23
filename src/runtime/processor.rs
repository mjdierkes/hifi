//! Site scan orchestration: root fetch, document scan, asset queue, output assembly.

use super::engine::{
    collect_apis, decode_output_binary, encode_output_binary, warnings_from_assets, Api, CacheStatus,
    Output, RuntimeError,
};
use super::{cache, fetch, fetch_root, http::Client};
use crate::discover::{self, DocumentKind};
use crate::url::Url;
use std::sync::Arc;
use std::time::Instant;

type Result<T> = std::result::Result<T, RuntimeError>;

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
    .await
    .map_err(RuntimeError::from)?;
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
