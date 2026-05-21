//! Grep subcommand.
//!
//! Grep reuses document discovery to find static assets, then searches the raw
//! fetched bytes. It is intentionally separate from the endpoint scanner because
//! callers expect grep-like text hits, not interpreted API shapes.

use crate::app::{escape_terminal, normalize_url, AppError};
use crate::discover::{self, AssetRef, DocumentKind};
use crate::runtime::net;
use futures_util::{stream, StreamExt};
use reqwest::Client;
use url::Url;

type Hit = (String, usize, String);

#[derive(Default)]
struct GrepResult {
    hits: Vec<Hit>,
    failed: usize,
}

pub async fn run(args: &[String], client: Client, concurrency: usize) -> Result<i32, AppError> {
    let mut url = None;
    let mut pattern = None;
    let mut context: usize = 2;
    let mut iter = args.iter();
    while let Some(a) = iter.next() {
        match a.as_str() {
            "-C" | "--context" => {
                let v = iter.next().ok_or("'-C' needs a number")?;
                context = v.parse().map_err(|_| format!("'-C {v}' is not a number"))?;
            }
            s if s.starts_with("--") || s.starts_with('-') => {
                return Err(format!("unknown flag '{s}' (try --help)").into());
            }
            _ if url.is_none() => url = Some(a.clone()),
            _ if pattern.is_none() => pattern = Some(a.clone()),
            _ => return Err(format!("unexpected argument '{a}'").into()),
        }
    }
    let url = url.ok_or("usage: hifi grep <url> <pattern> [-C N]")?;
    let pattern = pattern.ok_or("usage: hifi grep <url> <pattern> [-C N]")?;
    if pattern.is_empty() {
        return Err("pattern must not be empty".into());
    }
    let url = normalize_url(&url)?;

    let base = Url::parse(&url)?;
    let response = net::get_limited(&client, base.clone(), net::allow_private_networks()).await?;
    let final_base = response.url().clone();
    let html = net::read_limited(response).await?;
    let assets = discover::scan_document(&html, &final_base, DocumentKind::Html).assets;

    let result = grep_assets(client, assets.into_iter(), concurrency, &pattern, context).await;
    if result.failed > 0 {
        eprintln!(
            "hifi: warning: failed to read {} assets; results may be incomplete",
            result.failed
        );
    }
    eprintln!("{} hits", result.hits.len());
    for (url, line, snippet) in &result.hits {
        println!(
            "{}:{line}\t{}",
            escape_terminal(url),
            escape_terminal(snippet)
        );
    }
    Ok(if result.hits.is_empty() { 1 } else { 0 })
}

async fn grep_assets(
    client: Client,
    assets: impl Iterator<Item = AssetRef>,
    concurrency: usize,
    pattern: &str,
    context: usize,
) -> GrepResult {
    let pat = std::sync::Arc::new(pattern.to_string());
    let mut searched = stream::iter(assets)
        .map(|asset| grep_one(client.clone(), asset, pat.clone(), context))
        .buffer_unordered(concurrency);

    let mut result = GrepResult::default();
    while let Some(chunk) = searched.next().await {
        match chunk {
            Ok(mut hits) => result.hits.append(&mut hits),
            Err(()) => result.failed += 1,
        }
    }
    result
}

async fn grep_one(
    client: Client,
    asset: AssetRef,
    pattern: std::sync::Arc<String>,
    context: usize,
) -> Result<Vec<Hit>, ()> {
    let body = net::get_bytes_limited(&client, asset.url.clone(), net::allow_private_networks())
        .await
        .map_err(|_| ())?;

    let mut hits = Vec::new();
    let bytes = &body[..];
    let pat_bytes = pattern.as_bytes();
    if pat_bytes.is_empty() {
        return Ok(hits);
    }

    let line_starts: Vec<usize> = std::iter::once(0)
        .chain(memchr::memchr_iter(b'\n', bytes).map(|i| i + 1))
        .collect();

    for abs in memchr::memmem::find_iter(bytes, pat_bytes) {
        let line_idx = line_starts.partition_point(|&s| s <= abs).saturating_sub(1);
        let lo_line = line_idx.saturating_sub(context);
        let hi_line = (line_idx + context + 1).min(line_starts.len());
        let lo = line_starts[lo_line];
        let hi = line_starts.get(hi_line).copied().unwrap_or(bytes.len());
        let snippet = String::from_utf8_lossy(&bytes[lo..hi])
            .trim_end_matches('\n')
            .replace('\n', " ");
        hits.push((asset.url.to_string(), line_idx + 1, snippet));
    }
    Ok(hits)
}
