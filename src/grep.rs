//! Grep subcommand.
//!
//! Grep reuses document discovery to find static assets, then searches the raw
//! fetched bytes. It is intentionally separate from the endpoint scanner because
//! callers expect grep-like text hits, not interpreted API shapes.

use crate::app::{escape_terminal, normalize_url, AppError};
use crate::discover::{self, AssetRef, DocumentKind};
use crate::runtime::config::RuntimeConfig;
use crate::runtime::fetch::MAX_TOTAL_ASSETS;
use crate::runtime::http::Client;
use crate::runtime::net;
use crate::url::Url;
use futures_util::{stream, StreamExt};
use std::sync::Arc;

const DEFAULT_MAX_HITS: usize = 50;
const DEFAULT_MAX_BYTES_PER_HIT: usize = 200;

#[derive(Clone, Debug)]
struct GrepOptions {
    context: usize,
    max_hits: Option<usize>,
    max_bytes_per_hit: usize,
}

impl Default for GrepOptions {
    fn default() -> Self {
        Self {
            context: 2,
            max_hits: Some(DEFAULT_MAX_HITS),
            max_bytes_per_hit: DEFAULT_MAX_BYTES_PER_HIT,
        }
    }
}

#[derive(Debug, Eq, PartialEq)]
struct Hit {
    url: String,
    line: usize,
    column: usize,
    snippet: String,
}

#[derive(Default)]
struct GrepResult {
    hits: Vec<Hit>,
    files_failed: usize,
    hits_not_printed: usize,
    files_with_hits_not_printed: usize,
    bytes_not_displayed_estimate: usize,
    snippets_shortened: usize,
}

pub async fn run(args: &[String], client: Client, config: RuntimeConfig) -> Result<i32, AppError> {
    let mut url = None;
    let mut pattern = None;
    let mut options = GrepOptions::default();
    let mut iter = args.iter();
    while let Some(a) = iter.next() {
        match a.as_str() {
            "-C" | "--context" => {
                let v = iter.next().ok_or("'-C' needs a number")?;
                options.context = v.parse().map_err(|_| format!("'-C {v}' is not a number"))?;
            }
            "--max-hits" => {
                let v = iter.next().ok_or("'--max-hits' needs a number")?;
                options.max_hits = Some(
                    v.parse()
                        .map_err(|_| format!("'--max-hits {v}' is not a number"))?,
                );
            }
            "--max-bytes-per-hit" => {
                let v = iter.next().ok_or("'--max-bytes-per-hit' needs a number")?;
                options.max_bytes_per_hit = v
                    .parse()
                    .map_err(|_| format!("'--max-bytes-per-hit {v}' is not a number"))?;
            }
            "-a" | "--all" => {
                options.max_hits = None;
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
    let response = net::get_limited(&client, base.clone(), config.allow_private).await?;
    let final_base = response.url().clone();
    let html = net::read_limited(response).await?;
    let mut assets = discover::scan_document(&html, &final_base, DocumentKind::Html).assets;
    let assets_capped = assets.len() > MAX_TOTAL_ASSETS;
    if assets_capped {
        assets.truncate(MAX_TOTAL_ASSETS);
    }

    let mut result = grep_bytes(final_base.as_str(), &html, pattern.as_bytes(), &options);
    let assets = grep_assets(client, assets, config, &pattern, options.clone()).await;
    merge_chunk(&mut result, assets, options.max_hits);
    if assets_capped {
        eprintln!(
            "hifi: warning: stopped after {MAX_TOTAL_ASSETS} discovered assets; results incomplete"
        );
    }
    if result.files_failed > 0 {
        eprintln!(
            "hifi: warning: failed to read {} files; results incomplete",
            result.files_failed
        );
    }
    if result.hits_not_printed > 0 || result.snippets_shortened > 0 {
        eprintln!(
            "hifi: ...truncated ({} not displayed, {} hits not printed in {} files, {} snippets shortened)",
            format_bytes(result.bytes_not_displayed_estimate),
            result.hits_not_printed,
            result.files_with_hits_not_printed,
            result.snippets_shortened
        );
    }
    eprintln!("{} hits", result.hits.len());
    for hit in &result.hits {
        println!(
            "{}:{}:{}\t{}",
            escape_terminal(&hit.url),
            hit.line,
            hit.column,
            escape_terminal(&hit.snippet)
        );
    }
    Ok(if result.hits.is_empty() { 1 } else { 0 })
}

async fn grep_assets(
    client: Client,
    assets: Vec<AssetRef>,
    config: RuntimeConfig,
    pattern: &str,
    options: GrepOptions,
) -> GrepResult {
    let pat = Arc::new(pattern.to_string());
    let options = Arc::new(options);
    let mut searched = stream::iter(assets.into_iter().enumerate())
        .map(|(idx, asset)| {
            grep_one(
                client.clone(),
                idx,
                asset,
                pat.clone(),
                options.clone(),
                config.allow_private,
            )
        })
        .buffer_unordered(config.chunk_concurrency);

    let mut chunks = Vec::new();
    let mut result = GrepResult::default();
    while let Some(chunk) = searched.next().await {
        match chunk {
            Ok(chunk) => chunks.push(chunk),
            Err(()) => result.files_failed += 1,
        }
    }
    chunks.sort_by_key(|(idx, _)| *idx);
    for (_, chunk) in chunks {
        merge_chunk(&mut result, chunk, options.max_hits);
    }
    result
}

fn merge_chunk(result: &mut GrepResult, mut chunk: GrepResult, max_hits: Option<usize>) {
    result.hits_not_printed += chunk.hits_not_printed;
    result.files_with_hits_not_printed += chunk.files_with_hits_not_printed;
    result.bytes_not_displayed_estimate += chunk.bytes_not_displayed_estimate;
    result.snippets_shortened += chunk.snippets_shortened;
    result.files_failed += chunk.files_failed;

    let Some(max_hits) = max_hits else {
        result.hits.append(&mut chunk.hits);
        return;
    };
    let remaining = max_hits.saturating_sub(result.hits.len());
    if chunk.hits.len() <= remaining {
        result.hits.append(&mut chunk.hits);
        return;
    }

    let omitted = chunk.hits.split_off(remaining);
    result.hits_not_printed += omitted.len();
    result.bytes_not_displayed_estimate +=
        omitted.iter().map(|hit| hit.snippet.len()).sum::<usize>();
    if !omitted.is_empty() && chunk.files_with_hits_not_printed == 0 {
        result.files_with_hits_not_printed += 1;
    }
    result.hits.append(&mut chunk.hits);
}

async fn grep_one(
    client: Client,
    idx: usize,
    asset: AssetRef,
    pattern: Arc<String>,
    options: Arc<GrepOptions>,
    allow_private: bool,
) -> Result<(usize, GrepResult), ()> {
    let body = net::get_bytes_limited(&client, asset.url.clone(), allow_private)
        .await
        .map_err(|_| ())?;

    Ok((
        idx,
        grep_bytes(asset.url.as_str(), &body, pattern.as_bytes(), &options),
    ))
}

fn grep_bytes(url: &str, bytes: &[u8], pat_bytes: &[u8], options: &GrepOptions) -> GrepResult {
    let mut result = GrepResult::default();
    if pat_bytes.is_empty() {
        return result;
    }
    let max_hits = options.max_hits.unwrap_or(usize::MAX);
    let mut file_omitted = false;

    let line_starts: Vec<usize> = std::iter::once(0)
        .chain(memchr::memchr_iter(b'\n', bytes).map(|i| i + 1))
        .collect();

    for abs in memchr::memmem::find_iter(bytes, pat_bytes) {
        let line_idx = line_starts.partition_point(|&s| s <= abs).saturating_sub(1);
        let lo_line = line_idx.saturating_sub(options.context);
        let hi_line = (line_idx + options.context + 1).min(line_starts.len());
        let lo = line_starts[lo_line];
        let hi = line_starts.get(hi_line).copied().unwrap_or(bytes.len());
        if result.hits.len() >= max_hits {
            result.hits_not_printed += 1;
            result.bytes_not_displayed_estimate += hi.saturating_sub(lo);
            file_omitted = true;
            continue;
        }
        let (snip_lo, snip_hi) = snippet_window(
            bytes,
            lo,
            hi,
            abs,
            pat_bytes.len(),
            options.max_bytes_per_hit,
        );
        let shortened = snip_lo > lo || snip_hi < hi;
        if shortened {
            result.snippets_shortened += 1;
            result.bytes_not_displayed_estimate += (hi - lo) - (snip_hi - snip_lo);
        }
        let raw = String::from_utf8_lossy(&bytes[snip_lo..snip_hi])
            .trim_end_matches('\n')
            .replace('\n', " ");
        let mut snippet = String::new();
        if snip_lo > lo {
            snippet.push('…');
        }
        snippet.push_str(&raw);
        if snip_hi < hi {
            snippet.push('…');
        }
        result.hits.push(Hit {
            url: url.to_string(),
            line: line_idx + 1,
            column: abs.saturating_sub(line_starts[line_idx]) + 1,
            snippet,
        });
    }
    if file_omitted {
        result.files_with_hits_not_printed = 1;
    }
    result
}

/// Pick a byte range inside [lo, hi] that fits within `max` bytes and stays
/// centered on the match at absolute offset `abs` with length `pat_len`.
/// Snaps both ends to UTF-8 boundaries so the slice decodes cleanly.
fn snippet_window(
    bytes: &[u8],
    lo: usize,
    hi: usize,
    abs: usize,
    pat_len: usize,
    max: usize,
) -> (usize, usize) {
    let span = hi - lo;
    if span <= max {
        return (lo, hi);
    }
    let match_end = abs + pat_len;
    // If the match itself is bigger than max, return the prefix of the match.
    if pat_len >= max {
        return (abs, snap_up(bytes, abs + max, hi));
    }
    let slack = max - pat_len;
    let before = slack / 2;
    let after = slack - before;
    let mut start = abs.saturating_sub(before).max(lo);
    let mut end = match_end.saturating_add(after).min(hi);
    // If we hit one boundary, give the leftover budget to the other side.
    if end - start < max {
        if start == lo {
            end = (start + max).min(hi);
        } else if end == hi {
            start = end.saturating_sub(max).max(lo);
        }
    }
    let start = snap_down(bytes, start, lo);
    let end = snap_up(bytes, end, hi);
    (start, end)
}

/// Move `idx` backward until it sits on a UTF-8 char boundary (or hits `floor`).
fn snap_down(bytes: &[u8], mut idx: usize, floor: usize) -> usize {
    while idx > floor && (bytes[idx] & 0b1100_0000) == 0b1000_0000 {
        idx -= 1;
    }
    idx
}

/// Move `idx` forward until it sits on a UTF-8 char boundary (or hits `ceil`).
fn snap_up(bytes: &[u8], mut idx: usize, ceil: usize) -> usize {
    while idx < ceil && (bytes[idx] & 0b1100_0000) == 0b1000_0000 {
        idx += 1;
    }
    idx
}

fn format_bytes(bytes: usize) -> String {
    const KIB: f64 = 1024.0;
    const MIB: f64 = KIB * 1024.0;
    if bytes >= 1024 * 1024 {
        format!("{:.1}MB", bytes as f64 / MIB)
    } else if bytes >= 1024 {
        format!("{:.1}KB", bytes as f64 / KIB)
    } else {
        format!("{bytes}B")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn grep_bytes_caps_hits_and_records_omissions() {
        let options = GrepOptions {
            context: 0,
            max_hits: Some(2),
            max_bytes_per_hit: 200,
        };
        let result = grep_bytes(
            "https://x.test/app.js",
            b"algolia\nalgolia\nalgolia",
            b"algolia",
            &options,
        );

        assert_eq!(result.hits.len(), 2);
        assert_eq!(result.hits_not_printed, 1);
        assert_eq!(result.files_with_hits_not_printed, 1);
    }

    #[test]
    fn grep_bytes_centers_snippet_on_match_in_long_line() {
        // Minified-style: one long line, match in the middle. Old behavior
        // returned the file prefix; new behavior centers the window on the match.
        let body = b"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAtargetBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB";
        let options = GrepOptions {
            context: 2,
            max_hits: Some(10),
            max_bytes_per_hit: 16,
        };
        let result = grep_bytes("https://x.test/app.js", body, b"target", &options);

        assert_eq!(result.hits.len(), 1);
        let hit = &result.hits[0];
        assert!(
            hit.snippet.contains("target"),
            "snippet should contain the match, got: {:?}",
            hit.snippet
        );
        assert!(hit.snippet.starts_with('…') && hit.snippet.ends_with('…'));
        assert_eq!(hit.column, 33);
        assert_eq!(result.snippets_shortened, 1);
    }

    #[test]
    fn grep_bytes_snaps_window_to_utf8_boundaries() {
        // The naive midpoint would split a multibyte char; snap_down / snap_up
        // must keep the snippet decodable.
        let body = "padding éééééé target éééééé padding".as_bytes();
        let options = GrepOptions {
            context: 0,
            max_hits: Some(1),
            max_bytes_per_hit: 12,
        };
        let result = grep_bytes("https://x.test/app.js", body, b"target", &options);

        assert_eq!(result.hits.len(), 1);
        // Just verifying it decodes cleanly and contains the match.
        assert!(result.hits[0].snippet.contains("target"));
    }

    #[test]
    fn all_disables_hit_cap() {
        let options = GrepOptions {
            context: 0,
            max_hits: None,
            max_bytes_per_hit: 200,
        };
        let result = grep_bytes("https://x.test/app.js", b"x\nx\nx", b"x", &options);

        assert_eq!(result.hits.len(), 3);
        assert_eq!(result.hits_not_printed, 0);
    }

    #[test]
    fn merge_chunk_enforces_global_cap() {
        let mut result = GrepResult::default();
        let chunk = grep_bytes(
            "https://x.test/app.js",
            b"x\nx\nx",
            b"x",
            &GrepOptions {
                context: 0,
                max_hits: Some(10),
                max_bytes_per_hit: 200,
            },
        );

        merge_chunk(&mut result, chunk, Some(2));

        assert_eq!(result.hits.len(), 2);
        assert_eq!(result.hits_not_printed, 1);
        assert_eq!(result.files_with_hits_not_printed, 1);
    }
}
