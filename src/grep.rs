use crate::app::normalize_url;
use crate::scan::html;
use futures_util::{stream, StreamExt};
use reqwest::Client;
use std::error::Error;
use url::Url;

type Hit = (String, usize, String);

pub async fn run(
    args: &[String],
    client: Client,
    concurrency: usize,
) -> Result<i32, Box<dyn Error>> {
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
    let url = normalize_url(&url);

    let base = Url::parse(&url)?;
    let response = client.get(base.clone()).send().await?;
    let final_base = response.url().clone();
    let html = response.bytes().await?;
    let chunks = html::extract_chunks(&html, &final_base);

    let hits = grep_chunks(client, chunks.into_iter(), concurrency, &pattern, context).await;
    eprintln!("{} hits", hits.len());
    for (url, line, snippet) in &hits {
        println!("{url}:{line}\t{snippet}");
    }
    Ok(if hits.is_empty() { 1 } else { 0 })
}

async fn grep_chunks(
    client: Client,
    chunks: impl Iterator<Item = Url>,
    concurrency: usize,
    pattern: &str,
    context: usize,
) -> Vec<Hit> {
    let pat = std::sync::Arc::new(pattern.to_string());
    let mut searched = stream::iter(chunks)
        .map(|url| grep_one(client.clone(), url, pat.clone(), context))
        .buffer_unordered(concurrency);

    let mut hits = Vec::new();
    while let Some(mut h) = searched.next().await {
        hits.append(&mut h);
    }
    hits
}

async fn grep_one(
    client: Client,
    url: Url,
    pattern: std::sync::Arc<String>,
    context: usize,
) -> Vec<Hit> {
    let Ok(resp) = client.get(url.clone()).send().await else {
        return Vec::new();
    };
    let Ok(resp) = resp.error_for_status() else {
        return Vec::new();
    };
    let Ok(body) = resp.bytes().await else {
        return Vec::new();
    };

    let mut hits = Vec::new();
    let bytes = &body[..];
    let pat_bytes = pattern.as_bytes();
    if pat_bytes.is_empty() {
        return hits;
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
        hits.push((url.to_string(), line_idx + 1, snippet));
    }
    hits
}
