use crate::html;
use futures_util::{stream, StreamExt};
use reqwest::Client;
use std::error::Error;
use url::Url;

pub async fn run(
    args: &[String],
    client: Client,
    concurrency: usize,
) -> Result<(), Box<dyn Error>> {
    let mut url = None;
    let mut pattern = None;
    let mut context: usize = 60;
    let mut iter = args.iter();
    while let Some(a) = iter.next() {
        match a.as_str() {
            "-C" | "--context" => {
                context = iter.next().and_then(|v| v.parse().ok()).unwrap_or(context);
            }
            _ if !a.starts_with("--") && url.is_none() => url = Some(a.clone()),
            _ if !a.starts_with("--") && pattern.is_none() => pattern = Some(a.clone()),
            _ => {}
        }
    }
    let url = url.ok_or("usage: hifi grep <url> <pattern> [-C N]")?;
    let pattern = pattern.ok_or("usage: hifi grep <url> <pattern> [-C N]")?;

    let base = Url::parse(&url)?;
    let response = client.get(base.clone()).send().await?;
    let final_base = response.url().clone();
    let html = response.bytes().await?;
    let chunks = html::extract_chunks(&html, &final_base);

    let hits = grep_chunks(client, chunks.into_iter(), concurrency, &pattern, context).await;
    eprintln!("{} hits", hits.len());
    for h in hits {
        println!("{}@{}\t{}", h.url, h.offset, h.snippet);
    }
    Ok(())
}

async fn grep_chunks(
    client: Client,
    chunks: impl Iterator<Item = Url>,
    concurrency: usize,
    pattern: &str,
    context: usize,
) -> Vec<GrepHit> {
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

struct GrepHit {
    url: String,
    offset: usize,
    snippet: String,
}

async fn grep_one(
    client: Client,
    url: Url,
    pattern: std::sync::Arc<String>,
    context: usize,
) -> Vec<GrepHit> {
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
    for abs in memchr::memmem::find_iter(bytes, pat_bytes) {
        let lo = abs.saturating_sub(context);
        let hi = (abs + pat_bytes.len() + context).min(bytes.len());
        let snippet = String::from_utf8_lossy(&bytes[lo..hi]).replace('\n', " ");
        hits.push(GrepHit {
            url: url.to_string(),
            offset: abs,
            snippet,
        });
    }
    hits
}
