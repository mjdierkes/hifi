use crate::scan::{self, ApiMap};
use futures_util::StreamExt;
use reqwest::Client;
use tokio::task::JoinSet;
use url::Url;

const STREAM_OVERLAP: usize = 1024;
const INLINE_SCAN_MAX: usize = 16 * 1024;

pub async fn scan_chunks(
    client: Client,
    mut chunks: impl Iterator<Item = Url>,
    concurrency: usize,
    apis: &mut ApiMap,
) -> (usize, usize) {
    let mut set = JoinSet::new();
    for _ in 0..concurrency {
        let Some(url) = chunks.next() else { break };
        spawn_fetch(&mut set, client.clone(), url);
    }

    let mut scanned = 0usize;
    let mut errors = 0usize;
    while let Some(res) = set.join_next().await {
        match res {
            Ok(Ok(chunk_apis)) => {
                scanned += 1;
                scan::merge_into(apis, chunk_apis);
            }
            _ => errors += 1,
        }

        if let Some(url) = chunks.next() {
            spawn_fetch(&mut set, client.clone(), url);
        }
    }

    (scanned, errors)
}

fn spawn_fetch(set: &mut JoinSet<Result<ApiMap, ()>>, client: Client, url: Url) {
    set.spawn(async move {
        let response = client
            .get(url)
            .send()
            .await
            .map_err(|_| ())?
            .error_for_status()
            .map_err(|_| ())?;
        let mut stream = response.bytes_stream();
        let mut apis = ApiMap::default();
        let mut tail = Vec::with_capacity(STREAM_OVERLAP);

        while let Some(chunk) = stream.next().await {
            let chunk = chunk.map_err(|_| ())?;
            let mut window = Vec::with_capacity(tail.len() + chunk.len());
            window.extend_from_slice(&tail);
            window.extend_from_slice(&chunk);
            scan_bytes(window, &mut apis).await?;

            if chunk.len() >= STREAM_OVERLAP {
                tail.clear();
                tail.extend_from_slice(&chunk[chunk.len() - STREAM_OVERLAP..]);
            } else {
                tail.extend_from_slice(&chunk);
                if tail.len() > STREAM_OVERLAP {
                    let drop = tail.len() - STREAM_OVERLAP;
                    tail.drain(..drop);
                }
            }
        }

        if !tail.is_empty() {
            scan::scan(&tail, &mut apis);
        }

        Ok(apis)
    });
}

pub async fn grep_chunks(
    client: Client,
    mut chunks: impl Iterator<Item = Url>,
    concurrency: usize,
    pattern: &str,
    context: usize,
) -> Vec<GrepHit> {
    let mut set: JoinSet<Vec<GrepHit>> = JoinSet::new();
    let pat = std::sync::Arc::new(pattern.to_string());

    let mut spawn = |set: &mut JoinSet<Vec<GrepHit>>, url: Url| {
        let client = client.clone();
        let pat = pat.clone();
        set.spawn(async move { grep_one(client, url, &pat, context).await });
    };

    for _ in 0..concurrency {
        let Some(url) = chunks.next() else { break };
        spawn(&mut set, url);
    }

    let mut hits = Vec::new();
    while let Some(res) = set.join_next().await {
        if let Ok(mut h) = res {
            hits.append(&mut h);
        }
        if let Some(url) = chunks.next() {
            spawn(&mut set, url);
        }
    }
    hits
}

pub struct GrepHit {
    pub url: String,
    pub offset: usize,
    pub snippet: String,
}

async fn grep_one(client: Client, url: Url, pattern: &str, context: usize) -> Vec<GrepHit> {
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
    let mut start = 0;
    while let Some(rel) = memchr_substr(&bytes[start..], pat_bytes) {
        let abs = start + rel;
        let lo = abs.saturating_sub(context);
        let hi = (abs + pat_bytes.len() + context).min(bytes.len());
        let snippet = String::from_utf8_lossy(&bytes[lo..hi]).replace('\n', " ");
        hits.push(GrepHit {
            url: url.to_string(),
            offset: abs,
            snippet,
        });
        start = abs + pat_bytes.len();
    }
    hits
}

fn memchr_substr(hay: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || hay.len() < needle.len() {
        return None;
    }
    let first = needle[0];
    let mut i = 0;
    while i + needle.len() <= hay.len() {
        if let Some(p) = memchr::memchr(first, &hay[i..]) {
            let abs = i + p;
            if abs + needle.len() > hay.len() {
                return None;
            }
            if &hay[abs..abs + needle.len()] == needle {
                return Some(abs);
            }
            i = abs + 1;
        } else {
            return None;
        }
    }
    None
}

async fn scan_bytes(bytes: Vec<u8>, apis: &mut ApiMap) -> Result<(), ()> {
    if bytes.len() <= INLINE_SCAN_MAX {
        scan::scan(&bytes, apis);
        return Ok(());
    }

    let chunk_apis = tokio::task::spawn_blocking(move || {
        let mut chunk_apis = ApiMap::default();
        scan::scan(&bytes, &mut chunk_apis);
        chunk_apis
    })
    .await
    .map_err(|_| ())?;
    scan::merge_into(apis, chunk_apis);
    Ok(())
}
