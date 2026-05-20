use crate::scan::{self, ApiMap};
use futures_util::{stream, StreamExt};
use reqwest::Client;
use url::Url;

const STREAM_OVERLAP: usize = 1024;
const INLINE_SCAN_MAX: usize = 16 * 1024;

pub async fn scan_chunks(
    client: Client,
    chunks: impl Iterator<Item = Url>,
    concurrency: usize,
    apis: &mut ApiMap,
) -> (usize, usize) {
    let mut scanned = 0usize;
    let mut errors = 0usize;

    let mut fetched = stream::iter(chunks)
        .map(|url| fetch_scan(client.clone(), url))
        .buffer_unordered(concurrency);

    while let Some(res) = fetched.next().await {
        match res {
            Ok(chunk_apis) => {
                scanned += 1;
                scan::merge_into(apis, chunk_apis);
            }
            _ => errors += 1,
        }
    }

    (scanned, errors)
}

async fn fetch_scan(client: Client, url: Url) -> Result<ApiMap, ()> {
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
}

pub async fn grep_chunks(
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

pub struct GrepHit {
    pub url: String,
    pub offset: usize,
    pub snippet: String,
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
