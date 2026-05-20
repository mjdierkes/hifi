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
