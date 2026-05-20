use crate::scan::{self, ApiMap};
use reqwest::Client;
use tokio::task::JoinSet;
use url::Url;

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
        let bytes = client
            .get(url)
            .send()
            .await
            .map_err(|_| ())?
            .error_for_status()
            .map_err(|_| ())?
            .bytes()
            .await
            .map_err(|_| ())?;

        tokio::task::spawn_blocking(move || {
            let mut apis = ApiMap::default();
            scan::scan(&bytes, &mut apis);
            apis
        })
        .await
        .map_err(|_| ())
    });
}
