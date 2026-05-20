use crate::scan::{self, Shape};
use reqwest::Client;
use std::collections::BTreeMap;
use tokio::task::JoinSet;
use url::Url;

pub async fn scan_chunks(
    client: Client,
    mut chunks: impl Iterator<Item = Url>,
    concurrency: usize,
    apis: &mut BTreeMap<String, Shape>,
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
            Ok(Ok(bytes)) => {
                scanned += 1;
                scan::scan(&bytes, apis);
            }
            _ => errors += 1,
        }

        if let Some(url) = chunks.next() {
            spawn_fetch(&mut set, client.clone(), url);
        }
    }

    (scanned, errors)
}

fn spawn_fetch(set: &mut JoinSet<Result<bytes::Bytes, reqwest::Error>>, client: Client, url: Url) {
    set.spawn(async move {
        client
            .get(url)
            .send()
            .await?
            .error_for_status()?
            .bytes()
            .await
    });
}
