use crate::grep;
use crate::runtime::daemon;
use crate::runtime::processor::{CacheContext, Processor, CACHE_FRESH_SECS};
use reqwest::Client;
use std::{error::Error, time::Duration};

const MAX_CHUNK_CONCURRENCY: usize = 32;

pub async fn run(raw: Vec<String>) -> Result<(), Box<dyn Error>> {
    let concurrency = chunk_concurrency();
    let client = make_client(concurrency)?;

    if raw.first().map(|s| s.as_str()) == Some("grep") {
        return grep::run(&raw[1..], client, concurrency).await;
    }

    let mut url = None;
    let (mut no_cache, mut no_daemon) = (false, false);
    for arg in raw {
        match arg.as_str() {
            "serve" => return daemon::serve(client, concurrency).await,
            "--no-cache" => no_cache = true,
            "--no-daemon" => no_daemon = true,
            _ if !arg.starts_with("--") && url.is_none() => url = Some(arg),
            _ => {}
        }
    }
    let url = url.ok_or("usage: hifi <url> | hifi serve | hifi grep <url> <pattern>")?;

    if !no_daemon {
        if let Some(json) = daemon_json(&url, no_cache).await {
            println!("{}", json);
            return Ok(());
        }
    }

    let out = Processor::new(&client, concurrency, CacheContext::default())
        .process(&url, no_cache, std::time::Instant::now())
        .await?;
    println!("{}", out);
    Ok(())
}

async fn daemon_json(url: &str, no_cache: bool) -> Option<String> {
    if let Some(json) = daemon::request(url, no_cache).await {
        return Some(json);
    }
    if daemon::start() {
        for _ in 0..20 {
            std::thread::sleep(Duration::from_millis(25));
            if let Some(json) = daemon::request(url, no_cache).await {
                return Some(json);
            }
        }
    }
    None
}

fn chunk_concurrency() -> usize {
    std::env::var("HIFI_CHUNK_CONCURRENCY")
        .ok()
        .and_then(|v| v.parse().ok())
        .filter(|v| *v > 0)
        .unwrap_or(MAX_CHUNK_CONCURRENCY)
}

fn make_client(chunk_concurrency: usize) -> reqwest::Result<Client> {
    Client::builder()
        .pool_max_idle_per_host(chunk_concurrency)
        .pool_idle_timeout(Duration::from_secs(CACHE_FRESH_SECS))
        .tcp_keepalive(Duration::from_secs(30))
        .user_agent("hifi/0.1")
        .build()
}
