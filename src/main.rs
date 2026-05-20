mod cache;
mod fetch;
mod html;
mod literals;
mod scan;

use reqwest::Client;
use scan::Shape;
use std::collections::BTreeMap;
use std::time::Instant;
use url::Url;

const MAX_CHUNK_CONCURRENCY: usize = 32;

#[tokio::main(flavor = "multi_thread")]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let url = std::env::args().nth(1).ok_or("usage: hifi <url>")?;
    let no_cache = std::env::args().any(|a| a == "--no-cache");
    let t0 = Instant::now();

    let client = Client::builder()
        .pool_max_idle_per_host(16)
        .tcp_keepalive(std::time::Duration::from_secs(30))
        .user_agent("hifi/0.1")
        .build()?;

    let base = Url::parse(&url)?;
    let html = client.get(base.clone()).send().await?.text().await?;
    let chunks = html::extract_chunks(&html, &base);
    let build_id = html::extract_build_id(&html).or_else(|| Some(cache::fingerprint(&chunks)));

    let cache_path = cache::path_for(&base);
    if !no_cache {
        if let Some(cached) = cache::read(&cache_path, build_id.as_deref()) {
            let elapsed = t0.elapsed();
            let mut v = cached;
            if let Some(obj) = v.as_object_mut() {
                obj.insert("cache".into(), serde_json::json!("hit"));
                obj.insert("elapsed_ms".into(), serde_json::json!(elapsed.as_millis()));
            }
            println!("{}", serde_json::to_string_pretty(&v)?);
            return Ok(());
        }
    }

    let mut apis: BTreeMap<String, Shape> = BTreeMap::new();
    scan::scan(html.as_bytes(), &mut apis);

    let (chunks_scanned, chunk_fetch_errors) = fetch::scan_chunks(
        client,
        chunks.iter().cloned(),
        MAX_CHUNK_CONCURRENCY,
        &mut apis,
    )
    .await;

    let elapsed = t0.elapsed();
    let out = serde_json::json!({
        "url": url,
        "build_id": build_id,
        "chunks_discovered": chunks.len(),
        "chunks_scanned": chunks_scanned,
        "chunk_fetch_errors": chunk_fetch_errors,
        "apis": apis,
        "cache": "miss",
        "elapsed_ms": elapsed.as_millis(),
    });
    if !no_cache {
        cache::write(&cache_path, &out);
    }
    println!("{}", serde_json::to_string_pretty(&out)?);
    Ok(())
}
