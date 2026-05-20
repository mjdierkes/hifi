mod cache;
mod fetch;
mod html;
mod literals;
mod scan;

use reqwest::Client;
use scan::Shape;
use std::collections::BTreeMap;
use std::time::Instant;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::{UnixListener, UnixStream};
use url::Url;

const MAX_CHUNK_CONCURRENCY: usize = 32;
const CACHE_FRESH_SECS: u64 = 300; // serve immediately, no network
const CACHE_STALE_SECS: u64 = 3600; // serve + refresh in background

fn socket_path() -> std::path::PathBuf {
    let dir = std::env::var("XDG_RUNTIME_DIR")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|_| std::env::temp_dir());
    dir.join("hifi.sock")
}

fn make_client() -> reqwest::Result<Client> {
    Client::builder()
        .pool_max_idle_per_host(16)
        .pool_idle_timeout(std::time::Duration::from_secs(300))
        .tcp_keepalive(std::time::Duration::from_secs(30))
        .user_agent("hifi/0.1")
        .build()
}

#[tokio::main(flavor = "multi_thread")]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut url = None;
    let (mut no_cache, mut no_daemon) = (false, false);
    for arg in std::env::args().skip(1) {
        match arg.as_str() {
            "serve" => return serve().await,
            "--no-cache" => no_cache = true,
            "--no-daemon" => no_daemon = true,
            _ if !arg.starts_with("--") && url.is_none() => url = Some(arg),
            _ => {}
        }
    }
    let url = url.ok_or("usage: hifi <url> | hifi serve")?;

    // try daemon first
    if !no_daemon {
        if let Some(json) = try_daemon(&url, no_cache).await {
            println!("{}", json);
            return Ok(());
        }
    }

    let t0 = Instant::now();
    let client = make_client()?;
    let out = process(&client, &url, no_cache, t0).await?;
    println!("{}", serde_json::to_string_pretty(&out)?);
    Ok(())
}

async fn try_daemon(url: &str, no_cache: bool) -> Option<String> {
    let path = socket_path();
    let mut stream = UnixStream::connect(&path).await.ok()?;
    stream
        .write_all(format!("{}\t{url}\n", no_cache as u8).as_bytes())
        .await
        .ok()?;
    stream.shutdown().await.ok();
    let mut buf = Vec::with_capacity(4096);
    stream.read_to_end(&mut buf).await.ok()?;
    String::from_utf8(buf).ok()
}

async fn serve() -> Result<(), Box<dyn std::error::Error>> {
    let path = socket_path();
    let _ = std::fs::remove_file(&path);
    let listener = UnixListener::bind(&path)?;
    eprintln!("hifi daemon listening on {}", path.display());

    let client = std::sync::Arc::new(make_client()?);

    loop {
        let (stream, _) = listener.accept().await?;
        let client = client.clone();
        tokio::spawn(async move {
            if let Err(e) = handle_conn(stream, client).await {
                eprintln!("conn error: {e}");
            }
        });
    }
}

async fn handle_conn(
    stream: UnixStream,
    client: std::sync::Arc<Client>,
) -> Result<(), Box<dyn std::error::Error>> {
    let (rd, mut wr) = stream.into_split();
    let mut rd = BufReader::new(rd);
    let mut line = String::new();
    rd.read_line(&mut line).await?;
    let no_cache = line.starts_with("1\t");
    let url = line.get(2..).unwrap_or("").trim_end();

    let t0 = Instant::now();
    let out = match process(&client, url, no_cache, t0).await {
        Ok(v) => v,
        Err(e) => serde_json::json!({ "error": e.to_string() }),
    };
    let body = serde_json::to_string_pretty(&out)?;
    wr.write_all(body.as_bytes()).await?;
    wr.flush().await?;
    Ok(())
}

async fn process(
    client: &Client,
    url: &str,
    no_cache: bool,
    t0: Instant,
) -> Result<serde_json::Value, Box<dyn std::error::Error>> {
    let base = Url::parse(url)?;
    let cache_path = cache::path_for(&base);

    // TTL fast path: serve cache immediately if fresh, refresh in background if stale.
    if !no_cache {
        if let Some((v, age)) = cache::read_any(&cache_path) {
            if age < CACHE_FRESH_SECS {
                return Ok(annotate(v, t0, "fresh", age));
            }
            if age < CACHE_STALE_SECS {
                let client = client.clone();
                let url = url.to_string();
                let cache_path = cache_path.clone();
                tokio::spawn(async move {
                    let _ = refresh(&client, &url, &cache_path).await;
                });
                return Ok(annotate(v, t0, "stale", age));
            }
        }
    }

    let html = client.get(base.clone()).send().await?.text().await?;
    let chunks = html::extract_chunks(&html, &base);
    let build_id = html::extract_build_id(&html).or_else(|| Some(cache::fingerprint(&chunks)));

    if !no_cache {
        if let Some(cached) = cache::read(&cache_path, build_id.as_deref()) {
            let elapsed = t0.elapsed();
            let mut v = cached;
            if let Some(obj) = v.as_object_mut() {
                obj.insert("cache".into(), serde_json::json!("hit"));
                obj.insert("elapsed_ms".into(), serde_json::json!(elapsed.as_millis()));
            }
            return Ok(v);
        }
    }

    let mut apis: BTreeMap<String, Shape> = BTreeMap::new();
    scan::scan(html.as_bytes(), &mut apis);

    let (chunks_scanned, chunk_fetch_errors) = fetch::scan_chunks(
        client.clone(),
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
    Ok(out)
}

fn annotate(mut v: serde_json::Value, t0: Instant, status: &str, age_secs: u64) -> serde_json::Value {
    if let Some(obj) = v.as_object_mut() {
        obj.insert("cache".into(), serde_json::json!(status));
        obj.insert("cache_age_secs".into(), serde_json::json!(age_secs));
        obj.insert(
            "elapsed_ms".into(),
            serde_json::json!(t0.elapsed().as_millis()),
        );
    }
    v
}

async fn refresh(client: &Client, url: &str, cache_path: &std::path::Path) -> Result<(), Box<dyn std::error::Error>> {
    let base = Url::parse(url)?;
    let html = client.get(base.clone()).send().await?.text().await?;
    let chunks = html::extract_chunks(&html, &base);
    let build_id = html::extract_build_id(&html).or_else(|| Some(cache::fingerprint(&chunks)));

    // skip rescan if buildId matches existing cache
    if let Some((existing, _)) = cache::read_any(cache_path) {
        let same = existing.get("build_id").and_then(|b| b.as_str()) == build_id.as_deref();
        if same {
            // bump mtime
            cache::write(cache_path, &existing);
            return Ok(());
        }
    }

    let mut apis: BTreeMap<String, Shape> = BTreeMap::new();
    scan::scan(html.as_bytes(), &mut apis);
    let (chunks_scanned, chunk_fetch_errors) =
        fetch::scan_chunks(client.clone(), chunks.iter().cloned(), MAX_CHUNK_CONCURRENCY, &mut apis).await;

    let out = serde_json::json!({
        "url": url,
        "build_id": build_id,
        "chunks_discovered": chunks.len(),
        "chunks_scanned": chunks_scanned,
        "chunk_fetch_errors": chunk_fetch_errors,
        "apis": apis,
        "cache": "miss",
    });
    cache::write(cache_path, &out);
    Ok(())
}
