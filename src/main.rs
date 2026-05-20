mod cache;
mod fetch;
mod html;
mod literals;
mod scan;

use reqwest::Client;
use scan::ApiMap;
use serde_json::{json, Value};
use std::{
    collections::HashMap,
    error::Error,
    path::{Path, PathBuf},
    sync::{Arc, RwLock},
    time::{Duration, Instant},
};
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::{UnixListener, UnixStream};
use url::Url;

const MAX_CHUNK_CONCURRENCY: usize = 32;
const CACHE_FRESH_SECS: u64 = 300;
const CACHE_STALE_SECS: u64 = 3600;

type MemoryCache = Arc<RwLock<HashMap<PathBuf, MemoryEntry>>>;

#[derive(Clone)]
struct MemoryEntry {
    value: Value,
    written: Instant,
}

struct DaemonState {
    client: Client,
    memory: MemoryCache,
}

fn socket_path() -> PathBuf {
    let dir = std::env::var("XDG_RUNTIME_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|_| std::env::temp_dir());
    dir.join("hifi.sock")
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

#[tokio::main(flavor = "multi_thread")]
async fn main() -> Result<(), Box<dyn Error>> {
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
    let concurrency = chunk_concurrency();
    let client = make_client(concurrency)?;
    let out = process(&client, &url, no_cache, t0, concurrency, None).await?;
    println!("{}", serde_json::to_string(&out)?);
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

async fn serve() -> Result<(), Box<dyn Error>> {
    let path = socket_path();
    let _ = std::fs::remove_file(&path);
    let listener = UnixListener::bind(&path)?;
    eprintln!("hifi daemon listening on {}", path.display());

    let concurrency = chunk_concurrency();
    let state = Arc::new(DaemonState {
        client: make_client(concurrency)?,
        memory: Arc::new(RwLock::new(HashMap::new())),
    });

    loop {
        let (stream, _) = listener.accept().await?;
        let state = state.clone();
        tokio::spawn(async move {
            if let Err(e) = handle_conn(stream, state, concurrency).await {
                eprintln!("conn error: {e}");
            }
        });
    }
}

async fn handle_conn(
    stream: UnixStream,
    state: Arc<DaemonState>,
    concurrency: usize,
) -> Result<(), Box<dyn Error>> {
    let (rd, mut wr) = stream.into_split();
    let mut rd = BufReader::new(rd);
    let mut line = String::new();
    rd.read_line(&mut line).await?;
    let no_cache = line.starts_with("1\t");
    let url = line.get(2..).unwrap_or("").trim_end();

    let t0 = Instant::now();
    let out = match process(
        &state.client,
        url,
        no_cache,
        t0,
        concurrency,
        Some(state.memory.clone()),
    )
    .await
    {
        Ok(v) => v,
        Err(e) => json!({ "error": e.to_string() }),
    };
    let body = serde_json::to_string(&out)?;
    wr.write_all(body.as_bytes()).await?;
    wr.flush().await?;
    Ok(())
}

async fn process(
    client: &Client,
    url: &str,
    no_cache: bool,
    t0: Instant,
    concurrency: usize,
    memory: Option<MemoryCache>,
) -> Result<Value, Box<dyn Error>> {
    let base = Url::parse(url)?;
    let cache_path = cache::path_for(&base);

    if !no_cache {
        if let Some((v, age)) = read_memory(memory.as_ref(), &cache_path) {
            if age < CACHE_FRESH_SECS {
                return Ok(annotate(v, t0, "memory", age));
            }
            if age < CACHE_STALE_SECS {
                let client = client.clone();
                let url = url.to_string();
                let cache_path = cache_path.clone();
                let memory = memory.clone();
                tokio::spawn(async move {
                    let _ = refresh(&client, &url, &cache_path, concurrency, memory).await;
                });
                return Ok(annotate(v, t0, "memory-stale", age));
            }
        }
        if let Some((v, age)) = cache::read_any(&cache_path) {
            write_memory(memory.as_ref(), cache_path.clone(), v.clone());
            if age < CACHE_FRESH_SECS {
                return Ok(annotate(v, t0, "fresh", age));
            }
            if age < CACHE_STALE_SECS {
                let client = client.clone();
                let url = url.to_string();
                let cache_path = cache_path.clone();
                let memory = memory.clone();
                tokio::spawn(async move {
                    let _ = refresh(&client, &url, &cache_path, concurrency, memory).await;
                });
                return Ok(annotate(v, t0, "stale", age));
            }
        }
    }

    let (out, cache_hit) = collect(
        client,
        url,
        &base,
        (!no_cache).then_some(cache_path.as_path()),
        Some(t0),
        concurrency,
    )
    .await?;
    if !no_cache && !cache_hit {
        cache::write(&cache_path, &out);
        write_memory(memory.as_ref(), cache_path, out.clone());
    }
    Ok(out)
}

fn read_memory(memory: Option<&MemoryCache>, path: &Path) -> Option<(Value, u64)> {
    let entry = memory
        .and_then(|m| m.read().ok()?.get(path).cloned())?;
    let age = entry.written.elapsed().as_secs();
    Some((entry.value, age))
}

fn write_memory(memory: Option<&MemoryCache>, path: PathBuf, value: Value) {
    if let Some(memory) = memory {
        if let Ok(mut entries) = memory.write() {
            entries.insert(
                path,
                MemoryEntry {
                    value,
                    written: Instant::now(),
                },
            );
        }
    }
}

fn annotate(mut v: Value, t0: Instant, status: &str, age_secs: u64) -> Value {
    if let Some(obj) = v.as_object_mut() {
        obj.insert("cache".into(), json!(status));
        obj.insert("cache_age_secs".into(), json!(age_secs));
        obj.insert("elapsed_ms".into(), json!(t0.elapsed().as_millis()));
    }
    v
}

async fn refresh(
    client: &Client,
    url: &str,
    cache_path: &Path,
    concurrency: usize,
    memory: Option<MemoryCache>,
) -> Result<(), Box<dyn Error>> {
    let base = Url::parse(url)?;
    let (out, _) = collect(client, url, &base, Some(cache_path), None, concurrency).await?;
    cache::write(cache_path, &out);
    write_memory(memory.as_ref(), cache_path.to_path_buf(), out);
    Ok(())
}

async fn collect(
    client: &Client,
    url: &str,
    base: &Url,
    cache_path: Option<&Path>,
    t0: Option<Instant>,
    concurrency: usize,
) -> Result<(Value, bool), Box<dyn Error>> {
    let html = client.get(base.clone()).send().await?.text().await?;
    let chunks = html::extract_chunks(&html, base);
    let build_id = html::extract_build_id(&html).or_else(|| Some(cache::fingerprint(&chunks)));

    if let Some(mut v) = cache_path.and_then(|p| cache::read(p, build_id.as_deref())) {
        if let (Some(obj), Some(t0)) = (v.as_object_mut(), t0) {
            obj.insert("cache".into(), json!("hit"));
            obj.insert("elapsed_ms".into(), json!(t0.elapsed().as_millis()));
        }
        return Ok((v, true));
    }

    let mut apis = ApiMap::default();
    scan::scan(html.as_bytes(), &mut apis);

    let (chunks_scanned, chunk_fetch_errors) = fetch::scan_chunks(
        client.clone(),
        chunks.iter().cloned(),
        concurrency,
        &mut apis,
    )
    .await;

    let mut out = json!({
        "url": url,
        "build_id": build_id,
        "chunks_discovered": chunks.len(),
        "chunks_scanned": chunks_scanned,
        "chunk_fetch_errors": chunk_fetch_errors,
        "apis": scan::sorted(apis),
        "cache": "miss",
    });
    if let (Some(obj), Some(t0)) = (out.as_object_mut(), t0) {
        obj.insert("elapsed_ms".into(), json!(t0.elapsed().as_millis()));
    }
    Ok((out, false))
}
