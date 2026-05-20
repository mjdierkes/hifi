use crate::scan::ApiMap;
use crate::{cache, fetch, html, scan};
use reqwest::Client;
use rustc_hash::FxHashMap;
use serde_json::{json, Value};
use std::{
    error::Error,
    path::{Path, PathBuf},
    process::{Command, Stdio},
    sync::{Arc, RwLock},
    time::{Duration, Instant},
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::{oneshot, Mutex};
use url::Url;

const MAX_CHUNK_CONCURRENCY: usize = 32;
const CACHE_FRESH_SECS: u64 = 300;
const CACHE_STALE_SECS: u64 = 3600;

type Body = Arc<str>;
type MemoryCache = Arc<RwLock<FxHashMap<String, (Body, Instant)>>>;
type Inflight = Arc<Mutex<FxHashMap<String, Vec<oneshot::Sender<Body>>>>>;

#[derive(Clone)]
struct DaemonState {
    client: Client,
    memory: MemoryCache,
    inflight: Inflight,
}

impl DaemonState {
    fn new(client: Client) -> Self {
        Self {
            client,
            memory: Arc::new(RwLock::new(FxHashMap::default())),
            inflight: Arc::new(Mutex::new(FxHashMap::default())),
        }
    }
}

pub async fn run(raw: Vec<String>) -> Result<(), Box<dyn Error>> {
    if raw.first().map(|s| s.as_str()) == Some("grep") {
        return grep_cmd(&raw[1..]).await;
    }

    let mut url = None;
    let (mut no_cache, mut no_daemon) = (false, false);
    for arg in raw {
        match arg.as_str() {
            "serve" => return serve().await,
            "--no-cache" => no_cache = true,
            "--no-daemon" => no_daemon = true,
            _ if !arg.starts_with("--") && url.is_none() => url = Some(arg),
            _ => {}
        }
    }
    let url = url.ok_or("usage: hifi <url> | hifi serve | hifi grep <url> <pattern>")?;

    if !no_daemon {
        if let Some(json) = request_daemon(&url, no_cache).await {
            println!("{}", json);
            return Ok(());
        }
        if start_daemon() {
            for _ in 0..20 {
                std::thread::sleep(Duration::from_millis(25));
                if let Some(json) = request_daemon(&url, no_cache).await {
                    println!("{}", json);
                    return Ok(());
                }
            }
        }
    }

    let t0 = Instant::now();
    let concurrency = chunk_concurrency();
    let client = make_client(concurrency)?;
    let out = process(&client, &url, no_cache, t0, concurrency, None).await?;
    println!("{}", serde_json::to_string(&out)?);
    Ok(())
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

fn start_daemon() -> bool {
    std::env::current_exe()
        .ok()
        .and_then(|exe| {
            Command::new(exe)
                .arg("serve")
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()
                .ok()
        })
        .is_some()
}

async fn request_daemon(url: &str, no_cache: bool) -> Option<String> {
    let mut stream = UnixStream::connect(socket_path()).await.ok()?;
    stream.write_all(&[b'0' + no_cache as u8]).await.ok()?;
    stream.write_all(url.as_bytes()).await.ok()?;
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
    let state = DaemonState::new(make_client(concurrency)?);

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
    mut stream: UnixStream,
    state: DaemonState,
    concurrency: usize,
) -> Result<(), Box<dyn Error>> {
    let t0 = Instant::now();
    let mut req = Vec::with_capacity(512);
    stream.read_to_end(&mut req).await?;
    let no_cache = req.first() == Some(&b'1');
    let url = std::str::from_utf8(req.get(1..).unwrap_or_default())?;

    if !no_cache {
        if let Some((body, age)) = read_memory(&state.memory, url) {
            if age < CACHE_STALE_SECS {
                if age >= CACHE_FRESH_SECS {
                    spawn_refresh(&state.client, url, concurrency, Some(state.memory.clone()));
                }
                return reply(&mut stream, body.as_ref()).await;
            }
        }

        if let Some(rx) = join_inflight(&state.inflight, url).await {
            if let Ok(body) = rx.await {
                return reply(&mut stream, body.as_ref()).await;
            }
        }
    }

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
    if !no_cache {
        let body: Body = Arc::from(body);
        write_memory(&state.memory, url.to_string(), body.clone());
        finish_inflight(&state.inflight, url, body.clone()).await;
        return reply(&mut stream, body.as_ref()).await;
    }
    reply(&mut stream, &body).await
}

async fn reply(stream: &mut UnixStream, body: &str) -> Result<(), Box<dyn Error>> {
    stream.write_all(body.as_bytes()).await?;
    Ok(())
}

async fn join_inflight(inflight: &Inflight, url: &str) -> Option<oneshot::Receiver<Body>> {
    let mut in_flight = inflight.lock().await;
    if let Some(waiters) = in_flight.get_mut(url) {
        let (tx, rx) = oneshot::channel();
        waiters.push(tx);
        Some(rx)
    } else {
        in_flight.insert(url.to_string(), Vec::new());
        None
    }
}

async fn finish_inflight(inflight: &Inflight, url: &str, body: Body) {
    for tx in inflight.lock().await.remove(url).unwrap_or_default() {
        let _ = tx.send(body.clone());
    }
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
        if let Some((v, age)) = cache::read_any(&cache_path) {
            if age < CACHE_STALE_SECS {
                let status = if age < CACHE_FRESH_SECS {
                    "fresh"
                } else {
                    spawn_refresh(client, url, concurrency, memory.clone());
                    "stale"
                };
                return Ok(annotate(v, t0, status, age));
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
        write_caches(&cache_path, &out, url, memory)?;
    }
    Ok(out)
}

fn read_memory(memory: &MemoryCache, url: &str) -> Option<(Body, u64)> {
    memory
        .read()
        .ok()?
        .get(url)
        .cloned()
        .map(|(body, t)| (body, t.elapsed().as_secs()))
}

fn spawn_refresh(client: &Client, url: &str, concurrency: usize, memory: Option<MemoryCache>) {
    let client = client.clone();
    let url = url.to_string();
    tokio::spawn(async move {
        let _ = refresh(&client, &url, concurrency, memory).await;
    });
}

fn write_memory(memory: &MemoryCache, url: String, body: Body) {
    if let Ok(mut entries) = memory.write() {
        entries.insert(url, (body, Instant::now()));
    }
}

fn write_caches(
    cache_path: &Path,
    out: &Value,
    url: &str,
    memory: Option<MemoryCache>,
) -> Result<(), Box<dyn Error>> {
    cache::write(cache_path, out);
    if let Some(memory) = memory {
        write_memory(
            &memory,
            url.to_string(),
            Arc::from(serde_json::to_string(out)?),
        );
    }
    Ok(())
}

fn annotate(mut v: Value, t0: Instant, status: &str, age_secs: u64) -> Value {
    if let Some(obj) = v.as_object_mut() {
        insert_elapsed(obj, t0);
        obj.insert("cache".into(), json!(status));
        obj.insert("cache_age_secs".into(), json!(age_secs));
    }
    v
}

fn insert_elapsed(obj: &mut serde_json::Map<String, Value>, t0: Instant) {
    let elapsed = t0.elapsed();
    obj.insert("elapsed_ms".into(), json!(elapsed.as_millis()));
    obj.insert("elapsed_us".into(), json!(elapsed.as_micros()));
    obj.insert("elapsed_ns".into(), json!(elapsed.as_nanos()));
}

async fn refresh(
    client: &Client,
    url: &str,
    concurrency: usize,
    memory: Option<MemoryCache>,
) -> Result<(), Box<dyn Error>> {
    let base = Url::parse(url)?;
    let cache_path = cache::path_for(&base);
    let (out, _) = collect(
        client,
        url,
        &base,
        Some(cache_path.as_path()),
        None,
        concurrency,
    )
    .await?;
    write_caches(&cache_path, &out, url, memory)
}

async fn collect(
    client: &Client,
    url: &str,
    base: &Url,
    cache_path: Option<&Path>,
    t0: Option<Instant>,
    concurrency: usize,
) -> Result<(Value, bool), Box<dyn Error>> {
    let html = client.get(base.clone()).send().await?.bytes().await?;
    let chunks = html::extract_chunks(&html, base);
    let build_id = html::extract_build_id(&html).or_else(|| Some(cache::fingerprint(&chunks)));

    if let Some(mut v) = cache_path.and_then(|p| cache::read(p, build_id.as_deref())) {
        if let (Some(obj), Some(t0)) = (v.as_object_mut(), t0) {
            insert_elapsed(obj, t0);
            obj.insert("cache".into(), json!("hit"));
        }
        return Ok((v, true));
    }

    let mut apis = ApiMap::default();
    scan::scan(&html, &mut apis);

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
        "apis": apis,
        "cache": "miss",
    });
    if let (Some(obj), Some(t0)) = (out.as_object_mut(), t0) {
        insert_elapsed(obj, t0);
    }
    Ok((out, false))
}

async fn grep_cmd(args: &[String]) -> Result<(), Box<dyn Error>> {
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

    let concurrency = chunk_concurrency();
    let client = make_client(concurrency)?;
    let base = Url::parse(&url)?;
    let html = client.get(base.clone()).send().await?.bytes().await?;
    let chunks = html::extract_chunks(&html, &base);

    let hits = fetch::grep_chunks(client, chunks.into_iter(), concurrency, &pattern, context).await;
    eprintln!("{} hits", hits.len());
    for h in hits {
        println!("{}@{}\t{}", h.url, h.offset, h.snippet);
    }
    Ok(())
}
