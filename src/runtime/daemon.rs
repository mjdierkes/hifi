use super::fetch;
use super::processor::{
    read_memory, spawn_refresh, write_memory, Body, CacheContext, MemoryCache, Processor,
    RedirectMemory, CACHE_FRESH_SECS, CACHE_STALE_SECS,
};
use crate::app::{render_json_mode, OutputMode};
use reqwest::Client;
use rustc_hash::FxHashMap;
use std::{
    error::Error,
    path::PathBuf,
    process::{Command, Stdio},
    sync::{Arc, RwLock},
    time::Instant,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::{oneshot, Mutex};

type Result<T = ()> = std::result::Result<T, Box<dyn Error>>;
type Inflight = Arc<Mutex<FxHashMap<String, Vec<oneshot::Sender<Body>>>>>;

#[derive(Clone)]
struct State {
    client: Client,
    memory: MemoryCache,
    chunks: fetch::ChunkMemoryCache,
    redirects: RedirectMemory,
    inflight: Inflight,
}

impl State {
    fn new(client: Client) -> Self {
        Self {
            client,
            memory: Arc::new(RwLock::new(FxHashMap::default())),
            chunks: Arc::new(RwLock::new(FxHashMap::default())),
            redirects: Arc::new(RwLock::new(FxHashMap::default())),
            inflight: Arc::new(Mutex::new(FxHashMap::default())),
        }
    }

    fn cache(&self) -> CacheContext {
        CacheContext {
            memory: Some(self.memory.clone()),
            chunks: Some(self.chunks.clone()),
            redirects: Some(self.redirects.clone()),
        }
    }
}

pub fn start() -> bool {
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

pub async fn request(url: &str, no_cache: bool, mode: OutputMode) -> Option<String> {
    let mut stream = UnixStream::connect(socket_path()).await.ok()?;
    stream
        .write_all(&[b'0' + no_cache as u8, mode.as_daemon_byte()])
        .await
        .ok()?;
    stream.write_all(url.as_bytes()).await.ok()?;
    stream.shutdown().await.ok();

    let mut buf = Vec::with_capacity(4096);
    stream.read_to_end(&mut buf).await.ok()?;
    String::from_utf8(buf).ok()
}

pub async fn serve(client: Client, concurrency: usize) -> Result {
    let path = socket_path();
    let _ = std::fs::remove_file(&path);
    let listener = UnixListener::bind(&path)?;
    eprintln!("hifi daemon listening on {}", path.display());

    let state = State::new(client);
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

fn socket_path() -> PathBuf {
    let dir = std::env::var("XDG_RUNTIME_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|_| std::env::temp_dir());
    dir.join("hifi.sock")
}

async fn handle_conn(mut stream: UnixStream, state: State, concurrency: usize) -> Result {
    let t0 = Instant::now();
    let mut req = Vec::with_capacity(512);
    stream.read_to_end(&mut req).await?;
    let no_cache = req.first() == Some(&b'1');
    let (mode, url_bytes) = req
        .get(1)
        .and_then(|b| OutputMode::from_daemon_byte(*b))
        .map(|mode| (mode, req.get(2..).unwrap_or_default()))
        .unwrap_or((OutputMode::Json, req.get(1..).unwrap_or_default()));
    let url = std::str::from_utf8(url_bytes)?;

    if !no_cache {
        if let Some((body, age)) = read_memory(&state.memory, url) {
            if age < CACHE_STALE_SECS {
                if age >= CACHE_FRESH_SECS {
                    spawn_refresh(state.client.clone(), concurrency, url, state.cache());
                }
                let rendered = render_json_mode(body.as_ref(), mode);
                return reply(&mut stream, &rendered).await;
            }
        }

        if let Some(rx) = join_inflight(&state.inflight, url).await {
            if let Ok(body) = rx.await {
                let rendered = render_json_mode(body.as_ref(), mode);
                return reply(&mut stream, &rendered).await;
            }
        }
    }

    let out = Processor::new(&state.client, concurrency, state.cache())
        .process(url, no_cache, t0)
        .await
        .unwrap_or_else(|e| serde_json::json!({ "error": e.to_string() }).to_string());
    let body = out;
    if !no_cache {
        let body: Body = Arc::from(body);
        write_memory(&state.memory, url.to_string(), body.clone());
        finish_inflight(&state.inflight, url, body.clone()).await;
        let rendered = render_json_mode(body.as_ref(), mode);
        return reply(&mut stream, &rendered).await;
    }
    let rendered = render_json_mode(&body, mode);
    reply(&mut stream, &rendered).await
}

async fn reply(stream: &mut UnixStream, body: &str) -> Result {
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
