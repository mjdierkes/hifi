use super::fetch;
use super::processor::{
    memory_cache, read_memory, redirect_cache, spawn_refresh, write_memory, Body, CacheContext,
    MemoryCache, Processor, RedirectMemory, CACHE_FRESH_SECS, CACHE_STALE_SECS,
};
use crate::app::{render_json_mode, warning_text, warning_text_from_json, OutputMode};
use reqwest::Client;
use rustc_hash::FxHashMap;
use serde::{Deserialize, Serialize};
use std::{
    io,
    path::PathBuf,
    process::{Command, Stdio},
    sync::Arc,
    time::Instant,
};
use thiserror::Error;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::{oneshot, Mutex};

type Result<T = ()> = std::result::Result<T, DaemonError>;
type Inflight = Arc<Mutex<FxHashMap<String, Vec<oneshot::Sender<Body>>>>>;
const MAX_DAEMON_REQUEST_BYTES: usize = 8192;

#[derive(Debug, Error)]
pub enum DaemonError {
    #[error(transparent)]
    Io(#[from] io::Error),
    #[error(transparent)]
    Json(#[from] serde_json::Error),
    #[error(transparent)]
    Runtime(#[from] super::processor::RuntimeError),
    #[error(transparent)]
    Utf8(#[from] std::str::Utf8Error),
}

#[derive(Debug, Serialize, Deserialize)]
pub struct DaemonReply {
    pub exit_code: i32,
    pub stdout: String,
    #[serde(default)]
    pub stderr: String,
}

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
            memory: memory_cache(),
            chunks: fetch::chunk_memory_cache(),
            redirects: redirect_cache(),
            inflight: Arc::new(Mutex::new(FxHashMap::default())),
        }
    }

    fn cache(&self) -> CacheContext {
        CacheContext {
            memory: Some(self.memory.clone()),
            chunks: Some(self.chunks.clone()),
            redirects: Some(self.redirects.clone()),
            allow_private: super::net::allow_private_networks(),
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

pub async fn request(url: &str, no_cache: bool, mode: OutputMode) -> Option<DaemonReply> {
    let mut stream = UnixStream::connect(socket_path()).await.ok()?;
    stream
        .write_all(&[b'0' + no_cache as u8, mode.as_daemon_byte()])
        .await
        .ok()?;
    stream.write_all(url.as_bytes()).await.ok()?;
    stream.shutdown().await.ok();

    let mut buf = Vec::with_capacity(4096);
    stream.read_to_end(&mut buf).await.ok()?;
    let body = String::from_utf8(buf).ok()?;
    serde_json::from_str(&body).ok().or_else(|| {
        if let Some(error) = serde_json::from_str::<serde_json::Value>(&body)
            .ok()
            .and_then(|v| v.get("error").and_then(|e| e.as_str()).map(str::to_string))
        {
            return Some(DaemonReply {
                exit_code: 2,
                stdout: String::new(),
                stderr: format!("hifi: {error}\n"),
            });
        }
        Some(DaemonReply {
            exit_code: 0,
            stdout: body,
            stderr: String::new(),
        })
    })
}

pub async fn serve(client: Client, concurrency: usize) -> Result {
    let path = socket_path();
    prepare_socket_dir(&path)?;
    let _ = std::fs::remove_file(&path);
    let listener = UnixListener::bind(&path)?;
    set_socket_private(&path)?;
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
        .unwrap_or_else(|_| private_runtime_dir());
    dir.join("hifi.sock")
}

fn private_runtime_dir() -> PathBuf {
    let uid = std::env::var("UID").unwrap_or_else(|_| std::process::id().to_string());
    std::env::temp_dir().join(format!("hifi-{uid}"))
}

#[cfg(unix)]
fn prepare_socket_dir(path: &std::path::Path) -> io::Result<()> {
    use std::os::unix::fs::PermissionsExt;

    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)?;
        std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))?;
    }
    Ok(())
}

#[cfg(not(unix))]
fn prepare_socket_dir(path: &std::path::Path) -> io::Result<()> {
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)?;
    }
    Ok(())
}

async fn handle_conn(mut stream: UnixStream, state: State, concurrency: usize) -> Result {
    let t0 = Instant::now();
    let mut req = Vec::with_capacity(512);
    (&mut stream)
        .take(MAX_DAEMON_REQUEST_BYTES as u64 + 1)
        .read_to_end(&mut req)
        .await?;
    if req.len() > MAX_DAEMON_REQUEST_BYTES {
        return reply(
            &mut stream,
            DaemonReply {
                exit_code: 2,
                stdout: String::new(),
                stderr: "hifi: request too large\n".into(),
            },
        )
        .await;
    }
    let no_cache = req.first() == Some(&b'1');
    let (mode, url_bytes) = req
        .get(1)
        .and_then(|b| OutputMode::from_daemon_byte(*b))
        .map(|mode| (mode, req.get(2..).unwrap_or_default()))
        .unwrap_or((OutputMode::Json, req.get(1..).unwrap_or_default()));
    let url = std::str::from_utf8(url_bytes)?;
    if let Ok(parsed) = url::Url::parse(url) {
        if let Err(e) = super::net::validate_url(&parsed, super::net::allow_private_networks()) {
            return reply(
                &mut stream,
                DaemonReply {
                    exit_code: 2,
                    stdout: String::new(),
                    stderr: format!("hifi: {e}\n"),
                },
            )
            .await;
        }
    }

    let mut inflight_guard = None;
    if !no_cache {
        if let Some((body, age)) = read_memory(&state.memory, url) {
            if age < CACHE_STALE_SECS {
                if age >= CACHE_FRESH_SECS {
                    spawn_refresh(state.client.clone(), concurrency, url, state.cache());
                }
                let rendered = render_json_mode(body.as_ref(), mode);
                let stderr = warning_text_from_json(body.as_ref());
                return reply(
                    &mut stream,
                    DaemonReply {
                        exit_code: 0,
                        stdout: rendered,
                        stderr,
                    },
                )
                .await;
            }
        }

        let Some(mut guard) = join_inflight(&state.inflight, url).await else {
            return reply(
                &mut stream,
                DaemonReply {
                    exit_code: 2,
                    stdout: String::new(),
                    stderr: "hifi: too many inflight requests\n".into(),
                },
            )
            .await;
        };
        if let Some(rx) = guard.waiter.take() {
            if let Ok(body) = rx.await {
                let rendered = render_json_mode(body.as_ref(), mode);
                let stderr = warning_text_from_json(body.as_ref());
                return reply(
                    &mut stream,
                    DaemonReply {
                        exit_code: 0,
                        stdout: rendered,
                        stderr,
                    },
                )
                .await;
            }
        }
        if guard.owner {
            inflight_guard = Some(guard);
        }
    }

    let processed = Processor::new(&state.client, concurrency, state.cache())
        .process_for_display(url, no_cache, t0)
        .await;
    let out = match processed {
        Ok(out) => out,
        Err(e) => {
            return reply(
                &mut stream,
                DaemonReply {
                    exit_code: 2,
                    stdout: String::new(),
                    stderr: format!("hifi: {e}\n"),
                },
            )
            .await;
        }
    };
    let stderr = warning_text(&out);
    let body = out.to_json_string()?;
    if !no_cache {
        let body: Body = Arc::from(body);
        write_memory(&state.memory, url.to_string(), body.clone());
        finish_inflight(&state.inflight, url, body.clone()).await;
        drop(inflight_guard);
        let rendered = render_json_mode(body.as_ref(), mode);
        return reply(
            &mut stream,
            DaemonReply {
                exit_code: 0,
                stdout: rendered,
                stderr,
            },
        )
        .await;
    }
    let rendered = render_json_mode(&body, mode);
    reply(
        &mut stream,
        DaemonReply {
            exit_code: 0,
            stdout: rendered,
            stderr,
        },
    )
    .await
}

async fn reply(stream: &mut UnixStream, body: DaemonReply) -> Result {
    let body = serde_json::to_string(&body)?;
    stream.write_all(body.as_bytes()).await?;
    Ok(())
}

struct InflightGuard {
    inflight: Inflight,
    url: String,
    waiter: Option<oneshot::Receiver<Body>>,
    owner: bool,
}

impl Drop for InflightGuard {
    fn drop(&mut self) {
        if self.owner {
            let inflight = self.inflight.clone();
            let url = self.url.clone();
            tokio::spawn(async move {
                inflight.lock().await.remove(&url);
            });
        }
    }
}

async fn join_inflight(inflight: &Inflight, url: &str) -> Option<InflightGuard> {
    let mut in_flight = inflight.lock().await;
    if let Some(waiters) = in_flight.get_mut(url) {
        let (tx, rx) = oneshot::channel();
        waiters.push(tx);
        Some(InflightGuard {
            inflight: inflight.clone(),
            url: url.to_string(),
            waiter: Some(rx),
            owner: false,
        })
    } else {
        in_flight.insert(url.to_string(), Vec::new());
        Some(InflightGuard {
            inflight: inflight.clone(),
            url: url.to_string(),
            waiter: None,
            owner: true,
        })
    }
}

async fn finish_inflight(inflight: &Inflight, url: &str, body: Body) {
    for tx in inflight.lock().await.remove(url).unwrap_or_default() {
        let _ = tx.send(body.clone());
    }
}

#[cfg(unix)]
fn set_socket_private(path: &std::path::Path) -> io::Result<()> {
    use std::os::unix::fs::PermissionsExt;

    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)?;
        let _ = std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700));
    }
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
}

#[cfg(not(unix))]
fn set_socket_private(path: &std::path::Path) -> io::Result<()> {
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)?;
    }
    let _ = path;
    Ok(())
}
