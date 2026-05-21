//! Local daemon for warm scans.
//!
//! The daemon owns in-memory processed/asset/redirect caches and coalesces
//! simultaneous requests for the same URL. The wire protocol is intentionally
//! tiny because it is only used by this binary over a private Unix socket.

use super::config::RuntimeConfig;
use super::fetch;
use super::processor::{
    mark_cached_body, memory_cache, read_memory, Body, CacheContext, CacheStatus, MemoryCache,
    Processor, CACHE_FRESH_SECS,
};
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
type SharedScan = Arc<std::result::Result<Body, DaemonReply>>;
type Inflight = Arc<Mutex<FxHashMap<String, Vec<oneshot::Sender<SharedScan>>>>>;
const DAEMON_PROTOCOL: &str = "hifi-daemon-v1";
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

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DaemonReply {
    pub exit_code: i32,
    pub stdout: String,
    #[serde(default)]
    pub stderr: String,
}

#[derive(Debug)]
pub enum DaemonRequest {
    Reply(DaemonReply),
    StaleDaemon,
    Unavailable,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
struct DaemonIdentity {
    version: String,
    build: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct WireRequest {
    protocol: String,
    client: DaemonIdentity,
    no_cache: bool,
    url: String,
}

impl WireRequest {
    fn scan(url: &str, no_cache: bool) -> Self {
        Self {
            protocol: DAEMON_PROTOCOL.to_string(),
            client: current_identity(),
            no_cache,
            url: url.to_string(),
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
struct WireReply {
    protocol: String,
    daemon: DaemonIdentity,
    status: WireStatus,
    #[serde(skip_serializing_if = "Option::is_none")]
    reply: Option<DaemonReply>,
}

impl WireReply {
    fn ok(reply: DaemonReply) -> Self {
        Self {
            protocol: DAEMON_PROTOCOL.to_string(),
            daemon: current_identity(),
            status: WireStatus::Ok,
            reply: Some(reply),
        }
    }

    fn version_mismatch() -> Self {
        Self {
            protocol: DAEMON_PROTOCOL.to_string(),
            daemon: current_identity(),
            status: WireStatus::VersionMismatch,
            reply: None,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum WireStatus {
    Ok,
    VersionMismatch,
}

#[derive(Clone)]
struct State {
    client: Client,
    config: RuntimeConfig,
    memory: MemoryCache,
    assets: fetch::AssetMemoryCache,
    inflight: Inflight,
}

impl State {
    fn new(client: Client, config: RuntimeConfig) -> Self {
        Self {
            client,
            config,
            memory: memory_cache(),
            assets: fetch::asset_memory_cache(),
            inflight: Arc::new(Mutex::new(FxHashMap::default())),
        }
    }

    fn cache(&self) -> CacheContext {
        CacheContext {
            memory: Some(self.memory.clone()),
            assets: Some(self.assets.clone()),
            allow_private: self.config.allow_private,
        }
    }
}

pub fn start() -> bool {
    std::env::current_exe()
        .ok()
        .and_then(|exe| {
            let mut command = Command::new(exe);
            command
                .arg("serve")
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null());
            detach_daemon(&mut command);
            command.spawn().ok()
        })
        .is_some()
}

#[cfg(unix)]
fn detach_daemon(command: &mut Command) {
    use std::os::unix::process::CommandExt;

    unsafe {
        command.pre_exec(|| {
            if libc::setsid() == -1 {
                Err(io::Error::last_os_error())
            } else {
                Ok(())
            }
        });
    }
}

#[cfg(not(unix))]
fn detach_daemon(_command: &mut Command) {}

pub async fn request(url: &str, no_cache: bool) -> DaemonRequest {
    let mut stream = match UnixStream::connect(socket_path()).await {
        Ok(stream) => stream,
        Err(_) => return DaemonRequest::Unavailable,
    };
    let peer_pid = peer_pid(&stream);
    let body = match serde_json::to_vec(&WireRequest::scan(url, no_cache)) {
        Ok(body) => body,
        Err(_) => return DaemonRequest::Unavailable,
    };
    if stream.write_all(&body).await.is_err() || stream.shutdown().await.is_err() {
        return DaemonRequest::Unavailable;
    }

    let mut buf = Vec::with_capacity(4096);
    if stream.read_to_end(&mut buf).await.is_err() {
        return DaemonRequest::Unavailable;
    }
    let reply = match serde_json::from_slice::<WireReply>(&buf) {
        Ok(reply) => reply,
        Err(_) => {
            retire_daemon(peer_pid);
            return DaemonRequest::StaleDaemon;
        }
    };
    if reply.protocol != DAEMON_PROTOCOL
        || reply.daemon != current_identity()
        || reply.status == WireStatus::VersionMismatch
    {
        retire_daemon(peer_pid);
        return DaemonRequest::StaleDaemon;
    }
    match reply.reply {
        Some(reply) => DaemonRequest::Reply(reply),
        None => DaemonRequest::Unavailable,
    }
}

pub async fn serve(client: Client, config: RuntimeConfig) -> Result {
    let path = socket_path();
    prepare_socket_dir(&path)?;
    let _ = std::fs::remove_file(&path);
    let listener = UnixListener::bind(&path)?;
    set_socket_private(&path)?;
    eprintln!("hifi daemon listening on {}", path.display());

    let state = State::new(client, config);
    loop {
        let (stream, _) = listener.accept().await?;
        let state = state.clone();
        tokio::spawn(async move {
            if let Err(e) = handle_conn(stream, state).await {
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

fn current_identity() -> DaemonIdentity {
    DaemonIdentity {
        version: env!("CARGO_PKG_VERSION").to_string(),
        build: env!("HIFI_BUILD_HASH").to_string(),
    }
}

fn client_matches_daemon(client: &DaemonIdentity) -> bool {
    *client == current_identity()
}

fn retire_daemon(peer_pid: Option<u32>) {
    if let Some(pid) = peer_pid.filter(|pid| *pid != std::process::id()) {
        terminate_process(pid);
    }
    let _ = std::fs::remove_file(socket_path());
}

#[cfg(unix)]
fn terminate_process(pid: u32) {
    let _ = unsafe { libc::kill(pid as libc::pid_t, libc::SIGTERM) };
}

#[cfg(not(unix))]
fn terminate_process(_pid: u32) {}

#[cfg(any(target_os = "linux", target_os = "android"))]
fn peer_pid(stream: &UnixStream) -> Option<u32> {
    use std::{mem, os::fd::AsRawFd};

    let mut cred: libc::ucred = unsafe { mem::zeroed() };
    let mut len = mem::size_of::<libc::ucred>() as libc::socklen_t;
    let ok = unsafe {
        libc::getsockopt(
            stream.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            &mut cred as *mut _ as *mut libc::c_void,
            &mut len,
        )
    } == 0;
    (ok && cred.pid > 0).then_some(cred.pid as u32)
}

#[cfg(target_os = "macos")]
fn peer_pid(stream: &UnixStream) -> Option<u32> {
    use std::{mem, os::fd::AsRawFd};

    let mut pid: libc::pid_t = 0;
    let mut len = mem::size_of::<libc::pid_t>() as libc::socklen_t;
    let ok = unsafe {
        libc::getsockopt(
            stream.as_raw_fd(),
            libc::SOL_LOCAL,
            libc::LOCAL_PEERPID,
            &mut pid as *mut _ as *mut libc::c_void,
            &mut len,
        )
    } == 0;
    (ok && pid > 0).then_some(pid as u32)
}

#[cfg(not(any(target_os = "linux", target_os = "android", target_os = "macos")))]
fn peer_pid(_stream: &UnixStream) -> Option<u32> {
    None
}

fn private_runtime_dir() -> PathBuf {
    let uid = user_id();
    std::env::temp_dir().join(format!("hifi-{uid}"))
}

#[cfg(unix)]
fn user_id() -> String {
    unsafe { libc::getuid() }.to_string()
}

#[cfg(not(unix))]
fn user_id() -> String {
    std::env::var("USERNAME")
        .or_else(|_| std::env::var("USER"))
        .unwrap_or_else(|_| std::process::id().to_string())
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

async fn handle_conn(mut stream: UnixStream, state: State) -> Result {
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
    let wire = match serde_json::from_slice::<WireRequest>(&req) {
        Ok(wire) if wire.protocol == DAEMON_PROTOCOL => wire,
        _ => {
            return reply_legacy(
                &mut stream,
                DaemonReply {
                    exit_code: 2,
                    stdout: String::new(),
                    stderr: "hifi: daemon protocol mismatch; restart hifi\n".into(),
                },
            )
            .await;
        }
    };
    if !client_matches_daemon(&wire.client) {
        reply_wire(&mut stream, WireReply::version_mismatch()).await?;
        std::process::exit(0);
    }
    let no_cache = wire.no_cache;
    let url = wire.url.as_str();
    if let Ok(parsed) = url::Url::parse(url) {
        if let Err(e) = super::net::validate_url(&parsed, state.config.allow_private) {
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
            if age < CACHE_FRESH_SECS {
                let body = mark_cached_body(&body, t0, CacheStatus::Fresh, age)?;
                return reply(
                    &mut stream,
                    DaemonReply {
                        exit_code: 0,
                        stdout: body.to_string(),
                        stderr: String::new(),
                    },
                )
                .await;
            }
        }

        let mut guard = join_inflight(&state.inflight, url).await;
        if let Some(rx) = guard.waiter.take() {
            if let Ok(shared) = rx.await {
                return match &*shared {
                    Ok(body) => {
                        reply(
                            &mut stream,
                            DaemonReply {
                                exit_code: 0,
                                stdout: body.to_string(),
                                stderr: String::new(),
                            },
                        )
                        .await
                    }
                    Err(error) => reply(&mut stream, error.clone()).await,
                };
            }
        }
        if guard.owner {
            inflight_guard = Some(guard);
        }
    }

    let processed = Processor::new(&state.client, state.config.chunk_concurrency, state.cache())
        .process_for_display(url, no_cache, t0)
        .await;
    let out = match processed {
        Ok(out) => out,
        Err(e) => {
            let error = DaemonReply {
                exit_code: 2,
                stdout: String::new(),
                stderr: format!("hifi: {e}\n"),
            };
            if !no_cache {
                finish_inflight(&state.inflight, url, Arc::new(Err(error.clone()))).await;
                drop(inflight_guard);
            }
            return reply(&mut stream, error).await;
        }
    };
    let body = out.to_json_string()?;
    if !no_cache {
        let body: Body = Arc::from(body);
        finish_inflight(&state.inflight, url, Arc::new(Ok(body.clone()))).await;
        drop(inflight_guard);
        return reply(
            &mut stream,
            DaemonReply {
                exit_code: 0,
                stdout: body.to_string(),
                stderr: String::new(),
            },
        )
        .await;
    }
    reply(
        &mut stream,
        DaemonReply {
            exit_code: 0,
            stdout: body,
            stderr: String::new(),
        },
    )
    .await
}

async fn reply(stream: &mut UnixStream, body: DaemonReply) -> Result {
    reply_wire(stream, WireReply::ok(body)).await
}

async fn reply_wire(stream: &mut UnixStream, body: WireReply) -> Result {
    let body = serde_json::to_string(&body)?;
    stream.write_all(body.as_bytes()).await?;
    Ok(())
}

async fn reply_legacy(stream: &mut UnixStream, body: DaemonReply) -> Result {
    let body = serde_json::to_string(&body)?;
    stream.write_all(body.as_bytes()).await?;
    Ok(())
}

struct InflightGuard {
    inflight: Inflight,
    url: String,
    waiter: Option<oneshot::Receiver<SharedScan>>,
    owner: bool,
}

// Only one task computes a cold URL. Other callers wait on the owner and all
// receive the same serialized body when the scan finishes.
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

async fn join_inflight(inflight: &Inflight, url: &str) -> InflightGuard {
    let mut in_flight = inflight.lock().await;
    if let Some(waiters) = in_flight.get_mut(url) {
        let (tx, rx) = oneshot::channel();
        waiters.push(tx);
        InflightGuard {
            inflight: inflight.clone(),
            url: url.to_string(),
            waiter: Some(rx),
            owner: false,
        }
    } else {
        in_flight.insert(url.to_string(), Vec::new());
        InflightGuard {
            inflight: inflight.clone(),
            url: url.to_string(),
            waiter: None,
            owner: true,
        }
    }
}

async fn finish_inflight(inflight: &Inflight, url: &str, result: SharedScan) {
    for tx in inflight.lock().await.remove(url).unwrap_or_default() {
        let _ = tx.send(result.clone());
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wire_request_carries_current_identity() {
        let request = WireRequest::scan("https://example.com/", true);

        assert_eq!(request.protocol, DAEMON_PROTOCOL);
        assert_eq!(request.client, current_identity());
        assert!(request.no_cache);
        assert_eq!(request.url, "https://example.com/");
    }

    #[test]
    fn mismatched_client_identity_is_rejected() {
        let mut stale = current_identity();
        stale.build.push_str("-stale");

        assert!(!client_matches_daemon(&stale));
    }
}
