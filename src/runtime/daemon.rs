//! Local daemon for warm scans.
//!
//! The daemon owns in-memory processed/asset/redirect caches and coalesces
//! simultaneous requests for the same URL. The wire protocol is intentionally
//! tiny because it is only used by this binary over a private Unix socket.

#[cfg(unix)]
use super::cache::CACHE_FRESH_SECS;
use super::config::RuntimeConfig;
#[cfg(unix)]
use super::fetch;
use super::http::Client;
#[cfg(unix)]
use super::processor::{
    decode_output_binary, encode_output_binary, mark_cached_body, memory_cache, read_memory,
    CacheContext, CacheStatus, MemoryBody, MemoryCache, Output, Processor,
};
#[cfg(unix)]
use crate::hash::FxHashMap;
use std::io;
#[cfg(unix)]
use std::{
    path::PathBuf,
    process::{Command, Stdio},
    sync::Arc,
    time::Instant,
};
use thiserror::Error;
#[cfg(unix)]
use tokio::io::{AsyncReadExt, AsyncWriteExt};
#[cfg(unix)]
use tokio::net::{UnixListener, UnixStream};
#[cfg(unix)]
use tokio::sync::{oneshot, Mutex};

type Result<T = ()> = std::result::Result<T, DaemonError>;
#[cfg(unix)]
type SharedScan = Arc<std::result::Result<MemoryBody, DaemonReply>>;
#[cfg(unix)]
type Inflight = Arc<Mutex<FxHashMap<String, Vec<oneshot::Sender<SharedScan>>>>>;
#[cfg(unix)]
const MAX_DAEMON_REQUEST_BYTES: usize = 8192;
const MAX_DAEMON_REPLY_BYTES: usize = 16 * 1024 * 1024;

#[derive(Debug, Error)]
pub enum DaemonError {
    #[error(transparent)]
    Io(#[from] io::Error),
    #[error("daemon wire decode failed")]
    WireDecode,
    #[error(transparent)]
    Runtime(#[from] super::processor::RuntimeError),
    #[error(transparent)]
    Utf8(#[from] std::str::Utf8Error),
    #[cfg(not(unix))]
    #[error("daemon is unsupported on this platform; run scans without the daemon")]
    UnsupportedPlatform,
}

#[derive(Clone, Debug)]
pub struct DaemonReply {
    pub exit_code: i32,
    pub stdout: String,
    pub stderr: String,
    pub output: Option<Output>,
}

#[derive(Debug)]
pub enum DaemonRequest {
    Reply(Box<DaemonReply>),
    StaleDaemon,
    Unavailable,
}

#[cfg(unix)]
#[derive(Clone, Debug, Eq, PartialEq)]
struct DaemonIdentity {
    version: String,
    build: String,
}

#[cfg(unix)]
struct WireRequest {
    client: DaemonIdentity,
    no_cache: bool,
    url: String,
}

#[cfg(unix)]
impl WireRequest {
    fn scan(url: &str, no_cache: bool) -> Self {
        Self {
            client: current_identity(),
            no_cache,
            url: url.to_string(),
        }
    }
}

#[cfg(unix)]
struct WireReply {
    daemon: DaemonIdentity,
    status: WireStatus,
    reply: Option<DaemonReply>,
}

#[cfg(unix)]
impl WireReply {
    fn ok(reply: DaemonReply) -> Self {
        Self {
            daemon: current_identity(),
            status: WireStatus::Ok,
            reply: Some(reply),
        }
    }

    fn version_mismatch() -> Self {
        Self {
            daemon: current_identity(),
            status: WireStatus::VersionMismatch,
            reply: None,
        }
    }
}

#[cfg(unix)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum WireStatus {
    Ok,
    VersionMismatch,
}

// Binary wire format. The magic bytes identify the protocol; a daemon and CLI
// built from different versions will fail to decode each other's messages and
// the stale daemon will retire.
#[cfg(unix)]
const WIRE_REQUEST_MAGIC: &[u8; 8] = b"HIFIRQ4\0";
#[cfg(unix)]
const WIRE_REPLY_MAGIC: &[u8; 8] = b"HIFIRP4\0";

#[cfg(unix)]
fn put_u32(out: &mut Vec<u8>, value: u32) {
    out.extend_from_slice(&value.to_le_bytes());
}

#[cfg(unix)]
fn put_string(out: &mut Vec<u8>, value: &str) {
    put_u32(out, value.len() as u32);
    out.extend_from_slice(value.as_bytes());
}

#[cfg(unix)]
fn put_bytes(out: &mut Vec<u8>, value: &[u8]) {
    put_u32(out, value.len() as u32);
    out.extend_from_slice(value);
}

#[cfg(unix)]
fn put_identity(out: &mut Vec<u8>, id: &DaemonIdentity) {
    put_string(out, &id.version);
    put_string(out, &id.build);
}

#[cfg(unix)]
struct WireReader<'a> {
    bytes: &'a [u8],
    pos: usize,
}

#[cfg(unix)]
impl<'a> WireReader<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, pos: 0 }
    }
    fn expect_magic(&mut self, magic: &[u8; 8]) -> Option<()> {
        let slice = self.bytes.get(self.pos..self.pos + 8)?;
        if slice != magic {
            return None;
        }
        self.pos += 8;
        Some(())
    }
    fn u8(&mut self) -> Option<u8> {
        let b = *self.bytes.get(self.pos)?;
        self.pos += 1;
        Some(b)
    }
    fn i32(&mut self) -> Option<i32> {
        let slice = self.bytes.get(self.pos..self.pos + 4)?;
        self.pos += 4;
        Some(i32::from_le_bytes(slice.try_into().ok()?))
    }
    fn u32(&mut self) -> Option<u32> {
        let slice = self.bytes.get(self.pos..self.pos + 4)?;
        self.pos += 4;
        Some(u32::from_le_bytes(slice.try_into().ok()?))
    }
    fn string(&mut self) -> Option<String> {
        let len = self.u32()? as usize;
        let slice = self.bytes.get(self.pos..self.pos + len)?;
        self.pos += len;
        std::str::from_utf8(slice).ok().map(str::to_owned)
    }
    fn bytes(&mut self) -> Option<&'a [u8]> {
        let len = self.u32()? as usize;
        let slice = self.bytes.get(self.pos..self.pos + len)?;
        self.pos += len;
        Some(slice)
    }
    fn identity(&mut self) -> Option<DaemonIdentity> {
        Some(DaemonIdentity {
            version: self.string()?,
            build: self.string()?,
        })
    }
    fn finish(&self) -> Option<()> {
        (self.pos == self.bytes.len()).then_some(())
    }
}

#[cfg(unix)]
impl WireRequest {
    fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(64 + self.url.len());
        out.extend_from_slice(WIRE_REQUEST_MAGIC);
        put_identity(&mut out, &self.client);
        out.push(self.no_cache as u8);
        put_string(&mut out, &self.url);
        out
    }

    fn decode(bytes: &[u8]) -> Option<Self> {
        let mut r = WireReader::new(bytes);
        r.expect_magic(WIRE_REQUEST_MAGIC)?;
        let client = r.identity()?;
        let no_cache = match r.u8()? {
            0 => false,
            1 => true,
            _ => return None,
        };
        let url = r.string()?;
        r.finish()?;
        Some(Self {
            client,
            no_cache,
            url,
        })
    }
}

#[cfg(unix)]
impl WireReply {
    fn encode(&self) -> Vec<u8> {
        let approx = 32
            + self.daemon.version.len()
            + self.daemon.build.len()
            + self
                .reply
                .as_ref()
                .map_or(0, |r| r.stdout.len() + r.stderr.len() + 16);
        let mut out = Vec::with_capacity(approx);
        out.extend_from_slice(WIRE_REPLY_MAGIC);
        put_identity(&mut out, &self.daemon);
        out.push(match self.status {
            WireStatus::Ok => 0,
            WireStatus::VersionMismatch => 1,
        });
        match &self.reply {
            Some(reply) => {
                out.push(1);
                out.extend_from_slice(&reply.exit_code.to_le_bytes());
                put_string(&mut out, &reply.stdout);
                put_string(&mut out, &reply.stderr);
                match &reply.output {
                    Some(output) => {
                        out.push(1);
                        put_bytes(&mut out, &encode_output_binary(output));
                    }
                    None => out.push(0),
                }
            }
            None => out.push(0),
        }
        out
    }

    fn decode(bytes: &[u8]) -> Option<Self> {
        let mut r = WireReader::new(bytes);
        r.expect_magic(WIRE_REPLY_MAGIC)?;
        let daemon = r.identity()?;
        let status = match r.u8()? {
            0 => WireStatus::Ok,
            1 => WireStatus::VersionMismatch,
            _ => return None,
        };
        let reply = match r.u8()? {
            0 => None,
            1 => Some(DaemonReply {
                exit_code: r.i32()?,
                stdout: r.string()?,
                stderr: r.string()?,
                output: match r.u8()? {
                    0 => None,
                    1 => Some(decode_output_binary(r.bytes()?)?),
                    _ => return None,
                },
            }),
            _ => return None,
        };
        r.finish()?;
        Some(Self {
            daemon,
            status,
            reply,
        })
    }
}

#[cfg(unix)]
#[derive(Clone)]
struct State {
    client: Client,
    config: RuntimeConfig,
    memory: MemoryCache,
    assets: fetch::AssetMemoryCache,
    inflight: Inflight,
}

#[cfg(unix)]
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

#[cfg(not(unix))]
pub fn start() -> bool {
    false
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

#[cfg(unix)]
pub async fn request(url: &str, no_cache: bool) -> DaemonRequest {
    let mut stream = match UnixStream::connect(socket_path()).await {
        Ok(stream) => stream,
        Err(_) => return DaemonRequest::Unavailable,
    };
    let peer_pid = peer_pid(&stream);
    let body = WireRequest::scan(url, no_cache).encode();
    if stream.write_all(&body).await.is_err() || stream.shutdown().await.is_err() {
        return DaemonRequest::Unavailable;
    }

    let mut buf = Vec::with_capacity(4096);
    if (&mut stream)
        .take(MAX_DAEMON_REPLY_BYTES as u64 + 1)
        .read_to_end(&mut buf)
        .await
        .is_err()
    {
        return DaemonRequest::Unavailable;
    }
    if buf.len() > MAX_DAEMON_REPLY_BYTES {
        return DaemonRequest::Unavailable;
    }
    let reply = match WireReply::decode(&buf) {
        Some(reply) => reply,
        None => {
            retire_daemon(peer_pid);
            return DaemonRequest::StaleDaemon;
        }
    };
    if reply.daemon != current_identity() || reply.status == WireStatus::VersionMismatch {
        retire_daemon(peer_pid);
        return DaemonRequest::StaleDaemon;
    }
    match reply.reply {
        Some(reply) => DaemonRequest::Reply(Box::new(reply)),
        None => DaemonRequest::Unavailable,
    }
}

#[cfg(not(unix))]
pub async fn request(_url: &str, _no_cache: bool) -> DaemonRequest {
    DaemonRequest::Unavailable
}

#[cfg(unix)]
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

#[cfg(not(unix))]
pub async fn serve(_client: Client, _config: RuntimeConfig) -> Result {
    Err(DaemonError::UnsupportedPlatform)
}

#[cfg(unix)]
fn socket_path() -> PathBuf {
    let dir = std::env::var("XDG_RUNTIME_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|_| private_runtime_dir());
    dir.join("hifi.sock")
}

#[cfg(unix)]
fn current_identity() -> DaemonIdentity {
    DaemonIdentity {
        version: env!("CARGO_PKG_VERSION").to_string(),
        build: env!("HIFI_BUILD_HASH").to_string(),
    }
}

#[cfg(unix)]
fn client_matches_daemon(client: &DaemonIdentity) -> bool {
    *client == current_identity()
}

#[cfg(unix)]
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

#[cfg(unix)]
fn private_runtime_dir() -> PathBuf {
    let uid = user_id();
    std::env::temp_dir().join(format!("hifi-{uid}"))
}

#[cfg(unix)]
fn user_id() -> String {
    unsafe { libc::getuid() }.to_string()
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

#[cfg(unix)]
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
                output: None,
            },
        )
        .await;
    }
    let wire = match WireRequest::decode(&req) {
        Some(wire) => wire,
        None => {
            reply_wire(&mut stream, WireReply::version_mismatch()).await?;
            std::process::exit(0);
        }
    };
    if !client_matches_daemon(&wire.client) {
        reply_wire(&mut stream, WireReply::version_mismatch()).await?;
        std::process::exit(0);
    }
    let no_cache = wire.no_cache;
    let url = wire.url.as_str();
    if let Ok(parsed) = crate::url::Url::parse(url) {
        if let Err(e) = super::net::validate_url(&parsed, state.config.allow_private) {
            return reply(
                &mut stream,
                DaemonReply {
                    exit_code: 2,
                    stdout: String::new(),
                    stderr: format!("hifi: {e}\n"),
                    output: None,
                },
            )
            .await;
        }
    }

    let mut inflight_guard = None;
    if !no_cache {
        if let Some((body, age)) = read_memory(&state.memory, url) {
            if age < CACHE_FRESH_SECS {
                let body = mark_cached_body(&body, t0, CacheStatus::Fresh, age);
                return reply(
                    &mut stream,
                    DaemonReply {
                        exit_code: 0,
                        stdout: String::new(),
                        stderr: String::new(),
                        output: Some((*body).clone()),
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
                                stdout: String::new(),
                                stderr: String::new(),
                                output: Some((**body).clone()),
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
                output: None,
            };
            if !no_cache {
                finish_inflight(&state.inflight, url, Arc::new(Err(error.clone()))).await;
                drop(inflight_guard);
            }
            return reply(&mut stream, error).await;
        }
    };
    if !no_cache {
        let body = Arc::new(out);
        finish_inflight(&state.inflight, url, Arc::new(Ok(body.clone()))).await;
        drop(inflight_guard);
        return reply(
            &mut stream,
            DaemonReply {
                exit_code: 0,
                stdout: String::new(),
                stderr: String::new(),
                output: Some((*body).clone()),
            },
        )
        .await;
    }
    reply(
        &mut stream,
        DaemonReply {
            exit_code: 0,
            stdout: String::new(),
            stderr: String::new(),
            output: Some(out),
        },
    )
    .await
}

#[cfg(unix)]
async fn reply(stream: &mut UnixStream, body: DaemonReply) -> Result {
    reply_wire(stream, WireReply::ok(body)).await
}

#[cfg(unix)]
async fn reply_wire(stream: &mut UnixStream, body: WireReply) -> Result {
    let body = body.encode();
    stream.write_all(&body).await?;
    Ok(())
}

#[cfg(unix)]
struct InflightGuard {
    inflight: Inflight,
    url: String,
    waiter: Option<oneshot::Receiver<SharedScan>>,
    owner: bool,
}

// Only one task computes a cold URL. Other callers wait on the owner and all
// receive the same serialized body when the scan finishes.
#[cfg(unix)]
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

#[cfg(unix)]
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

#[cfg(unix)]
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

#[cfg(unix)]
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wire_request_carries_current_identity() {
        let request = WireRequest::scan("https://example.com/", true);

        assert_eq!(request.client, current_identity());
        assert!(request.no_cache);
        assert_eq!(request.url, "https://example.com/");
    }

    #[test]
    fn wire_request_roundtrips_through_binary() {
        let original = WireRequest::scan("https://example.com/foo?q=1", true);
        let bytes = original.encode();
        let decoded = WireRequest::decode(&bytes).expect("decode");
        assert_eq!(decoded.client, original.client);
        assert_eq!(decoded.no_cache, original.no_cache);
        assert_eq!(decoded.url, original.url);
    }

    #[test]
    fn wire_reply_roundtrips_through_binary() {
        let original = WireReply::ok(DaemonReply {
            exit_code: 42,
            stdout: "hello".into(),
            stderr: "warn\n".into(),
            output: None,
        });
        let bytes = original.encode();
        let decoded = WireReply::decode(&bytes).expect("decode");
        assert_eq!(decoded.daemon, original.daemon);
        assert_eq!(decoded.status, original.status);
        let reply = decoded.reply.expect("reply present");
        assert_eq!(reply.exit_code, 42);
        assert_eq!(reply.stdout, "hello");
        assert_eq!(reply.stderr, "warn\n");
    }

    #[test]
    fn wire_reply_with_no_payload_roundtrips() {
        let original = WireReply::version_mismatch();
        let bytes = original.encode();
        let decoded = WireReply::decode(&bytes).expect("decode");
        assert_eq!(decoded.status, WireStatus::VersionMismatch);
        assert!(decoded.reply.is_none());
    }

    #[test]
    fn wire_decode_rejects_wrong_magic() {
        let mut bytes = WireRequest::scan("https://example.com/", false).encode();
        bytes[0] = b'X';
        assert!(WireRequest::decode(&bytes).is_none());
    }

    #[test]
    fn wire_decode_rejects_trailing_bytes() {
        let mut bytes = WireRequest::scan("https://example.com/", false).encode();
        bytes.push(0);
        assert!(WireRequest::decode(&bytes).is_none());

        let mut bytes = WireReply::version_mismatch().encode();
        bytes.push(0);
        assert!(WireReply::decode(&bytes).is_none());
    }

    #[test]
    fn wire_request_rejects_invalid_bool() {
        let mut bytes = WireRequest::scan("https://example.com/", false).encode();
        let bool_pos =
            8 + 4 + current_identity().version.len() + 4 + current_identity().build.len();
        bytes[bool_pos] = 2;
        assert!(WireRequest::decode(&bytes).is_none());
    }

    #[test]
    fn mismatched_client_identity_is_rejected() {
        let mut stale = current_identity();
        stale.build.push_str("-stale");

        assert!(!client_matches_daemon(&stale));
    }
}
