use crate::grep;
use crate::runtime::daemon;
use crate::runtime::net;
use crate::runtime::processor::{CacheContext, Output, Processor, CACHE_FRESH_SECS};
use reqwest::Client;
use std::io::{self, Write};
use std::time::Duration;
use thiserror::Error;

const MAX_CHUNK_CONCURRENCY: usize = 32;
const HARD_MAX_CHUNK_CONCURRENCY: usize = 128;

const HELP: &str = "\
hifi — map an HTTP API surface

USAGE:
    hifi <url> [--no-cache] [--no-daemon] [--flat|--json]
    hifi grep <url> <pattern> [-C N]
    hifi serve

EXAMPLES:
    hifi example.com
    hifi https://api.example.com/v2
    hifi grep example.com TODO -C 2

FLAGS:
    -h, --help        show this help
        --no-cache    bypass cached results
        --no-daemon   skip the background daemon
        --flat        print tab-separated output
        --json        print machine-readable JSON
";

#[derive(Debug, Error)]
pub enum AppError {
    #[error("{0}")]
    Message(String),
    #[error(transparent)]
    Daemon(#[from] daemon::DaemonError),
    #[error(transparent)]
    Io(#[from] io::Error),
    #[error(transparent)]
    Json(#[from] serde_json::Error),
    #[error(transparent)]
    Net(#[from] net::NetError),
    #[error(transparent)]
    Reqwest(#[from] reqwest::Error),
    #[error(transparent)]
    Runtime(#[from] crate::runtime::processor::RuntimeError),
    #[error(transparent)]
    Url(#[from] url::ParseError),
}

impl From<String> for AppError {
    fn from(value: String) -> Self {
        Self::Message(value)
    }
}

impl From<&'static str> for AppError {
    fn from(value: &'static str) -> Self {
        Self::Message(value.to_string())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OutputMode {
    Auto,
    Flat,
    Json,
}

impl OutputMode {
    pub fn for_stdout(self) -> Self {
        match self {
            Self::Auto => Self::Flat,
            mode => mode,
        }
    }

    pub fn as_daemon_byte(self) -> u8 {
        match self.for_stdout() {
            Self::Auto => b'a',
            Self::Flat => b'f',
            Self::Json => b'j',
        }
    }

    pub fn from_daemon_byte(b: u8) -> Option<Self> {
        Some(match b {
            b'f' => Self::Flat,
            b'j' => Self::Json,
            b'a' => Self::Auto,
            _ => return None,
        })
    }
}

pub async fn run(raw: Vec<String>) -> Result<i32, AppError> {
    if raw.is_empty() {
        print!("{HELP}");
        return Ok(0);
    }
    if matches!(raw[0].as_str(), "-h" | "--help" | "help") {
        print!("{HELP}");
        return Ok(0);
    }

    let concurrency = chunk_concurrency();
    let client = make_client(concurrency)?;

    if raw[0] == "grep" {
        return grep::run(&raw[1..], client, concurrency).await;
    }
    if raw[0] == "serve" {
        daemon::serve(client, concurrency).await?;
        return Ok(0);
    }

    let mut url = None;
    let (mut no_cache, mut no_daemon) = (false, false);
    let mut mode = OutputMode::Auto;
    for arg in &raw {
        match arg.as_str() {
            "--no-cache" => no_cache = true,
            "--no-daemon" => no_daemon = true,
            "--flat" => mode = set_mode(mode, OutputMode::Flat)?,
            "--json" => mode = set_mode(mode, OutputMode::Json)?,
            s if s.starts_with("--") || s.starts_with('-') => {
                return Err(format!("unknown flag '{s}' (try --help)").into());
            }
            _ if url.is_none() => url = Some(arg.clone()),
            _ => return Err(format!("unexpected argument '{arg}' (try --help)").into()),
        }
    }
    let url = url.ok_or("missing URL (try --help)")?;
    let url = normalize_url(&url)?;

    if !no_daemon {
        if let Some(reply) = daemon_output(&url, no_cache, mode).await {
            print!("{}", reply.stdout);
            eprint!("{}", reply.stderr);
            return Ok(reply.exit_code);
        }
    }

    let out = Processor::new(
        &client,
        concurrency,
        CacheContext {
            allow_private: net::allow_private_networks(),
            ..CacheContext::default()
        },
    )
    .process_for_display(&url, no_cache, std::time::Instant::now())
    .await?;
    render_processed(&out, mode)?;
    render_warnings(&out);
    Ok(0)
}

fn set_mode(current: OutputMode, next: OutputMode) -> Result<OutputMode, AppError> {
    if current != OutputMode::Auto && current != next {
        return Err("choose only one of --flat or --json".into());
    }
    Ok(next)
}

pub fn normalize_url(url: &str) -> Result<String, AppError> {
    if url.contains("://") {
        let parsed = url::Url::parse(url)?;
        if !matches!(parsed.scheme(), "http" | "https") {
            return Err(format!("unsupported URL scheme '{}'", parsed.scheme()).into());
        }
        Ok(parsed.to_string())
    } else {
        Ok(url::Url::parse(&format!("https://{url}"))?.to_string())
    }
}

pub fn render_json_mode(json: &str, mode: OutputMode) -> String {
    match mode.for_stdout() {
        OutputMode::Json => {
            let mut out = String::with_capacity(json.len() + 1);
            out.push_str(json);
            if !out.ends_with('\n') {
                out.push('\n');
            }
            out
        }
        OutputMode::Flat | OutputMode::Auto => render_flat(json),
    }
}

fn render_processed(out: &Output, mode: OutputMode) -> Result<(), AppError> {
    let stdout = io::stdout();
    let mut stdout = io::BufWriter::new(stdout.lock());
    match mode.for_stdout() {
        OutputMode::Json => {
            serde_json::to_writer(&mut stdout, &out)?;
            stdout.write_all(b"\n")?;
        }
        OutputMode::Flat | OutputMode::Auto => render_flat_output(out, &mut stdout)?,
    }
    Ok(())
}

pub fn warning_text(out: &Output) -> String {
    out.warnings
        .iter()
        .map(|w| format!("hifi: warning: {w}\n"))
        .collect()
}

pub fn warning_text_from_json(json: &str) -> String {
    serde_json::from_str::<Output>(json)
        .map(|out| warning_text(&out))
        .unwrap_or_default()
}

fn render_warnings(out: &Output) {
    eprint!("{}", warning_text(out));
}

fn render_flat_output<W: Write>(v: &Output, out: &mut W) -> io::Result<()> {
    let mut keys: Vec<&String> = v.apis.keys().collect();
    keys.sort_unstable();
    for k in keys {
        let shape = &v.apis[k];
        writeln!(
            out,
            "{}\t{}\t{}",
            shape.methods_csv(),
            escape_terminal(k),
            shape.flags_csv()
        )?;
    }
    let mut keys: Vec<&String> = v.candidates.keys().collect();
    keys.sort_unstable();
    for k in keys {
        writeln!(out, "?\t{}\t", escape_terminal(k))?;
    }
    let mut keys: Vec<&String> = v.routes.keys().collect();
    keys.sort_unstable();
    for k in keys {
        writeln!(out, "route\t{}\t", escape_terminal(k))?;
    }
    Ok(())
}

fn render_flat(json: &str) -> String {
    let Ok(v) = serde_json::from_str::<Output>(json) else {
        return format!("{json}\n");
    };
    let mut out = Vec::new();
    if render_flat_output(&v, &mut out).is_err() {
        return format!("{json}\n");
    }
    String::from_utf8(out).unwrap_or_else(|_| format!("{json}\n"))
}

async fn daemon_output(url: &str, no_cache: bool, mode: OutputMode) -> Option<daemon::DaemonReply> {
    if let Some(out) = daemon::request(url, no_cache, mode).await {
        return Some(out);
    }
    if daemon::start() {
        for _ in 0..20 {
            std::thread::sleep(Duration::from_millis(25));
            if let Some(out) = daemon::request(url, no_cache, mode).await {
                return Some(out);
            }
        }
    }
    None
}

fn chunk_concurrency() -> usize {
    std::env::var("HIFI_CHUNK_CONCURRENCY")
        .ok()
        .and_then(|v| v.parse::<usize>().ok())
        .filter(|v| *v > 0)
        .map(|v| v.min(HARD_MAX_CHUNK_CONCURRENCY))
        .unwrap_or(MAX_CHUNK_CONCURRENCY)
}

fn make_client(chunk_concurrency: usize) -> reqwest::Result<Client> {
    Client::builder()
        .pool_max_idle_per_host(chunk_concurrency)
        .pool_idle_timeout(Duration::from_secs(CACHE_FRESH_SECS))
        .tcp_keepalive(Duration::from_secs(30))
        .connect_timeout(Duration::from_secs(5))
        .timeout(Duration::from_secs(12))
        .redirect(reqwest::redirect::Policy::custom(|attempt| {
            if net::validate_url(attempt.url(), net::allow_private_networks()).is_ok() {
                attempt.follow()
            } else {
                attempt.error("blocked redirect to private or unsupported URL")
            }
        }))
        .user_agent("hifi/0.1")
        .build()
}

pub fn escape_terminal(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for ch in s.chars() {
        if ch.is_control() || ch == '\u{7f}' {
            use std::fmt::Write as _;
            let _ = write!(out, "\\x{:02x}", ch as u32);
        } else {
            out.push(ch);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn terminal_escape_rewrites_control_bytes() {
        assert_eq!(escape_terminal("ok\u{1b}[31m"), "ok\\x1b[31m");
    }

    #[test]
    fn normalize_url_adds_https_to_bare_hosts() {
        assert_eq!(
            normalize_url("example.com/path").unwrap(),
            "https://example.com/path"
        );
    }

    #[test]
    fn normalize_url_rejects_unsupported_schemes() {
        let err = normalize_url("ftp://example.com").unwrap_err().to_string();
        assert_eq!(err, "unsupported URL scheme 'ftp'");
    }
}
