use crate::grep;
use crate::runtime::daemon;
use crate::runtime::processor::{CacheContext, Output, Processor, CACHE_FRESH_SECS};
use reqwest::Client;
use std::io::{self, Write};
use std::{error::Error, time::Duration};

const MAX_CHUNK_CONCURRENCY: usize = 32;

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

pub async fn run(raw: Vec<String>) -> Result<i32, Box<dyn Error>> {
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
    let url = normalize_url(&url);

    if !no_daemon {
        if let Some(out) = daemon_output(&url, no_cache, mode).await {
            print!("{out}");
            return Ok(0);
        }
    }

    let out = Processor::new(&client, concurrency, CacheContext::default())
        .process_for_display(&url, no_cache, std::time::Instant::now())
        .await?;
    render_processed(out, mode)?;
    Ok(0)
}

fn set_mode(current: OutputMode, next: OutputMode) -> Result<OutputMode, Box<dyn Error>> {
    if current != OutputMode::Auto && current != next {
        return Err("choose only one of --flat or --json".into());
    }
    Ok(next)
}

pub fn normalize_url(url: &str) -> String {
    if url.starts_with("http://") || url.starts_with("https://") {
        url.to_string()
    } else {
        format!("https://{url}")
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

fn render_processed(out: Output, mode: OutputMode) -> Result<(), Box<dyn Error>> {
    let stdout = io::stdout();
    let mut stdout = io::BufWriter::new(stdout.lock());
    match mode.for_stdout() {
        OutputMode::Json => {
            serde_json::to_writer(&mut stdout, &out)?;
            stdout.write_all(b"\n")?;
        }
        OutputMode::Flat | OutputMode::Auto => render_flat_output(&out, &mut stdout)?,
    }
    Ok(())
}

fn render_flat_output<W: Write>(v: &Output, out: &mut W) -> io::Result<()> {
    let mut keys: Vec<&String> = v.apis.keys().collect();
    keys.sort_unstable();
    for k in keys {
        let shape = &v.apis[k];
        writeln!(out, "{}\t{k}\t{}", shape.methods_csv(), shape.flags_csv())?;
    }
    let mut keys: Vec<&String> = v.candidates.keys().collect();
    keys.sort_unstable();
    for k in keys {
        writeln!(out, "?\t{k}\t")?;
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

async fn daemon_output(url: &str, no_cache: bool, mode: OutputMode) -> Option<String> {
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
        .and_then(|v| v.parse().ok())
        .filter(|v| *v > 0)
        .unwrap_or(MAX_CHUNK_CONCURRENCY)
}

fn make_client(chunk_concurrency: usize) -> reqwest::Result<Client> {
    Client::builder()
        .pool_max_idle_per_host(chunk_concurrency)
        .pool_idle_timeout(Duration::from_secs(CACHE_FRESH_SECS))
        .tcp_keepalive(Duration::from_secs(30))
        .connect_timeout(Duration::from_secs(5))
        .timeout(Duration::from_secs(12))
        .user_agent("hifi/0.1")
        .build()
}
