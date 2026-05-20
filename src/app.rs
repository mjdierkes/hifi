use crate::grep;
use crate::runtime::daemon;
use crate::runtime::processor::{
    CacheContext, Output, Processed, Processor, RunStats, TimingStats, CACHE_FRESH_SECS,
};
use crate::runtime::{cache, cache::ChunkData};
use crate::scan::{self, html, ApiMap, CandidateMap};
use reqwest::Client;
use rustc_hash::{FxHashMap, FxHashSet};
use std::io::{self, IsTerminal, Write};
use std::{
    error::Error,
    sync::mpsc,
    time::{Duration, Instant},
};
use url::Url;

const MAX_CHUNK_CONCURRENCY: usize = 32;

const HELP: &str = "\
hifi — map an HTTP API surface

USAGE:
    hifi <url> [--no-cache] [--no-daemon] [--flat|--tree|--json]
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
        --tree        print tree output
        --json        print machine-readable JSON
";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OutputMode {
    Auto,
    Flat,
    Tree,
    Json,
}

impl OutputMode {
    pub fn for_stdout(self) -> Self {
        match self {
            Self::Auto if std::io::stdout().is_terminal() => Self::Tree,
            Self::Auto => Self::Flat,
            mode => mode,
        }
    }

    pub fn as_daemon_byte(self) -> u8 {
        match self.for_stdout() {
            Self::Auto => b'a',
            Self::Flat => b'f',
            Self::Tree => b't',
            Self::Json => b'j',
        }
    }

    pub fn from_daemon_byte(b: u8) -> Option<Self> {
        Some(match b {
            b'f' => Self::Flat,
            b't' => Self::Tree,
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
            "--tree" => mode = set_mode(mode, OutputMode::Tree)?,
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

pub fn try_run_cached(raw: &[String]) -> Option<Result<i32, Box<dyn Error>>> {
    match try_run_cached_inner(raw) {
        Ok(Some(code)) => Some(Ok(code)),
        Ok(None) => None,
        Err(e) => Some(Err(e)),
    }
}

fn try_run_cached_inner(raw: &[String]) -> Result<Option<i32>, Box<dyn Error>> {
    if raw.is_empty() || matches!(raw[0].as_str(), "-h" | "--help" | "help" | "grep" | "serve") {
        return Ok(None);
    }

    let mut url = None;
    let (mut no_cache, mut no_daemon) = (false, false);
    let mut mode = OutputMode::Auto;
    for arg in raw {
        match arg.as_str() {
            "--no-cache" => no_cache = true,
            "--no-daemon" => no_daemon = true,
            "--flat" => mode = set_mode(mode, OutputMode::Flat)?,
            "--tree" => mode = set_mode(mode, OutputMode::Tree)?,
            "--json" => mode = set_mode(mode, OutputMode::Json)?,
            s if s.starts_with("--") || s.starts_with('-') => return Ok(None),
            _ if url.is_none() => url = Some(arg.clone()),
            _ => return Ok(None),
        }
    }
    if !no_cache || !no_daemon {
        return Ok(None);
    }

    let url = normalize_url(&url.ok_or("missing URL (try --help)")?);
    let base = Url::parse(&url)?;
    let Some((html, final_base)) = cache::read_page(&base) else {
        return Ok(None);
    };
    let Some(out) = collect_cached_raw(&html, &final_base) else {
        return Ok(None);
    };
    render_processed(Processed::Output(out), mode)?;
    Ok(Some(0))
}

fn collect_cached_raw(html: &[u8], final_base: &Url) -> Option<Output> {
    let total_t0 = Instant::now();
    let parse_t0 = Instant::now();
    let chunks = html::extract_chunks(html, final_base);
    let build_id = html::extract_build_id(html).or_else(|| Some(cache::fingerprint(&chunks)));
    let parse_elapsed = parse_t0.elapsed();
    let entries = cache::read_bundle_pack(&chunks)?;
    let html_body = bytes::Bytes::copy_from_slice(html);
    let html_bytes = html.len() as u64;

    let chunk_t0 = Instant::now();
    let (tx, rx) = mpsc::channel();
    std::thread::scope(|scope| {
        let html_tx = tx.clone();
        scope.spawn(move || {
            let scan_t0 = Instant::now();
            let mut apis = ApiMap::default();
            let mut candidates = CandidateMap::default();
            scan::scan(&html_body, &mut apis);
            scan::scan_candidates(&html_body, &mut candidates);
            let _ = html_tx.send(CachedScanPart::Html {
                apis,
                candidates,
                elapsed: scan_t0.elapsed(),
            });
        });

        let workers = std::thread::available_parallelism()
            .map(|n| n.get())
            .unwrap_or(1)
            .min(entries.len().max(1));
        let stride = entries.len().div_ceil(workers);
        for chunk in entries.chunks(stride) {
            let tx = tx.clone();
            scope.spawn(move || {
                let mut out = Vec::with_capacity(chunk.len());
                for (url, body) in chunk {
                    out.push(scan_cached_bundle(url, body));
                }
                let _ = tx.send(CachedScanPart::Chunks(out));
            });
        }
    });
    drop(tx);

    let mut apis = ApiMap::default();
    let mut candidates = CandidateMap::default();
    let mut html_scan_us = 0;
    let mut chunk_scan_us = 0;
    let mut chunk_ref_us = 0;
    let mut chunk_api_scan_us = 0;
    let mut chunk_candidate_scan_us = 0;
    let mut chunk_bytes = 0;
    let mut scanned = 0;
    let mut refs = Vec::new();
    let mut pack_urls = FxHashSet::default();
    for part in rx {
        match part {
            CachedScanPart::Html {
                apis: html_apis,
                candidates: html_candidates,
                elapsed,
            } => {
                scan::merge_into(&mut apis, html_apis);
                scan::merge_candidates_into(&mut candidates, html_candidates);
                html_scan_us = elapsed.as_micros();
            }
            CachedScanPart::Chunks(chunks) => {
                for chunk in chunks {
                    pack_urls.insert(chunk.url);
                    scan::merge_into(&mut apis, chunk.data.apis);
                    scan::merge_candidates_into(&mut candidates, chunk.data.candidates);
                    refs.extend(chunk.data.refs);
                    chunk_scan_us += chunk.scan_us;
                    chunk_ref_us += chunk.ref_us;
                    chunk_api_scan_us += chunk.api_us;
                    chunk_candidate_scan_us += chunk.candidate_us;
                    chunk_bytes += chunk.bytes;
                    scanned += 1;
                }
            }
        }
    }

    if refs.iter().any(|url| !pack_urls.contains(url)) {
        return None;
    }
    for url in apis.keys() {
        candidates.remove(url);
    }

    let chunk_wall_elapsed = chunk_t0.elapsed();
    let html_scan_us = parse_elapsed.as_micros() + html_scan_us;
    let total_elapsed = total_t0.elapsed();
    Some(Output {
        apis,
        candidates,
        build_id,
        cache: "miss".into(),
        cache_age_secs: None,
        elapsed_ms: Some(total_elapsed.as_millis()),
        elapsed_us: Some(total_elapsed.as_micros()),
        timings: Some(TimingStats {
            page_fetch_ms: 0,
            page_fetch_us: 0,
            html_scan_ms: html_scan_us / 1000,
            html_scan_us,
            manifest_fetch_ms: 0,
            manifest_fetch_us: 0,
            manifest_scan_ms: 0,
            manifest_scan_us: 0,
            chunk_wall_ms: chunk_wall_elapsed.as_millis(),
            chunk_wall_us: chunk_wall_elapsed.as_micros(),
            chunk_fetch_ms: 0,
            chunk_fetch_us: 0,
            chunk_scan_ms: chunk_scan_us / 1000,
            chunk_scan_us,
            chunk_ref_us,
            chunk_api_scan_us,
            chunk_candidate_scan_us,
            total_ms: total_elapsed.as_millis(),
            total_us: total_elapsed.as_micros(),
        }),
        stats: Some(RunStats {
            html_bytes,
            page_cache_hit: true,
            page_bytes_fetched: 0,
            manifest_bytes: 0,
            chunk_bytes_fetched: 0,
            chunk_bytes_scanned: chunk_bytes,
            chunks_discovered: scanned,
            chunks_scanned: scanned,
            chunk_cache_hits: 0,
            chunk_bundle_hits: scanned,
            chunk_bundle_pack_hits: scanned,
            chunk_memory_hits: 0,
            manifest_scanned: 0,
            manifest_errors: 0,
            chunk_errors: 0,
            scan_mib_per_sec: mib_per_sec_from_us(
                html_bytes + chunk_bytes,
                html_scan_us + chunk_scan_us,
            ),
            fetch_mib_per_sec: 0.0,
        }),
    })
}

enum CachedScanPart {
    Html {
        apis: ApiMap,
        candidates: CandidateMap,
        elapsed: Duration,
    },
    Chunks(Vec<CachedBundleScan>),
}

struct CachedBundleScan {
    url: Url,
    data: ChunkData,
    bytes: u64,
    scan_us: u128,
    ref_us: u128,
    api_us: u128,
    candidate_us: u128,
}

fn scan_cached_bundle(url: &Url, body: &[u8]) -> CachedBundleScan {
    let ref_t0 = Instant::now();
    let refs = html::extract_chunk_refs(body, url);
    let ref_us = ref_t0.elapsed().as_micros();
    let scan_t0 = Instant::now();
    let api_t0 = Instant::now();
    let mut apis = ApiMap::default();
    scan::scan(body, &mut apis);
    let api_us = api_t0.elapsed().as_micros();
    let candidate_t0 = Instant::now();
    let mut candidates = CandidateMap::default();
    scan::scan_candidates(body, &mut candidates);
    let candidate_us = candidate_t0.elapsed().as_micros();
    CachedBundleScan {
        url: url.clone(),
        data: ChunkData {
            apis,
            candidates,
            refs,
        },
        bytes: body.len() as u64,
        scan_us: scan_t0.elapsed().as_micros(),
        ref_us,
        api_us,
        candidate_us,
    }
}

fn mib_per_sec_from_us(bytes: u64, us: u128) -> f64 {
    if bytes == 0 || us == 0 {
        return 0.0;
    }
    (bytes as f64 / 1_048_576.0) / (us as f64 / 1_000_000.0)
}

fn set_mode(current: OutputMode, next: OutputMode) -> Result<OutputMode, Box<dyn Error>> {
    if current != OutputMode::Auto && current != next {
        return Err("choose only one of --flat, --tree, or --json".into());
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

#[derive(Default)]
struct Node<'a> {
    shape: Option<&'a crate::scan::Shape>,
    children: FxHashMap<String, Node<'a>>,
}

fn insert<'a>(root: &mut Node<'a>, segments: &[&str], shape: Option<&'a crate::scan::Shape>) {
    if segments.is_empty() {
        root.shape = shape;
        return;
    }
    let child = root.children.entry(segments[0].to_string()).or_default();
    insert(child, &segments[1..], shape);
}

fn render_node<W: Write>(out: &mut W, node: &Node, prefix: &str) -> io::Result<()> {
    let mut children: Vec<_> = node.children.iter().collect();
    children.sort_unstable_by(|a, b| a.0.cmp(b.0));
    let count = children.len();
    for (i, (name, child)) in children.into_iter().enumerate() {
        let last = i + 1 == count;
        let connector = if last { "└── " } else { "├── " };
        let label = child
            .shape
            .map(|s| format!(" {}", s.tree_label()))
            .unwrap_or_default();
        let display = if name.is_empty() { "/" } else { name.as_str() };
        writeln!(out, "{prefix}{connector}{display}{label}")?;
        let next_prefix = format!("{prefix}{}", if last { "    " } else { "│   " });
        render_node(out, child, &next_prefix)?;
    }
    Ok(())
}

fn segments_of(rel: &str) -> Vec<&str> {
    if rel.is_empty() {
        return Vec::new();
    }
    let s = rel.strip_prefix('/').unwrap_or(rel);
    s.split('/').collect()
}

fn group_paths<'a, I: Iterator<Item = &'a str>>(paths: I) -> Vec<(String, Vec<String>)> {
    let mut groups: FxHashMap<String, Vec<String>> = FxHashMap::default();
    for p in paths {
        let branch = if let Some(rest) = p.strip_prefix("http://").or(p.strip_prefix("https://")) {
            let host_end = rest.find('/').unwrap_or(rest.len());
            let host = &rest[..host_end];
            let scheme = if p.starts_with("https://") {
                "https://"
            } else {
                "http://"
            };
            format!("{scheme}{host}")
        } else if let Some(rest) = p.strip_prefix('/') {
            let seg_end = rest.find('/').unwrap_or(rest.len());
            format!("/{}", &rest[..seg_end])
        } else {
            p.to_string()
        };
        groups.entry(branch).or_default().push(p.to_string());
    }
    let mut groups: Vec<_> = groups.into_iter().collect();
    groups.sort_unstable_by(|a, b| a.0.cmp(&b.0));
    groups
}

fn strip_branch(branch: &str, path: &str) -> String {
    path.strip_prefix(branch)
        .map(|s| s.to_string())
        .unwrap_or_else(|| path.to_string())
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
        OutputMode::Tree => render_tree(json),
        OutputMode::Flat | OutputMode::Auto => render_flat(json),
    }
}

fn render_processed(out: Processed, mode: OutputMode) -> Result<(), Box<dyn Error>> {
    match out {
        Processed::Json(json) => {
            print!("{}", render_json_mode(&json, mode));
            Ok(())
        }
        Processed::Output(out) => {
            let stdout = io::stdout();
            let mut stdout = io::BufWriter::new(stdout.lock());
            match mode.for_stdout() {
                OutputMode::Json => {
                    serde_json::to_writer(&mut stdout, &out)?;
                    stdout.write_all(b"\n")?;
                }
                OutputMode::Tree => render_tree_output(&out, &mut stdout)?,
                OutputMode::Flat | OutputMode::Auto => render_flat_output(&out, &mut stdout)?,
            }
            Ok(())
        }
    }
}

fn render_tree_output<W: Write>(v: &Output, out: &mut W) -> io::Result<()> {
    let groups = group_paths(v.apis.keys().map(|s| s.as_str()));
    for (branch, paths) in &groups {
        let mut root = Node::default();
        for p in paths {
            let rel = strip_branch(branch, p);
            let segs = segments_of(&rel);
            insert(&mut root, &segs, v.apis.get(p.as_str()));
        }
        let root_label = root
            .shape
            .map(|s| format!(" {}", s.tree_label()))
            .unwrap_or_default();
        writeln!(out, "{branch}{root_label}")?;
        render_node(out, &root, "")?;
    }
    if !v.candidates.is_empty() {
        let groups = group_paths(v.candidates.keys().map(|s| s.as_str()));
        for (branch, ps) in &groups {
            let mut root = Node::default();
            for p in ps {
                let rel = strip_branch(branch, p);
                let segs = segments_of(&rel);
                insert(&mut root, &segs, None);
            }
            writeln!(out, "? {branch}")?;
            render_node(out, &root, "")?;
        }
    }
    writeln!(out, "{} {}ms", v.cache, v.elapsed_ms.unwrap_or(0))
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

fn render_tree(json: &str) -> String {
    let Ok(v) = serde_json::from_str::<Output>(json) else {
        return format!("{json}\n");
    };
    let mut out = Vec::new();
    if render_tree_output(&v, &mut out).is_err() {
        return format!("{json}\n");
    }
    String::from_utf8(out).unwrap_or_else(|_| format!("{json}\n"))
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
