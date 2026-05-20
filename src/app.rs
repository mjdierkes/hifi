use crate::grep;
use crate::runtime::daemon;
use crate::runtime::processor::{CacheContext, Processor, CACHE_FRESH_SECS};
use reqwest::Client;
use serde_json::Value;
use std::io::IsTerminal;
use std::{error::Error, time::Duration};

const MAX_CHUNK_CONCURRENCY: usize = 32;

const HELP: &str = "\
hifi — map an HTTP API surface

USAGE:
    hifi <url> [--no-cache] [--no-daemon]
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
";

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
    for arg in &raw {
        match arg.as_str() {
            "--no-cache" => no_cache = true,
            "--no-daemon" => no_daemon = true,
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
        if let Some(json) = daemon_json(&url, no_cache).await {
            print!("{}", render(&json));
            return Ok(0);
        }
    }

    let out = Processor::new(&client, concurrency, CacheContext::default())
        .process(&url, no_cache, std::time::Instant::now())
        .await?;
    print!("{}", render(&out));
    Ok(0)
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
    shape: Option<&'a Value>,
    children: std::collections::BTreeMap<String, Node<'a>>,
}

fn insert<'a>(root: &mut Node<'a>, segments: &[&str], shape: Option<&'a Value>) {
    if segments.is_empty() {
        root.shape = shape;
        return;
    }
    let child = root.children.entry(segments[0].to_string()).or_default();
    insert(child, &segments[1..], shape);
}

fn shape_label(shape: &Value) -> String {
    let methods = shape
        .get("methods")
        .and_then(|m| m.as_array())
        .map(|a| {
            a.iter()
                .filter_map(|x| x.as_str())
                .collect::<Vec<_>>()
                .join(",")
        })
        .unwrap_or_default();
    let mut flags: Vec<&str> = Vec::new();
    if shape.get("has_body") == Some(&Value::Bool(true)) {
        flags.push("body");
    }
    if shape.get("has_headers") == Some(&Value::Bool(true)) {
        flags.push("headers");
    }
    if let Some(cts) = shape.get("content_types").and_then(|x| x.as_array()) {
        for ct in cts.iter().filter_map(|x| x.as_str()) {
            flags.push(if ct == "application/json" { "json" } else { ct });
        }
    }
    if shape.get("auth") == Some(&Value::Bool(true)) {
        flags.push("auth");
    }
    if flags.is_empty() {
        format!("[{methods}]")
    } else {
        format!("[{methods}] [{}]", flags.join(","))
    }
}

fn render_node(out: &mut String, node: &Node, prefix: &str) {
    let count = node.children.len();
    for (i, (name, child)) in node.children.iter().enumerate() {
        let last = i + 1 == count;
        let connector = if last { "└── " } else { "├── " };
        let label = child
            .shape
            .map(|s| format!(" {}", shape_label(s)))
            .unwrap_or_default();
        let display = if name.is_empty() { "/" } else { name.as_str() };
        out.push_str(&format!("{prefix}{connector}{display}{label}\n"));
        let next_prefix = format!("{prefix}{}", if last { "    " } else { "│   " });
        render_node(out, child, &next_prefix);
    }
}

fn segments_of(rel: &str) -> Vec<&str> {
    if rel.is_empty() {
        return Vec::new();
    }
    let s = rel.strip_prefix('/').unwrap_or(rel);
    s.split('/').collect()
}

fn group_paths<'a, I: Iterator<Item = &'a str>>(paths: I) -> Vec<(String, Vec<String>)> {
    let mut groups: std::collections::BTreeMap<String, Vec<String>> = Default::default();
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
    groups.into_iter().collect()
}

fn strip_branch(branch: &str, path: &str) -> String {
    path.strip_prefix(branch)
        .map(|s| s.to_string())
        .unwrap_or_else(|| path.to_string())
}

fn render(json: &str) -> String {
    if std::io::stdout().is_terminal() {
        render_tree(json)
    } else {
        render_flat(json)
    }
}

fn render_tree(json: &str) -> String {
    let Ok(v) = serde_json::from_str::<Value>(json) else {
        return format!("{json}\n");
    };
    let mut out = String::new();
    if let Some(apis) = v.get("apis").and_then(|x| x.as_object()) {
        let groups = group_paths(apis.keys().map(|s| s.as_str()));
        for (branch, paths) in &groups {
            let mut root = Node::default();
            for p in paths {
                let rel = strip_branch(branch, p);
                let segs = segments_of(&rel);
                insert(&mut root, &segs, apis.get(p.as_str()));
            }
            let root_label = root
                .shape
                .map(|s| format!(" {}", shape_label(s)))
                .unwrap_or_default();
            out.push_str(&format!("{branch}{root_label}\n"));
            render_node(&mut out, &root, "");
        }
    }
    if let Some(cands) = v.get("candidates").and_then(|x| x.as_object()) {
        let paths: Vec<&String> = cands.keys().collect();
        if !paths.is_empty() {
            let groups = group_paths(paths.iter().map(|s| s.as_str()));
            for (branch, ps) in &groups {
                let mut root = Node::default();
                for p in ps {
                    let rel = strip_branch(branch, p);
                    let segs = segments_of(&rel);
                    insert(&mut root, &segs, None);
                }
                out.push_str(&format!("? {branch}\n"));
                render_node(&mut out, &root, "");
            }
        }
    }
    let cache = v.get("cache").and_then(|x| x.as_str()).unwrap_or("?");
    let ms = v.get("elapsed_ms").and_then(|x| x.as_u64()).unwrap_or(0);
    out.push_str(&format!("{cache} {ms}ms\n"));
    out
}

fn render_flat(json: &str) -> String {
    let Ok(v) = serde_json::from_str::<Value>(json) else {
        return format!("{json}\n");
    };
    let mut out = String::new();
    if let Some(apis) = v.get("apis").and_then(|x| x.as_object()) {
        let mut keys: Vec<&String> = apis.keys().collect();
        keys.sort();
        for k in keys {
            let shape = &apis[k];
            let methods = shape
                .get("methods")
                .and_then(|m| m.as_array())
                .map(|a| {
                    a.iter()
                        .filter_map(|x| x.as_str())
                        .collect::<Vec<_>>()
                        .join(",")
                })
                .unwrap_or_default();
            let mut flags: Vec<&str> = Vec::new();
            if shape.get("has_body") == Some(&Value::Bool(true)) {
                flags.push("body");
            }
            if shape.get("has_headers") == Some(&Value::Bool(true)) {
                flags.push("headers");
            }
            if let Some(cts) = shape.get("content_types").and_then(|x| x.as_array()) {
                for ct in cts.iter().filter_map(|x| x.as_str()) {
                    flags.push(if ct == "application/json" { "json" } else { ct });
                }
            }
            if shape.get("auth") == Some(&Value::Bool(true)) {
                flags.push("auth");
            }
            out.push_str(&format!("{methods}\t{k}\t{}\n", flags.join(",")));
        }
    }
    if let Some(cands) = v.get("candidates").and_then(|x| x.as_object()) {
        let mut keys: Vec<&String> = cands.keys().collect();
        keys.sort();
        for k in keys {
            out.push_str(&format!("?\t{k}\t\n"));
        }
    }
    out
}

async fn daemon_json(url: &str, no_cache: bool) -> Option<String> {
    if let Some(json) = daemon::request(url, no_cache).await {
        return Some(json);
    }
    if daemon::start() {
        for _ in 0..20 {
            std::thread::sleep(Duration::from_millis(25));
            if let Some(json) = daemon::request(url, no_cache).await {
                return Some(json);
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
        .user_agent("hifi/0.1")
        .build()
}
