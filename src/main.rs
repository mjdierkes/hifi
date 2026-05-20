use aho_corasick::AhoCorasick;
use futures::stream::{FuturesUnordered, StreamExt};
use reqwest::Client;
use scraper::{Html, Selector};
use std::collections::BTreeMap;
use std::time::Instant;
use url::Url;

const API_LITERALS: &[&str] = &["/api/", "/_next/data/", "/graphql"];

const SHAPE_LITERALS: &[&str] = &[
    "method:\"POST\"",
    "method:'POST'",
    "method:\"PUT\"",
    "method:'PUT'",
    "method:\"DELETE\"",
    "method:'DELETE'",
    "method:\"PATCH\"",
    "method:'PATCH'",
    "method:\"GET\"",
    "method:'GET'",
    "body:",
    "headers:",
    "Content-Type",
    "application/json",
    "Authorization",
    "Bearer",
];

#[derive(Default, Clone, serde::Serialize)]
struct Shape {
    methods: Vec<String>,
    has_body: bool,
    has_headers: bool,
    content_types: Vec<String>,
    auth: bool,
}

#[tokio::main(flavor = "multi_thread")]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let url = std::env::args().nth(1).ok_or("usage: hifi <url>")?;
    let t0 = Instant::now();

    let client = Client::builder()
        .pool_max_idle_per_host(16)
        .tcp_keepalive(std::time::Duration::from_secs(30))
        .user_agent("hifi/0.1")
        .build()?;

    let base = Url::parse(&url)?;
    let html = client.get(base.clone()).send().await?.text().await?;
    let chunks = extract_chunks(&html, &base);
    let build_id = extract_build_id(&html);

    let api_ac = AhoCorasick::new(API_LITERALS)?;
    let shape_ac = AhoCorasick::new(SHAPE_LITERALS)?;

    let mut apis: BTreeMap<String, Shape> = BTreeMap::new();

    scan(html.as_bytes(), &api_ac, &shape_ac, &mut apis);

    let mut futs = FuturesUnordered::new();
    for u in chunks.iter() {
        let c = client.clone();
        let u = u.clone();
        futs.push(async move { c.get(u).send().await.ok()?.bytes().await.ok() });
    }
    while let Some(res) = futs.next().await {
        if let Some(bytes) = res {
            scan(&bytes, &api_ac, &shape_ac, &mut apis);
        }
    }

    let elapsed = t0.elapsed();
    let out = serde_json::json!({
        "url": url,
        "build_id": build_id,
        "chunks_scanned": chunks.len(),
        "apis": apis,
        "elapsed_ms": elapsed.as_millis(),
    });
    println!("{}", serde_json::to_string_pretty(&out)?);
    Ok(())
}

fn extract_chunks(html: &str, base: &Url) -> Vec<Url> {
    let doc = Html::parse_document(html);
    let sel = Selector::parse("script[src]").unwrap();
    let mut out = Vec::new();
    for el in doc.select(&sel) {
        if let Some(src) = el.value().attr("src") {
            if !src.contains("/_next/") {
                continue;
            }
            let lower = src.to_lowercase();
            if lower.contains("framework-")
                || lower.contains("polyfills-")
                || lower.contains("webpack-")
                || lower.contains("main-")
            {
                continue;
            }
            if let Ok(u) = base.join(src) {
                out.push(u);
            }
        }
    }
    out
}

fn extract_build_id(html: &str) -> Option<String> {
    let needle = "\"buildId\":\"";
    let i = html.find(needle)?;
    let rest = &html[i + needle.len()..];
    let end = rest.find('"')?;
    Some(rest[..end].to_string())
}

fn scan(
    bytes: &[u8],
    api_ac: &AhoCorasick,
    shape_ac: &AhoCorasick,
    apis: &mut BTreeMap<String, Shape>,
) {
    const WIN: usize = 400;
    for m in api_ac.find_iter(bytes) {
        let lo = backtrack(bytes, m.start());
        let hi = forward(bytes, m.end());
        let s = match std::str::from_utf8(&bytes[lo..hi]) {
            Ok(v) => v.trim_matches(|c: char| c == '"' || c == '\'' || c == '`'),
            Err(_) => continue,
        };
        if !is_api_like(s) {
            continue;
        }
        // shape window: ~WIN bytes after the api literal
        let ws = m.start().saturating_sub(WIN);
        let we = (hi + WIN).min(bytes.len());
        let window = &bytes[ws..we];

        let entry = apis.entry(s.to_string()).or_default();
        for sm in shape_ac.find_iter(window) {
            let pat = SHAPE_LITERALS[sm.pattern().as_usize()];
            match pat {
                p if p.starts_with("method:") => {
                    let method = p
                        .trim_start_matches("method:")
                        .trim_matches(|c| c == '"' || c == '\'')
                        .to_string();
                    if !entry.methods.contains(&method) {
                        entry.methods.push(method);
                    }
                }
                "body:" => entry.has_body = true,
                "headers:" => entry.has_headers = true,
                "application/json" => {
                    let ct = "application/json".to_string();
                    if !entry.content_types.contains(&ct) {
                        entry.content_types.push(ct);
                    }
                }
                "Authorization" | "Bearer" => entry.auth = true,
                _ => {}
            }
        }
        if entry.methods.is_empty() {
            entry.methods.push("GET".to_string());
        }
    }
}

fn is_api_like(s: &str) -> bool {
    if s.len() < 4 || s.len() > 256 {
        return false;
    }
    let ok = s.starts_with('/') || s.starts_with("http://") || s.starts_with("https://");
    if !ok {
        return false;
    }
    s.chars().any(|c| c.is_ascii_alphanumeric())
}

fn backtrack(b: &[u8], mut i: usize) -> usize {
    while i > 0 {
        let c = b[i - 1];
        if matches!(c, b'"' | b'\'' | b'`' | b'(' | b' ' | b',' | b'\n' | b';' | b'=') {
            break;
        }
        i -= 1;
    }
    i
}

fn forward(b: &[u8], mut i: usize) -> usize {
    while i < b.len() {
        let c = b[i];
        if matches!(c, b'"' | b'\'' | b'`' | b')' | b' ' | b',' | b'\n' | b';') {
            break;
        }
        i += 1;
    }
    i
}
