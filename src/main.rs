use aho_corasick::AhoCorasick;
use futures::stream::{self, StreamExt};
use reqwest::Client;
use std::collections::BTreeMap;
use std::time::Instant;
use url::Url;

const MAX_CHUNK_CONCURRENCY: usize = 32;

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
    methods: Vec<&'static str>,
    has_body: bool,
    has_headers: bool,
    content_types: Vec<&'static str>,
    auth: bool,
}

#[tokio::main(flavor = "multi_thread")]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let url = std::env::args().nth(1).ok_or("usage: hifi <url>")?;
    let no_cache = std::env::args().any(|a| a == "--no-cache");
    let t0 = Instant::now();

    let client = Client::builder()
        .pool_max_idle_per_host(16)
        .tcp_keepalive(std::time::Duration::from_secs(30))
        .user_agent("hifi/0.1")
        .build()?;

    let base = Url::parse(&url)?;
    let html = client.get(base.clone()).send().await?.text().await?;
    let chunks = extract_chunks(&html, &base);
    let build_id = extract_build_id(&html).or_else(|| Some(fingerprint(&chunks)));

    let cache_path = cache_path_for(&base);
    if !no_cache {
        if let Some(cached) = read_cache(&cache_path, build_id.as_deref()) {
            let elapsed = t0.elapsed();
            let mut v = cached;
            if let Some(obj) = v.as_object_mut() {
                obj.insert("cache".into(), serde_json::json!("hit"));
                obj.insert("elapsed_ms".into(), serde_json::json!(elapsed.as_millis()));
            }
            println!("{}", serde_json::to_string_pretty(&v)?);
            return Ok(());
        }
    }

    let api_ac = AhoCorasick::new(API_LITERALS)?;
    let shape_ac = AhoCorasick::new(SHAPE_LITERALS)?;

    let mut apis: BTreeMap<String, Shape> = BTreeMap::new();

    scan(html.as_bytes(), &api_ac, &shape_ac, &mut apis);

    let mut chunk_fetch_errors = 0usize;
    let mut chunks_scanned = 0usize;
    let mut futs = stream::iter(chunks.iter().cloned())
        .map(|u| {
            let c = client.clone();
            async move { c.get(u).send().await?.error_for_status()?.bytes().await }
        })
        .buffer_unordered(MAX_CHUNK_CONCURRENCY);
    while let Some(res) = futs.next().await {
        match res {
            Ok(bytes) => {
                chunks_scanned += 1;
                scan(&bytes, &api_ac, &shape_ac, &mut apis);
            }
            Err(_) => chunk_fetch_errors += 1,
        }
    }

    let elapsed = t0.elapsed();
    let out = serde_json::json!({
        "url": url,
        "build_id": build_id,
        "chunks_discovered": chunks.len(),
        "chunks_scanned": chunks_scanned,
        "chunk_fetch_errors": chunk_fetch_errors,
        "apis": apis,
        "cache": "miss",
        "elapsed_ms": elapsed.as_millis(),
    });
    if !no_cache {
        write_cache(&cache_path, &out);
    }
    println!("{}", serde_json::to_string_pretty(&out)?);
    Ok(())
}

fn fingerprint(chunks: &[Url]) -> String {
    // simple fnv-1a 64-bit over sorted chunk paths
    let mut paths: Vec<&str> = chunks.iter().map(|u| u.path()).collect();
    paths.sort();
    let mut h: u64 = 0xcbf29ce484222325;
    for p in paths {
        for b in p.as_bytes() {
            h ^= *b as u64;
            h = h.wrapping_mul(0x100000001b3);
        }
        h ^= b'\n' as u64;
        h = h.wrapping_mul(0x100000001b3);
    }
    format!("{h:016x}")
}

fn cache_dir() -> std::path::PathBuf {
    let home = std::env::var("HOME").unwrap_or_else(|_| ".".into());
    std::path::PathBuf::from(home).join(".cache/hifi")
}

fn cache_path_for(base: &Url) -> std::path::PathBuf {
    let host = base.host_str().unwrap_or("unknown").replace('/', "_");
    cache_dir().join(format!("{host}.json"))
}

fn read_cache(path: &std::path::Path, build_id: Option<&str>) -> Option<serde_json::Value> {
    let bytes = std::fs::read(path).ok()?;
    let v: serde_json::Value = serde_json::from_slice(&bytes).ok()?;
    let cached_build = v.get("build_id").and_then(|b| b.as_str());
    match (build_id, cached_build) {
        (Some(a), Some(b)) if a == b => Some(v),
        _ => None,
    }
}

fn write_cache(path: &std::path::Path, value: &serde_json::Value) {
    if let Some(dir) = path.parent() {
        let _ = std::fs::create_dir_all(dir);
    }
    if let Ok(s) = serde_json::to_vec(value) {
        let _ = std::fs::write(path, s);
    }
}

fn extract_chunks(html: &str, base: &Url) -> Vec<Url> {
    let mut out = Vec::new();
    let mut offset = 0;
    while let Some(rel) = find_ascii_ci(&html.as_bytes()[offset..], b"<script") {
        let start = offset + rel;
        let Some(end_rel) = html.as_bytes()[start..].iter().position(|&b| b == b'>') else {
            break;
        };
        let end = start + end_rel + 1;
        let tag = &html[start..end];

        if let Some(src) = attr_value(tag, "src") {
            if src.contains("/_next/") && !is_skipped_chunk(src) {
                if let Ok(u) = base.join(src) {
                    out.push(u);
                }
            }
        }

        offset = end;
    }
    out
}

fn extract_build_id(html: &str) -> Option<String> {
    // try __NEXT_DATA__ first
    let needle = "\"buildId\":\"";
    if let Some(i) = html.find(needle) {
        let rest = &html[i + needle.len()..];
        if let Some(end) = rest.find('"') {
            return Some(rest[..end].to_string());
        }
    }
    // fallback: extract from /_next/static/<id>/ in any script src
    let marker = "/_next/static/";
    let i = html.find(marker)?;
    let rest = &html[i + marker.len()..];
    let end = rest.find('/')?;
    let candidate = &rest[..end];
    // skip known non-id segments
    if matches!(candidate, "chunks" | "css" | "media" | "development") {
        return None;
    }
    Some(candidate.to_string())
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
                    let method = method_from_pattern(p);
                    if !entry.methods.contains(&method) {
                        entry.methods.push(method);
                    }
                }
                "body:" => entry.has_body = true,
                "headers:" => entry.has_headers = true,
                "application/json" => {
                    if !entry.content_types.contains(&"application/json") {
                        entry.content_types.push("application/json");
                    }
                }
                "Authorization" | "Bearer" => entry.auth = true,
                _ => {}
            }
        }
        if entry.methods.is_empty() {
            entry.methods.push("GET");
        }
    }
}

fn method_from_pattern(p: &str) -> &'static str {
    match p {
        "method:\"POST\"" | "method:'POST'" => "POST",
        "method:\"PUT\"" | "method:'PUT'" => "PUT",
        "method:\"DELETE\"" | "method:'DELETE'" => "DELETE",
        "method:\"PATCH\"" | "method:'PATCH'" => "PATCH",
        "method:\"GET\"" | "method:'GET'" => "GET",
        _ => "GET",
    }
}

fn is_skipped_chunk(src: &str) -> bool {
    contains_ascii_ci(src, "framework-")
        || contains_ascii_ci(src, "polyfills-")
        || contains_ascii_ci(src, "webpack-")
        || contains_ascii_ci(src, "main-")
}

fn attr_value<'a>(tag: &'a str, name: &str) -> Option<&'a str> {
    let bytes = tag.as_bytes();
    let needle = name.as_bytes();
    let mut offset = 0;

    while let Some(rel) = find_ascii_ci(&bytes[offset..], needle) {
        let name_start = offset + rel;
        let name_end = name_start + needle.len();

        if name_start > 0 && is_attr_char(bytes[name_start - 1]) {
            offset = name_end;
            continue;
        }

        let mut i = name_end;
        while i < bytes.len() && bytes[i].is_ascii_whitespace() {
            i += 1;
        }
        if i >= bytes.len() || bytes[i] != b'=' {
            offset = name_end;
            continue;
        }
        i += 1;
        while i < bytes.len() && bytes[i].is_ascii_whitespace() {
            i += 1;
        }
        if i >= bytes.len() {
            return None;
        }

        let value_start;
        let value_end;
        if matches!(bytes[i], b'"' | b'\'') {
            let quote = bytes[i];
            value_start = i + 1;
            value_end = bytes[value_start..]
                .iter()
                .position(|&b| b == quote)
                .map(|p| value_start + p)?;
        } else {
            value_start = i;
            value_end = bytes[value_start..]
                .iter()
                .position(|&b| b.is_ascii_whitespace() || b == b'>')
                .map(|p| value_start + p)
                .unwrap_or(bytes.len());
        }
        return Some(&tag[value_start..value_end]);
    }

    None
}

fn contains_ascii_ci(haystack: &str, needle: &str) -> bool {
    find_ascii_ci(haystack.as_bytes(), needle.as_bytes()).is_some()
}

fn find_ascii_ci(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() {
        return Some(0);
    }
    if needle.len() > haystack.len() {
        return None;
    }

    haystack
        .windows(needle.len())
        .position(|w| w.eq_ignore_ascii_case(needle))
}

fn is_attr_char(b: u8) -> bool {
    b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-' | b':')
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
        if matches!(
            c,
            b'"' | b'\'' | b'`' | b'(' | b' ' | b',' | b'\n' | b';' | b'='
        ) {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extracts_next_script_chunks_without_framework_noise() {
        let base = Url::parse("https://example.com/app/page").unwrap();
        let html = r#"
            <script src="/_next/static/chunks/framework-abc.js"></script>
            <script defer SRC='/_next/static/chunks/app/dashboard-123.js'></script>
            <script src="/assets/site.js"></script>
        "#;

        let chunks = extract_chunks(html, &base);

        assert_eq!(chunks.len(), 1);
        assert_eq!(
            chunks[0].as_str(),
            "https://example.com/_next/static/chunks/app/dashboard-123.js"
        );
    }

    #[test]
    fn reads_quoted_and_unquoted_attributes() {
        assert_eq!(
            attr_value(r#"<script defer src="/_next/a.js">"#, "src"),
            Some("/_next/a.js")
        );
        assert_eq!(
            attr_value("<script src=/_next/b.js async>", "src"),
            Some("/_next/b.js")
        );
        assert_eq!(
            attr_value(r#"<script data-src="/_next/wrong.js">"#, "src"),
            None
        );
    }
}
