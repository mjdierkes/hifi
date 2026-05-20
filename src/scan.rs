use crate::literals::{method_from_pattern, BAD_EXTS, CALL_LITERALS, SHAPE_LITERALS};
use aho_corasick::AhoCorasick;
use std::collections::BTreeMap;
use std::sync::LazyLock;

static CALL_AC: LazyLock<AhoCorasick> =
    LazyLock::new(|| AhoCorasick::new(CALL_LITERALS).expect("valid call literals"));
static SHAPE_AC: LazyLock<AhoCorasick> =
    LazyLock::new(|| AhoCorasick::new(SHAPE_LITERALS).expect("valid shape literals"));

#[derive(Default, Clone, serde::Serialize)]
pub struct Shape {
    methods: Vec<&'static str>,
    has_body: bool,
    has_headers: bool,
    content_types: Vec<&'static str>,
    auth: bool,
}

pub fn scan(bytes: &[u8], apis: &mut BTreeMap<String, Shape>) {
    const WIN: usize = 400;

    for m in CALL_AC.find_iter(bytes) {
        let after = m.end();
        let Some(url) = extract_url_arg(bytes, after) else {
            continue;
        };
        if !is_url_like(url) {
            continue;
        }

        let ws = m.start().saturating_sub(WIN);
        let we = (after + WIN).min(bytes.len());
        let window = &bytes[ws..we];

        let entry = apis.entry(url.to_owned()).or_default();
        for sm in SHAPE_AC.find_iter(window) {
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

fn extract_url_arg(bytes: &[u8], start: usize) -> Option<&str> {
    let mut i = start;
    while i < bytes.len() && matches!(bytes[i], b' ' | b'\t' | b'\n' | b'\r') {
        i += 1;
    }
    if i >= bytes.len() {
        return None;
    }

    let quote = bytes[i];
    if !matches!(quote, b'"' | b'\'' | b'`') {
        return None;
    }

    let s = i + 1;
    let mut e = s;
    while e < bytes.len() && bytes[e] != quote {
        if bytes[e] == b'\\' && e + 1 < bytes.len() {
            e += 2;
            continue;
        }
        if quote == b'`' && bytes[e] == b'$' && e + 1 < bytes.len() && bytes[e + 1] == b'{' {
            break;
        }
        e += 1;
    }

    std::str::from_utf8(&bytes[s..e]).ok()
}

fn is_url_like(s: &str) -> bool {
    let bytes = s.as_bytes();
    if bytes.len() < 2 || bytes.len() > 512 {
        return false;
    }
    if !(s.starts_with('/') || s.starts_with("http://") || s.starts_with("https://")) {
        return false;
    }
    if s == "/" || is_bad_asset_url(bytes) {
        return false;
    }
    bytes.iter().any(u8::is_ascii_alphanumeric)
}

fn is_bad_asset_url(s: &[u8]) -> bool {
    let path = s.split(|b| *b == b'?').next().unwrap_or(s);
    BAD_EXTS
        .iter()
        .any(|ext| path.ends_with_ignore_ascii_case(ext.as_bytes()))
}

trait EndsWithIgnoreAsciiCase {
    fn ends_with_ignore_ascii_case(&self, suffix: &[u8]) -> bool;
}

impl EndsWithIgnoreAsciiCase for [u8] {
    fn ends_with_ignore_ascii_case(&self, suffix: &[u8]) -> bool {
        self.len() >= suffix.len() && self[self.len() - suffix.len()..].eq_ignore_ascii_case(suffix)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn url_arg_borrows_string_literal_content() {
        assert_eq!(
            extract_url_arg(br#"fetch("/api/users", opts)"#, 6),
            Some("/api/users")
        );
        assert_eq!(
            extract_url_arg(br#"fetch(`/api/${id}`, opts)"#, 6),
            Some("/api/")
        );
    }

    #[test]
    fn url_filter_rejects_assets_without_allocating_lowercase_copy() {
        assert!(is_url_like("/api/users"));
        assert!(!is_url_like("/images/LOGO.PNG?cache=1"));
        assert!(!is_url_like("/"));
    }
}
