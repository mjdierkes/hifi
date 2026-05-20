use crate::literals::{method_from_pattern, BAD_EXTS, CALL_LITERALS, SHAPE_LITERALS};
use aho_corasick::AhoCorasick;
use serde::ser::{SerializeStruct, Serializer};
use std::collections::{BTreeMap, HashMap};
use std::sync::LazyLock;

static CALL_AC: LazyLock<AhoCorasick> =
    LazyLock::new(|| AhoCorasick::new(CALL_LITERALS).expect("valid call literals"));
static SHAPE_AC: LazyLock<AhoCorasick> =
    LazyLock::new(|| AhoCorasick::new(SHAPE_LITERALS).expect("valid shape literals"));

pub type ApiMap = HashMap<String, Shape>;

const METHOD_GET: u8 = 1 << 0;
const METHOD_POST: u8 = 1 << 1;
const METHOD_PUT: u8 = 1 << 2;
const METHOD_DELETE: u8 = 1 << 3;
const METHOD_PATCH: u8 = 1 << 4;
const CONTENT_JSON: u8 = 1 << 0;

#[derive(Default, Clone)]
pub struct Shape {
    methods: u8,
    has_body: bool,
    has_headers: bool,
    content_types: u8,
    auth: bool,
}

impl serde::Serialize for Shape {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut st = serializer.serialize_struct("Shape", 5)?;
        st.serialize_field("methods", &self.methods())?;
        st.serialize_field("has_body", &self.has_body)?;
        st.serialize_field("has_headers", &self.has_headers)?;
        st.serialize_field("content_types", &self.content_types())?;
        st.serialize_field("auth", &self.auth)?;
        st.end()
    }
}

impl Shape {
    fn add_method(&mut self, method: &'static str) {
        self.methods |= match method {
            "GET" => METHOD_GET,
            "POST" => METHOD_POST,
            "PUT" => METHOD_PUT,
            "DELETE" => METHOD_DELETE,
            "PATCH" => METHOD_PATCH,
            _ => METHOD_GET,
        };
    }

    fn methods(&self) -> Vec<&'static str> {
        [
            (METHOD_GET, "GET"),
            (METHOD_POST, "POST"),
            (METHOD_PUT, "PUT"),
            (METHOD_DELETE, "DELETE"),
            (METHOD_PATCH, "PATCH"),
        ]
        .into_iter()
        .filter_map(|(bit, method)| (self.methods & bit != 0).then_some(method))
        .collect()
    }

    fn content_types(&self) -> Vec<&'static str> {
        (self.content_types & CONTENT_JSON != 0)
            .then_some("application/json")
            .into_iter()
            .collect()
    }

    fn merge(&mut self, other: Shape) {
        self.methods |= other.methods;
        self.has_body |= other.has_body;
        self.has_headers |= other.has_headers;
        self.content_types |= other.content_types;
        self.auth |= other.auth;
    }
}

pub fn scan(bytes: &[u8], apis: &mut ApiMap) {
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
                    entry.add_method(method);
                }
                "body:" => entry.has_body = true,
                "headers:" => entry.has_headers = true,
                "application/json" => entry.content_types |= CONTENT_JSON,
                "Authorization" | "Bearer" => entry.auth = true,
                _ => {}
            }
        }
        if entry.methods == 0 {
            entry.add_method("GET");
        }
    }
}

pub fn merge_into(dst: &mut ApiMap, src: ApiMap) {
    for (url, shape) in src {
        dst.entry(url).or_default().merge(shape);
    }
}

pub fn sorted(apis: ApiMap) -> BTreeMap<String, Shape> {
    apis.into_iter().collect()
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
