use crate::literals::{BAD_EXTS, CALL_LITERALS, SHAPE_LITERALS};
use aho_corasick::AhoCorasick;
use rustc_hash::FxHashMap;
use serde::ser::{SerializeSeq, SerializeStruct, Serializer};
use std::sync::LazyLock;

static CALL_AC: LazyLock<AhoCorasick> =
    LazyLock::new(|| AhoCorasick::new(CALL_LITERALS).expect("valid call literals"));
static SHAPE_AC: LazyLock<AhoCorasick> =
    LazyLock::new(|| AhoCorasick::new(SHAPE_LITERALS).expect("valid shape literals"));

pub type ApiMap = FxHashMap<String, Shape>;

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
        st.serialize_field("methods", &Methods(self.methods))?;
        st.serialize_field("has_body", &self.has_body)?;
        st.serialize_field("has_headers", &self.has_headers)?;
        st.serialize_field("content_types", &ContentTypes(self.content_types))?;
        st.serialize_field("auth", &self.auth)?;
        st.end()
    }
}

struct Methods(u8);

impl serde::Serialize for Methods {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let methods = [
            (METHOD_GET, "GET"),
            (METHOD_POST, "POST"),
            (METHOD_PUT, "PUT"),
            (METHOD_DELETE, "DELETE"),
            (METHOD_PATCH, "PATCH"),
        ];
        let len = methods.iter().filter(|(bit, _)| self.0 & *bit != 0).count();
        let mut seq = serializer.serialize_seq(Some(len))?;
        for (bit, method) in methods {
            if self.0 & bit != 0 {
                seq.serialize_element(method)?;
            }
        }
        seq.end()
    }
}

struct ContentTypes(u8);

impl serde::Serialize for ContentTypes {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let has_json = self.0 & CONTENT_JSON != 0;
        let mut seq = serializer.serialize_seq(Some(has_json as usize))?;
        if has_json {
            seq.serialize_element("application/json")?;
        }
        seq.end()
    }
}

impl Shape {
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
            match sm.pattern().as_usize() {
                0 | 1 => entry.methods |= METHOD_POST,
                2 | 3 => entry.methods |= METHOD_PUT,
                4 | 5 => entry.methods |= METHOD_DELETE,
                6 | 7 => entry.methods |= METHOD_PATCH,
                8 | 9 => entry.methods |= METHOD_GET,
                10 => entry.has_body = true,
                11 => entry.has_headers = true,
                13 => entry.content_types |= CONTENT_JSON,
                14 | 15 => entry.auth = true,
                _ => {}
            }
        }
        if entry.methods == 0 {
            entry.methods = METHOD_GET;
        }
    }
}

pub fn merge_into(dst: &mut ApiMap, src: ApiMap) {
    for (url, shape) in src {
        dst.entry(url).or_default().merge(shape);
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
        .any(|ext| ends_with_ci(path, ext.as_bytes()))
}

fn ends_with_ci(s: &[u8], suffix: &[u8]) -> bool {
    s.len() >= suffix.len() && s[s.len() - suffix.len()..].eq_ignore_ascii_case(suffix)
}
