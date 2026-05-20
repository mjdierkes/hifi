use self::literals::{BAD_EXTS, CALL_LITERALS, SHAPE_LITERALS};
use aho_corasick::AhoCorasick;
use rustc_hash::FxHashMap;
use serde::{Deserialize, Serialize};
use std::sync::LazyLock;

static CALL_AC: LazyLock<AhoCorasick> =
    LazyLock::new(|| AhoCorasick::new(CALL_LITERALS).expect("valid call literals"));
static SHAPE_AC: LazyLock<AhoCorasick> =
    LazyLock::new(|| AhoCorasick::new(SHAPE_LITERALS).expect("valid shape literals"));

pub type ApiMap = FxHashMap<String, Shape>;

pub mod html;
pub mod literals;

const METHOD_GET: u8 = 1 << 0;
const METHOD_POST: u8 = 1 << 1;
const METHOD_PUT: u8 = 1 << 2;
const METHOD_DELETE: u8 = 1 << 3;
const METHOD_PATCH: u8 = 1 << 4;
const CONTENT_JSON: u8 = 1 << 0;
const METHODS: [(u8, &str); 5] = [
    (METHOD_GET, "GET"),
    (METHOD_POST, "POST"),
    (METHOD_PUT, "PUT"),
    (METHOD_DELETE, "DELETE"),
    (METHOD_PATCH, "PATCH"),
];

#[derive(Default, Clone, Serialize, Deserialize)]
pub struct Shape {
    #[serde(
        serialize_with = "serialize_methods",
        deserialize_with = "deserialize_methods"
    )]
    methods: u8,
    has_body: bool,
    has_headers: bool,
    #[serde(
        serialize_with = "serialize_content_types",
        deserialize_with = "deserialize_content_types"
    )]
    content_types: u8,
    auth: bool,
}

fn serialize_methods<S: serde::Serializer>(bits: &u8, s: S) -> Result<S::Ok, S::Error> {
    METHODS
        .iter()
        .filter_map(|(bit, method)| (bits & bit != 0).then_some(*method))
        .collect::<Vec<_>>()
        .serialize(s)
}

fn serialize_content_types<S: serde::Serializer>(bits: &u8, s: S) -> Result<S::Ok, S::Error> {
    let content_types = ["application/json"];
    content_types[..(bits & CONTENT_JSON != 0) as usize].serialize(s)
}

fn deserialize_methods<'de, D: serde::Deserializer<'de>>(d: D) -> Result<u8, D::Error> {
    let methods = Vec::<String>::deserialize(d)?;
    let mut bits = 0;
    for method in methods {
        bits |= match method.as_str() {
            "GET" => METHOD_GET,
            "POST" => METHOD_POST,
            "PUT" => METHOD_PUT,
            "DELETE" => METHOD_DELETE,
            "PATCH" => METHOD_PATCH,
            _ => 0,
        };
    }
    Ok(bits)
}

fn deserialize_content_types<'de, D: serde::Deserializer<'de>>(d: D) -> Result<u8, D::Error> {
    let content_types = Vec::<String>::deserialize(d)?;
    let mut bits = 0;
    for content_type in content_types {
        if content_type == "application/json" {
            bits |= CONTENT_JSON;
        }
    }
    Ok(bits)
}

impl Shape {
    fn merge_ref(&mut self, other: &Shape) {
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

        entry.methods |= method_hint(CALL_LITERALS[m.pattern().as_usize()]);

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
        dst.entry(url).or_default().merge_ref(&shape);
    }
}

pub fn merge_refs_into<'a>(
    dst: &mut ApiMap,
    src: impl IntoIterator<Item = (&'a String, &'a Shape)>,
) {
    for (url, shape) in src {
        dst.entry(url.clone()).or_default().merge_ref(shape);
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

    let mut s = i + 1;

    // Template literal starting with `${expr}` — skip the expression so we
    // can capture the literal suffix after it (e.g. `${base}/foo` → "/foo").
    if quote == b'`' && s + 1 < bytes.len() && bytes[s] == b'$' && bytes[s + 1] == b'{' {
        let mut j = s + 2;
        let mut depth = 1;
        while j < bytes.len() && depth > 0 {
            match bytes[j] {
                b'{' => depth += 1,
                b'}' => depth -= 1,
                _ => {}
            }
            j += 1;
        }
        s = j;
    }

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

fn method_hint(anchor: &str) -> u8 {
    match anchor {
        "axios.get(" | "ky.get(" | ".get(" => METHOD_GET,
        "axios.post(" | "ky.post(" | ".post(" => METHOD_POST,
        "axios.put(" | ".put(" => METHOD_PUT,
        "axios.delete(" | ".delete(" => METHOD_DELETE,
        "axios.patch(" | ".patch(" => METHOD_PATCH,
        _ => 0,
    }
}

fn is_url_like(s: &str) -> bool {
    let bytes = s.as_bytes();
    (2..=512).contains(&bytes.len())
        && (s.starts_with('/') || s.starts_with("http://") || s.starts_with("https://"))
        && s != "/"
        && !is_bad_asset_url(bytes)
        && bytes.iter().any(u8::is_ascii_alphanumeric)
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
