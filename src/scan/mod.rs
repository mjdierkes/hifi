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
pub type CandidateMap = FxHashMap<String, Candidate>;

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
const CONTENT_TYPES: [(u8, &str); 1] = [(CONTENT_JSON, "application/json")];

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

#[derive(Clone, Serialize, Deserialize)]
pub struct Candidate {
    source: String,
    confidence: String,
}

impl Default for Candidate {
    fn default() -> Self {
        Self {
            source: "literal".into(),
            confidence: "candidate".into(),
        }
    }
}

fn serialize_methods<S: serde::Serializer>(bits: &u8, s: S) -> Result<S::Ok, S::Error> {
    serialize_flags(bits, &METHODS, s)
}

fn serialize_content_types<S: serde::Serializer>(bits: &u8, s: S) -> Result<S::Ok, S::Error> {
    serialize_flags(bits, &CONTENT_TYPES, s)
}

fn serialize_flags<S: serde::Serializer>(
    bits: &u8,
    flags: &[(u8, &str)],
    s: S,
) -> Result<S::Ok, S::Error> {
    flags
        .iter()
        .filter_map(|(bit, name)| (bits & bit != 0).then_some(*name))
        .collect::<Vec<_>>()
        .serialize(s)
}

fn deserialize_methods<'de, D: serde::Deserializer<'de>>(d: D) -> Result<u8, D::Error> {
    deserialize_flags(d, &METHODS)
}

fn deserialize_content_types<'de, D: serde::Deserializer<'de>>(d: D) -> Result<u8, D::Error> {
    deserialize_flags(d, &CONTENT_TYPES)
}

fn deserialize_flags<'de, D: serde::Deserializer<'de>>(
    d: D,
    flags: &[(u8, &str)],
) -> Result<u8, D::Error> {
    let mut bits = 0;
    for value in Vec::<String>::deserialize(d)? {
        if let Some((bit, _)) = flags.iter().find(|(_, name)| *name == value) {
            bits |= *bit;
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

pub fn scan_candidates(bytes: &[u8], candidates: &mut CandidateMap) {
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'"' | b'\'' | b'`' => {
                let quote = bytes[i];
                let start = i + 1;
                let mut end = start;
                while end < bytes.len() && bytes[end] != quote {
                    if bytes[end] == b'\\' && end + 1 < bytes.len() {
                        end += 2;
                        continue;
                    }
                    if quote == b'`'
                        && bytes[end] == b'$'
                        && end + 1 < bytes.len()
                        && bytes[end + 1] == b'{'
                    {
                        scan_candidate_text(&bytes[start..end], candidates);
                        end = skip_template_expr(bytes, end + 2);
                        continue;
                    }
                    end += 1;
                }
                scan_candidate_text(&bytes[start..end], candidates);
                i = end.saturating_add(1);
            }
            _ => i += 1,
        }
    }
}

pub fn merge_candidates_into(dst: &mut CandidateMap, src: CandidateMap) {
    for (url, candidate) in src {
        dst.entry(url).or_insert(candidate);
    }
}

pub fn merge_candidate_refs_into<'a>(
    dst: &mut CandidateMap,
    src: impl IntoIterator<Item = (&'a String, &'a Candidate)>,
) {
    for (url, candidate) in src {
        dst.entry(url.clone()).or_insert_with(|| candidate.clone());
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

fn skip_template_expr(bytes: &[u8], mut i: usize) -> usize {
    let mut depth = 1;
    while i < bytes.len() && depth > 0 {
        match bytes[i] {
            b'{' => depth += 1,
            b'}' => depth -= 1,
            b'\\' if i + 1 < bytes.len() => i += 1,
            _ => {}
        }
        i += 1;
    }
    i
}

fn scan_candidate_text(bytes: &[u8], candidates: &mut CandidateMap) {
    for needle in [
        b"/api".as_slice(),
        b"/graphql".as_slice(),
        b"/trpc".as_slice(),
        b"/_next/data".as_slice(),
    ] {
        let mut offset = 0;
        while let Some(rel) = memchr::memmem::find(&bytes[offset..], needle) {
            let pos = offset + rel;
            if let Some(url) = extract_candidate_at(bytes, pos) {
                candidates.entry(url).or_default();
            }
            offset = pos + needle.len();
        }
    }
}

fn extract_candidate_at(bytes: &[u8], pos: usize) -> Option<String> {
    let start = walk_candidate_start(bytes, pos);
    let end = bytes[pos..]
        .iter()
        .position(|b| is_candidate_delim(*b))
        .map(|n| pos + n)
        .unwrap_or(bytes.len());
    let raw = std::str::from_utf8(&bytes[start..end]).ok()?;
    let url = raw.trim_matches('\\');
    is_api_candidate(url).then(|| url.to_owned())
}

fn walk_candidate_start(bytes: &[u8], pos: usize) -> usize {
    let mut s = pos;
    while s > 0 && !is_candidate_delim(bytes[s - 1]) {
        s -= 1;
    }
    s
}

fn is_candidate_delim(b: u8) -> bool {
    b.is_ascii_whitespace()
        || matches!(
            b,
            b'"' | b'\''
                | b'`'
                | b'<'
                | b'>'
                | b')'
                | b'('
                | b','
                | b';'
                | b'{'
                | b'}'
                | b'['
                | b']'
        )
}

fn is_api_candidate(s: &str) -> bool {
    is_url_like(s)
        && (s.starts_with("/api")
            || s.starts_with("/graphql")
            || s.starts_with("/trpc")
            || s.starts_with("/_next/data")
            || ((s.starts_with("http://") || s.starts_with("https://"))
                && (s.contains("/api/")
                    || s.ends_with("/api")
                    || s.contains("/graphql")
                    || s.contains("/trpc")
                    || s.contains("/_next/data/"))))
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
