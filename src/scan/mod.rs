use self::literals::{
    BAD_EXTS, CALL_LITERALS, ROUTE_BAD_EXTS, ROUTE_CALL_LITERALS, ROUTE_START_LITERALS,
    ROUTE_VALUE_LITERALS, SKIPPED_CHUNK_FRAGMENTS,
};
use aho_corasick::{AhoCorasick, MatchKind};
use rustc_hash::{FxHashMap, FxHashSet};
use serde::{Deserialize, Serialize};
use std::sync::LazyLock;
use url::Url;

mod literals;

pub type ApiMap = FxHashMap<String, Shape>;
pub type CandidateMap = FxHashMap<String, ()>;
pub type RouteMap = FxHashMap<String, ()>;

const METHOD_GET: u8 = 1 << 0;
const METHOD_POST: u8 = 1 << 1;
const METHOD_PUT: u8 = 1 << 2;
const METHOD_DELETE: u8 = 1 << 3;
const METHOD_PATCH: u8 = 1 << 4;
const METHOD_HEAD: u8 = 1 << 5;
const METHOD_OPTIONS: u8 = 1 << 6;
const CONTENT_JSON: u8 = 1 << 0;
const CONTENT_FORM: u8 = 1 << 1;
const CONTENT_URLENCODED: u8 = 1 << 2;
const CONTENT_TEXT: u8 = 1 << 3;
const METHODS: [(u8, &str); 7] = [
    (METHOD_GET, "GET"),
    (METHOD_POST, "POST"),
    (METHOD_PUT, "PUT"),
    (METHOD_DELETE, "DELETE"),
    (METHOD_PATCH, "PATCH"),
    (METHOD_HEAD, "HEAD"),
    (METHOD_OPTIONS, "OPTIONS"),
];
const CONTENT_TYPES: [(u8, &str); 4] = [
    (CONTENT_JSON, "application/json"),
    (CONTENT_FORM, "multipart/form-data"),
    (CONTENT_URLENCODED, "application/x-www-form-urlencoded"),
    (CONTENT_TEXT, "text/plain"),
];
const CANDIDATE_LITERALS: &[&str] = &["/api", "/graphql", "/trpc", "/_next/data"];
const SHAPE_WINDOW: usize = 400;

static DOCUMENT_AC: LazyLock<AhoCorasick> = LazyLock::new(|| {
    let mut patterns = Vec::with_capacity(
        CALL_LITERALS.len()
            + CANDIDATE_LITERALS.len()
            + ROUTE_CALL_LITERALS.len()
            + ROUTE_VALUE_LITERALS.len()
            + ROUTE_START_LITERALS.len()
            + 2,
    );
    patterns.extend_from_slice(CALL_LITERALS);
    patterns.extend_from_slice(CANDIDATE_LITERALS);
    patterns.extend_from_slice(ROUTE_CALL_LITERALS);
    patterns.extend_from_slice(ROUTE_VALUE_LITERALS);
    patterns.extend_from_slice(ROUTE_START_LITERALS);
    patterns.push("/_next/");
    patterns.push("static/chunks/");
    AhoCorasick::builder()
        .match_kind(MatchKind::LeftmostLongest)
        .build(patterns)
        .expect("valid scan literals")
});

#[derive(Default, Clone, Serialize, Deserialize)]
pub struct ScanResult {
    pub apis: ApiMap,
    #[serde(default, skip_serializing_if = "RouteMap::is_empty")]
    pub routes: RouteMap,
    #[serde(default, skip_serializing_if = "CandidateMap::is_empty")]
    pub candidates: CandidateMap,
    pub refs: Vec<Url>,
}

impl ScanResult {
    pub fn merge(&mut self, other: ScanResult) {
        self.merge_findings(&other);
        self.refs.extend(other.refs);
        self.refs.sort_unstable();
        self.refs.dedup();
    }

    pub fn merge_findings(&mut self, other: &ScanResult) {
        for (url, shape) in &other.apis {
            self.apis.entry(url.clone()).or_default().merge(shape);
        }
        self.routes
            .extend(other.routes.keys().map(|url| (url.clone(), ())));
        self.candidates
            .extend(other.candidates.keys().map(|url| (url.clone(), ())));
    }

    pub fn finalize(&mut self) {
        for url in self.apis.keys() {
            self.candidates.remove(url);
            self.routes.remove(url);
        }
        for url in self.candidates.keys() {
            self.routes.remove(url);
        }
    }
}

#[derive(Default, Clone, Serialize, Deserialize)]
pub struct Shape {
    methods: u8,
    has_body: bool,
    has_headers: bool,
    content_types: u8,
    auth: bool,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    query_params: Vec<String>,
}

impl Shape {
    pub fn methods_csv(&self) -> String {
        METHODS
            .iter()
            .filter_map(|(bit, name)| (self.methods & bit != 0).then_some(*name))
            .collect::<Vec<_>>()
            .join(",")
    }

    pub fn flags_csv(&self) -> String {
        let mut flags = Vec::with_capacity(6);
        if self.has_body {
            flags.push("body");
        }
        if self.has_headers {
            flags.push("headers");
        }
        for (bit, name) in CONTENT_TYPES {
            if self.content_types & bit != 0 {
                flags.push(match name {
                    "application/json" => "json",
                    "multipart/form-data" => "form",
                    "application/x-www-form-urlencoded" => "urlencoded",
                    "text/plain" => "text",
                    _ => name,
                });
            }
        }
        if self.auth {
            flags.push("auth");
        }
        if !self.query_params.is_empty() {
            flags.push("query");
        }
        flags.join(",")
    }

    fn merge(&mut self, other: &Shape) {
        self.methods |= other.methods;
        self.has_body |= other.has_body;
        self.has_headers |= other.has_headers;
        self.content_types |= other.content_types;
        self.auth |= other.auth;
        for key in &other.query_params {
            push_unique_sorted(&mut self.query_params, key);
        }
    }
}

pub fn scan_document(bytes: &[u8], base: &Url) -> ScanResult {
    let mut out = ScanResult::default();
    let mut seen_refs = FxHashSet::default();
    let call_end = CALL_LITERALS.len();
    let candidate_end = call_end + CANDIDATE_LITERALS.len();
    let route_call_end = candidate_end + ROUTE_CALL_LITERALS.len();
    let route_value_end = route_call_end + ROUTE_VALUE_LITERALS.len();
    let route_start_end = route_value_end + ROUTE_START_LITERALS.len();

    for m in DOCUMENT_AC.find_iter(bytes) {
        let pat = m.pattern().as_usize();
        if pat < call_end {
            if let Some((url, mut shape)) = scan_call(bytes, m.start(), m.end(), CALL_LITERALS[pat])
            {
                if is_url_like(&url) {
                    if shape.methods == 0 {
                        shape.methods = METHOD_GET;
                    }
                    apply_query_params(&mut shape, &url);
                    out.apis.entry(url).or_default().merge(&shape);
                }
            }
        } else if pat < candidate_end {
            push_candidate(bytes, m.start(), &mut out);
        } else if pat < route_call_end {
            if let Some(url) = extract_url_arg(bytes, m.end()).filter(|url| is_client_route(url)) {
                out.routes.entry(url.to_owned()).or_default();
            }
        } else if pat < route_value_end {
            if is_identifier_boundary_before(bytes, m.start()) {
                if let Some(url) =
                    extract_value_after_anchor(bytes, m.end()).filter(|url| is_client_route(url))
                {
                    out.routes.entry(url.to_owned()).or_default();
                }
            }
        } else if pat < route_start_end {
            let slash = m.end().saturating_sub(1);
            if !push_candidate(bytes, slash, &mut out) {
                if bytes[slash..].starts_with(b"/_next/") {
                    push_chunk_at(bytes, slash, base, false, &mut seen_refs, &mut out.refs);
                } else if let Some(url) = extract_route_at(bytes, slash) {
                    out.routes.entry(url).or_default();
                }
            }
        } else if pat == route_start_end {
            push_chunk_at(bytes, m.start(), base, false, &mut seen_refs, &mut out.refs);
        } else if m.start() < 7 || &bytes[m.start() - 7..m.start()] != b"/_next/" {
            push_chunk_at(bytes, m.start(), base, true, &mut seen_refs, &mut out.refs);
        }
    }
    out
}

pub fn extract_build_id(html: &[u8]) -> Option<String> {
    let needle = br#""buildId":""#;
    if let Some(i) = memchr::memmem::find(html, needle) {
        let rest = &html[i + needle.len()..];
        if let Some(end) = memchr::memchr(b'"', rest) {
            return std::str::from_utf8(&rest[..end]).ok().map(str::to_string);
        }
    }
    let marker = b"/_next/static/";
    let rest = &html[memchr::memmem::find(html, marker)? + marker.len()..];
    let candidate = &rest[..memchr::memchr(b'/', rest)?];
    (!matches!(candidate, b"chunks" | b"css" | b"media" | b"development"))
        .then(|| std::str::from_utf8(candidate).ok().map(str::to_string))?
}

fn scan_call(bytes: &[u8], start: usize, after: usize, anchor: &str) -> Option<(String, Shape)> {
    let url = extract_url_arg(bytes, after)?.to_owned();
    let lo = statement_start(bytes, start);
    let hi = statement_end(bytes, after);
    let mut shape = shape_from_window(&bytes[lo..hi]);
    shape.methods |= method_hint(anchor);
    Some((url, shape))
}

fn shape_from_window(bytes: &[u8]) -> Shape {
    let lower = bytes.to_ascii_lowercase();
    let mut shape = Shape::default();
    for method in memchr::memmem::find_iter(&lower, b"method") {
        shape.methods |= parse_method(&lower[method + 6..]);
    }
    shape.has_body = contains(&lower, b"body") || contains(&lower, b"formdata(");
    shape.has_headers = contains(&lower, b"headers")
        || contains(&lower, b"content-type")
        || contains(&lower, b"authorization");
    shape.auth = contains(&lower, b"authorization") || contains(&lower, b"bearer");
    if contains(&lower, b"application/json") {
        shape.content_types |= CONTENT_JSON;
    }
    if contains(&lower, b"multipart/form-data") || contains(&lower, b"formdata(") {
        shape.content_types |= CONTENT_FORM;
    }
    if contains(&lower, b"application/x-www-form-urlencoded")
        || contains(&lower, b"urlsearchparams(")
    {
        shape.content_types |= CONTENT_URLENCODED;
    }
    if contains(&lower, b"text/plain") {
        shape.content_types |= CONTENT_TEXT;
    }
    shape
}

fn parse_method(mut bytes: &[u8]) -> u8 {
    while bytes.first().is_some_and(|b| b.is_ascii_whitespace()) {
        bytes = &bytes[1..];
    }
    if bytes.first() == Some(&b':') {
        bytes = &bytes[1..];
    }
    while bytes.first().is_some_and(|b| b.is_ascii_whitespace()) {
        bytes = &bytes[1..];
    }
    if matches!(bytes.first(), Some(b'"' | b'\'' | b'`')) {
        bytes = &bytes[1..];
    }
    let end = bytes
        .iter()
        .position(|b| !b.is_ascii_alphabetic())
        .unwrap_or(bytes.len());
    match &bytes[..end] {
        b"get" => METHOD_GET,
        b"post" => METHOD_POST,
        b"put" => METHOD_PUT,
        b"delete" => METHOD_DELETE,
        b"patch" => METHOD_PATCH,
        b"head" => METHOD_HEAD,
        b"options" => METHOD_OPTIONS,
        _ => 0,
    }
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    memchr::memmem::find(haystack, needle).is_some()
}

fn extract_url_arg(bytes: &[u8], start: usize) -> Option<&str> {
    if start > 0 && matches!(bytes[start - 1], b'"' | b'\'' | b'`') {
        return extract_quoted(bytes, start, bytes[start - 1]).and_then(|(url, _)| url);
    }
    let mut i = skip_ws(bytes, start);
    let quote = *bytes.get(i)?;
    if !matches!(quote, b'"' | b'\'' | b'`') {
        return None;
    }
    i += 1;
    if quote == b'`' && bytes.get(i..i + 2) == Some(b"${") {
        i = skip_template_expr(bytes, i + 2);
    }
    extract_quoted(bytes, i, quote).and_then(|(url, _)| url)
}

fn extract_quoted(bytes: &[u8], start: usize, quote: u8) -> Option<(Option<&str>, usize)> {
    let mut i = start;
    while i < bytes.len() {
        if bytes[i] == b'\\' && i + 1 < bytes.len() {
            i += 2;
        } else if quote == b'`' && bytes.get(i..i + 2) == Some(b"${") {
            return Some((
                std::str::from_utf8(&bytes[start..i]).ok().map(|s| {
                    if s.is_empty() {
                        "{dynamic}"
                    } else {
                        s
                    }
                }),
                i,
            ));
        } else if bytes[i] == quote {
            return Some((std::str::from_utf8(&bytes[start..i]).ok(), i + 1));
        } else {
            i += 1;
        }
    }
    Some((std::str::from_utf8(&bytes[start..]).ok(), bytes.len()))
}

fn extract_value_after_anchor(bytes: &[u8], mut i: usize) -> Option<&str> {
    i = skip_ws(bytes, i);
    if matches!(bytes.get(i), Some(b'"' | b'\'' | b'`')) {
        let quote = bytes[i];
        i = skip_ws(bytes, i + 1);
        if bytes.get(i) == Some(&quote) {
            i += 1;
        }
    }
    i = skip_ws(bytes, i);
    if !matches!(bytes.get(i), Some(b':' | b'=')) {
        return None;
    }
    extract_url_arg(bytes, i + 1)
}

fn push_candidate(bytes: &[u8], pos: usize, out: &mut ScanResult) -> bool {
    if let Some(url) = extract_candidate_at(bytes, pos) {
        out.candidates.entry(url).or_default();
        true
    } else {
        false
    }
}

fn extract_candidate_at(bytes: &[u8], pos: usize) -> Option<String> {
    let start = walk_token_start(bytes, pos);
    let url = token_string(bytes, start)?;
    is_api_candidate(&url).then_some(url)
}

fn extract_route_at(bytes: &[u8], pos: usize) -> Option<String> {
    let url = token_string(bytes, pos)?;
    is_client_route(&url).then_some(url)
}

fn token_string(bytes: &[u8], start: usize) -> Option<String> {
    let mut out = None;
    let end = token_end(bytes, start, &mut out);
    if let Some(out) = out {
        return String::from_utf8(out)
            .ok()
            .map(|s| s.trim_matches('\\').to_string());
    }
    std::str::from_utf8(&bytes[start..end])
        .ok()
        .map(|s| s.trim_matches('\\').to_string())
}

fn token_end(bytes: &[u8], mut i: usize, normalized: &mut Option<Vec<u8>>) -> usize {
    let start = i;
    while i < bytes.len() {
        if bytes[i..].starts_with(b"{dynamic}") {
            normalized
                .get_or_insert_with(|| bytes[start..i].to_vec())
                .extend_from_slice(b"{dynamic}");
            i += b"{dynamic}".len();
        } else if bytes.get(i..i + 2) == Some(b"${") {
            normalized
                .get_or_insert_with(|| bytes[start..i].to_vec())
                .extend_from_slice(b"{dynamic}");
            i = skip_template_expr(bytes, i + 2);
        } else if is_token_delim(bytes[i]) {
            break;
        } else {
            if let Some(out) = normalized {
                out.push(bytes[i]);
            }
            i += 1;
        }
    }
    i
}

fn walk_token_start(bytes: &[u8], pos: usize) -> usize {
    let mut start = pos;
    while start > 0 && !is_token_delim(bytes[start - 1]) {
        start -= 1;
    }
    start
}

fn is_token_delim(b: u8) -> bool {
    b.is_ascii_whitespace()
        || matches!(
            b,
            b'"' | b'\''
                | b'`'
                | b'<'
                | b'>'
                | b'='
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

fn skip_ws(bytes: &[u8], mut i: usize) -> usize {
    while bytes.get(i).is_some_and(|b| b.is_ascii_whitespace()) {
        i += 1;
    }
    i
}

fn statement_start(bytes: &[u8], pos: usize) -> usize {
    let start = pos.saturating_sub(SHAPE_WINDOW);
    bytes[start..pos]
        .iter()
        .rposition(|b| matches!(*b, b';' | b'\n' | b'\r'))
        .map(|rel| start + rel + 1)
        .unwrap_or(start)
}

fn statement_end(bytes: &[u8], pos: usize) -> usize {
    let end = (pos + SHAPE_WINDOW).min(bytes.len());
    bytes[pos..end]
        .iter()
        .position(|b| matches!(*b, b';' | b'\n' | b'\r'))
        .map(|rel| pos + rel)
        .unwrap_or(end)
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

fn is_api_candidate(s: &str) -> bool {
    is_url_like(s)
        && (s.starts_with("/api")
            || s.starts_with("/graphql")
            || s.starts_with("/trpc")
            || s.starts_with("/_next/data")
            || ((s.starts_with("http://") || s.starts_with("https://"))
                && ["/api/", "/graphql", "/trpc", "/_next/data/"]
                    .iter()
                    .any(|needle| s.contains(needle))))
}

fn is_client_route(s: &str) -> bool {
    is_route_like(s)
        && !s.starts_with("/api")
        && !s.starts_with("/graphql")
        && !s.starts_with("/trpc")
        && !s.starts_with("/_next")
}

fn is_route_like(s: &str) -> bool {
    let bytes = s.as_bytes();
    (2..=512).contains(&bytes.len())
        && s.starts_with('/')
        && !s.starts_with("//")
        && bytes.iter().any(u8::is_ascii_alphanumeric)
        && !bad_ext(bytes, ROUTE_BAD_EXTS, true)
}

fn is_url_like(s: &str) -> bool {
    let bytes = s.as_bytes();
    (2..=512).contains(&bytes.len())
        && (s.starts_with('/') || s.starts_with("http://") || s.starts_with("https://"))
        && s != "/"
        && !bad_ext(bytes, BAD_EXTS, false)
        && bytes.iter().any(u8::is_ascii_alphanumeric)
}

fn bad_ext(s: &[u8], exts: &[&str], strip_fragment: bool) -> bool {
    let path = s
        .split(|b| *b == b'?' || (strip_fragment && *b == b'#'))
        .next()
        .unwrap_or(s);
    exts.iter().any(|ext| {
        path.len() >= ext.len()
            && path[path.len() - ext.len()..].eq_ignore_ascii_case(ext.as_bytes())
    })
}

fn is_identifier_boundary_before(bytes: &[u8], pos: usize) -> bool {
    pos == 0
        || !matches!(
            bytes[pos - 1],
            b'a'..=b'z' | b'A'..=b'Z' | b'0'..=b'9' | b'_' | b'$'
        )
}

fn apply_query_params(shape: &mut Shape, url: &str) {
    let Some(query_start) = url.find('?') else {
        return;
    };
    let query = url[query_start + 1..].split('#').next().unwrap_or("");
    for key in query
        .split('&')
        .filter_map(|pair| pair.split('=').next().map(str::trim))
        .filter(|key| !key.is_empty() && key.len() <= 128)
    {
        push_unique_sorted(&mut shape.query_params, key);
    }
}

fn push_unique_sorted(dst: &mut Vec<String>, value: &str) {
    if !dst.iter().any(|existing| existing == value) {
        dst.push(value.to_owned());
        dst.sort_unstable();
    }
}

fn push_chunk_at(
    bytes: &[u8],
    pos: usize,
    base: &Url,
    nested: bool,
    seen: &mut FxHashSet<Url>,
    out: &mut Vec<Url>,
) {
    let start = if nested {
        pos
    } else {
        walk_token_start(bytes, pos)
    };
    let end = pos + chunk_url_len(&bytes[pos..], nested);
    let src = &bytes[start..end];
    if is_skipped_chunk(src)
        || (nested && !src.ends_with(b".js"))
        || (!nested && memchr::memmem::find(src, b".js").is_none())
    {
        return;
    }
    let Ok(src) = std::str::from_utf8(src) else {
        return;
    };
    let url = if nested {
        base.join(&format!("/_next/{src}"))
    } else {
        base.join(src)
    };
    if let Ok(url) = url {
        if seen.insert(url.clone()) {
            out.push(url);
        }
    }
}

fn chunk_url_len(bytes: &[u8], backtick: bool) -> usize {
    bytes
        .iter()
        .position(|b| {
            b.is_ascii_whitespace()
                || matches!(b, b'"' | b'\'' | b'<' | b'>' | b')' | b',' | b';')
                || (backtick && *b == b'`')
        })
        .unwrap_or(bytes.len())
}

fn is_skipped_chunk(src: &[u8]) -> bool {
    SKIPPED_CHUNK_FRAGMENTS
        .iter()
        .any(|f| memchr::memmem::find(src, f.as_bytes()).is_some())
}
