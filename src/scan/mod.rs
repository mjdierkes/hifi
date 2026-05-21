//! Endpoint and client-route scanner.
//!
//! This module turns source bytes into three buckets:
//! - confirmed API calls with method/body/header hints,
//! - API-like candidates that were seen as values rather than calls,
//! - client routes that are useful context but not API endpoints.
//!
//! The scanner is intentionally anchor based. `DOCUMENT_PATTERNS` assigns each
//! literal to a semantic `PatternKind`, and the dispatch below keeps that
//! classification visible when adding new framework/client patterns.

use self::literals::{
    BAD_EXTS, CALL_LITERALS, ROUTE_BAD_EXTS, ROUTE_CALL_LITERALS, ROUTE_START_LITERALS,
    ROUTE_VALUE_LITERALS,
};
use crate::source::{self, TemplateMode};
use aho_corasick::{AhoCorasick, MatchKind};
use rustc_hash::FxHashMap;
use serde::{Deserialize, Serialize};
use std::sync::LazyLock;

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
const CANDIDATE_LITERALS: &[&str] = &["/api", "/graphql", "/trpc"];
const SHAPE_WINDOW: usize = 400;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum PatternKind {
    ApiCall,
    ApiCandidate,
    RouteCall,
    RouteValue,
    RouteStart,
}

// Each literal must declare the kind of evidence it represents. That keeps the
// Aho-Corasick index from becoming hidden control flow.
#[derive(Clone, Copy, Debug)]
struct SearchPattern {
    literal: &'static str,
    kind: PatternKind,
}

static DOCUMENT_PATTERNS: LazyLock<Vec<SearchPattern>> = LazyLock::new(|| {
    let mut patterns = Vec::with_capacity(
        CALL_LITERALS.len()
            + CANDIDATE_LITERALS.len()
            + ROUTE_CALL_LITERALS.len()
            + ROUTE_VALUE_LITERALS.len()
            + ROUTE_START_LITERALS.len(),
    );
    patterns.extend(CALL_LITERALS.iter().map(|literal| SearchPattern {
        literal,
        kind: PatternKind::ApiCall,
    }));
    patterns.extend(CANDIDATE_LITERALS.iter().map(|literal| SearchPattern {
        literal,
        kind: PatternKind::ApiCandidate,
    }));
    patterns.extend(ROUTE_CALL_LITERALS.iter().map(|literal| SearchPattern {
        literal,
        kind: PatternKind::RouteCall,
    }));
    patterns.extend(ROUTE_VALUE_LITERALS.iter().map(|literal| SearchPattern {
        literal,
        kind: PatternKind::RouteValue,
    }));
    patterns.extend(ROUTE_START_LITERALS.iter().map(|literal| SearchPattern {
        literal,
        kind: PatternKind::RouteStart,
    }));
    patterns
});

static DOCUMENT_AC: LazyLock<AhoCorasick> = LazyLock::new(|| {
    AhoCorasick::builder()
        .match_kind(MatchKind::LeftmostLongest)
        .build(DOCUMENT_PATTERNS.iter().map(|pattern| pattern.literal))
        .expect("valid scan literals")
});

#[derive(Default, Clone, Serialize, Deserialize)]
pub struct ScanResult {
    pub apis: ApiMap,
    #[serde(default, skip_serializing_if = "RouteMap::is_empty")]
    pub routes: RouteMap,
    #[serde(default, skip_serializing_if = "CandidateMap::is_empty")]
    pub candidates: CandidateMap,
}

impl ScanResult {
    pub fn merge(&mut self, other: ScanResult) {
        self.merge_findings(&other);
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
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    body_params: Vec<String>,
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
        if !self.body_params.is_empty() {
            flags.push("body-shape");
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
        for key in &other.body_params {
            push_unique_sorted(&mut self.body_params, key);
        }
    }
}

pub fn scan_endpoints(bytes: &[u8]) -> ScanResult {
    let mut out = ScanResult::default();

    for m in DOCUMENT_AC.find_iter(bytes) {
        let pattern = DOCUMENT_PATTERNS[m.pattern().as_usize()];
        match pattern.kind {
            PatternKind::ApiCall => {
                record_api_call(bytes, m.start(), m.end(), pattern.literal, &mut out)
            }
            PatternKind::ApiCandidate => {
                push_candidate(bytes, m.start(), &mut out);
            }
            PatternKind::RouteCall => record_route_call(bytes, m.end(), &mut out),
            PatternKind::RouteValue => record_route_value(bytes, m.start(), m.end(), &mut out),
            PatternKind::RouteStart => record_route_start(bytes, m.end(), &mut out),
        }
    }
    out
}

fn record_api_call(bytes: &[u8], start: usize, after: usize, anchor: &str, out: &mut ScanResult) {
    let Some((url, mut shape)) = scan_call(bytes, start, after, anchor) else {
        return;
    };
    if !is_url_like(&url) {
        return;
    }
    if shape.methods == 0 {
        shape.methods = METHOD_GET;
    }
    apply_query_params(&mut shape, &url);
    let url = normalize_api_url(&url);
    out.apis.entry(url).or_default().merge(&shape);
}

fn record_route_call(bytes: &[u8], after: usize, out: &mut ScanResult) {
    if let Some(url) = extract_url_arg(bytes, after).filter(|url| is_client_route(url)) {
        out.routes.entry(url).or_default();
    }
}

fn record_route_value(bytes: &[u8], start: usize, after: usize, out: &mut ScanResult) {
    if !source::is_identifier_boundary_before(bytes, start) {
        return;
    }
    if let Some(url) = extract_value_after_anchor(bytes, after).filter(|url| is_client_route(url)) {
        out.routes.entry(url).or_default();
    }
}

fn record_route_start(bytes: &[u8], after: usize, out: &mut ScanResult) {
    let slash = after.saturating_sub(1);
    if !push_candidate(bytes, slash, out) {
        if let Some(url) = extract_route_at(bytes, slash) {
            out.routes.entry(url).or_default();
        }
    }
}

// Shape extraction is deliberately heuristic. It should capture useful request
// hints from nearby source without pretending to validate JavaScript semantics.
fn scan_call(bytes: &[u8], start: usize, after: usize, anchor: &str) -> Option<(String, Shape)> {
    let url = extract_url_arg(bytes, after)?;
    let lo = statement_start(bytes, start);
    let hi = statement_end(bytes, after);
    let mut shape = shape_from_window(&bytes[lo..hi]);
    let hint = method_hint(anchor);
    shape.methods |= hint;
    if method_allows_body(hint) {
        apply_second_arg_body_shape(bytes, after, &mut shape);
    }
    Some((url, shape))
}

fn shape_from_window(bytes: &[u8]) -> Shape {
    let lower = bytes.to_ascii_lowercase();
    let mut shape = Shape::default();
    for method in memchr::memmem::find_iter(&lower, b"method") {
        shape.methods |= parse_method(&lower[method + 6..]);
    }
    shape.has_body = source::contains(&lower, b"body") || source::contains(&lower, b"formdata(");
    shape.has_headers = source::contains(&lower, b"headers")
        || source::contains(&lower, b"content-type")
        || source::contains(&lower, b"authorization");
    shape.auth = source::contains(&lower, b"authorization") || source::contains(&lower, b"bearer");
    if source::contains(&lower, b"application/json") {
        shape.content_types |= CONTENT_JSON;
    }
    if source::contains(&lower, b"multipart/form-data") || source::contains(&lower, b"formdata(") {
        shape.content_types |= CONTENT_FORM;
    }
    if source::contains(&lower, b"application/x-www-form-urlencoded")
        || source::contains(&lower, b"urlsearchparams(")
    {
        shape.content_types |= CONTENT_URLENCODED;
    }
    if source::contains(&lower, b"text/plain") {
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

fn extract_url_arg(bytes: &[u8], start: usize) -> Option<String> {
    if start > 0 && matches!(bytes[start - 1], b'"' | b'\'' | b'`') {
        return source::quoted_string(
            bytes,
            start,
            bytes[start - 1],
            TemplateMode::ReplaceExpressions,
        );
    }
    let mut i = source::skip_ws(bytes, start);
    let quote = *bytes.get(i)?;
    if !matches!(quote, b'"' | b'\'' | b'`') {
        return None;
    }
    i += 1;
    if quote == b'`' && bytes.get(i..i + 2) == Some(b"${") {
        i = source::skip_template_expr(bytes, i + 2);
    }
    source::quoted_string(bytes, i, quote, TemplateMode::ReplaceExpressions)
}

fn apply_second_arg_body_shape(bytes: &[u8], start: usize, shape: &mut Shape) {
    let Some(first_end) = source::quoted_arg_end(bytes, start) else {
        return;
    };
    let mut i = source::skip_ws(bytes, first_end);
    if bytes.get(i) != Some(&b',') {
        return;
    }
    i = source::skip_ws(bytes, i + 1);
    if matches!(bytes.get(i), None | Some(b')')) {
        return;
    }
    shape.has_body = true;
    if let Some(keys) = object_keys(bytes, i) {
        shape.content_types |= CONTENT_JSON;
        for key in keys {
            push_unique_sorted(&mut shape.body_params, &key);
        }
    }
}

fn object_keys(bytes: &[u8], start: usize) -> Option<Vec<String>> {
    if bytes.get(start) != Some(&b'{') {
        return None;
    }
    let mut keys = Vec::new();
    let mut i = start + 1;
    let mut depth = 1usize;
    let mut read_key = true;
    while i < bytes.len() && depth > 0 {
        match bytes[i] {
            b'{' | b'[' | b'(' => {
                depth += 1;
                i += 1;
            }
            b'}' | b']' | b')' => {
                depth -= 1;
                i += 1;
                read_key = depth == 1;
            }
            b'"' | b'\'' | b'`' => {
                if depth == 1 && read_key {
                    let quote = bytes[i];
                    if let Some(end) = source::quoted_end(bytes, i + 1, quote) {
                        let key = std::str::from_utf8(&bytes[i + 1..end]).ok()?.to_string();
                        let after = source::skip_ws(bytes, end + 1);
                        if bytes.get(after) == Some(&b':') {
                            keys.push(key);
                            read_key = false;
                        }
                        i = end + 1;
                    } else {
                        return Some(keys);
                    }
                } else {
                    i = source::quoted_end(bytes, i + 1, bytes[i])
                        .map(|end| end + 1)
                        .unwrap_or(bytes.len());
                }
            }
            b',' if depth == 1 => {
                read_key = true;
                i += 1;
            }
            b':' if depth == 1 => {
                read_key = false;
                i += 1;
            }
            b if depth == 1 && read_key && (b == b'_' || b == b'$' || b.is_ascii_alphabetic()) => {
                let key_start = i;
                i += 1;
                while bytes
                    .get(i)
                    .is_some_and(|b| *b == b'_' || *b == b'$' || b.is_ascii_alphanumeric())
                {
                    i += 1;
                }
                let key = std::str::from_utf8(&bytes[key_start..i]).ok()?.to_string();
                let after = source::skip_ws(bytes, i);
                if matches!(bytes.get(after), Some(b':' | b',' | b'}')) {
                    keys.push(key);
                    read_key = !matches!(bytes.get(after), Some(b':'));
                }
            }
            _ => i += 1,
        }
    }
    Some(keys)
}

fn extract_value_after_anchor(bytes: &[u8], mut i: usize) -> Option<String> {
    i = source::skip_ws(bytes, i);
    if matches!(bytes.get(i), Some(b'"' | b'\'' | b'`')) {
        let quote = bytes[i];
        i = source::skip_ws(bytes, i + 1);
        if bytes.get(i) == Some(&quote) {
            i += 1;
        }
    }
    i = source::skip_ws(bytes, i);
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
    let start = source::walk_token_start(bytes, pos);
    let url = source::token_string(bytes, start, TemplateMode::ReplaceExpressions)?;
    is_api_candidate(&url).then(|| normalize_api_url(&url))
}

fn extract_route_at(bytes: &[u8], pos: usize) -> Option<String> {
    let url = source::token_string(bytes, pos, TemplateMode::ReplaceExpressions)?;
    is_client_route(&url).then_some(url)
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

fn method_allows_body(method: u8) -> bool {
    method & (METHOD_POST | METHOD_PUT | METHOD_PATCH) != 0
}

fn is_api_candidate(s: &str) -> bool {
    is_url_like(s)
        && (s.starts_with("/api")
            || s.starts_with("/graphql")
            || s.starts_with("/trpc")
            || ((s.starts_with("http://") || s.starts_with("https://"))
                && ["/api/", "/graphql", "/trpc"]
                    .iter()
                    .any(|needle| s.contains(needle))))
}

fn is_client_route(s: &str) -> bool {
    is_route_like(s)
        && !s.starts_with("/api")
        && !s.starts_with("/graphql")
        && !s.starts_with("/trpc")
        && !s.starts_with("/_next")
        && !s.starts_with("/_nuxt")
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
        && !has_bare_dynamic_suffix(s)
        && !bad_ext(bytes, BAD_EXTS, false)
        && bytes.iter().any(u8::is_ascii_alphanumeric)
}

fn normalize_api_url(s: &str) -> String {
    let without_fragment = s.split('#').next().unwrap_or(s);
    let Some((path, query)) = without_fragment.split_once('?') else {
        return without_fragment.to_owned();
    };

    let has_query_keys = query
        .split('&')
        .filter_map(|pair| pair.split('=').next().map(str::trim))
        .any(|key| !key.is_empty() && key.len() <= 128);
    if has_query_keys {
        path.to_owned()
    } else {
        without_fragment.to_owned()
    }
}

fn has_bare_dynamic_suffix(s: &str) -> bool {
    let Some(pos) = s.find("{dynamic}") else {
        return false;
    };
    pos > 0 && s.as_bytes()[pos - 1].is_ascii_alphanumeric()
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
