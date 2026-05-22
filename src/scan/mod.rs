//! Endpoint and client-route scanner.
//!
//! This module turns source bytes into three buckets:
//! - confirmed API calls with method/body/header hints,
//! - API-like candidates that were seen as values rather than calls,
//! - client routes that are useful context but not API endpoints.
//!
//! The scanner is intentionally anchor based. `patterns` registers each search
//! literal with a semantic kind, while `extract`, `classify`, and `shape` keep
//! parsing details out of the orchestration flow below.

use crate::source;
use patterns::{PatternKind, DOCUMENT_AC, DOCUMENT_PATTERNS};
use rustc_hash::FxHashMap;
use serde::{Deserialize, Serialize};

pub mod classify;
mod extract;
mod literals;
pub mod next;
mod patterns;
mod shape;

pub use shape::Shape;

pub type ApiMap = FxHashMap<String, Shape>;
pub type CandidateMap = FxHashMap<String, ()>;
pub type RouteMap = FxHashMap<String, ()>;

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceKind {
    Api,
    Route,
    Candidate,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Extractor {
    Literal,
    Manifest,
    Flight,
    ApiCall,
    RouteCall,
    ServerAction,
    NuxtPayload,
    SvelteKitData,
    RemixManifest,
    AstroIsland,
    ApiClient,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Confidence {
    Observed,
    Parsed,
    Inferred,
    Candidate,
}

impl Extractor {
    fn confidence(self) -> Confidence {
        match self {
            Self::ApiCall | Self::RouteCall | Self::ApiClient => Confidence::Observed,
            Self::Manifest
            | Self::Flight
            | Self::NuxtPayload
            | Self::SvelteKitData
            | Self::RemixManifest
            | Self::AstroIsland => Confidence::Parsed,
            Self::ServerAction => Confidence::Inferred,
            Self::Literal => Confidence::Candidate,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Evidence {
    pub url: String,
    pub kind: EvidenceKind,
    pub extractor: Extractor,
    pub confidence: Confidence,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub shape: Option<Shape>,
}

#[derive(Default, Clone, Serialize, Deserialize)]
pub struct ScanResult {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub evidence: Vec<Evidence>,
}

impl ScanResult {
    pub fn merge(&mut self, other: ScanResult) {
        self.merge_findings(&other);
    }

    pub fn merge_findings(&mut self, other: &ScanResult) {
        self.evidence.extend(other.evidence.iter().cloned());
    }

    pub fn finalize(&mut self) {
        self.canonicalize_routes();
        self.drop_demoted();
        self.compact();
    }

    pub fn record_api(&mut self, url: String, shape: Shape, extractor: Extractor) {
        self.evidence.push(Evidence {
            url,
            kind: EvidenceKind::Api,
            extractor,
            confidence: extractor.confidence(),
            shape: Some(shape),
        });
    }

    pub fn record_route(&mut self, url: String, extractor: Extractor) {
        self.evidence.push(Evidence {
            url,
            kind: EvidenceKind::Route,
            extractor,
            confidence: extractor.confidence(),
            shape: None,
        });
    }

    pub fn record_candidate(&mut self, url: String, extractor: Extractor) {
        self.evidence.push(Evidence {
            url,
            kind: EvidenceKind::Candidate,
            extractor,
            confidence: extractor.confidence(),
            shape: None,
        });
    }

    pub fn api_map(&self) -> ApiMap {
        let mut out = ApiMap::default();
        for evidence in &self.evidence {
            if evidence.kind == EvidenceKind::Api {
                if let Some(shape) = &evidence.shape {
                    out.entry(evidence.url.clone()).or_default().merge(shape);
                }
            }
        }
        out
    }

    pub fn route_map(&self) -> RouteMap {
        self.evidence
            .iter()
            .filter(|e| e.kind == EvidenceKind::Route)
            .map(|e| (e.url.clone(), ()))
            .collect()
    }

    pub fn candidate_map(&self) -> CandidateMap {
        self.evidence
            .iter()
            .filter(|e| e.kind == EvidenceKind::Candidate)
            .map(|e| (e.url.clone(), ()))
            .collect()
    }

    fn canonicalize_routes(&mut self) {
        for evidence in &mut self.evidence {
            if evidence.kind == EvidenceKind::Route {
                evidence.url = canonicalize_route(&evidence.url);
            }
        }
    }

    fn drop_demoted(&mut self) {
        let apis = self.api_map();
        let candidates = self.candidate_map();
        self.evidence.retain(|e| match e.kind {
            EvidenceKind::Api => true,
            EvidenceKind::Candidate => !apis.contains_key(&e.url),
            EvidenceKind::Route => !apis.contains_key(&e.url) && !candidates.contains_key(&e.url),
        });
    }

    fn compact(&mut self) {
        let mut compacted: Vec<Evidence> = Vec::with_capacity(self.evidence.len());
        for evidence in self.evidence.drain(..) {
            if let Some(existing) = compacted.iter_mut().find(|existing| {
                existing.url == evidence.url
                    && existing.kind == evidence.kind
                    && existing.extractor == evidence.extractor
            }) {
                if let (Some(dst), Some(src)) = (&mut existing.shape, &evidence.shape) {
                    dst.merge(src);
                }
            } else {
                compacted.push(evidence);
            }
        }
        self.evidence = compacted;
    }
}

fn canonicalize_route(s: &str) -> String {
    // Strip fragment and query; for navigation routes the path is canonical.
    let path = s.split(['?', '#']).next().unwrap_or(s);
    // Strip trailing slash but preserve root.
    let trimmed = path.trim_end_matches('/');
    if trimmed.is_empty() {
        "/".to_owned()
    } else {
        trimmed.to_owned()
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
    scan_api_clients(bytes, &mut out);
    out.compact();
    out
}

pub(crate) fn has_document_pattern(bytes: &[u8]) -> bool {
    DOCUMENT_AC.is_match(bytes)
}

fn record_api_call(bytes: &[u8], start: usize, after: usize, anchor: &str, out: &mut ScanResult) {
    let Some((url, mut shape)) = shape::scan_call(bytes, start, after, anchor) else {
        return;
    };
    if !classify::is_url_like(&url) {
        return;
    }

    shape.ensure_default_method();
    shape.apply_query_params(&url);
    let url = classify::normalize_api_url(&url);
    out.record_api(url, shape, Extractor::ApiCall);
}

fn record_route_call(bytes: &[u8], after: usize, out: &mut ScanResult) {
    if let Some(url) = extract::url_arg(bytes, after).filter(|url| classify::is_client_route(url)) {
        out.record_route(url, Extractor::RouteCall);
    }
}

fn record_route_value(bytes: &[u8], start: usize, after: usize, out: &mut ScanResult) {
    if !source::is_identifier_boundary_before(bytes, start) {
        return;
    }
    if let Some(url) =
        extract::value_after_anchor(bytes, after).filter(|url| classify::is_client_route(url))
    {
        out.record_route(url, Extractor::Literal);
    }
}

fn record_route_start(bytes: &[u8], after: usize, out: &mut ScanResult) {
    let slash = after.saturating_sub(1);
    if !push_candidate(bytes, slash, out) {
        if let Some(url) =
            extract::token_at(bytes, slash).filter(|url| classify::is_client_route(url))
        {
            out.record_route(url, Extractor::Literal);
        }
    }
}

fn push_candidate(bytes: &[u8], pos: usize, out: &mut ScanResult) -> bool {
    let Some(url) = extract::token_before(bytes, pos) else {
        return false;
    };
    if !classify::is_api_candidate(&url) {
        return false;
    }

    let url = classify::normalize_api_url(&url);
    out.record_candidate(url, Extractor::Literal);
    true
}

fn scan_api_clients(bytes: &[u8], out: &mut ScanResult) {
    let bindings = collect_string_bindings(bytes);
    for anchor in [
        b"$fetch(".as_slice(),
        b"useFetch(".as_slice(),
        b"useLazyFetch(".as_slice(),
        b"ofetch(".as_slice(),
        b"useRequestFetch()(".as_slice(),
        b"useNuxtApp().$fetch(".as_slice(),
        b"nuxtApp.$fetch(".as_slice(),
        b"ky(".as_slice(),
    ] {
        for pos in memchr::memmem::find_iter(bytes, anchor) {
            record_first_arg_client(bytes, pos + anchor.len(), &bindings, out);
        }
    }
    for anchor in [b"axios(".as_slice(), b"axios.request(".as_slice()] {
        for pos in memchr::memmem::find_iter(bytes, anchor) {
            record_object_client(bytes, pos + anchor.len(), &bindings, out);
        }
    }
    for (anchor, method) in [
        (b"$api.$get(".as_slice(), "GET"),
        (b"$api.get(".as_slice(), "GET"),
        (b"$api.$post(".as_slice(), "POST"),
        (b"$api.post(".as_slice(), "POST"),
        (b"$api.$put(".as_slice(), "PUT"),
        (b"$api.put(".as_slice(), "PUT"),
        (b"$api.$patch(".as_slice(), "PATCH"),
        (b"$api.patch(".as_slice(), "PATCH"),
        (b"$api.$delete(".as_slice(), "DELETE"),
        (b"$api.delete(".as_slice(), "DELETE"),
        (b"$axios.$get(".as_slice(), "GET"),
        (b"$axios.$post(".as_slice(), "POST"),
        (b"$axios.$put(".as_slice(), "PUT"),
        (b"$axios.$patch(".as_slice(), "PATCH"),
        (b"$axios.$delete(".as_slice(), "DELETE"),
    ] {
        for pos in memchr::memmem::find_iter(bytes, anchor) {
            record_first_arg_client_with_method(
                bytes,
                pos + anchor.len(),
                Some(method),
                &bindings,
                out,
            );
        }
    }
    scan_generic_method_clients(bytes, &bindings, out);
}

fn record_first_arg_client(
    bytes: &[u8],
    after: usize,
    bindings: &FxHashMap<String, String>,
    out: &mut ScanResult,
) {
    record_first_arg_client_with_method(bytes, after, method_near(bytes, after), bindings, out);
}

fn record_first_arg_client_with_method(
    bytes: &[u8],
    after: usize,
    method: Option<&str>,
    bindings: &FxHashMap<String, String>,
    out: &mut ScanResult,
) {
    let Some(url) = first_arg_url(bytes, after, bindings) else {
        return;
    };
    if !classify::is_url_like(&url) {
        return;
    }
    let mut shape = shape::Shape::inferred(method, false);
    shape.apply_query_params(&url);
    out.record_api(
        classify::normalize_api_url(&url),
        shape,
        Extractor::ApiClient,
    );
}

fn record_object_client(
    bytes: &[u8],
    after: usize,
    bindings: &FxHashMap<String, String>,
    out: &mut ScanResult,
) {
    let i = source::skip_ws(bytes, after);
    if bytes.get(i) != Some(&b'{') {
        return;
    }
    let end = object_end(bytes, i).unwrap_or_else(|| bytes.len().min(i + 1024));
    let obj = &bytes[i..end];
    let Some(url) = object_url_value(obj, &[b"url", b"URL", b"endpoint", b"path"], bindings) else {
        return;
    };
    if !classify::is_url_like(&url) {
        return;
    }
    let method = object_string_value(obj, &[b"method"])
        .or_else(|| method_near(bytes, i).map(str::to_string));
    let mut shape = shape::Shape::inferred(
        method.as_deref(),
        contains_key(obj, b"data") || contains_key(obj, b"body"),
    );
    shape.apply_query_params(&url);
    out.record_api(
        classify::normalize_api_url(&url),
        shape,
        Extractor::ApiClient,
    );
}

fn scan_generic_method_clients(
    bytes: &[u8],
    bindings: &FxHashMap<String, String>,
    out: &mut ScanResult,
) {
    for (anchor, method) in [
        (b".get(".as_slice(), "GET"),
        (b".post(".as_slice(), "POST"),
        (b".put(".as_slice(), "PUT"),
        (b".patch(".as_slice(), "PATCH"),
        (b".delete(".as_slice(), "DELETE"),
    ] {
        for pos in memchr::memmem::find_iter(bytes, anchor) {
            if !apiish_receiver_context(bytes, pos) {
                continue;
            }
            record_first_arg_client_with_method(
                bytes,
                pos + anchor.len(),
                Some(method),
                bindings,
                out,
            );
        }
    }
}

fn collect_string_bindings(bytes: &[u8]) -> FxHashMap<String, String> {
    let mut out = FxHashMap::default();
    for keyword in [b"const ".as_slice(), b"let ".as_slice(), b"var ".as_slice()] {
        for pos in memchr::memmem::find_iter(bytes, keyword) {
            collect_decl_bindings(bytes, pos + keyword.len(), &mut out);
        }
    }
    out
}

fn collect_decl_bindings(bytes: &[u8], mut i: usize, out: &mut FxHashMap<String, String>) {
    let end = bytes.len().min(i + 2048);
    while i < end {
        i = source::skip_ws(bytes, i);
        let Some(name) = source::identifier_at(bytes, i) else {
            return;
        };
        let name_end = i + name.len();
        i = source::skip_ws(bytes, name_end);
        if bytes.get(i) != Some(&b'=') {
            return;
        }
        i = source::skip_ws(bytes, i + 1);
        if let Some((value, value_end)) = static_string_expr(bytes, i, out) {
            if useful_binding(&value) {
                out.insert(String::from_utf8_lossy(name).to_string(), value);
            }
            i = source::skip_ws(bytes, value_end);
        } else {
            return;
        }
        match bytes.get(i) {
            Some(b',') => i += 1,
            _ => return,
        }
    }
}

fn first_arg_url(
    bytes: &[u8],
    start: usize,
    bindings: &FxHashMap<String, String>,
) -> Option<String> {
    if let Some(url) = extract::url_arg(bytes, start) {
        return Some(url);
    }
    let i = source::skip_ws(bytes, start);
    static_string_expr(bytes, i, bindings).map(|(value, _)| value)
}

fn object_url_value(
    bytes: &[u8],
    keys: &[&[u8]],
    bindings: &FxHashMap<String, String>,
) -> Option<String> {
    object_string_value(bytes, keys).or_else(|| object_static_value(bytes, keys, bindings))
}

fn object_static_value(
    bytes: &[u8],
    keys: &[&[u8]],
    bindings: &FxHashMap<String, String>,
) -> Option<String> {
    for key in keys {
        let mut offset = 0;
        while let Some(rel) = memchr::memmem::find(&bytes[offset..], key) {
            let pos = offset + rel;
            if !source::is_identifier_boundary_before(bytes, pos) {
                offset = pos + 1;
                continue;
            }
            let mut i = source::skip_ws(bytes, pos + key.len());
            if bytes.get(i) != Some(&b':') {
                offset = pos + 1;
                continue;
            }
            i = source::skip_ws(bytes, i + 1);
            if let Some((value, _)) = static_string_expr(bytes, i, bindings) {
                return Some(value);
            }
            offset = pos + 1;
        }
    }
    None
}

fn static_string_expr(
    bytes: &[u8],
    start: usize,
    bindings: &FxHashMap<String, String>,
) -> Option<(String, usize)> {
    let mut i = source::skip_ws(bytes, start);
    let mut out = String::new();
    let mut saw_part = false;
    while i < bytes.len() {
        i = source::skip_ws(bytes, i);
        match bytes.get(i).copied()? {
            quote @ (b'"' | b'\'' | b'`') => {
                let part = if quote == b'`' {
                    template_with_bindings(bytes, i + 1, bindings)?
                } else {
                    source::quoted_string(bytes, i + 1, quote, source::TemplateMode::Preserve)?
                };
                out.push_str(&part);
                i = source::quoted_end(bytes, i + 1, quote)? + 1;
                saw_part = true;
            }
            b if source::is_identifier_continue(b) => {
                let ident = source::identifier_at(bytes, i)?;
                let name = std::str::from_utf8(ident).ok()?;
                let value = bindings.get(name)?;
                out.push_str(value);
                i += ident.len();
                saw_part = true;
            }
            _ => break,
        }
        i = source::skip_ws(bytes, i);
        if bytes.get(i) != Some(&b'+') {
            break;
        }
        i += 1;
    }
    if saw_part && !out.starts_with("{dynamic}") {
        Some((out, i))
    } else {
        None
    }
}

fn template_with_bindings(
    bytes: &[u8],
    start: usize,
    bindings: &FxHashMap<String, String>,
) -> Option<String> {
    let mut out = String::new();
    let mut i = start;
    while i < bytes.len() {
        if bytes[i] == b'\\' && i + 1 < bytes.len() {
            out.push(bytes[i + 1] as char);
            i += 2;
        } else if bytes.get(i..i + 2) == Some(b"${") {
            let expr = i + 2;
            let end = source::skip_template_expr(bytes, expr);
            let inner_end = end.saturating_sub(1);
            let ident_start = source::skip_ws(bytes, expr);
            let ident = source::identifier_at(bytes, ident_start)
                .and_then(|name| {
                    let name_end = ident_start + name.len();
                    (source::skip_ws(bytes, name_end) == inner_end).then_some(name)
                })
                .and_then(|name| std::str::from_utf8(name).ok());
            if let Some(value) = ident.and_then(|name| bindings.get(name)) {
                out.push_str(value);
            } else {
                out.push_str("{dynamic}");
            }
            i = end;
        } else if bytes[i] == b'`' {
            return Some(out);
        } else {
            out.push(bytes[i] as char);
            i += 1;
        }
    }
    Some(out)
}

fn useful_binding(value: &str) -> bool {
    classify::is_url_like(value)
        || value == "/api"
        || value.starts_with("/api/")
        || value.starts_with("/graphql")
        || value.starts_with("/trpc")
        || value.contains("/api/")
}

fn apiish_receiver_context(bytes: &[u8], dot: usize) -> bool {
    let start = dot.saturating_sub(64);
    let context = &bytes[start..dot];
    [
        b"api".as_slice(),
        b"Api".as_slice(),
        b"API".as_slice(),
        b"axios".as_slice(),
        b"http".as_slice(),
        b"client".as_slice(),
        b"Client".as_slice(),
        b"service".as_slice(),
        b"Service".as_slice(),
        b"repo".as_slice(),
        b"Repo".as_slice(),
        b"request".as_slice(),
        b"Request".as_slice(),
    ]
    .iter()
    .any(|needle| memchr::memmem::find(context, needle).is_some())
}

fn object_string_value(bytes: &[u8], keys: &[&[u8]]) -> Option<String> {
    for key in keys {
        let mut offset = 0;
        while let Some(rel) = memchr::memmem::find(&bytes[offset..], key) {
            let pos = offset + rel;
            if !source::is_identifier_boundary_before(bytes, pos) {
                offset = pos + 1;
                continue;
            }
            let mut i = source::skip_ws(bytes, pos + key.len());
            if bytes.get(i) != Some(&b':') {
                offset = pos + 1;
                continue;
            }
            i = source::skip_ws(bytes, i + 1);
            if matches!(bytes.get(i), Some(b'"' | b'\'' | b'`')) {
                return extract::url_arg(bytes, i);
            }
            offset = pos + 1;
        }
    }
    None
}

fn method_near(bytes: &[u8], start: usize) -> Option<&'static str> {
    let end = memchr::memchr(b';', &bytes[start..])
        .map(|rel| start + rel)
        .unwrap_or_else(|| bytes.len().min(start + 256));
    ["DELETE", "PATCH", "POST", "PUT", "GET", "HEAD", "OPTIONS"]
        .into_iter()
        .find(|method| {
            source::find_ascii_ignore_case(&bytes[start..end], method.as_bytes()).is_some()
        })
}

fn contains_key(bytes: &[u8], key: &[u8]) -> bool {
    let mut offset = 0;
    while let Some(rel) = memchr::memmem::find(&bytes[offset..], key) {
        let pos = offset + rel;
        if source::is_identifier_boundary_before(bytes, pos) {
            return true;
        }
        offset = pos + 1;
    }
    false
}

fn object_end(bytes: &[u8], open: usize) -> Option<usize> {
    let mut depth = 0usize;
    let mut i = open;
    while i < bytes.len() {
        match bytes[i] {
            b'"' | b'\'' | b'`' => {
                i = source::quoted_end(bytes, i + 1, bytes[i])? + 1;
                continue;
            }
            b'{' | b'[' | b'(' => depth += 1,
            b'}' | b']' | b')' => {
                depth = depth.checked_sub(1)?;
                if depth == 0 {
                    return Some(i + 1);
                }
            }
            _ => {}
        }
        i += 1;
    }
    None
}
