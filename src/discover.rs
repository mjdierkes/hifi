//! Static asset discovery.
//!
//! Discovery finds additional documents worth scanning: HTML script tags,
//! preloads, framework manifests, payload JSON, dynamic imports, and bundled
//! chunk literals. It does not fetch anything; it only produces `AssetRef`s for
//! the runtime to schedule and deduplicate.

use crate::scan::{ScanResult, Shape};
use crate::source::{self, TemplateMode};
use aho_corasick::{AhoCorasick, MatchKind};
use rustc_hash::FxHashSet;
use serde::{Deserialize, Serialize};
use std::sync::LazyLock;
use url::Url;

const ASSET_LITERALS: &[&str] = &[
    "/_next/static/",
    "/_nuxt/",
    "/assets/",
    "assets/",
    "/static/js/",
    "static/js/",
    "/static/chunks/",
    "static/chunks/",
    "/_next/data/",
    "?_rsc=",
    "&_rsc=",
    ".rsc",
];
const NEXT_SKIP_FRAGMENTS: &[&str] = &[
    "framework-",
    "polyfills-",
    "webpack-",
    "main-app-",
    "_next/static/chunks/_turbopack_",
    "[turbopack]_runtime",
    "[next]_internal_",
    "react-refresh",
    "next/dist/",
];
const FRAMEWORK_DATA_MARKERS: &[&[u8]] = &[b"/_next/data/", b"/_payload.json", b"/__data.json"];
const NEXT_MANIFESTS: &[&str] = &["_buildManifest.js", "_ssgManifest.js"];
const NEXT_ACTION_MARKERS: &[&[u8]] = &[b"Next-Action", b"next-action", b"$ACTION_"];
const NEXT_FLIGHT_MARKER: &[u8] = b"self.__next_f.push";
const FLIGHT_SCAN_WINDOW: usize = 64 * 1024;

static ASSET_AC: LazyLock<AhoCorasick> = LazyLock::new(|| {
    AhoCorasick::builder()
        .match_kind(MatchKind::LeftmostLongest)
        .build(ASSET_LITERALS)
        .expect("valid asset literals")
});

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum DocumentKind {
    Html,
    Script,
    Manifest,
    Payload,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum AssetKind {
    Script,
    Manifest,
    Payload,
}

impl AssetKind {
    fn document_kind(self) -> DocumentKind {
        match self {
            Self::Script => DocumentKind::Script,
            Self::Manifest => DocumentKind::Manifest,
            Self::Payload => DocumentKind::Payload,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum AssetSource {
    HtmlScript,
    HtmlPreload,
    Literal,
    DynamicImport,
    NewUrl,
    NextManifest,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AssetRef {
    pub url: Url,
    pub kind: AssetKind,
    pub source: AssetSource,
}

impl AssetRef {
    pub fn document_kind(&self) -> DocumentKind {
        self.kind.document_kind()
    }
}

#[derive(Clone, Default, Serialize, Deserialize)]
pub struct DocumentScan {
    pub findings: ScanResult,
    pub assets: Vec<AssetRef>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub revision: Option<String>,
}

pub fn scan_document(bytes: &[u8], base: &Url, kind: DocumentKind) -> DocumentScan {
    let next_context = is_next_context(bytes, base);
    let mut out = DocumentScan {
        findings: crate::scan::scan_endpoints(bytes),
        assets: Vec::new(),
        revision: next_revision(bytes, next_context),
    };
    let mut seen = FxHashSet::default();

    push_framework_candidates(bytes, &mut out.findings);
    scan_next_flight(bytes, &mut out.findings);
    scan_next_server_action(bytes, base, kind, &mut out.findings);
    if kind == DocumentKind::Html {
        scan_html_assets(bytes, base, next_context, &mut seen, &mut out.assets);
    }
    scan_literal_assets(
        bytes,
        base,
        next_context,
        &mut out.findings,
        &mut seen,
        &mut out.assets,
    );
    scan_dynamic_assets(bytes, base, next_context, &mut seen, &mut out.assets);

    if kind == DocumentKind::Html {
        if let Some(revision) = out.revision.as_deref() {
            push_next_manifests(
                bytes,
                base,
                revision,
                next_context,
                &mut seen,
                &mut out.assets,
            );
        }
    }

    out
}

// HTML documents are the only place where tag structure is meaningful. Scripts,
// manifests, and payloads rely on literal and dynamic-reference discovery.
fn scan_html_assets(
    bytes: &[u8],
    base: &Url,
    next_context: bool,
    seen: &mut FxHashSet<Url>,
    out: &mut Vec<AssetRef>,
) {
    scan_tags(bytes, b"<script", |tag| {
        let Some(src) = attr_value(tag, b"src") else {
            return;
        };
        push_asset(base, src, next_context, AssetSource::HtmlScript, seen, out);
    });

    scan_tags(bytes, b"<link", |tag| {
        let Some(href) = attr_value(tag, b"href") else {
            return;
        };
        let rel = attr_value(tag, b"rel").unwrap_or_default();
        if rel.split_ascii_whitespace().any(|v| {
            matches_ignore_ascii_case(v, "preload")
                || matches_ignore_ascii_case(v, "modulepreload")
                || matches_ignore_ascii_case(v, "prefetch")
        }) {
            push_asset(
                base,
                href,
                next_context,
                AssetSource::HtmlPreload,
                seen,
                out,
            );
        }
    });
}

fn scan_tags(bytes: &[u8], needle: &[u8], mut f: impl FnMut(&[u8])) {
    let lower = bytes.to_ascii_lowercase();
    for start in memchr::memmem::find_iter(&lower, needle) {
        let Some(end_rel) = memchr::memchr(b'>', &bytes[start..]) else {
            break;
        };
        f(&bytes[start..start + end_rel + 1]);
    }
}

fn scan_literal_assets(
    bytes: &[u8],
    base: &Url,
    next_context: bool,
    findings: &mut ScanResult,
    seen: &mut FxHashSet<Url>,
    out: &mut Vec<AssetRef>,
) {
    for m in ASSET_AC.find_iter(bytes) {
        let start = source::walk_token_start(bytes, m.start());
        let Some(raw) = asset_token_string(bytes, start) else {
            continue;
        };
        if raw.starts_with("/_next/data/") {
            push_candidate(findings, &raw);
        }
        push_asset(base, &raw, next_context, AssetSource::Literal, seen, out);
    }
}

fn scan_dynamic_assets(
    bytes: &[u8],
    base: &Url,
    next_context: bool,
    seen: &mut FxHashSet<Url>,
    out: &mut Vec<AssetRef>,
) {
    for pos in memchr::memmem::find_iter(bytes, b"import(") {
        if let Some(raw) = source::quoted_arg(bytes, pos + b"import(".len()) {
            push_asset(
                base,
                raw,
                next_context,
                AssetSource::DynamicImport,
                seen,
                out,
            );
        }
    }
    for pos in memchr::memmem::find_iter(bytes, b"new URL(") {
        if let Some(raw) = source::quoted_arg(bytes, pos + b"new URL(".len()) {
            push_asset(base, raw, next_context, AssetSource::NewUrl, seen, out);
        }
    }
}

fn push_framework_candidates(bytes: &[u8], findings: &mut ScanResult) {
    for marker in FRAMEWORK_DATA_MARKERS {
        for pos in memchr::memmem::find_iter(bytes, marker) {
            let start = source::walk_token_start(bytes, pos);
            if let Some(raw) = asset_token_string(bytes, start) {
                push_candidate(findings, &raw);
            }
        }
    }
}

fn push_candidate(findings: &mut ScanResult, raw: &str) {
    let path = raw.split(['?', '#']).next().unwrap_or(raw);
    if is_framework_data(raw, path) && raw.len() <= 512 {
        findings.candidates.entry(raw.to_owned()).or_default();
    }
}

fn push_next_manifests(
    bytes: &[u8],
    base: &Url,
    revision: &str,
    next_context: bool,
    seen: &mut FxHashSet<Url>,
    out: &mut Vec<AssetRef>,
) {
    let root = next_static_mount(bytes, base, next_context)
        .and_then(|url| url.join(&format!("{revision}/")).ok())
        .or_else(|| base.join(&format!("/_next/static/{revision}/")).ok());
    let Some(root) = root else {
        return;
    };
    for name in NEXT_MANIFESTS {
        let Ok(url) = root.join(name) else {
            continue;
        };
        push_resolved_asset(
            url,
            AssetKind::Manifest,
            AssetSource::NextManifest,
            seen,
            out,
        );
    }
}

fn push_asset(
    base: &Url,
    raw: &str,
    next_context: bool,
    source: AssetSource,
    seen: &mut FxHashSet<Url>,
    out: &mut Vec<AssetRef>,
) {
    let Some(kind) = classify_asset(raw) else {
        return;
    };
    let Some(url) = resolve_asset(base, raw, next_context) else {
        return;
    };
    if should_skip(&url) {
        return;
    }
    push_resolved_asset(url, kind, source, seen, out);
}

fn push_resolved_asset(
    url: Url,
    kind: AssetKind,
    source: AssetSource,
    seen: &mut FxHashSet<Url>,
    out: &mut Vec<AssetRef>,
) {
    if seen.insert(url.clone()) {
        out.push(AssetRef { url, kind, source });
    }
}

fn classify_asset(raw: &str) -> Option<AssetKind> {
    let path = raw
        .split(['?', '#'])
        .next()
        .unwrap_or(raw)
        .to_ascii_lowercase();
    if is_next_manifest(&path) {
        Some(AssetKind::Manifest)
    } else if is_script_asset(&path) {
        Some(AssetKind::Script)
    } else if is_framework_payload(raw, &path) {
        Some(AssetKind::Payload)
    } else {
        None
    }
}

fn is_next_manifest(path: &str) -> bool {
    path.ends_with("_buildmanifest.js") || path.ends_with("_ssgmanifest.js")
}

fn is_script_asset(path: &str) -> bool {
    path.ends_with(".js") || path.ends_with(".mjs")
}

fn is_framework_data(raw: &str, path: &str) -> bool {
    raw.starts_with("/_next/data/")
        || path.contains("/_next/data/")
        || path.ends_with("/_payload.json")
        || path.ends_with("/__data.json")
}

fn is_framework_payload(raw: &str, path: &str) -> bool {
    (path.ends_with(".json") && is_framework_data(raw, path))
        || path.ends_with(".rsc")
        || raw.contains("?_rsc=")
        || raw.contains("&_rsc=")
}

// Bundlers often emit relative chunk names that are only meaningful in a
// framework context. The Next.js branch rewrites `static/...` to `/_next/...`
// only when the page or asset already proves that context.
fn resolve_asset(base: &Url, raw: &str, next_context: bool) -> Option<Url> {
    let raw = raw.trim_matches('\\');
    if raw.is_empty() || raw.starts_with("data:") || raw.starts_with("blob:") {
        return None;
    }
    if raw.starts_with("http://")
        || raw.starts_with("https://")
        || raw.starts_with('/')
        || raw.starts_with("./")
        || raw.starts_with("../")
    {
        return base.join(raw).ok();
    }

    let absolute = if raw.starts_with("static/") && next_context {
        Some(format!("/_next/{raw}"))
    } else if (raw.starts_with("assets/") && base.path().contains("/assets/"))
        || (raw.starts_with("static/") && base.path().contains("/static/"))
    {
        Some(format!("/{raw}"))
    } else {
        None
    };
    match absolute {
        Some(path) => base.join(&path).ok(),
        None => base.join(raw).ok(),
    }
}

fn is_next_context(bytes: &[u8], base: &Url) -> bool {
    base.path().contains("/_next/")
        || memchr::memmem::find(bytes, b"/_next/").is_some()
        || memchr::memmem::find(bytes, b"__NEXT_DATA__").is_some()
        || memchr::memmem::find(bytes, NEXT_FLIGHT_MARKER).is_some()
}

// Skip common framework runtime chunks. They are large, noisy, and usually do
// not contain application API calls; scanning them makes output less focused.
fn should_skip(url: &Url) -> bool {
    let path = url.path();
    path.contains("/_next/")
        && NEXT_SKIP_FRAGMENTS
            .iter()
            .any(|fragment| path.contains(fragment))
}

// Prefer explicit Next.js build IDs when present. Falling back to the
// `/_next/static/<revision>/...` path keeps manifest discovery working for
// pages that do not include inline `__NEXT_DATA__`.
fn next_revision(bytes: &[u8], next_context: bool) -> Option<String> {
    if next_context {
        let needle = br#""buildId":""#;
        if let Some(i) = memchr::memmem::find(bytes, needle) {
            let rest = &bytes[i + needle.len()..];
            if let Some(end) = memchr::memchr(b'"', rest) {
                return std::str::from_utf8(&rest[..end]).ok().map(str::to_string);
            }
        }
    }
    let marker = b"/_next/static/";
    let rest = &bytes[memchr::memmem::find(bytes, marker)? + marker.len()..];
    let candidate = &rest[..memchr::memchr(b'/', rest)?];
    (!matches!(candidate, b"chunks" | b"css" | b"media" | b"development"))
        .then(|| std::str::from_utf8(candidate).ok().map(str::to_string))?
}

fn next_static_mount(bytes: &[u8], base: &Url, next_context: bool) -> Option<Url> {
    let marker = b"/_next/static/";
    for pos in memchr::memmem::find_iter(bytes, marker) {
        let start = source::walk_token_start(bytes, pos);
        let Some(raw) = asset_token_string(bytes, start) else {
            continue;
        };
        let Some(url) = resolve_asset(base, &raw, next_context) else {
            continue;
        };
        let Some(path_pos) = url.path().find("/_next/static/") else {
            continue;
        };
        let mut root = url.clone();
        root.set_path(&url.path()[..path_pos + marker.len()]);
        root.set_query(None);
        root.set_fragment(None);
        return Some(root);
    }
    None
}

fn asset_token_string(bytes: &[u8], start: usize) -> Option<String> {
    let raw = source::token_string(bytes, start, TemplateMode::Preserve)?;
    if !raw.contains('?') && !raw.contains('&') {
        return Some(raw);
    }

    let mut end = start;
    while end < bytes.len() && !is_asset_token_delim(bytes[end]) {
        end += 1;
    }
    std::str::from_utf8(&bytes[start..end])
        .ok()
        .map(|s| s.trim_matches('\\').to_string())
}

fn is_asset_token_delim(b: u8) -> bool {
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

fn scan_next_flight(bytes: &[u8], findings: &mut ScanResult) {
    for pos in memchr::memmem::find_iter(bytes, NEXT_FLIGHT_MARKER) {
        let rest = &bytes[pos..];
        let script_end = memchr::memmem::find(rest, b"</script>").unwrap_or(FLIGHT_SCAN_WINDOW);
        let window = &rest[..script_end.min(FLIGHT_SCAN_WINDOW).min(rest.len())];
        let mut i = 0;
        while i < window.len() {
            let quote = window[i];
            if !matches!(quote, b'"' | b'\'' | b'`') {
                i += 1;
                continue;
            }
            let Some(end) = source::quoted_end(window, i + 1, quote) else {
                break;
            };
            if let Some(decoded) =
                source::quoted_string(window, i + 1, quote, TemplateMode::ReplaceExpressions)
            {
                findings.merge(crate::scan::scan_endpoints(decoded.as_bytes()));
            }
            i = end + 1;
        }
    }
}

fn scan_next_server_action(
    bytes: &[u8],
    base: &Url,
    kind: DocumentKind,
    findings: &mut ScanResult,
) {
    if !matches!(kind, DocumentKind::Html | DocumentKind::Payload)
        || !NEXT_ACTION_MARKERS
            .iter()
            .any(|marker| source::contains(bytes, marker))
    {
        return;
    }
    let Some(route) = next_route_from_payload(base) else {
        return;
    };
    findings
        .apis
        .entry(route)
        .or_default()
        .merge(&Shape::next_server_action());
}

fn next_route_from_payload(base: &Url) -> Option<String> {
    let mut path = base.path().to_owned();
    if let Some(pos) = path.find("/_next/data/") {
        let prefix = &path[..pos];
        let route = path[pos + "/_next/data/".len()..]
            .split_once('/')
            .map(|(_, route)| route)?;
        path = format!("{prefix}/{}", route.trim_end_matches(".json"));
    } else if let Some(pos) = path.find(".segments/") {
        path.truncate(pos);
    } else if let Some(stripped) = path.strip_suffix(".rsc") {
        path = stripped.to_owned();
    } else if path.starts_with("/_next/") {
        return None;
    }
    if path.is_empty() {
        path.push('/');
    }
    Some(path)
}

fn attr_value<'a>(tag: &'a [u8], name: &[u8]) -> Option<&'a str> {
    let lower = tag.to_ascii_lowercase();
    let mut offset = 0;
    while let Some(rel) = memchr::memmem::find(&lower[offset..], name) {
        let pos = offset + rel;
        let before_ok = pos == 0 || is_attr_delim(tag[pos - 1]);
        let mut i = pos + name.len();
        while tag.get(i).is_some_and(|b| b.is_ascii_whitespace()) {
            i += 1;
        }
        if before_ok && tag.get(i) == Some(&b'=') {
            i += 1;
            while tag.get(i).is_some_and(|b| b.is_ascii_whitespace()) {
                i += 1;
            }
            let quote = *tag.get(i)?;
            if matches!(quote, b'"' | b'\'') {
                i += 1;
                let end = tag[i..].iter().position(|b| *b == quote)? + i;
                return std::str::from_utf8(&tag[i..end]).ok();
            }
            let end = tag[i..]
                .iter()
                .position(|b| b.is_ascii_whitespace() || *b == b'>')
                .map(|rel| i + rel)
                .unwrap_or(tag.len());
            return std::str::from_utf8(&tag[i..end]).ok();
        }
        offset = pos + 1;
    }
    None
}

fn is_attr_delim(b: u8) -> bool {
    b.is_ascii_whitespace() || matches!(b, b'<' | b'/' | b'"' | b'\'')
}

fn matches_ignore_ascii_case(a: &str, b: &str) -> bool {
    a.len() == b.len() && a.as_bytes().eq_ignore_ascii_case(b.as_bytes())
}
