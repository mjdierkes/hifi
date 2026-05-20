use crate::scan::ScanResult;
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
    let mut out = DocumentScan {
        findings: crate::scan::scan_endpoints(bytes),
        assets: Vec::new(),
        revision: next_revision(bytes),
    };
    let mut seen = FxHashSet::default();
    let next_context = is_next_context(bytes, base);

    push_framework_candidates(bytes, &mut out.findings);
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
            push_next_manifests(base, revision, &mut seen, &mut out.assets);
        }
    }

    out
}

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
        let start = walk_token_start(bytes, m.start());
        let Some(raw) = token_string(bytes, start) else {
            continue;
        };
        if raw.starts_with("/_next/data/") {
            push_candidate(findings, &raw);
            continue;
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
        if let Some(raw) = quoted_arg(bytes, pos + b"import(".len()) {
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
        if let Some(raw) = quoted_arg(bytes, pos + b"new URL(".len()) {
            push_asset(base, raw, next_context, AssetSource::NewUrl, seen, out);
        }
    }
}

fn push_framework_candidates(bytes: &[u8], findings: &mut ScanResult) {
    for marker in [b"/_next/data/" as &[u8], b"/_payload.json", b"/__data.json"] {
        for pos in memchr::memmem::find_iter(bytes, marker) {
            let start = walk_token_start(bytes, pos);
            if let Some(raw) = token_string(bytes, start) {
                push_candidate(findings, &raw);
            }
        }
    }
}

fn push_candidate(findings: &mut ScanResult, raw: &str) {
    let path = raw.split(['?', '#']).next().unwrap_or(raw);
    let is_framework_data = raw.starts_with("/_next/data/")
        || path.ends_with("/_payload.json")
        || path.ends_with("/__data.json");
    if is_framework_data && raw.len() <= 512 {
        findings.candidates.entry(raw.to_owned()).or_default();
    }
}

fn push_next_manifests(
    base: &Url,
    revision: &str,
    seen: &mut FxHashSet<Url>,
    out: &mut Vec<AssetRef>,
) {
    for name in ["_buildManifest.js", "_ssgManifest.js"] {
        let Ok(url) = base.join(&format!("/_next/static/{revision}/{name}")) else {
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
    if path.ends_with("_buildmanifest.js") || path.ends_with("_ssgmanifest.js") {
        Some(AssetKind::Manifest)
    } else if path.ends_with(".js") || path.ends_with(".mjs") {
        Some(AssetKind::Script)
    } else if path.ends_with(".json")
        && (path.contains("/_next/data/")
            || path.ends_with("/_payload.json")
            || path.ends_with("/__data.json"))
    {
        Some(AssetKind::Payload)
    } else {
        None
    }
}

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
}

fn should_skip(url: &Url) -> bool {
    let path = url.path();
    path.contains("/_next/")
        && NEXT_SKIP_FRAGMENTS
            .iter()
            .any(|fragment| path.contains(fragment))
}

fn next_revision(bytes: &[u8]) -> Option<String> {
    let needle = br#""buildId":""#;
    if let Some(i) = memchr::memmem::find(bytes, needle) {
        let rest = &bytes[i + needle.len()..];
        if let Some(end) = memchr::memchr(b'"', rest) {
            return std::str::from_utf8(&rest[..end]).ok().map(str::to_string);
        }
    }
    let marker = b"/_next/static/";
    let rest = &bytes[memchr::memmem::find(bytes, marker)? + marker.len()..];
    let candidate = &rest[..memchr::memchr(b'/', rest)?];
    (!matches!(candidate, b"chunks" | b"css" | b"media" | b"development"))
        .then(|| std::str::from_utf8(candidate).ok().map(str::to_string))?
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

fn quoted_arg(bytes: &[u8], start: usize) -> Option<&str> {
    let mut i = skip_ws(bytes, start);
    let quote = *bytes.get(i)?;
    if !matches!(quote, b'"' | b'\'' | b'`') {
        return None;
    }
    i += 1;
    let end = quoted_end(bytes, i, quote)?;
    std::str::from_utf8(&bytes[i..end]).ok()
}

fn quoted_end(bytes: &[u8], mut i: usize, quote: u8) -> Option<usize> {
    while i < bytes.len() {
        if bytes[i] == b'\\' && i + 1 < bytes.len() {
            i += 2;
        } else if bytes[i] == quote {
            return Some(i);
        } else {
            i += 1;
        }
    }
    None
}

fn token_string(bytes: &[u8], start: usize) -> Option<String> {
    let end = token_end(bytes, start);
    std::str::from_utf8(&bytes[start..end])
        .ok()
        .map(|s| s.trim_matches('\\').to_string())
}

fn token_end(bytes: &[u8], mut i: usize) -> usize {
    while i < bytes.len() {
        if is_token_delim(bytes[i]) {
            break;
        }
        i += 1;
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

fn skip_ws(bytes: &[u8], mut i: usize) -> usize {
    while bytes.get(i).is_some_and(|b| b.is_ascii_whitespace()) {
        i += 1;
    }
    i
}

fn matches_ignore_ascii_case(a: &str, b: &str) -> bool {
    a.len() == b.len() && a.as_bytes().eq_ignore_ascii_case(b.as_bytes())
}
