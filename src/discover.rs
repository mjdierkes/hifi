//! Static asset discovery.
//!
//! Discovery finds additional documents worth scanning: HTML script tags,
//! preloads, framework manifests, payload JSON, dynamic imports, and bundled
//! chunk literals. It does not fetch anything; it only produces `AssetRef`s for
//! the runtime to schedule and deduplicate.

use crate::framework;
use crate::framework::FrameworkConfig;
use crate::scan::next::NextConfig;
use crate::scan::{FindingSource, ScanResult};
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
const FRAMEWORK_DATA_MARKERS: &[&[u8]] = &[b"/_next/data/", b"/_payload.json", b"/__data.json"];

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
    #[serde(default, skip_serializing_if = "FrameworkConfig::is_none")]
    pub framework_config: FrameworkConfig,
}

pub fn scan_document(bytes: &[u8], base: &Url, kind: DocumentKind) -> DocumentScan {
    scan_document_with_config(bytes, base, kind, None)
}

/// Variant of [`scan_document`] that accepts a parent-scan-derived `NextConfig`.
/// Used when scanning sub-resources (RSC payloads, JSON manifests) that cannot
/// host their own `__NEXT_DATA__` block but still need the page's locale and
/// base path to reconstruct routes.
pub fn scan_document_with_config(
    bytes: &[u8],
    base: &Url,
    kind: DocumentKind,
    parent_config: Option<&NextConfig>,
) -> DocumentScan {
    let mut next_config = framework::next::parse_page_config(bytes, kind);
    if next_config.is_none() {
        next_config = parent_config.cloned();
    }
    let next_context = framework::next::is_context(bytes, base, next_config.as_ref());
    let revision = framework::next::revision(bytes, next_context, next_config.as_ref());
    let mut out = DocumentScan {
        findings: crate::scan::scan_endpoints(bytes),
        assets: Vec::new(),
        revision,
        framework_config: FrameworkConfig::from(next_config.clone()),
    };
    let mut seen = FxHashSet::default();

    if let Some(routes) = framework::next::parse_manifest_routes(bytes, base, kind) {
        for route in routes {
            // Some Next.js manifests (notably app-build-manifest in v15+) list
            // asset chunk paths alongside real route keys. Run them through
            // the same quality bar as scanner-inferred routes so the output
            // doesn't fill up with `/_next/static/chunks/*.js` entries.
            if !crate::scan::classify::is_client_route(&route) {
                continue;
            }
            out.findings.routes.entry(route.clone()).or_default();
            out.findings
                .bump_provenance(route, FindingSource::ManifestParsed);
        }
    }

    push_framework_candidates(bytes, &mut out.findings);
    framework::next::scan_flight(bytes, &mut out.findings);
    framework::next::scan_server_action(bytes, base, kind, next_config.as_ref(), &mut out.findings);
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
            framework::next::push_manifests(
                bytes,
                base,
                revision,
                next_config.as_ref(),
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
        // Reject tokens that aren't preceded by a string-literal delimiter.
        // Comment substrings, property accesses, and identifier prefixes look
        // identical to real URL literals after `walk_token_start` and produce
        // the bulk of the regular tier's false positives.
        if !is_string_literal_context(bytes, start) {
            continue;
        }
        let Some(raw) = asset_token_string(bytes, start) else {
            continue;
        };
        if raw.starts_with("/_next/data/") {
            push_candidate(findings, &raw);
        }
        push_asset(base, &raw, next_context, AssetSource::Literal, seen, out);
    }
}

fn is_string_literal_context(bytes: &[u8], start: usize) -> bool {
    start > 0 && matches!(bytes[start - 1], b'"' | b'\'' | b'`')
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
            if !is_string_literal_context(bytes, start) {
                continue;
            }
            if let Some(raw) = asset_token_string(bytes, start) {
                push_candidate(findings, &raw);
            }
        }
    }
}

fn push_candidate(findings: &mut ScanResult, raw: &str) {
    framework::next::push_framework_candidate(findings, raw);
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
    if framework::next::should_skip(&url) {
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
    if framework::next::is_manifest(&path) {
        Some(AssetKind::Manifest)
    } else if is_script_asset(&path) {
        Some(AssetKind::Script)
    } else if framework::next::is_payload(raw, &path) {
        Some(AssetKind::Payload)
    } else {
        None
    }
}

fn is_script_asset(path: &str) -> bool {
    path.ends_with(".js") || path.ends_with(".mjs")
}

// Bundlers often emit relative chunk names that are only meaningful in a
// framework context. The Next.js branch rewrites `static/...` to `/_next/...`
// only when the page or asset already proves that context.
fn resolve_asset(base: &Url, raw: &str, next_context: bool) -> Option<Url> {
    let raw = raw.trim_matches('\\');
    if raw.is_empty() || raw.starts_with("data:") || raw.starts_with("blob:") {
        return None;
    }
    if let Some(url) = framework::next::resolve_asset(base, raw, next_context) {
        return Some(url);
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

fn asset_token_string(bytes: &[u8], start: usize) -> Option<String> {
    let raw = source::token_string(bytes, start, TemplateMode::Preserve)?;
    if !raw.contains('?') && !raw.contains('&') {
        return Some(raw);
    }

    let mut end = start;
    while end < bytes.len() && !source::is_token_delim(bytes[end], false) {
        end += 1;
    }
    std::str::from_utf8(&bytes[start..end])
        .ok()
        .map(|s| s.trim_matches('\\').to_string())
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
