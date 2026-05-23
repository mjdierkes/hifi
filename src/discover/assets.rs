//! Asset reference discovery from document bytes.

use super::{push_asset, push_candidate, AssetRef, AssetSource, DocumentKind};
use crate::framework::DetectedSite;
use crate::hash::FxHashSet;
use crate::literal::LiteralSet;
use crate::scan::findings::FindingsBuilder;
use crate::source::{self, TemplateMode};
use crate::url::Url;
use std::sync::LazyLock;

pub(crate) const ASSET_LITERALS: &[&str] = &[
    "/_next/static/",
    "/_nuxt/",
    "_nuxt/",
    "/__nuxt_island/",
    "pages/",
    "components/",
    "composables/",
    "plugins/",
    "/_app/immutable/",
    "_app/immutable/",
    "nodes/",
    "chunks/",
    "entry/",
    "/_astro/",
    "_astro/",
    "/_actions/",
    "/build/routes/",
    "build/routes/",
    "routes/",
    "/assets/routes/",
    "/assets/",
    "assets/",
    "/static/js/",
    "static/js/",
    "/static/chunks/",
    "static/chunks/",
    "/_next/data/",
    "?_rsc=",
    "&_rsc=",
    "?_data=",
    "&_data=",
    ".rsc",
    "_payload.json",
    "__data.json",
];

pub(crate) const FRAMEWORK_DATA_MARKERS: &[&[u8]] = &[
    b"/_next/data/",
    b"/_payload.json",
    b"_payload.json",
    b"/__data.json",
    b"__data.json",
    b"?_data=",
    b"&_data=",
    b"/_actions/",
];

pub(crate) static ASSET_LITERALS_SET: LazyLock<LiteralSet<()>> = LazyLock::new(|| {
    LiteralSet::from_strs(ASSET_LITERALS.iter().copied().map(|literal| (literal, ())))
});

/// Enumerate static assets in document bytes without running endpoint scan.
pub fn scan_assets(
    bytes: &[u8],
    base: &Url,
    kind: DocumentKind,
    site: &DetectedSite,
) -> Vec<AssetRef> {
    let mut seen = FxHashSet::default();
    let mut out = Vec::new();
    if kind == DocumentKind::Html {
        scan_html_assets(bytes, base, site, &mut seen, &mut out);
    }
    let mut findings = FindingsBuilder::default();
    scan_literal_assets(bytes, base, site, &mut findings, &mut seen, &mut out);
    scan_dynamic_assets(bytes, base, site, &mut seen, &mut out);
    out
}

pub(crate) fn is_empty_script(bytes: &[u8], kind: DocumentKind) -> bool {
    kind == DocumentKind::Script
        && !crate::scan::has_document_pattern(bytes)
        && !ASSET_LITERALS_SET.is_match(bytes)
        && !source::contains(bytes, b"import(")
        && !source::contains(bytes, b"new URL(")
        && !FRAMEWORK_DATA_MARKERS
            .iter()
            .any(|marker| source::contains(bytes, marker))
        && !source::contains(bytes, b"__next_f.push")
        && !source::contains(bytes, b"Next-Action")
        && !source::contains(bytes, b"next-action")
        && !source::contains(bytes, b"$ACTION_")
        && !source::contains(bytes, b"__NUXT_DATA__")
        && !source::contains(bytes, b"__sveltekit_")
        && !source::contains(bytes, b"astro-island")
        && !source::contains(bytes, b"__remixContext")
}

pub(crate) fn scan_html_assets(
    bytes: &[u8],
    base: &Url,
    contexts: &DetectedSite,
    seen: &mut FxHashSet<Url>,
    out: &mut Vec<AssetRef>,
) {
    scan_tags(bytes, b"<script", |tag| {
        let Some(src) = attr_value(tag, b"src") else {
            return;
        };
        push_asset(base, src, contexts, AssetSource::HtmlScript, seen, out);
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
            push_asset(base, href, contexts, AssetSource::HtmlPreload, seen, out);
        }
    });
    scan_tags(bytes, b"<astro-island", |tag| {
        for attr in [b"component-url".as_slice(), b"renderer-url".as_slice()] {
            let Some(raw) = attr_value(tag, attr) else {
                continue;
            };
            push_asset(base, raw, contexts, AssetSource::HtmlPreload, seen, out);
        }
    });
}

pub(crate) fn scan_literal_assets(
    bytes: &[u8],
    base: &Url,
    contexts: &DetectedSite,
    findings: &mut FindingsBuilder,
    seen: &mut FxHashSet<Url>,
    out: &mut Vec<AssetRef>,
) {
    for m in ASSET_LITERALS_SET.find_iter(bytes) {
        let start = source::walk_token_start(bytes, m.start());
        if !source::is_string_literal_start(bytes, start) {
            continue;
        }
        let Some(raw) = asset_token_string(bytes, start) else {
            continue;
        };
        if raw.starts_with("/_next/data/") {
            push_candidate(findings, &raw);
        }
        push_asset(base, &raw, contexts, AssetSource::Literal, seen, out);
    }
}

pub(crate) fn scan_dynamic_assets(
    bytes: &[u8],
    base: &Url,
    contexts: &DetectedSite,
    seen: &mut FxHashSet<Url>,
    out: &mut Vec<AssetRef>,
) {
    for pos in memchr::memmem::find_iter(bytes, b"import(") {
        if let Some(raw) = source::quoted_arg(bytes, pos + b"import(".len()) {
            push_asset(base, raw, contexts, AssetSource::DynamicImport, seen, out);
        }
    }
    for pos in memchr::memmem::find_iter(bytes, b"new URL(") {
        if let Some(raw) = source::quoted_arg(bytes, pos + b"new URL(".len()) {
            push_asset(base, raw, contexts, AssetSource::NewUrl, seen, out);
        }
    }
}

pub(crate) fn scan_framework_markers(bytes: &[u8], findings: &mut FindingsBuilder) {
    for marker in FRAMEWORK_DATA_MARKERS {
        for pos in memchr::memmem::find_iter(bytes, marker) {
            let start = source::walk_token_start(bytes, pos);
            if !source::is_string_literal_start(bytes, start) {
                continue;
            }
            if let Some(raw) = asset_token_string(bytes, start) {
                super::push_candidate(findings, &raw);
            }
        }
    }
}

fn scan_tags(bytes: &[u8], needle: &[u8], mut f: impl FnMut(&[u8])) {
    let mut offset = 0;
    while let Some(rel) = source::find_ascii_ignore_case(&bytes[offset..], needle) {
        let start = offset + rel;
        let Some(end_rel) = memchr::memchr(b'>', &bytes[start..]) else {
            break;
        };
        f(&bytes[start..start + end_rel + 1]);
        offset = start + 1;
    }
}

fn asset_token_string(bytes: &[u8], start: usize) -> Option<String> {
    let raw = source::token_string(bytes, start, TemplateMode::Preserve)?;
    if !raw.contains('?') && !raw.contains('&') {
        return Some(raw);
    }

    let end =
        start + source::find_token_delim(&bytes[start..], false).unwrap_or(bytes.len() - start);
    std::str::from_utf8(&bytes[start..end])
        .ok()
        .map(|s| s.trim_matches('\\').to_string())
}

fn attr_value<'a>(tag: &'a [u8], name: &[u8]) -> Option<&'a str> {
    let mut offset = 0;
    while let Some(rel) = source::find_ascii_ignore_case(&tag[offset..], name) {
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
