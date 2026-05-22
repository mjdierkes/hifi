//! Static asset discovery.
//!
//! Discovery finds additional documents worth scanning: HTML script tags,
//! preloads, framework manifests, payload JSON, dynamic imports, and bundled
//! chunk literals. It does not fetch anything; it only produces `AssetRef`s for
//! the runtime to schedule and deduplicate.

use crate::framework;
use crate::framework::{AssetContext as FrameworkContexts, FrameworkConfig};
use crate::hash::FxHashSet;
use crate::scan::next::NextConfig;
use crate::scan::{Extractor, FindingsBuilder};
use crate::source::{self, TemplateMode};
use crate::url::Url;
use aho_corasick::{AhoCorasick, MatchKind};
use std::sync::LazyLock;

const ASSET_LITERALS: &[&str] = &[
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
const FRAMEWORK_DATA_MARKERS: &[&[u8]] = &[
    b"/_next/data/",
    b"/_payload.json",
    b"_payload.json",
    b"/__data.json",
    b"__data.json",
    b"?_data=",
    b"&_data=",
    b"/_actions/",
];

static ASSET_AC: LazyLock<AhoCorasick> = LazyLock::new(|| {
    AhoCorasick::builder()
        .match_kind(MatchKind::LeftmostLongest)
        .build(ASSET_LITERALS)
        .expect("valid asset literals")
});

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DocumentKind {
    Html,
    Script,
    Manifest,
    Payload,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AssetSource {
    HtmlScript,
    HtmlPreload,
    Literal,
    DynamicImport,
    NewUrl,
    NextManifest,
    FrameworkManifest,
}

#[derive(Clone, Debug)]
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

#[derive(Clone, Default)]
pub struct DocumentScan {
    pub findings: FindingsBuilder,
    pub assets: Vec<AssetRef>,
    pub revision: Option<String>,
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
    scan_document_with_config_and_findings(bytes, base, kind, parent_config, None)
}

pub(crate) fn scan_document_with_config_and_findings(
    bytes: &[u8],
    base: &Url,
    kind: DocumentKind,
    parent_config: Option<&NextConfig>,
    cached_findings: Option<FindingsBuilder>,
) -> DocumentScan {
    if is_empty_script(bytes, kind) {
        return DocumentScan::default();
    }

    let mut next_config = framework::next::parse_page_config(bytes, kind);
    if next_config.is_none() {
        next_config = parent_config.cloned();
    }
    let next_context = framework::next::is_context(bytes, base, next_config.as_ref());
    let nuxt_context = framework::nuxt::is_context(bytes, base);
    let sveltekit_context = framework::sveltekit::is_context(bytes, base);
    let astro_context = framework::astro::is_context(bytes, base);
    let remix_context = framework::remix::is_context(bytes, base);
    let contexts = FrameworkContexts {
        next: next_context,
        nuxt: nuxt_context,
        sveltekit: sveltekit_context,
        sveltekit_immutable_root: sveltekit_context
            .then(|| framework::sveltekit::primary_immutable_root(bytes, base))
            .flatten(),
        astro: astro_context,
        remix: remix_context,
    };
    let revision = framework::next::revision(bytes, next_context, next_config.as_ref());
    // If we recognized this as a Next context (e.g. via `/_next/` paths) but had
    // no parseable __NEXT_DATA__, still mark the framework so callers can label
    // the output. The build_id stays empty in that case.
    let framework_config = match next_config.clone() {
        Some(cfg) => FrameworkConfig::Next(cfg),
        None if next_context => FrameworkConfig::Next(crate::scan::next::NextConfig::default()),
        None if nuxt_context => FrameworkConfig::Nuxt,
        None if sveltekit_context => FrameworkConfig::SvelteKit,
        None if astro_context => FrameworkConfig::Astro,
        None if remix_context => FrameworkConfig::Remix,
        None => FrameworkConfig::None,
    };
    let mut out = DocumentScan {
        findings: cached_findings.unwrap_or_else(|| crate::scan::scan_endpoints(bytes)),
        assets: Vec::new(),
        revision,
        framework_config,
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
            out.findings.record_route(route, Extractor::Manifest);
        }
    }

    push_framework_candidates(bytes, &mut out.findings);
    framework::scan_data_findings(bytes, base, kind, &contexts, &mut out.findings);
    framework::next::scan_flight(bytes, &mut out.findings);
    framework::next::scan_server_action(bytes, base, kind, next_config.as_ref(), &mut out.findings);
    if contexts.sveltekit {
        let routes = framework::sveltekit::record_routes(bytes, &mut out.findings);
        framework::sveltekit::push_data_assets_for_routes(
            &routes,
            base,
            framework::sveltekit::base_path(bytes).as_deref(),
            &mut seen,
            &mut out.assets,
        );
    }
    if kind == DocumentKind::Html {
        scan_html_assets(bytes, base, contexts.clone(), &mut seen, &mut out.assets);
    }
    scan_literal_assets(
        bytes,
        base,
        contexts.clone(),
        &mut out.findings,
        &mut seen,
        &mut out.assets,
    );
    scan_dynamic_assets(bytes, base, contexts, &mut seen, &mut out.assets);

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
        if nuxt_context {
            framework::nuxt::push_manifests(bytes, base, &mut seen, &mut out.assets);
        }
        if sveltekit_context {
            framework::sveltekit::push_manifests(bytes, base, &mut seen, &mut out.assets);
        }
    }

    out
}

fn is_empty_script(bytes: &[u8], kind: DocumentKind) -> bool {
    kind == DocumentKind::Script
        && !crate::scan::has_document_pattern(bytes)
        && !ASSET_AC.is_match(bytes)
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

// HTML documents are the only place where tag structure is meaningful. Scripts,
// manifests, and payloads rely on literal and dynamic-reference discovery.
fn scan_html_assets(
    bytes: &[u8],
    base: &Url,
    contexts: FrameworkContexts,
    seen: &mut FxHashSet<Url>,
    out: &mut Vec<AssetRef>,
) {
    scan_tags(bytes, b"<script", |tag| {
        let Some(src) = attr_value(tag, b"src") else {
            return;
        };
        push_asset(base, src, &contexts, AssetSource::HtmlScript, seen, out);
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
            push_asset(base, href, &contexts, AssetSource::HtmlPreload, seen, out);
        }
    });
    scan_tags(bytes, b"<astro-island", |tag| {
        for attr in [b"component-url".as_slice(), b"renderer-url".as_slice()] {
            let Some(raw) = attr_value(tag, attr) else {
                continue;
            };
            push_asset(base, raw, &contexts, AssetSource::HtmlPreload, seen, out);
        }
    });
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

fn scan_literal_assets(
    bytes: &[u8],
    base: &Url,
    contexts: FrameworkContexts,
    findings: &mut FindingsBuilder,
    seen: &mut FxHashSet<Url>,
    out: &mut Vec<AssetRef>,
) {
    for m in ASSET_AC.find_iter(bytes) {
        let start = source::walk_token_start(bytes, m.start());
        // Reject tokens that aren't preceded by a string-literal delimiter.
        // Comment substrings, property accesses, and identifier prefixes look
        // identical to real URL literals after `walk_token_start` and produce
        // the bulk of the regular tier's false positives.
        if !source::is_string_literal_start(bytes, start) {
            continue;
        }
        let Some(raw) = asset_token_string(bytes, start) else {
            continue;
        };
        if raw.starts_with("/_next/data/") {
            push_candidate(findings, &raw);
        }
        push_asset(base, &raw, &contexts, AssetSource::Literal, seen, out);
    }
}

fn scan_dynamic_assets(
    bytes: &[u8],
    base: &Url,
    contexts: FrameworkContexts,
    seen: &mut FxHashSet<Url>,
    out: &mut Vec<AssetRef>,
) {
    for pos in memchr::memmem::find_iter(bytes, b"import(") {
        if let Some(raw) = source::quoted_arg(bytes, pos + b"import(".len()) {
            push_asset(base, raw, &contexts, AssetSource::DynamicImport, seen, out);
        }
    }
    for pos in memchr::memmem::find_iter(bytes, b"new URL(") {
        if let Some(raw) = source::quoted_arg(bytes, pos + b"new URL(".len()) {
            push_asset(base, raw, &contexts, AssetSource::NewUrl, seen, out);
        }
    }
}

fn push_framework_candidates(bytes: &[u8], findings: &mut FindingsBuilder) {
    for marker in FRAMEWORK_DATA_MARKERS {
        for pos in memchr::memmem::find_iter(bytes, marker) {
            let start = source::walk_token_start(bytes, pos);
            if !source::is_string_literal_start(bytes, start) {
                continue;
            }
            if let Some(raw) = asset_token_string(bytes, start) {
                push_candidate(findings, &raw);
            }
        }
    }
}

fn push_candidate(findings: &mut FindingsBuilder, raw: &str) {
    framework::next::push_framework_candidate(findings, raw);
    let path = raw.split(['?', '#']).next().unwrap_or(raw);
    if (framework::nuxt::is_payload(raw, path)
        || framework::sveltekit::is_payload(raw, path)
        || framework::astro::is_payload(raw, path)
        || framework::remix::is_payload(raw, path))
        && crate::scan::classify::is_api_candidate(raw)
    {
        findings.record_candidate(
            crate::scan::classify::normalize_api_url(raw),
            Extractor::Literal,
        );
    }
}

fn push_asset(
    base: &Url,
    raw: &str,
    contexts: &FrameworkContexts,
    source: AssetSource,
    seen: &mut FxHashSet<Url>,
    out: &mut Vec<AssetRef>,
) {
    let Some(kind) = framework::classify_asset(raw) else {
        return;
    };
    let Some(url) = framework::resolve_asset(base, raw, contexts) else {
        return;
    };
    if framework::should_skip(&url) {
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
