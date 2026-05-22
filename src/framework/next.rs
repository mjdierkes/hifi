//! Next.js discovery policy and runtime hooks.

use crate::discover::{AssetKind, AssetRef, AssetSource, DocumentKind};
use crate::hash::FxHashSet;
use crate::scan::next::{self as parser, NextConfig};
use crate::scan::{Extractor, FindingsBuilder, Shape};
use crate::source::{self, TemplateMode};
use crate::url::Url;

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
    "instrumentation-",
    "app-pages-internals-",
    "app-client-internals-",
];
const NEXT_ARTIFACTS: &[NextArtifact] = &[
    NextArtifact {
        name: "_buildManifest.js",
        parser: ArtifactParser::BuildManifest,
        discover: true,
    },
    NextArtifact {
        name: "_ssgManifest.js",
        parser: ArtifactParser::None,
        discover: true,
    },
    NextArtifact {
        name: "app-build-manifest.json",
        parser: ArtifactParser::AppBuildManifest,
        discover: true,
    },
    NextArtifact {
        name: "_clientReferenceManifest.json",
        parser: ArtifactParser::ClientReferenceManifest,
        discover: true,
    },
    NextArtifact {
        name: "client-reference-manifest.json",
        parser: ArtifactParser::ClientReferenceManifest,
        discover: false,
    },
];
const NEXT_ACTION_MARKERS: &[&[u8]] = &[b"Next-Action", b"next-action", b"$ACTION_"];
const NEXT_FLIGHT_MARKER: &[u8] = b"self.__next_f.push";

#[derive(Clone, Copy)]
struct NextArtifact {
    name: &'static str,
    parser: ArtifactParser,
    discover: bool,
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum ArtifactParser {
    None,
    BuildManifest,
    AppBuildManifest,
    ClientReferenceManifest,
}

pub fn parse_page_config(bytes: &[u8], kind: DocumentKind) -> Option<NextConfig> {
    (kind == DocumentKind::Html)
        .then(|| parser::parse_next_data(bytes))
        .flatten()
}

pub fn is_context(bytes: &[u8], base: &Url, config: Option<&NextConfig>) -> bool {
    config.is_some()
        || base.path().contains("/_next/")
        || source::contains(bytes, b"/_next/")
        || source::contains(bytes, b"__NEXT_DATA__")
        || source::contains(bytes, NEXT_FLIGHT_MARKER)
}

pub fn revision(bytes: &[u8], context: bool, config: Option<&NextConfig>) -> Option<String> {
    config
        .and_then(|cfg| cfg.build_id.clone())
        .or_else(|| revision_from_bytes(bytes, context))
}

pub fn parse_manifest_routes(bytes: &[u8], base: &Url, kind: DocumentKind) -> Option<Vec<String>> {
    if !matches!(kind, DocumentKind::Manifest | DocumentKind::Payload) {
        return None;
    }
    let path = base.path();
    let artifact = artifact_for_path(path)?;
    let routes = match artifact.parser {
        ArtifactParser::None => Vec::new(),
        ArtifactParser::BuildManifest => parser::parse_build_manifest_js(bytes),
        ArtifactParser::AppBuildManifest => parser::parse_app_build_manifest(bytes),
        ArtifactParser::ClientReferenceManifest => parser::parse_client_reference_manifest(bytes),
    };
    (!routes.is_empty()).then_some(routes)
}

pub fn push_manifests(
    bytes: &[u8],
    base: &Url,
    revision: &str,
    config: Option<&NextConfig>,
    context: bool,
    seen: &mut FxHashSet<Url>,
    out: &mut Vec<AssetRef>,
) {
    let root = config
        .and_then(|cfg| asset_prefix_root(cfg, base))
        .and_then(|url| url.join(&format!("{revision}/")).ok())
        .or_else(|| {
            static_mount(bytes, base, context)
                .and_then(|url| url.join(&format!("{revision}/")).ok())
        })
        .or_else(|| {
            let prefix = config.and_then(|c| c.base_path.as_deref()).unwrap_or("");
            base.join(&format!("{prefix}/_next/static/{revision}/"))
                .ok()
        });
    let Some(root) = root else {
        return;
    };
    for artifact in NEXT_ARTIFACTS.iter().filter(|artifact| artifact.discover) {
        let Ok(url) = root.join(artifact.name) else {
            continue;
        };
        super::push_asset(
            url,
            AssetKind::Manifest,
            AssetSource::NextManifest,
            seen,
            out,
        );
    }
}

pub fn resolve_asset(base: &Url, raw: &str, context: bool) -> Option<Url> {
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
    if raw.starts_with("static/") && context {
        return base.join(&format!("/_next/{raw}")).ok();
    }
    None
}

pub fn should_skip(url: &Url) -> bool {
    let path = url.path();
    path.contains("/_next/") && super::path_contains_any(path, NEXT_SKIP_FRAGMENTS)
}

pub fn is_manifest(path: &str) -> bool {
    artifact_for_path(path).is_some()
}

pub fn is_payload(raw: &str, path: &str) -> bool {
    (source::ends_with_ascii_ignore_case(path, ".json") && is_framework_data(raw, path))
        || (source::ends_with_ascii_ignore_case(path, ".rsc") && has_meaningful_rsc_stem(path))
        || raw.contains("?_rsc=")
        || raw.contains("&_rsc=")
}

pub fn push_framework_candidate(findings: &mut FindingsBuilder, raw: &str) {
    let path = raw.split(['?', '#']).next().unwrap_or(raw);
    if is_framework_data(raw, path) && raw.len() <= 512 {
        findings.record_candidate(raw.to_owned(), Extractor::Literal);
    }
}

pub fn scan_flight(bytes: &[u8], findings: &mut FindingsBuilder) {
    for route in parser::extract_flight_routes(bytes) {
        if crate::scan::classify::is_api_candidate(&route) {
            let url = crate::scan::classify::normalize_api_url(&route);
            findings.record_candidate(url, Extractor::Flight);
            continue;
        }
        if !crate::scan::classify::is_client_route(&route) {
            continue;
        }
        findings.record_route(route, Extractor::Flight);
    }
}

fn artifact_for_path(path: &str) -> Option<&'static NextArtifact> {
    NEXT_ARTIFACTS
        .iter()
        .find(|artifact| source::ends_with_ascii_ignore_case(path, artifact.name))
}

pub fn scan_server_action(
    bytes: &[u8],
    base: &Url,
    kind: DocumentKind,
    config: Option<&NextConfig>,
    findings: &mut FindingsBuilder,
) {
    if !matches!(kind, DocumentKind::Html | DocumentKind::Payload)
        || !NEXT_ACTION_MARKERS
            .iter()
            .any(|marker| source::contains(bytes, marker))
    {
        return;
    }
    let Some(route) = route_from_payload(base, config) else {
        return;
    };
    findings.record_api(route, Shape::next_server_action(), Extractor::ServerAction);
}

pub fn is_rsc_payload(url: &Url) -> bool {
    url.path().ends_with(".rsc")
        || url
            .query_pairs()
            .any(|(key, _)| key.eq_ignore_ascii_case("_rsc"))
}

fn asset_prefix_root(cfg: &NextConfig, base: &Url) -> Option<Url> {
    let prefix = cfg.asset_prefix.as_deref()?.trim_end_matches('/');
    if prefix.is_empty() {
        return None;
    }
    let base_path = cfg.base_path.as_deref().unwrap_or("");
    let is_absolute = prefix.starts_with("http://") || prefix.starts_with("https://");
    if !is_absolute && !prefix.starts_with('/') {
        return None;
    }
    let combined = format!("{prefix}{base_path}/_next/static/");
    if is_absolute {
        Url::parse(&combined).ok()
    } else {
        base.join(&combined).ok()
    }
}

fn static_mount(bytes: &[u8], base: &Url, context: bool) -> Option<Url> {
    let marker = b"/_next/static/";
    for pos in memchr::memmem::find_iter(bytes, marker) {
        let start = source::walk_token_start(bytes, pos);
        let Some(raw) = asset_token_string(bytes, start) else {
            continue;
        };
        let Some(url) = resolve_asset(base, &raw, context) else {
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

fn revision_from_bytes(bytes: &[u8], context: bool) -> Option<String> {
    if context {
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

fn is_framework_data(raw: &str, path: &str) -> bool {
    raw.starts_with("/_next/data/")
        || path.contains("/_next/data/")
        || source::ends_with_ascii_ignore_case(path, "/_payload.json")
        || source::ends_with_ascii_ignore_case(path, "/__data.json")
}

fn has_meaningful_rsc_stem(path: &str) -> bool {
    let Some(file) = path.rsplit('/').next() else {
        return false;
    };
    if file.len() < 4 || !source::ends_with_ascii_ignore_case(file, ".rsc") {
        return false;
    }
    let stem = &file[..file.len() - 4];
    if stem.is_empty()
        || !stem
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'))
    {
        return false;
    }
    let first_segment = stem.split('.').next().unwrap_or(stem);
    first_segment.len() >= 2
}

fn route_from_payload(base: &Url, config: Option<&NextConfig>) -> Option<String> {
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
    if let Some(cfg) = config {
        if let Some(base_path) = cfg.base_path.as_deref() {
            if !base_path.is_empty() {
                if let Some(stripped) = path.strip_prefix(base_path) {
                    path = if stripped.is_empty() {
                        "/".to_owned()
                    } else {
                        stripped.to_owned()
                    };
                }
            }
        }
        if !cfg.locales.is_empty() {
            path = parser::strip_locale(&path, &cfg.locales);
        }
    }
    path = parser::normalize_app_route(&path);
    Some(path)
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
