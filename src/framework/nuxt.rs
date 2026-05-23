//! Nuxt discovery policy and runtime hooks.

use crate::discover::{AssetKind, AssetRef, AssetSource};
use crate::generated::{NUXT_CONTEXT_PREFIXES, NUXT_IS_CONTEXT_MARKERS, NUXT_SKIP_FRAGMENTS};
use crate::hash::FxHashSet;
use crate::framework::FrameworkId;
use crate::scan::findings::{Channel, Provenance};
use crate::scan::Shape;
use crate::source::{self, TemplateMode};
use crate::url::Url;

const MANIFEST_ENDS_WITH: &[&str] = &["/_nuxt/manifest.json", "/_nuxt/prerendered.json"];
const MANIFEST_GATED: &[(&str, &str)] = &[("/_nuxt/builds/", ".json")];

pub fn is_context(bytes: &[u8], base: &Url) -> bool {
    base.path().contains("/_nuxt/")
        || base.path().ends_with("_payload.json")
        || source::bytes_contain_any_str(bytes, NUXT_IS_CONTEXT_MARKERS)
}

pub fn should_skip(url: &Url) -> bool {
    super::resolve::should_skip_fragments(url, "/_nuxt/", NUXT_SKIP_FRAGMENTS)
}

pub fn is_payload(raw: &str, path: &str) -> bool {
    source::ends_with_ascii_ignore_case(path, "_payload.json")
        || raw.contains("/_payload.json?")
        || path.contains("/__nuxt_island/")
}

pub fn is_manifest(path: &str) -> bool {
    super::resolve::manifest_matches(path, MANIFEST_ENDS_WITH, &[], MANIFEST_GATED)
}

pub fn resolve(base: &Url, raw: &str, context: bool) -> Option<Url> {
    super::resolve::resolve_prefixed_or_under(
        base,
        raw,
        context,
        "_nuxt/",
        NUXT_CONTEXT_PREFIXES,
        "/_nuxt/",
    )
}

pub fn record_routes(bytes: &[u8], findings: &mut crate::scan::FindingsBuilder) {
    for route in parse_routes(bytes) {
        findings.record_route(route, Provenance::framework(Channel::Manifest, FrameworkId::Nuxt));
    }
}

pub fn record_page_route(bytes: &[u8], findings: &mut crate::scan::FindingsBuilder) {
    for key in [b"routePath".as_slice(), b"path".as_slice()] {
        let Some(route) = source::field_string(bytes, key, b":", true) else {
            continue;
        };
        let path = route.split(['?', '#']).next().unwrap_or(&route);
        if crate::scan::classify::is_client_route(path) {
            findings.record_route(path.to_owned(), Provenance::framework(Channel::Manifest, FrameworkId::Nuxt));
            return;
        }
    }
}

pub fn record_endpoint_maps(bytes: &[u8], findings: &mut crate::scan::FindingsBuilder) {
    for endpoint in endpoint_map_urls(bytes) {
        findings.record_api(
            endpoint,
            Shape::inferred(None, false),
            Provenance::framework(Channel::Literal, FrameworkId::Nuxt),
        );
    }
}

pub fn push_manifests(
    bytes: &[u8],
    base: &Url,
    seen: &mut FxHashSet<Url>,
    out: &mut Vec<AssetRef>,
) {
    for raw in manifest_candidates(bytes) {
        let Some(url) = super::resolve::resolve_prefixed(base, &raw, "_nuxt/")
            .or_else(|| base.join(&raw).ok())
        else {
            continue;
        };
        super::insert_asset(
            url,
            AssetKind::Manifest,
            AssetSource::FrameworkManifest,
            seen,
            out,
        );
    }
    let Some(build_id) = build_id(bytes) else {
        return;
    };
    for root in manifest_roots(bytes, base) {
        for name in [
            format!("builds/meta/{build_id}.json"),
            "builds/latest.json".to_string(),
        ] {
            let Ok(url) = root.join(&name) else {
                continue;
            };
            super::insert_asset(
                url,
                AssetKind::Manifest,
                AssetSource::FrameworkManifest,
                seen,
                out,
            );
        }
    }
}

fn manifest_candidates(bytes: &[u8]) -> Vec<String> {
    let mut out = Vec::new();
    collect_literal_manifest_candidates(bytes, &mut out);
    out.sort();
    out.dedup();
    out
}

fn manifest_roots(bytes: &[u8], base: &Url) -> Vec<Url> {
    let mut out = Vec::new();
    let base_path = app_base_url(bytes).unwrap_or_else(|| "/".to_owned());
    let assets_dir = build_assets_dir(bytes).unwrap_or_else(|| "/_nuxt/".to_owned());
    let path = super::join_paths(&base_path, &assets_dir);
    if let Some(cdn) = app_cdn_url(bytes) {
        if let Ok(root) = Url::parse(&super::join_paths(&cdn, &path)) {
            out.push(root);
        }
    }
    if let Ok(root) = base.join(&path) {
        out.push(root);
    }
    out.sort_by(|a, b| a.as_str().cmp(b.as_str()));
    out.dedup_by(|a, b| a.as_str() == b.as_str());
    out
}

fn collect_literal_manifest_candidates(bytes: &[u8], out: &mut Vec<String>) {
    super::scan_quoted_after_markers(
        bytes,
        &[
            "/_nuxt/builds/",
            "_nuxt/builds/",
            "/_nuxt/prerendered.json",
        ],
        TemplateMode::Preserve,
        |raw| {
            let path = raw.split(['?', '#']).next().unwrap_or(raw);
            if is_manifest(path) {
                out.push(raw.to_owned());
            }
        },
    );
}

fn parse_routes(bytes: &[u8]) -> Vec<String> {
    let mut out = Vec::new();
    let slice = super::json_slice(bytes);
    crate::json::walk(slice, |evt| match evt {
        crate::json::Visit::Key(key) if !route_key_context(key) => push_route(&mut out, key),
        crate::json::Visit::String(_, value) => push_route(&mut out, value),
        _ => {}
    });
    collect_literal_routes(bytes, &mut out);
    out.sort();
    out.dedup();
    out
}

pub(super) fn endpoint_map_urls(bytes: &[u8]) -> Vec<String> {
    let mut out = Vec::new();
    let bases = runtime_api_bases(bytes);
    collect_endpoint_json(bytes, &mut out);
    collect_endpoint_literals(bytes, &mut out);
    collect_relative_endpoint_literals(bytes, &bases, &mut out);
    out.sort();
    out.dedup();
    out
}

fn collect_endpoint_json(bytes: &[u8], out: &mut Vec<String>) {
    crate::json::walk(bytes, |evt| {
        if let crate::json::Visit::String(key, value) = evt {
            if key.is_some_and(endpoint_key_context) {
                push_endpoint(out, value);
            }
        }
    });
}

fn collect_endpoint_literals(bytes: &[u8], out: &mut Vec<String>) {
    super::scan_key_windows(
        bytes,
        &[
            b"endpoint".as_slice(),
            b"apiUrl".as_slice(),
            b"baseURL".as_slice(),
            b"url".as_slice(),
        ],
        0,
        |pos, key, _| {
            if let Some(endpoint) = source::field_string(&bytes[pos..], key, b":", true) {
                push_endpoint(out, &endpoint);
            }
        },
    );
    super::scan_key_windows(
        bytes,
        &[b"endpoints".as_slice(), b"api".as_slice()],
        4096,
        |_, _, window| collect_api_strings(window, out),
    );
}

fn collect_relative_endpoint_literals(bytes: &[u8], bases: &[String], out: &mut Vec<String>) {
    if bases.is_empty() {
        return;
    }
    super::scan_key_windows(
        bytes,
        &[
            b"endpoint".as_slice(),
            b"endpoints".as_slice(),
            b"path".as_slice(),
            b"url".as_slice(),
            b"api".as_slice(),
        ],
        4096,
        |_, _, window| collect_relative_api_strings(window, bases, out),
    );
}

fn collect_relative_api_strings(bytes: &[u8], bases: &[String], out: &mut Vec<String>) {
    super::scan_quoted_strings(bytes, TemplateMode::ReplaceExpressions, |raw| {
        push_relative_endpoint(out, raw, bases);
    });
}

fn runtime_api_bases(bytes: &[u8]) -> Vec<String> {
    let mut out = Vec::new();
    super::scan_key_windows(
        bytes,
        &[
            b"apiBase".as_slice(),
            b"apiBaseURL".as_slice(),
            b"apiBaseUrl".as_slice(),
            b"apiUrl".as_slice(),
            b"apiURL".as_slice(),
            b"baseURL".as_slice(),
            b"baseUrl".as_slice(),
        ],
        0,
        |pos, key, _| {
            if let Some(value) = source::field_string(&bytes[pos..], key, b":", true) {
                push_runtime_api_base(&mut out, &value);
            }
        },
    );
    out.sort();
    out.dedup();
    out
}

fn collect_api_strings(bytes: &[u8], out: &mut Vec<String>) {
    super::scan_quoted_strings(bytes, TemplateMode::ReplaceExpressions, |raw| {
        push_endpoint(out, raw);
    });
}

fn endpoint_key_context(key: &str) -> bool {
    let key = key.to_ascii_lowercase();
    key == "api"
        || key == "url"
        || key == "endpoint"
        || key == "endpoints"
        || key == "baseurl"
        || key.ends_with("api")
        || key.ends_with("url")
        || key.ends_with("endpoint")
}

fn push_endpoint(out: &mut Vec<String>, raw: &str) {
    if crate::scan::classify::is_api_candidate(raw) {
        out.push(crate::scan::classify::normalize_api_url(raw));
    }
}

fn push_runtime_api_base(out: &mut Vec<String>, raw: &str) {
    let base = raw.trim_end_matches('/');
    if crate::scan::classify::is_api_candidate(base)
        || base == "/api"
        || base.starts_with("/api/")
    {
        out.push(base.to_owned());
    }
}

fn push_relative_endpoint(out: &mut Vec<String>, raw: &str, bases: &[String]) {
    if crate::scan::classify::is_api_candidate(raw) {
        out.push(crate::scan::classify::normalize_api_url(raw));
        return;
    }
    if !is_relative_endpoint_leaf(raw) {
        return;
    }
    for base in bases {
        push_endpoint(out, &super::join_paths(base, raw));
    }
}

fn is_relative_endpoint_leaf(raw: &str) -> bool {
    let path = raw.split(['?', '#']).next().unwrap_or(raw);
    let first = path.split('/').next().unwrap_or(path);
    !path.is_empty()
        && !path.starts_with('/')
        && !path.starts_with("http://")
        && !path.starts_with("https://")
        && !path.contains("{dynamic}")
        && !path.contains('.')
        && !matches!(
            first,
            "asset" | "assets" | "image" | "images" | "img" | "media" | "static" | "public"
        )
        && path.len() <= 160
        && path
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'/'))
        && path.split('/').any(|seg| seg.len() >= 3)
}

fn collect_literal_routes(bytes: &[u8], out: &mut Vec<String>) {
    for key in [
        b"routePath".as_slice(),
        b"path".as_slice(),
        b"routes".as_slice(),
        b"prerenderedRoutes".as_slice(),
    ] {
        let mut offset = 0;
        while let Some(rel) = memchr::memmem::find(&bytes[offset..], key) {
            let pos = offset + rel;
            if let Some(route) = source::field_string(&bytes[pos..], key, b":", true) {
                push_route(out, &route);
            }
            collect_route_strings(&bytes[pos..bytes.len().min(pos + 2048)], out);
            offset = pos + key.len();
        }
    }
}

fn collect_route_strings(bytes: &[u8], out: &mut Vec<String>) {
    super::scan_quoted_strings(bytes, TemplateMode::ReplaceExpressions, |raw| {
        push_route(out, raw);
    });
}

fn route_key_context(key: &str) -> bool {
    matches!(
        key,
        "path" | "route" | "routePath" | "routes" | "prerenderedRoutes"
    )
}

fn push_route(out: &mut Vec<String>, raw: &str) {
    let path = raw.split(['?', '#']).next().unwrap_or(raw);
    if crate::scan::classify::is_client_route(path) {
        out.push(path.to_owned());
    }
}

fn build_id(bytes: &[u8]) -> Option<String> {
    source::field_string(bytes, b"buildId", b":", true).filter(|value| {
        (4..=128).contains(&value.len())
            && value
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_'))
    })
}

fn app_base_url(bytes: &[u8]) -> Option<String> {
    source::field_string(bytes, b"baseURL", b":", true).filter(|value| value.starts_with('/'))
}

fn app_cdn_url(bytes: &[u8]) -> Option<String> {
    source::field_string(bytes, b"cdnURL", b":", true)
        .filter(|value| value.starts_with("http://") || value.starts_with("https://"))
}

fn build_assets_dir(bytes: &[u8]) -> Option<String> {
    source::field_string(bytes, b"buildAssetsDir", b":", true)
        .filter(|value| value.contains("_nuxt"))
}
