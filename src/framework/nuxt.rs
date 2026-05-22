//! Nuxt discovery policy and runtime hooks.

use crate::discover::{AssetKind, AssetRef, AssetSource};
use crate::scan::{Extractor, Shape};
use crate::source::{self, TemplateMode};
use crate::url::Url;
use rustc_hash::FxHashSet;

const SKIP_FRAGMENTS: &[&str] = &[
    "/_nuxt/error-",
    "/_nuxt/entry.",
    "/_nuxt/node_modules/",
    "/_nuxt/@vite/",
    "/_nuxt/vendors",
    "/_nuxt/vendor",
    "/_nuxt/polyfills",
];

pub fn is_context(bytes: &[u8], base: &Url) -> bool {
    base.path().contains("/_nuxt/")
        || base.path().ends_with("_payload.json")
        || source::contains(bytes, b"/_nuxt/")
        || source::contains(bytes, b"__NUXT_DATA__")
        || source::contains(bytes, b"_payload.json")
}

pub fn should_skip(url: &Url) -> bool {
    let path = url.path();
    path.contains("/_nuxt/")
        && SKIP_FRAGMENTS
            .iter()
            .any(|fragment| path.contains(fragment))
}

pub fn is_payload(raw: &str, path: &str) -> bool {
    source::ends_with_ascii_ignore_case(path, "_payload.json")
        || raw.contains("/_payload.json?")
        || path.contains("/__nuxt_island/")
}

pub fn is_manifest(path: &str) -> bool {
    path.contains("/_nuxt/builds/") && source::ends_with_ascii_ignore_case(path, ".json")
        || source::ends_with_ascii_ignore_case(path, "/_nuxt/manifest.json")
        || source::ends_with_ascii_ignore_case(path, "/_nuxt/prerendered.json")
}

pub fn resolve_asset(base: &Url, raw: &str) -> Option<Url> {
    if raw.starts_with("_nuxt/") {
        return base.join(&format!("/{raw}")).ok();
    }
    None
}

pub fn resolve_context_asset(base: &Url, raw: &str, context: bool) -> Option<Url> {
    if !context {
        return None;
    }
    if raw.starts_with("chunks/")
        || raw.starts_with("entry/")
        || raw.starts_with("pages/")
        || raw.starts_with("components/")
        || raw.starts_with("composables/")
        || raw.starts_with("plugins/")
    {
        return base.join(&format!("/_nuxt/{raw}")).ok();
    }
    None
}

pub fn route_from_payload(base: &Url) -> Option<String> {
    let path = base.path();
    let route = path.strip_suffix("/_payload.json")?;
    Some(if route.is_empty() {
        "/".to_owned()
    } else {
        route.to_owned()
    })
}

pub fn record_routes(bytes: &[u8], findings: &mut crate::scan::FindingsBuilder) {
    for route in parse_routes(bytes) {
        findings.record_route(route, Extractor::NuxtPayload);
    }
}

pub fn record_page_route(bytes: &[u8], findings: &mut crate::scan::FindingsBuilder) {
    for key in [b"routePath".as_slice(), b"path".as_slice()] {
        let Some(route) = string_value_after_key(bytes, key) else {
            continue;
        };
        let path = route.split(['?', '#']).next().unwrap_or(&route);
        if crate::scan::classify::is_client_route(path) {
            findings.record_route(path.to_owned(), Extractor::NuxtPayload);
            return;
        }
    }
}

pub fn record_endpoint_maps(bytes: &[u8], findings: &mut crate::scan::FindingsBuilder) {
    for endpoint in endpoint_map_urls(bytes) {
        findings.record_api(
            endpoint,
            Shape::inferred(None, false),
            Extractor::NuxtPayload,
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
        let Some(url) = resolve_asset(base, &raw).or_else(|| base.join(&raw).ok()) else {
            continue;
        };
        push_resolved_asset(url, AssetKind::Manifest, seen, out);
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
            push_resolved_asset(url, AssetKind::Manifest, seen, out);
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
    let path = join_paths(&base_path, &assets_dir);
    if let Some(cdn) = app_cdn_url(bytes) {
        if let Ok(root) = Url::parse(&join_paths(&cdn, &path)) {
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
    for marker in [
        b"/_nuxt/builds/".as_slice(),
        b"_nuxt/builds/".as_slice(),
        b"/_nuxt/prerendered.json".as_slice(),
    ] {
        for pos in memchr::memmem::find_iter(bytes, marker) {
            let start = source::walk_token_start(bytes, pos);
            if !source::is_string_literal_start(bytes, start) {
                continue;
            }
            let Some(raw) = source::token_string(bytes, start, TemplateMode::Preserve) else {
                continue;
            };
            let path = raw.split(['?', '#']).next().unwrap_or(&raw);
            if is_manifest(path) {
                out.push(raw);
            }
        }
    }
}

fn parse_routes(bytes: &[u8]) -> Vec<String> {
    let mut out = Vec::new();
    if let Ok(value) = serde_json::from_slice::<serde_json::Value>(bytes) {
        collect_json_routes(&value, &mut out);
    } else if let Some(start) = bytes.iter().position(|b| matches!(*b, b'{' | b'[')) {
        if let Ok(value) = serde_json::from_slice::<serde_json::Value>(&bytes[start..]) {
            collect_json_routes(&value, &mut out);
        }
    }
    collect_literal_routes(bytes, &mut out);
    out.sort();
    out.dedup();
    out
}

fn endpoint_map_urls(bytes: &[u8]) -> Vec<String> {
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
    let Ok(value) = serde_json::from_slice::<serde_json::Value>(bytes) else {
        return;
    };
    collect_json_endpoints(&value, None, out);
}

fn collect_json_endpoints(value: &serde_json::Value, key: Option<&str>, out: &mut Vec<String>) {
    match value {
        serde_json::Value::String(s) => {
            if key.is_some_and(endpoint_key_context) {
                push_endpoint(out, s);
            }
        }
        serde_json::Value::Array(arr) => {
            for item in arr {
                collect_json_endpoints(item, key, out);
            }
        }
        serde_json::Value::Object(obj) => {
            for (child_key, child_value) in obj {
                collect_json_endpoints(child_value, Some(child_key), out);
            }
        }
        _ => {}
    }
}

fn collect_endpoint_literals(bytes: &[u8], out: &mut Vec<String>) {
    for key in [
        b"endpoint".as_slice(),
        b"apiUrl".as_slice(),
        b"baseURL".as_slice(),
        b"url".as_slice(),
    ] {
        let mut offset = 0;
        while let Some(rel) = memchr::memmem::find(&bytes[offset..], key) {
            let pos = offset + rel;
            if !source::is_identifier_boundary(bytes, pos, key.len()) {
                offset = pos + key.len();
                continue;
            }
            if let Some(endpoint) = string_value_after_key(&bytes[pos..], key) {
                push_endpoint(out, &endpoint);
            }
            offset = pos + key.len();
        }
    }
    for key in [b"endpoints".as_slice(), b"api".as_slice()] {
        let mut offset = 0;
        while let Some(rel) = memchr::memmem::find(&bytes[offset..], key) {
            let pos = offset + rel;
            if source::is_identifier_boundary(bytes, pos, key.len()) {
                collect_api_strings(&bytes[pos..bytes.len().min(pos + 4096)], out);
            }
            offset = pos + key.len();
        }
    }
}

fn collect_relative_endpoint_literals(bytes: &[u8], bases: &[String], out: &mut Vec<String>) {
    if bases.is_empty() {
        return;
    }
    for key in [
        b"endpoint".as_slice(),
        b"endpoints".as_slice(),
        b"path".as_slice(),
        b"url".as_slice(),
        b"api".as_slice(),
    ] {
        let mut offset = 0;
        while let Some(rel) = memchr::memmem::find(&bytes[offset..], key) {
            let pos = offset + rel;
            if source::is_identifier_boundary(bytes, pos, key.len()) {
                collect_relative_api_strings(&bytes[pos..bytes.len().min(pos + 4096)], bases, out);
            }
            offset = pos + key.len();
        }
    }
}

fn collect_relative_api_strings(bytes: &[u8], bases: &[String], out: &mut Vec<String>) {
    let mut i = 0;
    while i < bytes.len() {
        let b = bytes[i];
        if matches!(b, b'"' | b'\'' | b'`') {
            if let Some(s) =
                source::quoted_string(bytes, i + 1, b, TemplateMode::ReplaceExpressions)
            {
                push_relative_endpoint(out, &s, bases);
            }
            i = source::quoted_end(bytes, i + 1, b).map_or(i + 1, |end| end + 1);
            continue;
        }
        i += 1;
    }
}

fn runtime_api_bases(bytes: &[u8]) -> Vec<String> {
    let mut out = Vec::new();
    for key in [
        b"apiBase".as_slice(),
        b"apiBaseURL".as_slice(),
        b"apiBaseUrl".as_slice(),
        b"apiUrl".as_slice(),
        b"apiURL".as_slice(),
        b"baseURL".as_slice(),
        b"baseUrl".as_slice(),
    ] {
        let mut offset = 0;
        while let Some(rel) = memchr::memmem::find(&bytes[offset..], key) {
            let pos = offset + rel;
            if source::is_identifier_boundary(bytes, pos, key.len()) {
                if let Some(value) = string_value_after_key(&bytes[pos..], key) {
                    push_runtime_api_base(&mut out, &value);
                }
            }
            offset = pos + key.len();
        }
    }
    out.sort();
    out.dedup();
    out
}

fn collect_api_strings(bytes: &[u8], out: &mut Vec<String>) {
    let mut i = 0;
    while i < bytes.len() {
        let b = bytes[i];
        if matches!(b, b'"' | b'\'' | b'`') {
            if let Some(s) =
                source::quoted_string(bytes, i + 1, b, TemplateMode::ReplaceExpressions)
            {
                push_endpoint(out, &s);
            }
            i = source::quoted_end(bytes, i + 1, b).map_or(i + 1, |end| end + 1);
            continue;
        }
        i += 1;
    }
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
    if base == "/api"
        || base.starts_with("/api/")
        || base.starts_with("/graphql")
        || base.starts_with("/trpc")
        || ((base.starts_with("http://") || base.starts_with("https://"))
            && ["/api", "/graphql", "/trpc"]
                .iter()
                .any(|needle| base.contains(needle)))
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
        push_endpoint(out, &join_paths(base, raw));
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

fn collect_json_routes(value: &serde_json::Value, out: &mut Vec<String>) {
    match value {
        serde_json::Value::String(s) => push_route(out, s),
        serde_json::Value::Array(arr) => {
            for item in arr {
                collect_json_routes(item, out);
            }
        }
        serde_json::Value::Object(obj) => {
            for (key, value) in obj {
                if route_key_context(key) {
                    match value {
                        serde_json::Value::String(s) => push_route(out, s),
                        serde_json::Value::Array(_) | serde_json::Value::Object(_) => {
                            collect_json_routes(value, out)
                        }
                        _ => {}
                    }
                } else {
                    push_route(out, key);
                    collect_json_routes(value, out);
                }
            }
        }
        _ => {}
    }
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
            if let Some(route) = string_value_after_key(&bytes[pos..], key) {
                push_route(out, &route);
            }
            collect_route_strings(&bytes[pos..bytes.len().min(pos + 2048)], out);
            offset = pos + key.len();
        }
    }
}

fn collect_route_strings(bytes: &[u8], out: &mut Vec<String>) {
    let mut i = 0;
    while i < bytes.len() {
        let b = bytes[i];
        if matches!(b, b'"' | b'\'' | b'`') {
            if let Some(s) =
                source::quoted_string(bytes, i + 1, b, TemplateMode::ReplaceExpressions)
            {
                push_route(out, &s);
            }
            i = source::quoted_end(bytes, i + 1, b).map_or(i + 1, |end| end + 1);
            continue;
        }
        i += 1;
    }
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

pub fn build_id(bytes: &[u8]) -> Option<String> {
    string_value_after_key(bytes, b"buildId").filter(|value| {
        (4..=128).contains(&value.len())
            && value
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_'))
    })
}

pub fn app_base_url(bytes: &[u8]) -> Option<String> {
    string_value_after_key(bytes, b"baseURL").filter(|value| value.starts_with('/'))
}

pub fn app_cdn_url(bytes: &[u8]) -> Option<String> {
    string_value_after_key(bytes, b"cdnURL")
        .filter(|value| value.starts_with("http://") || value.starts_with("https://"))
}

pub fn build_assets_dir(bytes: &[u8]) -> Option<String> {
    string_value_after_key(bytes, b"buildAssetsDir").filter(|value| value.contains("_nuxt"))
}

fn join_paths(left: &str, right: &str) -> String {
    let left = left.trim_end_matches('/');
    let right = right.trim_start_matches('/');
    if left.is_empty() {
        format!("/{right}")
    } else {
        format!("{left}/{right}")
    }
}

fn string_value_after_key(bytes: &[u8], key: &[u8]) -> Option<String> {
    source::keyed_string_value(bytes, key, b":", true)
}

fn push_resolved_asset(
    url: Url,
    kind: AssetKind,
    seen: &mut FxHashSet<Url>,
    out: &mut Vec<AssetRef>,
) {
    if seen.insert(url.clone()) {
        out.push(AssetRef {
            url,
            kind,
            source: AssetSource::FrameworkManifest,
        });
    }
}
