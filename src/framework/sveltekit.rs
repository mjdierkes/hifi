//! SvelteKit discovery policy.

use crate::discover::{AssetKind, AssetRef, AssetSource};
use crate::hash::FxHashSet;
use crate::scan::{Extractor, Shape};
use crate::source;
use crate::source::TemplateMode;
use crate::url::Url;

const SKIP_FRAGMENTS: &[&str] = &[
    "/_app/immutable/chunks/scheduler.",
    "/_app/immutable/chunks/index.",
    "/_app/immutable/chunks/runtime.",
    "/_app/immutable/chunks/vendor",
];

pub fn is_context(bytes: &[u8], base: &Url) -> bool {
    base.path().contains("/_app/immutable/")
        || base.path().contains("/immutable/")
        || base.path().ends_with("/__data.json")
        || source::contains(bytes, b"/_app/immutable/")
        || source::contains(bytes, b"/immutable/entry/")
        || source::contains(bytes, b"/immutable/nodes/")
        || source::contains(bytes, b"/immutable/chunks/")
        || source::contains(bytes, b"/_app/version.json")
        || source::contains(bytes, b"__sveltekit_")
        || source::contains(bytes, b"__SVELTEKIT")
        || source::contains(bytes, b"data-sveltekit")
        || source::contains(bytes, b"x-sveltekit-action")
        || source::contains(bytes, b"x-sveltekit-invalidated")
        || source::contains(bytes, b"/__data.json")
}

pub fn should_skip(url: &Url) -> bool {
    let path = url.path();
    path.contains("/immutable/")
        && SKIP_FRAGMENTS
            .iter()
            .any(|fragment| path.contains(fragment))
}

pub fn is_manifest(path: &str) -> bool {
    source::ends_with_ascii_ignore_case(path, "/_app/version.json")
        || (source::ends_with_ascii_ignore_case(path, "/version.json")
            && path.contains("/immutable/"))
}

pub fn is_payload(raw: &str, path: &str) -> bool {
    source::ends_with_ascii_ignore_case(path, "/__data.json") || raw.contains("/__data.json?")
}

pub fn resolve_asset(base: &Url, raw: &str) -> Option<Url> {
    if raw.starts_with("_app/") {
        return base.join(&format!("/{raw}")).ok();
    }
    None
}

pub fn resolve_context_asset(
    base: &Url,
    raw: &str,
    context: bool,
    immutable_root: Option<&str>,
) -> Option<Url> {
    if !context {
        return None;
    }
    if raw.starts_with("nodes/")
        || raw.starts_with("chunks/")
        || raw.starts_with("entry/")
        || raw.starts_with("assets/")
    {
        let root = immutable_root
            .map(str::to_owned)
            .or_else(|| observed_immutable_root(base))
            .unwrap_or_else(|| "/_app/immutable/".to_owned());
        return base.join(&format!("{root}{raw}")).ok();
    }
    None
}

pub fn route_from_payload(base: &Url) -> Option<String> {
    let path = base.path();
    let route = path.strip_suffix("/__data.json")?;
    Some(if route.is_empty() {
        "/".to_owned()
    } else {
        route.to_owned()
    })
}

pub fn data_path_for_route(route: &str) -> Option<String> {
    if !crate::scan::classify::is_client_route(route) {
        return None;
    }
    Some(if route == "/" {
        "/__data.json".to_owned()
    } else {
        format!("{}/__data.json", route.trim_end_matches('/'))
    })
}

pub fn data_path_for_route_with_base(route: &str, base_path: Option<&str>) -> Option<String> {
    let data = data_path_for_route(route)?;
    let Some(base_path) = base_path
        .map(str::trim)
        .filter(|base| !base.is_empty() && *base != "/")
    else {
        return Some(data);
    };
    Some(super::join_paths(base_path, &data))
}

pub fn push_manifests(
    bytes: &[u8],
    base: &Url,
    seen: &mut FxHashSet<Url>,
    out: &mut Vec<AssetRef>,
) {
    for root in immutable_roots(bytes, base) {
        let Some(app_root) = app_root_from_immutable(&root) else {
            continue;
        };
        let Ok(url) = base.join(&format!("{app_root}version.json")) else {
            continue;
        };
        super::push_asset(
            url,
            AssetKind::Manifest,
            AssetSource::FrameworkManifest,
            seen,
            out,
        );
    }
}

pub fn push_data_assets_for_routes(
    routes: &[String],
    base: &Url,
    base_path: Option<&str>,
    seen: &mut FxHashSet<Url>,
    out: &mut Vec<AssetRef>,
) {
    for route in routes {
        let Some(path) = data_path_for_route_with_base(route, base_path) else {
            continue;
        };
        let Ok(url) = base.join(&path) else {
            continue;
        };
        super::push_asset(
            url,
            AssetKind::Payload,
            AssetSource::FrameworkManifest,
            seen,
            out,
        );
    }
}

pub fn primary_immutable_root(bytes: &[u8], base: &Url) -> Option<String> {
    observed_immutable_root(base)
        .or_else(|| {
            let mut roots = Vec::new();
            collect_literal_immutable_roots(bytes, &mut roots);
            roots.into_iter().next()
        })
        .or_else(|| app_dir(bytes).map(|dir| format!("/{}/immutable/", dir.trim_matches('/'))))
        .or_else(|| Some("/_app/immutable/".to_owned()))
}

pub fn base_path(bytes: &[u8]) -> Option<String> {
    string_value_after_key(bytes, b"base")
        .or_else(|| string_value_after_key(bytes, b"baseUrl"))
        .or_else(|| string_value_after_key(bytes, b"paths.base"))
        .filter(|value| value.starts_with('/') && !value.starts_with("//"))
}

pub fn routes(bytes: &[u8]) -> Vec<String> {
    let mut routes = parse_routes(bytes);
    routes.sort();
    routes.dedup();
    routes
}

pub fn record_routes(bytes: &[u8], findings: &mut crate::scan::FindingsBuilder) -> Vec<String> {
    let routes = routes(bytes);
    for route in &routes {
        findings.record_route(route.clone(), Extractor::SvelteKitData);
    }
    routes
}

pub fn record_form_actions(bytes: &[u8], base: &Url, findings: &mut crate::scan::FindingsBuilder) {
    scan_action_attrs(bytes, base, findings);
    scan_action_literals(bytes, base, findings);
    if source::contains(bytes, b"x-sveltekit-action") || source::contains(bytes, b"enhance(") {
        if let Some(route) = route_from_page(base) {
            findings.record_api(
                route,
                Shape::inferred(Some("POST"), true),
                Extractor::SvelteKitData,
            );
        }
    }
}

pub fn record_data_dependencies(bytes: &[u8], findings: &mut crate::scan::FindingsBuilder) {
    let slice = super::json_slice(bytes);
    crate::json::walk_strings(slice, |key, value| {
        if key.is_some_and(dependency_key_context) {
            record_dependency_url(value, findings);
        }
    });
    collect_literal_dependency_values(bytes, findings);
}

fn parse_routes(bytes: &[u8]) -> Vec<String> {
    let mut out = Vec::new();
    let slice = super::json_slice(bytes);
    crate::json::walk(slice, |evt| match evt {
        crate::json::Visit::Key(key) if key.starts_with('/') => push_route(&mut out, key),
        crate::json::Visit::String(Some(k), value) if route_key_context(k) => {
            push_route(&mut out, value)
        }
        _ => {}
    });
    collect_literal_routes(bytes, &mut out);
    out
}

fn immutable_roots(bytes: &[u8], base: &Url) -> Vec<String> {
    let mut out = Vec::new();
    if let Some(root) = observed_immutable_root(base) {
        out.push(root);
    }
    collect_literal_immutable_roots(bytes, &mut out);
    if let Some(app_dir) = app_dir(bytes) {
        out.push(format!("/{}/immutable/", app_dir.trim_matches('/')));
    }
    out.push("/_app/immutable/".to_owned());
    out.sort();
    out.dedup();
    out
}

fn observed_immutable_root(base: &Url) -> Option<String> {
    let path = base.path();
    let pos = path.find("/immutable/")?;
    Some(path[..pos + "/immutable/".len()].to_owned())
}

fn app_root_from_immutable(root: &str) -> Option<String> {
    root.strip_suffix("immutable/").map(str::to_owned)
}

fn collect_literal_immutable_roots(bytes: &[u8], out: &mut Vec<String>) {
    for marker in [
        b"/immutable/entry/".as_slice(),
        b"/immutable/nodes/".as_slice(),
        b"/immutable/chunks/".as_slice(),
        b"/immutable/assets/".as_slice(),
    ] {
        for pos in memchr::memmem::find_iter(bytes, marker) {
            let start = source::walk_token_start(bytes, pos);
            if !source::is_string_literal_start(bytes, start) {
                continue;
            }
            let Some(raw) = source::token_string(bytes, start, TemplateMode::Preserve) else {
                continue;
            };
            let Some(root) = root_before_immutable_child(&raw) else {
                continue;
            };
            out.push(root);
        }
    }
}

fn root_before_immutable_child(raw: &str) -> Option<String> {
    for child in [
        "/immutable/entry/",
        "/immutable/nodes/",
        "/immutable/chunks/",
        "/immutable/assets/",
    ] {
        if let Some(pos) = raw.find(child) {
            return Some(raw[..pos + "/immutable/".len()].to_owned());
        }
    }
    None
}

fn app_dir(bytes: &[u8]) -> Option<String> {
    string_value_after_key(bytes, b"appDir")
        .or_else(|| string_value_after_key(bytes, b"app_dir"))
        .filter(|value| {
            !value.is_empty()
                && !value.contains("..")
                && value
                    .bytes()
                    .all(|b| b == b'_' || b == b'-' || b == b'/' || b.is_ascii_alphanumeric())
        })
}

fn string_value_after_key(bytes: &[u8], key: &[u8]) -> Option<String> {
    source::keyed_string_value(bytes, key, b":=", false)
}

fn collect_literal_routes(bytes: &[u8], out: &mut Vec<String>) {
    collect_keyed_literal_routes(bytes, out);
    collect_route_id_literals(bytes, out);
    collect_pattern_routes(bytes, out);
}

fn collect_keyed_literal_routes(bytes: &[u8], out: &mut Vec<String>) {
    for key in [
        b"id".as_slice(),
        b"route".as_slice(),
        b"path".as_slice(),
        b"href".as_slice(),
    ] {
        let mut offset = 0;
        while let Some(rel) = memchr::memmem::find(&bytes[offset..], key) {
            let pos = offset + rel;
            if !source::is_identifier_boundary_before(bytes, pos) {
                offset = pos + key.len();
                continue;
            }
            let mut i = source::skip_ws(bytes, pos + key.len());
            if bytes.get(i) != Some(&b':') {
                offset = pos + key.len();
                continue;
            }
            i = source::skip_ws(bytes, i + 1);
            let Some(route) = source::quoted_string_at(bytes, i, TemplateMode::Preserve) else {
                offset = pos + key.len();
                continue;
            };
            push_route(out, &route);
            offset = i + route.len();
        }
    }
}

fn collect_route_id_literals(bytes: &[u8], out: &mut Vec<String>) {
    for marker in [b"/[".as_slice(), b"/(".as_slice()] {
        for pos in memchr::memmem::find_iter(bytes, marker) {
            let start = source::walk_token_start(bytes, pos);
            if !source::is_string_literal_start(bytes, start) {
                continue;
            }
            let Some(route) = source::token_string(bytes, start, TemplateMode::Preserve) else {
                continue;
            };
            push_route(out, &route);
        }
    }
}

fn collect_pattern_routes(bytes: &[u8], out: &mut Vec<String>) {
    let mut offset = 0;
    while let Some(rel) = memchr::memmem::find(&bytes[offset..], b"pattern") {
        let pos = offset + rel;
        let search_end = bytes.len().min(pos + 512);
        if let Some(route) = route_from_regex_window(&bytes[pos..search_end]) {
            push_route(out, &route);
        }
        offset = pos + b"pattern".len();
    }
}

fn route_from_regex_window(bytes: &[u8]) -> Option<String> {
    let caret = memchr::memchr(b'^', bytes)?;
    let mut params = params_from_window(bytes);
    let mut out = String::from("/");
    let mut i = caret + 1;
    while i < bytes.len() {
        match bytes[i] {
            b'\\' if bytes.get(i + 1) == Some(&b'/') => {
                if !out.ends_with('/') {
                    out.push('/');
                }
                i += 2;
            }
            b'(' => {
                let name = if params.is_empty() {
                    "param".to_owned()
                } else {
                    params.remove(0)
                };
                if !out.ends_with('/') {
                    out.push('/');
                }
                out.push('[');
                out.push_str(&name);
                out.push(']');
                i = skip_group(bytes, i + 1);
            }
            b'$' => break,
            b'\\' if bytes.get(i + 1).is_some_and(|b| b.is_ascii_alphanumeric()) => break,
            b'?' if bytes.get(i.saturating_sub(1)) == Some(&b'/') => break,
            b'/' | b':' | b',' | b'}' | b']' => break,
            b if route_literal_byte(b) => {
                out.push(b as char);
                i += 1;
            }
            _ => i += 1,
        }
    }
    let route = out.trim_end_matches('/').to_owned();
    if route.is_empty() || route == "[" || route == "/" {
        None
    } else {
        Some(route)
    }
}

fn params_from_window(bytes: &[u8]) -> Vec<String> {
    let mut out = Vec::new();
    for key in [b"params".as_slice(), b"names".as_slice()] {
        let Some(pos) = memchr::memmem::find(bytes, key) else {
            continue;
        };
        let mut i = pos + key.len();
        while i < bytes.len().min(pos + 256) {
            if let Some(value) = source::quoted_string_at(bytes, i, TemplateMode::Preserve) {
                if value
                    .bytes()
                    .all(|b| b == b'_' || b == b'-' || b.is_ascii_alphanumeric())
                {
                    out.push(value);
                }
            }
            i += 1;
        }
        if !out.is_empty() {
            break;
        }
    }
    out
}

fn skip_group(bytes: &[u8], mut i: usize) -> usize {
    let mut depth = 1;
    while i < bytes.len() && depth > 0 {
        match bytes[i] {
            b'\\' if i + 1 < bytes.len() => i += 2,
            b'(' => {
                depth += 1;
                i += 1;
            }
            b')' => {
                depth -= 1;
                i += 1;
            }
            _ => i += 1,
        }
    }
    i
}

fn route_literal_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'~')
}

fn collect_literal_dependency_values(bytes: &[u8], findings: &mut crate::scan::FindingsBuilder) {
    for key in [
        b"dependencies".as_slice(),
        b"dependency".as_slice(),
        b"depends".as_slice(),
        b"action".as_slice(),
    ] {
        let mut offset = 0;
        while let Some(rel) = memchr::memmem::find(&bytes[offset..], key) {
            let pos = offset + rel;
            let end = bytes.len().min(pos + 1024);
            scan_dependency_window(&bytes[pos..end], findings);
            offset = pos + key.len();
        }
    }
}

fn scan_dependency_window(bytes: &[u8], findings: &mut crate::scan::FindingsBuilder) {
    for marker in [
        b"/api".as_slice(),
        b"/graphql".as_slice(),
        b"/trpc".as_slice(),
    ] {
        for pos in memchr::memmem::find_iter(bytes, marker) {
            let start = source::walk_token_start(bytes, pos);
            if !source::is_string_literal_start(bytes, start) {
                continue;
            }
            let Some(raw) = source::token_string(bytes, start, TemplateMode::Preserve) else {
                continue;
            };
            record_dependency_url(&raw, findings);
        }
    }
}

fn scan_action_attrs(bytes: &[u8], base: &Url, findings: &mut crate::scan::FindingsBuilder) {
    let mut offset = 0;
    while let Some(rel) = source::find_ascii_ignore_case(&bytes[offset..], b"action") {
        let pos = offset + rel;
        if !attr_name_boundary(bytes, pos) {
            offset = pos + 1;
            continue;
        }
        let mut i = source::skip_ws(bytes, pos + b"action".len());
        if bytes.get(i) != Some(&b'=') {
            offset = pos + 1;
            continue;
        }
        i = source::skip_ws(bytes, i + 1);
        let Some(raw) = source::quoted_string_at(bytes, i, TemplateMode::Preserve) else {
            offset = pos + 1;
            continue;
        };
        record_action(raw.as_str(), base, findings);
        offset = i + raw.len();
    }
}

fn scan_action_literals(bytes: &[u8], base: &Url, findings: &mut crate::scan::FindingsBuilder) {
    for marker in [b"?/".as_slice(), b"/__data.json?/".as_slice()] {
        for pos in memchr::memmem::find_iter(bytes, marker) {
            let start = source::walk_token_start(bytes, pos);
            if !source::is_string_literal_start(bytes, start) {
                continue;
            }
            let Some(raw) = source::token_string(bytes, start, TemplateMode::Preserve) else {
                continue;
            };
            record_action(raw.as_str(), base, findings);
        }
    }
}

fn record_action(raw: &str, base: &Url, findings: &mut crate::scan::FindingsBuilder) {
    let route = if raw.starts_with("?/") {
        route_from_page(base)
    } else if raw.contains("/__data.json?/") {
        raw.split("/__data.json?/")
            .next()
            .filter(|route| !route.is_empty())
            .map(str::to_owned)
    } else if raw.starts_with('/') && !raw.starts_with("/_app") {
        Some(raw.split(['?', '#']).next().unwrap_or(raw).to_owned())
    } else {
        None
    };
    let Some(route) = route.filter(|route| crate::scan::classify::is_client_route(route)) else {
        return;
    };
    findings.record_api(
        route,
        Shape::inferred(Some("POST"), true),
        Extractor::SvelteKitData,
    );
}

fn record_dependency_url(raw: &str, findings: &mut crate::scan::FindingsBuilder) {
    if !crate::scan::classify::is_api_candidate(raw) {
        return;
    }
    let mut shape = Shape::inferred(Some("GET"), false);
    shape.apply_query_params(raw);
    findings.record_api(
        crate::scan::classify::normalize_api_url(raw),
        shape,
        Extractor::SvelteKitData,
    );
}

fn route_from_page(base: &Url) -> Option<String> {
    route_from_payload(base).or_else(|| {
        let path = base.path();
        crate::scan::classify::is_client_route(path).then(|| path.to_owned())
    })
}

fn push_route(out: &mut Vec<String>, raw: &str) {
    let route = normalize_route_id(raw);
    if crate::scan::classify::is_client_route(&route) {
        out.push(route);
    }
}

fn normalize_route_id(raw: &str) -> String {
    let route = raw.split(['?', '#']).next().unwrap_or(raw);
    if route == "/" {
        return route.to_owned();
    }
    let route = route.trim_end_matches('/');
    let route = route.strip_suffix("/+page").unwrap_or(route);
    let route = route.strip_suffix("/+layout").unwrap_or(route);
    if route.is_empty() {
        "/".to_owned()
    } else {
        route.to_owned()
    }
}

fn route_key_context(key: &str) -> bool {
    matches!(
        key,
        "id" | "route" | "path" | "href" | "pathname" | "page" | "url"
    )
}

fn dependency_key_context(key: &str) -> bool {
    matches!(
        key,
        "dependencies" | "dependency" | "depends" | "href" | "url" | "action"
    )
}

fn attr_name_boundary(bytes: &[u8], pos: usize) -> bool {
    (pos == 0 || matches!(bytes[pos - 1], b'<' | b'/' | b' ' | b'\n' | b'\r' | b'\t'))
        && bytes
            .get(pos + b"action".len())
            .is_some_and(|b| matches!(*b, b'=' | b' ' | b'\n' | b'\r' | b'\t'))
}
