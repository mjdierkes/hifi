use crate::discover::{AssetKind, AssetRef, AssetSource, DocumentKind};
use crate::generated::{
    API_PATH_PREFIXES, ASTRO_SKIP_FRAGMENTS, NEXT_SKIP_FRAGMENTS, REMIX_SKIP_FRAGMENTS,
};
use crate::hash::FxHashSet;
use crate::scan::findings::{Channel, FindingsBuilder, Provenance};
use crate::scan::Shape;
use crate::framework::next::NextConfig;
use crate::source;
use crate::url::Url;

pub mod next;
pub mod nuxt;
pub mod sveltekit;
mod resolve;
mod site;

pub use site::{DetectedSite, FrameworkId};

struct FrameworkPolicy {
    id: FrameworkId,
    detect: fn(&[u8], &Url, Option<&NextConfig>) -> bool,
    should_skip: fn(&Url) -> bool,
    is_manifest: fn(&str) -> bool,
    is_payload: fn(&str, &str) -> bool,
    resolve: fn(&Url, &str, &DetectedSite) -> Option<Url>,
}

const POLICIES: &[FrameworkPolicy] = &[
    FrameworkPolicy {
        id: FrameworkId::Next,
        detect: |bytes, base, cfg| next::is_context(bytes, base, cfg),
        should_skip: |url| resolve::should_skip_fragments(url, "/_next/", NEXT_SKIP_FRAGMENTS),
        is_manifest: next::is_manifest,
        is_payload: next::is_payload,
        resolve: |base, raw, site| next::resolve_asset(base, raw, site.has(FrameworkId::Next)),
    },
    FrameworkPolicy {
        id: FrameworkId::Nuxt,
        detect: |bytes, base, _| nuxt::is_context(bytes, base),
        should_skip: nuxt::should_skip,
        is_manifest: nuxt::is_manifest,
        is_payload: nuxt::is_payload,
        resolve: |base, raw, site| nuxt::resolve(base, raw, site.has(FrameworkId::Nuxt)),
    },
    FrameworkPolicy {
        id: FrameworkId::SvelteKit,
        detect: |bytes, base, _| sveltekit::is_context(bytes, base),
        should_skip: sveltekit::should_skip,
        is_manifest: sveltekit::is_manifest,
        is_payload: sveltekit::is_payload,
        resolve: |base, raw, site| {
            sveltekit::resolve(
                base,
                raw,
                site.has(FrameworkId::SvelteKit),
                site.sveltekit_immutable_root.as_deref(),
            )
        },
    },
    FrameworkPolicy {
        id: FrameworkId::Astro,
        detect: |bytes, base, _| site::is_astro_context(bytes, base),
        should_skip: |url| {
            resolve::should_skip_fragments(url, "/_astro/", ASTRO_SKIP_FRAGMENTS)
        },
        is_manifest: |_| false,
        is_payload: |raw, path| raw.contains("/_actions/") || path.contains("/_server-islands/"),
        resolve: |base, raw, _| resolve::resolve_prefixed(base, raw, "_astro/"),
    },
    FrameworkPolicy {
        id: FrameworkId::Remix,
        detect: |bytes, base, _| site::is_remix_context(bytes, base),
        should_skip: |url| resolve::path_contains_any(url.path(), REMIX_SKIP_FRAGMENTS),
        is_manifest: |path| {
            resolve::manifest_matches(
                path,
                &["/manifest.js", "/manifest.json"],
                &[],
                &[],
            )
        },
        is_payload: |raw, path| {
            raw.contains("?_data=") || raw.contains("&_data=") || path.contains("/_data/")
        },
        resolve: |base, raw, site| resolve::resolve_remix(base, raw, site.has(FrameworkId::Remix)),
    },
];

pub(crate) fn route_from_suffix(base: &Url, suffix: &str) -> Option<String> {
    let route = base.path().strip_suffix(suffix)?;
    Some(if route.is_empty() {
        "/".to_owned()
    } else {
        route.to_owned()
    })
}

pub(crate) fn join_paths(left: &str, right: &str) -> String {
    let left = left.trim_end_matches('/');
    let right = right.trim_start_matches('/');
    if left.is_empty() {
        format!("/{right}")
    } else if right.is_empty() {
        left.to_owned()
    } else {
        format!("{left}/{right}")
    }
}

pub(crate) fn json_slice(bytes: &[u8]) -> &[u8] {
    match bytes.iter().position(|b| matches!(*b, b'{' | b'[')) {
        Some(0) => bytes,
        Some(start) => &bytes[start..],
        None => bytes,
    }
}

pub(crate) fn scan_quoted_after_markers(
    bytes: &[u8],
    markers: &[&str],
    mode: source::TemplateMode,
    mut visit: impl FnMut(&str),
) {
    for marker in markers {
        for pos in memchr::memmem::find_iter(bytes, marker.as_bytes()) {
            let start = source::walk_token_start(bytes, pos);
            if !source::is_string_literal_start(bytes, start) {
                continue;
            }
            if let Some(raw) = source::token_string(bytes, start, mode) {
                visit(&raw);
            }
        }
    }
}

pub(crate) fn scan_quoted_strings(bytes: &[u8], mode: source::TemplateMode, mut visit: impl FnMut(&str)) {
    let mut i = 0;
    while i < bytes.len() {
        let quote = bytes[i];
        if matches!(quote, b'"' | b'\'' | b'`') {
            if let Some(raw) = source::quoted_string(bytes, i + 1, quote, mode) {
                visit(&raw);
            }
            i = source::quoted_end(bytes, i + 1, quote).map_or(i + 1, |end| end + 1);
            continue;
        }
        i += 1;
    }
}

pub(crate) fn scan_key_windows(
    bytes: &[u8],
    keys: &[&[u8]],
    window_len: usize,
    mut visit: impl FnMut(usize, &[u8], &[u8]),
) {
    for key in keys {
        let mut offset = 0;
        while let Some(rel) = memchr::memmem::find(&bytes[offset..], key) {
            let pos = offset + rel;
            if source::is_identifier_boundary(bytes, pos, key.len()) {
                let end = if window_len == 0 {
                    bytes.len()
                } else {
                    bytes.len().min(pos + window_len)
                };
                visit(pos, key, &bytes[pos..end]);
            }
            offset = pos + key.len();
        }
    }
}

pub fn request_headers(url: &Url) -> &'static [(&'static str, &'static str)] {
    if next::is_rsc_payload(url) {
        &[("RSC", "1")]
    } else {
        &[]
    }
}

pub fn is_payload_candidate(raw: &str) -> bool {
    let path = raw.split(['?', '#']).next().unwrap_or(raw);
    POLICIES.iter().any(|p| (p.is_payload)(raw, path))
}

pub fn classify_asset(raw: &str) -> Option<AssetKind> {
    let path = raw.split(['?', '#']).next().unwrap_or(raw);
    if POLICIES.iter().any(|p| (p.is_manifest)(path)) {
        Some(AssetKind::Manifest)
    } else if is_payload_candidate(raw) {
        Some(AssetKind::Payload)
    } else if source::ends_with_ascii_ignore_case(path, ".js")
        || source::ends_with_ascii_ignore_case(path, ".mjs")
    {
        Some(AssetKind::Script)
    } else {
        None
    }
}

pub fn should_skip(url: &Url) -> bool {
    POLICIES.iter().any(|p| (p.should_skip)(url))
}

pub fn resolve_asset(base: &Url, raw: &str, site: &DetectedSite) -> Option<Url> {
    let raw = raw.trim_matches('\\');
    if raw.is_empty() || raw.starts_with("data:") || raw.starts_with("blob:") {
        return None;
    }
    for policy in POLICIES {
        if let Some(url) = (policy.resolve)(base, raw, site) {
            return Some(url);
        }
    }
    if is_context_relative_asset(raw) {
        return None;
    }
    let absolute = if raw.starts_with("static/") && site.has(FrameworkId::Next) {
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

pub fn scan_data_findings(
    bytes: &[u8],
    base: &Url,
    kind: DocumentKind,
    site: &DetectedSite,
    findings: &mut FindingsBuilder,
) {
    if site.has(FrameworkId::Nuxt) {
        scan_common_data_findings(bytes, base, kind, FrameworkId::Nuxt, findings);
        nuxt::record_endpoint_maps(bytes, findings);
        if matches!(kind, DocumentKind::Manifest | DocumentKind::Payload) {
            nuxt::record_routes(bytes, findings);
        } else {
            nuxt::record_page_route(bytes, findings);
        }
        scan_nuxt_islands(bytes, findings);
    }
    if site.has(FrameworkId::SvelteKit) {
        scan_common_data_findings(bytes, base, kind, FrameworkId::SvelteKit, findings);
        sveltekit::record_form_actions(bytes, base, findings);
        sveltekit::record_data_dependencies(bytes, findings);
    }
    if site.has(FrameworkId::Remix) {
        scan_common_data_findings(bytes, base, kind, FrameworkId::Remix, findings);
    }
    if site.has(FrameworkId::Astro) {
        scan_common_data_findings(bytes, base, kind, FrameworkId::Astro, findings);
        scan_astro_actions(bytes, findings);
    }
}

fn scan_common_data_findings(
    bytes: &[u8],
    base: &Url,
    kind: DocumentKind,
    framework: FrameworkId,
    findings: &mut FindingsBuilder,
) {
    record_payload_route(base, kind, framework, findings);
    scan_api_tokens(bytes, framework, findings);
}

pub fn scan_document(
    bytes: &[u8],
    base: &Url,
    kind: DocumentKind,
    site: &DetectedSite,
    next_config: Option<&NextConfig>,
    findings: &mut FindingsBuilder,
    assets: &mut Vec<AssetRef>,
    seen: &mut FxHashSet<Url>,
) {
    if let Some(routes) = next::parse_manifest_routes(bytes, base, kind) {
        for route in routes {
            if !crate::scan::classify::is_client_route(&route) {
                continue;
            }
            findings.record_route(route, Provenance::channel(Channel::Manifest));
        }
    }

    scan_data_findings(bytes, base, kind, site, findings);
    next::scan_flight(bytes, findings);
    next::scan_server_action(bytes, base, kind, next_config, findings);
    if site.has(FrameworkId::SvelteKit) {
        let routes = sveltekit::record_routes(bytes, findings);
        sveltekit::push_data_assets_for_routes(
            &routes,
            base,
            sveltekit::base_path(bytes).as_deref(),
            seen,
            assets,
        );
    }
    if kind == DocumentKind::Html {
        if let Some(revision) = next::revision(bytes, site.has(FrameworkId::Next), next_config) {
            next::push_manifests(
                bytes,
                base,
                &revision,
                next_config,
                site.has(FrameworkId::Next),
                seen,
                assets,
            );
        }
        if site.has(FrameworkId::Nuxt) {
            nuxt::push_manifests(bytes, base, seen, assets);
        }
        if site.has(FrameworkId::SvelteKit) {
            sveltekit::push_manifests(bytes, base, seen, assets);
        }
    }
}

fn is_context_relative_asset(raw: &str) -> bool {
    raw.starts_with("nodes/")
        || raw.starts_with("chunks/")
        || raw.starts_with("entry/")
        || raw.starts_with("routes/")
        || raw.starts_with("assets/routes/")
}

fn record_payload_route(
    base: &Url,
    kind: DocumentKind,
    framework: FrameworkId,
    findings: &mut FindingsBuilder,
) {
    if !matches!(kind, DocumentKind::Payload | DocumentKind::Manifest) {
        return;
    }
    let route = match framework {
        FrameworkId::Nuxt => route_from_suffix(base, "/_payload.json"),
        FrameworkId::SvelteKit => route_from_suffix(base, "/__data.json"),
        FrameworkId::Remix => {
            let path = base.path();
            if base.query_pairs().any(|(key, _)| key == "_data") {
                Some(path.to_owned())
            } else {
                path.strip_suffix("/_payload.json")
                    .or_else(|| path.strip_suffix("/__data.json"))
                    .map(|route| {
                        if route.is_empty() {
                            "/".to_owned()
                        } else {
                            route.to_owned()
                        }
                    })
            }
        }
        FrameworkId::Astro => base
            .path()
            .strip_suffix(".json")
            .filter(|route| crate::scan::classify::is_client_route(route))
            .map(str::to_owned),
        FrameworkId::Next => None,
    };
    if let Some(route) = route {
        findings.record_route(route, Provenance::framework(Channel::Manifest, framework));
    }
}

fn scan_api_tokens(bytes: &[u8], framework: FrameworkId, findings: &mut FindingsBuilder) {
    scan_quoted_after_markers(bytes, API_PATH_PREFIXES, source::TemplateMode::Preserve, |raw| {
        if crate::scan::classify::is_api_candidate(raw) {
            findings.record_candidate(
                crate::scan::classify::normalize_api_url(raw),
                Provenance::framework(Channel::Literal, framework),
            );
        }
    });
}

fn scan_astro_actions(bytes: &[u8], findings: &mut FindingsBuilder) {
    scan_quoted_after_markers(
        bytes,
        &["/_actions/"],
        source::TemplateMode::Preserve,
        |raw| {
            findings.record_api(
                raw.to_owned(),
                Shape::inferred(Some("POST"), true),
                Provenance::framework(Channel::Literal, FrameworkId::Astro),
            );
        },
    );
}

fn scan_nuxt_islands(bytes: &[u8], findings: &mut FindingsBuilder) {
    scan_quoted_after_markers(
        bytes,
        &["/__nuxt_island/"],
        source::TemplateMode::Preserve,
        |raw| {
            findings.record_api(
                raw.to_owned(),
                Shape::inferred(Some("GET"), false),
                Provenance::framework(Channel::Literal, FrameworkId::Nuxt),
            );
        },
    );
}

pub(crate) fn push_asset(
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
