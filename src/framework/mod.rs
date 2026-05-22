use crate::discover::{AssetKind, DocumentKind};
use crate::scan::next::NextConfig;
use crate::scan::{Extractor, FindingsBuilder, Shape};
use crate::source;
use serde::{Deserialize, Serialize};
use url::Url;

pub mod astro;
pub mod next;
pub mod nuxt;
pub mod remix;
pub mod sveltekit;

const MANIFEST_POLICIES: &[fn(&str) -> bool] = &[
    next::is_manifest,
    nuxt::is_manifest,
    sveltekit::is_manifest,
    remix::is_manifest,
];
const PAYLOAD_POLICIES: &[fn(&str, &str) -> bool] = &[
    next::is_payload,
    nuxt::is_payload,
    sveltekit::is_payload,
    astro::is_payload,
    remix::is_payload,
];
const SKIP_POLICIES: &[fn(&Url) -> bool] = &[
    next::should_skip,
    nuxt::should_skip,
    sveltekit::should_skip,
    astro::should_skip,
    remix::should_skip,
];

#[derive(Clone, Debug, Default)]
pub struct AssetContext {
    pub next: bool,
    pub nuxt: bool,
    pub sveltekit: bool,
    pub sveltekit_immutable_root: Option<String>,
    pub astro: bool,
    pub remix: bool,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "kind", content = "config")]
pub enum FrameworkConfig {
    #[default]
    None,
    Next(NextConfig),
    Nuxt,
    SvelteKit,
    Astro,
    Remix,
}

impl FrameworkConfig {
    pub fn is_none(&self) -> bool {
        matches!(self, Self::None)
    }

    pub fn as_next(&self) -> Option<&NextConfig> {
        match self {
            Self::Next(config) => Some(config),
            _ => None,
        }
    }

    pub fn label(&self) -> Option<String> {
        match self {
            Self::None => None,
            Self::Next(cfg) => Some(match cfg.build_id.as_deref() {
                Some(build) if !build.is_empty() => format!("Next.js (build {build})"),
                _ => "Next.js".to_string(),
            }),
            Self::Nuxt => Some("Nuxt".to_string()),
            Self::SvelteKit => Some("SvelteKit".to_string()),
            Self::Astro => Some("Astro".to_string()),
            Self::Remix => Some("Remix".to_string()),
        }
    }
}

impl From<Option<NextConfig>> for FrameworkConfig {
    fn from(value: Option<NextConfig>) -> Self {
        value.map(Self::Next).unwrap_or_default()
    }
}

pub fn request_headers(url: &Url) -> Vec<(&'static str, &'static str)> {
    if next::is_rsc_payload(url) {
        vec![("RSC", "1")]
    } else {
        Vec::new()
    }
}

pub fn classify_asset(raw: &str) -> Option<AssetKind> {
    let path = raw.split(['?', '#']).next().unwrap_or(raw);
    if MANIFEST_POLICIES.iter().any(|policy| policy(path)) {
        Some(AssetKind::Manifest)
    } else if PAYLOAD_POLICIES.iter().any(|policy| policy(raw, path)) {
        Some(AssetKind::Payload)
    } else if crate::source::ends_with_ascii_ignore_case(path, ".js")
        || crate::source::ends_with_ascii_ignore_case(path, ".mjs")
    {
        Some(AssetKind::Script)
    } else {
        None
    }
}

pub fn should_skip(url: &Url) -> bool {
    SKIP_POLICIES.iter().any(|policy| policy(url))
}

pub fn resolve_asset(base: &Url, raw: &str, context: &AssetContext) -> Option<Url> {
    let raw = raw.trim_matches('\\');
    if raw.is_empty() || raw.starts_with("data:") || raw.starts_with("blob:") {
        return None;
    }
    if let Some(url) = next::resolve_asset(base, raw, context.next)
        .or_else(|| nuxt::resolve_asset(base, raw))
        .or_else(|| nuxt::resolve_context_asset(base, raw, context.nuxt))
        .or_else(|| sveltekit::resolve_asset(base, raw))
        .or_else(|| {
            sveltekit::resolve_context_asset(
                base,
                raw,
                context.sveltekit,
                context.sveltekit_immutable_root.as_deref(),
            )
        })
        .or_else(|| astro::resolve_asset(base, raw))
        .or_else(|| remix::resolve_asset(base, raw))
        .or_else(|| remix::resolve_context_asset(base, raw, context.remix))
    {
        return Some(url);
    }
    if is_context_relative_asset(raw) {
        return None;
    }

    let absolute = if raw.starts_with("static/") && context.next {
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
    context: &AssetContext,
    findings: &mut FindingsBuilder,
) {
    let extractor = if context.nuxt {
        Some(Extractor::NuxtPayload)
    } else if context.sveltekit {
        Some(Extractor::SvelteKitData)
    } else if context.remix {
        Some(Extractor::RemixManifest)
    } else if context.astro {
        Some(Extractor::AstroIsland)
    } else {
        None
    };
    let Some(extractor) = extractor else {
        return;
    };

    record_payload_route(base, kind, extractor, findings);
    scan_api_tokens(bytes, extractor, findings);
    if context.nuxt {
        nuxt::record_endpoint_maps(bytes, findings);
        if matches!(kind, DocumentKind::Manifest | DocumentKind::Payload) {
            nuxt::record_routes(bytes, findings);
        } else {
            nuxt::record_page_route(bytes, findings);
        }
        scan_nuxt_islands(bytes, findings);
    }
    if context.sveltekit {
        sveltekit::record_form_actions(bytes, base, findings);
        sveltekit::record_data_dependencies(bytes, findings);
    }
    if context.astro {
        scan_astro_actions(bytes, findings);
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
    extractor: Extractor,
    findings: &mut FindingsBuilder,
) {
    if !matches!(kind, DocumentKind::Payload | DocumentKind::Manifest) {
        return;
    }
    let route = match extractor {
        Extractor::NuxtPayload => nuxt::route_from_payload(base),
        Extractor::SvelteKitData => sveltekit::route_from_payload(base),
        Extractor::RemixManifest => {
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
        Extractor::AstroIsland => base
            .path()
            .strip_suffix(".json")
            .filter(|route| crate::scan::classify::is_client_route(route))
            .map(str::to_owned),
        _ => None,
    };
    if let Some(route) = route {
        findings.record_route(route, extractor);
    }
}

fn scan_api_tokens(bytes: &[u8], extractor: Extractor, findings: &mut FindingsBuilder) {
    for marker in [
        b"/api/".as_slice(),
        b"/graphql".as_slice(),
        b"/trpc".as_slice(),
    ] {
        for pos in memchr::memmem::find_iter(bytes, marker) {
            let start = source::walk_token_start(bytes, pos);
            if !source::is_string_literal_start(bytes, start) {
                continue;
            }
            if let Some(raw) = source::token_string(bytes, start, source::TemplateMode::Preserve) {
                if crate::scan::classify::is_api_candidate(&raw) {
                    findings.record_candidate(
                        crate::scan::classify::normalize_api_url(&raw),
                        extractor,
                    );
                }
            }
        }
    }
}

fn scan_astro_actions(bytes: &[u8], findings: &mut FindingsBuilder) {
    for pos in memchr::memmem::find_iter(bytes, b"/_actions/") {
        let start = source::walk_token_start(bytes, pos);
        if !source::is_string_literal_start(bytes, start) {
            continue;
        }
        let Some(raw) = source::token_string(bytes, start, source::TemplateMode::Preserve) else {
            continue;
        };
        findings.record_api(
            raw,
            Shape::inferred(Some("POST"), true),
            Extractor::AstroIsland,
        );
    }
}

fn scan_nuxt_islands(bytes: &[u8], findings: &mut FindingsBuilder) {
    for pos in memchr::memmem::find_iter(bytes, b"/__nuxt_island/") {
        let start = source::walk_token_start(bytes, pos);
        if !source::is_string_literal_start(bytes, start) {
            continue;
        }
        let Some(raw) = source::token_string(bytes, start, source::TemplateMode::Preserve) else {
            continue;
        };
        findings.record_api(
            raw,
            Shape::inferred(Some("GET"), false),
            Extractor::NuxtPayload,
        );
    }
}
