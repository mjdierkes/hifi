//! Lightweight Remix / React Router framework discovery policy.

use crate::source;
use crate::url::Url;

const SKIP_FRAGMENTS: &[&str] = &[
    "/build/_shared/",
    "/build/manifest-",
    "/assets/manifest-",
    "/entry.client-",
];

pub fn is_context(bytes: &[u8], base: &Url) -> bool {
    base.path().contains("/build/")
        || base.query().is_some_and(|query| query.contains("_data="))
        || source::contains(bytes, b"window.__remixContext")
        || source::contains(bytes, b"__remixManifest")
        || source::contains(bytes, b"remix-route")
        || source::contains(bytes, b"/build/routes/")
}

pub fn should_skip(url: &Url) -> bool {
    let path = url.path();
    SKIP_FRAGMENTS
        .iter()
        .any(|fragment| path.contains(fragment))
}

pub fn is_manifest(path: &str) -> bool {
    source::ends_with_ascii_ignore_case(path, "/manifest.js")
        || source::ends_with_ascii_ignore_case(path, "/manifest.json")
        || path.contains("/manifest-")
}

pub fn is_payload(raw: &str, path: &str) -> bool {
    raw.contains("?_data=") || raw.contains("&_data=") || path.contains("/_data/")
}

pub fn resolve_asset(base: &Url, raw: &str) -> Option<Url> {
    if raw.starts_with("build/") {
        return base.join(&format!("/{raw}")).ok();
    }
    None
}

pub fn resolve_context_asset(base: &Url, raw: &str, context: bool) -> Option<Url> {
    if !context {
        return None;
    }
    if raw.starts_with("routes/") {
        return base.join(&format!("/build/{raw}")).ok();
    }
    if raw.starts_with("assets/routes/") {
        return base.join(&format!("/{raw}")).ok();
    }
    None
}
