//! Lightweight SvelteKit discovery policy.

use crate::source;
use url::Url;

const SKIP_FRAGMENTS: &[&str] = &[
    "/_app/immutable/chunks/scheduler.",
    "/_app/immutable/chunks/index.",
    "/_app/immutable/chunks/runtime.",
    "/_app/immutable/chunks/vendor",
    "/_app/version.json",
];

pub fn is_context(bytes: &[u8], base: &Url) -> bool {
    base.path().contains("/_app/immutable/")
        || base.path().ends_with("/__data.json")
        || source::contains(bytes, b"/_app/immutable/")
        || source::contains(bytes, b"__sveltekit_")
        || source::contains(bytes, b"data-sveltekit")
        || source::contains(bytes, b"/__data.json")
}

pub fn should_skip(url: &Url) -> bool {
    let path = url.path();
    path.contains("/_app/")
        && SKIP_FRAGMENTS
            .iter()
            .any(|fragment| path.contains(fragment))
}

pub fn is_manifest(path: &str) -> bool {
    source::ends_with_ascii_ignore_case(path, "/_app/version.json")
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

pub fn resolve_context_asset(base: &Url, raw: &str, context: bool) -> Option<Url> {
    if !context {
        return None;
    }
    if raw.starts_with("nodes/") || raw.starts_with("chunks/") || raw.starts_with("entry/") {
        return base.join(&format!("/_app/immutable/{raw}")).ok();
    }
    None
}
