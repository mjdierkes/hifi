//! Lightweight Nuxt discovery policy.

use crate::source;
use url::Url;

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
        || source::contains(bytes, b"window.__NUXT__")
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
        || source::ends_with_ascii_ignore_case(path, "/payload.js")
}

pub fn is_manifest(path: &str) -> bool {
    path.contains("/_nuxt/builds/") && source::ends_with_ascii_ignore_case(path, ".json")
        || source::ends_with_ascii_ignore_case(path, "/_nuxt/manifest.json")
}

pub fn resolve_asset(base: &Url, raw: &str) -> Option<Url> {
    if raw.starts_with("_nuxt/") {
        return base.join(&format!("/{raw}")).ok();
    }
    None
}
