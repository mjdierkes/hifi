//! Lightweight Astro discovery policy.

use crate::source;
use crate::url::Url;

const SKIP_FRAGMENTS: &[&str] = &["/_astro/hoisted.", "/_astro/polyfills", "/_astro/client."];

pub fn is_context(bytes: &[u8], base: &Url) -> bool {
    base.path().contains("/_astro/")
        || base.path().contains("/_actions/")
        || source::contains(bytes, b"/_astro/")
        || source::contains(bytes, b"astro-island")
        || source::contains(bytes, b"astro:actions")
        || source::contains(bytes, b"_actions/")
}

pub fn should_skip(url: &Url) -> bool {
    let path = url.path();
    path.contains("/_astro/")
        && SKIP_FRAGMENTS
            .iter()
            .any(|fragment| path.contains(fragment))
}

pub fn is_payload(raw: &str, path: &str) -> bool {
    raw.contains("/_actions/") || path.contains("/_server-islands/")
}

pub fn resolve_asset(base: &Url, raw: &str) -> Option<Url> {
    if raw.starts_with("_astro/") {
        return base.join(&format!("/{raw}")).ok();
    }
    None
}
