//! Shared asset resolution, skip, and manifest matching helpers.

use crate::source;
use crate::url::Url;

pub(crate) fn path_contains_any(path: &str, fragments: &[&str]) -> bool {
    fragments.iter().any(|fragment| path.contains(fragment))
}

pub(crate) fn resolve_prefixed(base: &Url, raw: &str, prefix: &str) -> Option<Url> {
    raw.starts_with(prefix)
        .then(|| base.join(&format!("/{raw}")).ok())
        .flatten()
}

pub(crate) fn resolve_under(
    base: &Url,
    raw: &str,
    context: bool,
    prefixes: &[&str],
    mount: &str,
) -> Option<Url> {
    if !context {
        return None;
    }
    prefixes
        .iter()
        .any(|prefix| raw.starts_with(prefix))
        .then(|| base.join(&format!("{mount}{raw}")).ok())
        .flatten()
}

pub(crate) fn resolve_prefixed_or_under(
    base: &Url,
    raw: &str,
    context: bool,
    prefix: &str,
    under_prefixes: &[&str],
    mount: &str,
) -> Option<Url> {
    resolve_prefixed(base, raw, prefix)
        .or_else(|| resolve_under(base, raw, context, under_prefixes, mount))
}

pub(crate) fn resolve_remix(base: &Url, raw: &str, context: bool) -> Option<Url> {
    resolve_prefixed(base, raw, "build/").or_else(|| {
        if !context {
            return None;
        }
        resolve_under(base, raw, true, &["routes/"], "/build/")
            .or_else(|| resolve_prefixed(base, raw, "assets/routes/"))
    })
}

pub(crate) fn should_skip_fragments(url: &Url, anchor: &str, fragments: &[&str]) -> bool {
    let path = url.path();
    path.contains(anchor) && path_contains_any(path, fragments)
}

pub(crate) fn manifest_matches(
    path: &str,
    ends_with: &[&str],
    contains: &[&str],
    gated: &[(&str, &str)],
) -> bool {
    ends_with
        .iter()
        .any(|suffix| source::ends_with_ascii_ignore_case(path, suffix))
        || contains.iter().any(|needle| path.contains(needle))
        || gated.iter().any(|(needle, suffix)| {
            path.contains(needle) && source::ends_with_ascii_ignore_case(path, suffix)
        })
}
