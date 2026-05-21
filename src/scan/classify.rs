use super::literals::{BAD_EXTS, ROUTE_BAD_EXTS};

// API candidates are values that look useful but were not observed as a call
// target. They stay separate from confirmed APIs so output can preserve
// evidence quality instead of merging every URL-shaped string together.
pub(crate) fn is_api_candidate(s: &str) -> bool {
    is_url_like(s)
        && (s.starts_with("/api")
            || s.starts_with("/graphql")
            || s.starts_with("/trpc")
            || ((s.starts_with("http://") || s.starts_with("https://"))
                && ["/api/", "/graphql", "/trpc"]
                    .iter()
                    .any(|needle| s.contains(needle))))
}

// Client routes are navigation targets, not HTTP endpoints. Keeping them in a
// separate bucket gives context without polluting the API surface.
pub(crate) fn is_client_route(s: &str) -> bool {
    is_route_like(s)
        && !s.starts_with("/api")
        && !s.starts_with("/graphql")
        && !s.starts_with("/trpc")
        && !s.starts_with("/_next")
        && !s.starts_with("/_nuxt")
}

pub(crate) fn is_url_like(s: &str) -> bool {
    let bytes = s.as_bytes();
    (2..=512).contains(&bytes.len())
        && (s.starts_with('/') || s.starts_with("http://") || s.starts_with("https://"))
        && s != "/"
        && !has_bare_dynamic_suffix(s)
        && !bad_ext(bytes, BAD_EXTS, false)
        && !has_markup_noise(bytes)
        && bytes.iter().any(u8::is_ascii_alphanumeric)
}

pub(crate) fn normalize_api_url(s: &str) -> String {
    let without_fragment = s.split('#').next().unwrap_or(s);
    let Some((path, query)) = without_fragment.split_once('?') else {
        return without_fragment.to_owned();
    };

    let has_query_keys = query
        .split('&')
        .filter_map(|pair| pair.split('=').next().map(str::trim))
        .any(|key| !key.is_empty() && key.len() <= 128);
    if has_query_keys {
        path.to_owned()
    } else {
        without_fragment.to_owned()
    }
}

fn is_route_like(s: &str) -> bool {
    let bytes = s.as_bytes();
    (2..=512).contains(&bytes.len())
        && s.starts_with('/')
        && !s.starts_with("//")
        && bytes.iter().any(u8::is_ascii_alphanumeric)
        && !bad_ext(bytes, ROUTE_BAD_EXTS, true)
        && !has_markup_noise(bytes)
}

// Reject strings that contain raw or percent-encoded markup. They are
// produced by inline SVG/HTML literals (e.g. Next.js's blur-SVG generator
// emitting "...%3E%3CfeGaussianBlur..."), never by real route or URL literals.
fn has_markup_noise(bytes: &[u8]) -> bool {
    if bytes
        .iter()
        .any(|b| matches!(*b, b'<' | b'>' | b'"' | b'\'' | b' ' | b'\n' | b'\r' | b'\t'))
    {
        return true;
    }
    let mut i = 0;
    while i + 2 < bytes.len() {
        if bytes[i] == b'%' {
            // %3C/%3E = <,>  %22 = "  %27 = '
            match (bytes[i + 1], bytes[i + 2] | 0x20) {
                (b'3', b'c') | (b'3', b'e') => return true,
                (b'2', b'2') | (b'2', b'7') => return true,
                _ => {}
            }
        }
        i += 1;
    }
    false
}

fn has_bare_dynamic_suffix(s: &str) -> bool {
    let Some(pos) = s.find("{dynamic}") else {
        return false;
    };
    pos > 0 && s.as_bytes()[pos - 1].is_ascii_alphanumeric()
}

fn bad_ext(s: &[u8], exts: &[&str], strip_fragment: bool) -> bool {
    let path = s
        .split(|b| *b == b'?' || (strip_fragment && *b == b'#'))
        .next()
        .unwrap_or(s);
    exts.iter().any(|ext| {
        path.len() >= ext.len()
            && path[path.len() - ext.len()..].eq_ignore_ascii_case(ext.as_bytes())
    })
}
