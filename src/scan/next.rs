//! Next.js-specific manifest and config parsing.
//!
//! Next.js emits machine-generated, structurally predictable bytes for its
//! build artifacts. This module extracts what would otherwise need a JS parser
//! by leaning on those fixed shapes: `__NEXT_DATA__` is JSON, the JSON build
//! manifests are JSON, and `_buildManifest.js` wraps a single returned object
//! literal that can be sliced out by bracket-walking and coerced to JSON.

use crate::source;
use serde::{Deserialize, Serialize};

/// Runtime configuration leaked into the page by Next.js. Each field maps to a
/// `__NEXT_DATA__` property and is `None` / empty when the page didn't expose
/// it. Discovery uses these to resolve asset URLs against the right origin and
/// to normalize routes back to their user-facing form.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct NextConfig {
    pub build_id: Option<String>,
    pub asset_prefix: Option<String>,
    pub base_path: Option<String>,
    pub locales: Vec<String>,
    pub default_locale: Option<String>,
    pub locale: Option<String>,
    pub page: Option<String>,
}

impl NextConfig {
    pub fn is_empty(&self) -> bool {
        self.build_id.is_none()
            && self.asset_prefix.is_none()
            && self.base_path.is_none()
            && self.locales.is_empty()
            && self.default_locale.is_none()
            && self.locale.is_none()
            && self.page.is_none()
    }
}

const NEXT_DATA_OPEN: &[u8] = b"<script id=\"__NEXT_DATA__\"";

/// Locate the `__NEXT_DATA__` JSON blob in an HTML document and extract the
/// fields we care about. Returns `None` if the script tag is absent or the
/// payload doesn't parse as JSON.
pub fn parse_next_data(bytes: &[u8]) -> Option<NextConfig> {
    let open = source::find_ascii_ignore_case(bytes, NEXT_DATA_OPEN)?;
    let tag_end = memchr::memchr(b'>', &bytes[open..]).map(|rel| open + rel + 1)?;
    let close =
        source::find_ascii_ignore_case(&bytes[tag_end..], b"</script>").map(|rel| tag_end + rel)?;
    let payload = bytes.get(tag_end..close)?;

    let build_id = json_string_field(payload, b"buildId");
    let asset_prefix = json_string_field(payload, b"assetPrefix");
    let base_path = json_string_field(payload, b"basePath").filter(|s| !s.is_empty());
    let locales = json_string_array_field(payload, b"locales");
    let default_locale = json_string_field(payload, b"defaultLocale");
    let locale = json_string_field(payload, b"locale");
    let page = json_string_field(payload, b"page");

    let cfg = NextConfig {
        build_id,
        asset_prefix,
        base_path,
        locales,
        default_locale,
        locale,
        page,
    };
    (!cfg.is_empty()).then_some(cfg)
}

fn json_string_field(bytes: &[u8], key: &[u8]) -> Option<String> {
    let pos = json_key_pos(bytes, key)?;
    let mut i = source::skip_ws(bytes, pos + key.len() + 2);
    if bytes.get(i) != Some(&b':') {
        return None;
    }
    i = source::skip_ws(bytes, i + 1);
    if bytes.get(i) != Some(&b'"') {
        return None;
    }
    source::quoted_string(bytes, i + 1, b'"', source::TemplateMode::Preserve)
}

fn json_string_array_field(bytes: &[u8], key: &[u8]) -> Vec<String> {
    let Some(pos) = json_key_pos(bytes, key) else {
        return Vec::new();
    };
    let mut i = source::skip_ws(bytes, pos + key.len() + 2);
    if bytes.get(i) != Some(&b':') {
        return Vec::new();
    }
    i = source::skip_ws(bytes, i + 1);
    if bytes.get(i) != Some(&b'[') {
        return Vec::new();
    }
    i += 1;
    let mut out = Vec::new();
    while i < bytes.len() {
        i = source::skip_ws(bytes, i);
        match bytes.get(i) {
            Some(b'"') => {
                if let Some(value) =
                    source::quoted_string(bytes, i + 1, b'"', source::TemplateMode::Preserve)
                {
                    out.push(value);
                }
                i = source::quoted_end(bytes, i + 1, b'"').map_or(i + 1, |end| end + 1);
            }
            Some(b']') | None => break,
            _ => i += 1,
        }
    }
    out
}

fn json_key_pos(bytes: &[u8], key: &[u8]) -> Option<usize> {
    let mut offset = 0;
    while let Some(rel) = memchr::memmem::find(&bytes[offset..], key) {
        let pos = offset + rel;
        let quoted_key = pos > 0
            && bytes.get(pos - 1) == Some(&b'"')
            && bytes.get(pos + key.len()) == Some(&b'"');
        if quoted_key {
            return Some(pos - 1);
        }
        offset = pos + key.len();
    }
    None
}

/// Strip the locale prefix from a route path when it matches one of the
/// configured locales. Returns the path unchanged when no locale matches.
pub fn strip_locale(path: &str, locales: &[String]) -> String {
    if locales.is_empty() {
        return path.to_owned();
    }
    let stripped = path.strip_prefix('/').unwrap_or(path);
    let (head, rest) = stripped.split_once('/').unwrap_or((stripped, ""));
    if locales.iter().any(|locale| locale == head) {
        if rest.is_empty() {
            return "/".to_owned();
        }
        return format!("/{rest}");
    }
    path.to_owned()
}

/// Decode App Router filesystem conventions into the user-facing URL. Strips
/// route groups `(group)` and parallel route slots `@slot`; intercepting
/// markers are removed while preserving the route segment they prefix.
pub fn normalize_app_route(raw: &str) -> String {
    if !raw.contains('(') && !raw.contains('@') {
        return raw.to_owned();
    }
    let mut out = String::with_capacity(raw.len());
    let mut first = true;
    for segment in raw.split('/') {
        if segment.is_empty() {
            if first {
                out.push('/');
                first = false;
            }
            continue;
        }
        first = false;
        if is_route_group(segment) || segment.starts_with('@') {
            continue;
        }
        let segment = strip_intercepting_marker(segment);
        if segment.is_empty() {
            continue;
        }
        if !out.ends_with('/') {
            out.push('/');
        }
        out.push_str(segment);
    }
    if out.is_empty() {
        out.push('/');
    }
    out
}

fn is_route_group(segment: &str) -> bool {
    segment.starts_with('(')
        && segment.ends_with(')')
        && !segment.starts_with("(.)")
        && !segment.starts_with("(..)")
        && !segment.starts_with("(...)")
}

fn strip_intercepting_marker(segment: &str) -> &str {
    for marker in ["(...)", "(..)", "(.)"] {
        if let Some(rest) = segment.strip_prefix(marker) {
            return rest;
        }
    }
    segment
}

/// Pull route keys out of a `_buildManifest.js` document by isolating the
/// returned object literal and coercing it to JSON. The file is shaped like
/// `self.__BUILD_MANIFEST = function(...){return {"/page": [...], ...}}(...);`.
pub fn parse_build_manifest_js(bytes: &[u8]) -> Vec<String> {
    // Modern Next wraps the object in `function(...){return {...}}(...)`;
    // older or hand-rolled forms write `self.__BUILD_MANIFEST = {...}` inline.
    // Try the `return` anchor first, then fall back to the first `{` after the
    // build-manifest identifier.
    let i = locate_build_manifest_object(bytes).or_else(|| locate_build_manifest_inline(bytes));
    let Some(i) = i else {
        return Vec::new();
    };
    if bytes.get(i) != Some(&b'{') {
        return Vec::new();
    }
    let Some(end) = source::balanced_end(bytes, i) else {
        return Vec::new();
    };
    let literal = &bytes[i..=end];
    extract_top_level_route_keys(literal)
}

/// Walk a JS object literal at depth 1 and collect top-level keys that look
/// like route paths. Skips nested objects/arrays and value strings. Handles
/// quoted (`"` / `'`) and bare-identifier keys.
fn extract_top_level_route_keys(literal: &[u8]) -> Vec<String> {
    let mut out = Vec::new();
    if literal.first() != Some(&b'{') {
        return out;
    }
    let mut i = 1;
    let mut depth: i32 = 0;
    let mut expect_key = true;
    while i < literal.len() {
        let b = literal[i];
        match b {
            b'{' | b'[' => {
                depth += 1;
                expect_key = false;
                i += 1;
            }
            b'}' | b']' => {
                if depth == 0 {
                    break;
                }
                depth -= 1;
                i += 1;
            }
            b',' if depth == 0 => {
                expect_key = true;
                i += 1;
            }
            b':' if depth == 0 => {
                expect_key = false;
                i += 1;
            }
            b'"' | b'\'' => {
                let quote = b;
                let start = i + 1;
                let mut j = start;
                while j < literal.len() && literal[j] != quote {
                    if literal[j] == b'\\' && j + 1 < literal.len() {
                        j += 2;
                        continue;
                    }
                    j += 1;
                }
                if expect_key && depth == 0 {
                    if let Ok(s) = std::str::from_utf8(&literal[start..j]) {
                        if s.starts_with('/') && !matches!(s, "/_app" | "/_error" | "/_document") {
                            out.push(s.to_string());
                        }
                    }
                }
                i = j + 1;
            }
            b if b.is_ascii_whitespace() => i += 1,
            b if expect_key
                && depth == 0
                && (b == b'_' || b == b'$' || b.is_ascii_alphabetic()) =>
            {
                // Bare identifier key — not a route (routes always start with '/'
                // and must therefore be quoted). Skip the identifier.
                if let Some(ident) = source::identifier_at(literal, i) {
                    i += ident.len();
                } else {
                    i += 1;
                }
            }
            _ => i += 1,
        }
    }
    out
}

fn locate_build_manifest_object(bytes: &[u8]) -> Option<usize> {
    let return_pos = memchr::memmem::find(bytes, b"return")?;
    let i = source::skip_ws(bytes, return_pos + b"return".len());
    (bytes.get(i) == Some(&b'{')).then_some(i)
}

fn locate_build_manifest_inline(bytes: &[u8]) -> Option<usize> {
    let ident_pos = memchr::memmem::find(bytes, b"__BUILD_MANIFEST")?;
    let mut i = ident_pos + b"__BUILD_MANIFEST".len();
    i = source::skip_ws(bytes, i);
    while i < bytes.len() && bytes[i] == b'=' {
        i += 1;
        i = source::skip_ws(bytes, i);
    }
    (bytes.get(i) == Some(&b'{')).then_some(i)
}

/// Parse `app-build-manifest.json` and return the App Router route patterns
/// it advertises. The manifest is a JSON object keyed by route pattern with
/// chunk arrays as values.
pub fn parse_app_build_manifest(bytes: &[u8]) -> Vec<String> {
    if let Some(keys) = crate::json::keys_under(bytes, "pages") {
        return keys.iter().map(|k| route_from_app_key(k)).collect();
    }
    // Some Next versions write the routes at the top level.
    crate::json::top_level_keys(bytes)
        .map(|keys| {
            keys.iter()
                .filter(|k| k.starts_with('/') || k.contains("/page"))
                .map(|k| route_from_app_key(k))
                .collect()
        })
        .unwrap_or_default()
}

fn route_from_app_key(key: &str) -> String {
    // App manifest keys look like "/dashboard/page" or "/(group)/about/page".
    let stripped = key
        .strip_suffix("/page")
        .or_else(|| key.strip_suffix("/route"))
        .or_else(|| key.strip_suffix("/layout"))
        .unwrap_or(key);
    let normalized = normalize_app_route(stripped);
    if normalized.is_empty() {
        "/".to_owned()
    } else {
        normalized
    }
}

/// Pull server action IDs and their backing routes from
/// `_clientReferenceManifest.json`. The exact shape varies by Next version, so
/// we walk the structure defensively and collect any `name`/`id` pairs that
/// look route-like.
pub fn parse_client_reference_manifest(bytes: &[u8]) -> Vec<String> {
    use crate::json::{Event, Parser};
    let mut out = Vec::new();
    let mut p = Parser::new(bytes);
    if !matches!(p.next(), Some(Event::BeginObject)) {
        return out;
    }
    // Find top-level "serverActions".
    loop {
        match p.next() {
            Some(Event::Key(k)) => {
                if k.as_str() == "serverActions" {
                    break;
                }
                if p.skip_value().is_none() {
                    return out;
                }
            }
            Some(Event::EndObject) | None => return out,
            _ => return out,
        }
    }
    if !matches!(p.next(), Some(Event::BeginObject)) {
        return out;
    }
    // Iterate action_ids.
    loop {
        match p.next() {
            Some(Event::EndObject) => return out,
            Some(Event::Key(_)) => {
                // Value is the action payload object. Find its "workers" object.
                if !matches!(p.next(), Some(Event::BeginObject)) {
                    return out;
                }
                loop {
                    match p.next() {
                        Some(Event::EndObject) => break,
                        Some(Event::Key(k)) => {
                            if k.as_str() == "workers" {
                                if !matches!(p.next(), Some(Event::BeginObject)) {
                                    return out;
                                }
                                loop {
                                    match p.next() {
                                        Some(Event::EndObject) => break,
                                        Some(Event::Key(wk)) => {
                                            if let Some(route) = route_from_app_chunk(wk.as_str()) {
                                                out.push(route);
                                            }
                                            if p.skip_value().is_none() {
                                                return out;
                                            }
                                        }
                                        _ => return out,
                                    }
                                }
                            } else if p.skip_value().is_none() {
                                return out;
                            }
                        }
                        _ => return out,
                    }
                }
            }
            _ => return out,
        }
    }
}

/// Walk every `__next_f.push([N, "..."])` payload in `bytes` and extract
/// route-like strings from the typed flight stream. Each push carries a
/// JS-escaped chunk of the React Flight protocol; lines are shaped as
/// `<id>:<prefix?><json>`, and the JSON portion is recursively scanned for
/// href / src / action attributes and route-like string values.
pub fn extract_flight_routes(bytes: &[u8]) -> Vec<String> {
    let mut out = Vec::new();
    let mut i = 0;
    while let Some(rel) = memchr::memmem::find(&bytes[i..], b"__next_f.push") {
        let pos = i + rel + b"__next_f.push".len();
        i = pos;
        // Bound the search to the enclosing </script> tag if there is one.
        let limit = memchr::memmem::find(&bytes[pos..], b"</script>")
            .map(|rel| pos + rel)
            .unwrap_or(bytes.len());
        let region = &bytes[pos..limit];
        let Some(payload) = decode_flight_push(region) else {
            continue;
        };
        walk_flight_payload(&payload, &mut out);
    }
    out
}

/// Parse the `__next_f.push([N, "..."])` argument and return the decoded
/// second-argument string. Returns `None` if the call shape is unexpected or
/// the payload isn't a quoted string.
fn decode_flight_push(region: &[u8]) -> Option<String> {
    let open = region.iter().position(|b| *b == b'(')?;
    let arr_open = region[open..].iter().position(|b| *b == b'[')?;
    let mut i = open + arr_open + 1;
    // Skip the first element (an id) and the comma.
    while i < region.len() && region[i] != b',' {
        i += 1;
    }
    if i >= region.len() {
        return None;
    }
    i += 1;
    while i < region.len() && region[i].is_ascii_whitespace() {
        i += 1;
    }
    let quote = *region.get(i)?;
    if !matches!(quote, b'"' | b'\'') {
        return None;
    }
    i += 1;
    let mut out = Vec::with_capacity(region.len() - i);
    while i < region.len() {
        let b = region[i];
        if b == b'\\' && i + 1 < region.len() {
            match region[i + 1] {
                b'n' => out.push(b'\n'),
                b't' => out.push(b'\t'),
                b'r' => out.push(b'\r'),
                b'\\' => out.push(b'\\'),
                b'"' => out.push(b'"'),
                b'\'' => out.push(b'\''),
                b'/' => out.push(b'/'),
                b'u' if i + 5 < region.len() => {
                    let hex = std::str::from_utf8(&region[i + 2..i + 6]).ok()?;
                    let code = u32::from_str_radix(hex, 16).ok()?;
                    if let Some(c) = char::from_u32(code) {
                        let mut buf = [0u8; 4];
                        out.extend_from_slice(c.encode_utf8(&mut buf).as_bytes());
                    }
                    i += 6;
                    continue;
                }
                other => out.push(other),
            }
            i += 2;
        } else if b == quote {
            return String::from_utf8(out).ok();
        } else {
            out.push(b);
            i += 1;
        }
    }
    None
}

fn walk_flight_payload(payload: &str, out: &mut Vec<String>) {
    for line in payload.split('\n') {
        let Some((_id, rest)) = line.split_once(':') else {
            continue;
        };
        // The line may have a one-character type prefix before the JSON
        // payload (e.g. `1:I[...]`, `M2:{...}`). Find the first JSON delimiter
        // and parse from there.
        let json_start = rest
            .bytes()
            .position(|b| matches!(b, b'[' | b'{' | b'"'))
            .unwrap_or(rest.len());
        let json = &rest[json_start..];
        if json.is_empty() {
            continue;
        }
        crate::json::walk_strings(json.as_bytes(), |key, value| {
            if let Some(k) = key {
                if matches!(k, "href" | "src" | "action" | "url" | "data-href")
                    && looks_like_route(value)
                {
                    out.push(value.to_owned());
                }
            }
        });
    }
}

fn looks_like_route(s: &str) -> bool {
    !s.is_empty()
        && s.starts_with('/')
        && !s.starts_with("//")
        && s.len() <= 512
        && !s.contains('\n')
        && !s.contains(' ')
}

fn route_from_app_chunk(key: &str) -> Option<String> {
    // Keys like "app/foo/page" or "app/(marketing)/about/page".
    let path = key.strip_prefix("app").unwrap_or(key);
    let stripped = path
        .strip_suffix("/page")
        .or_else(|| path.strip_suffix("/route"))
        .unwrap_or(path);
    let route = normalize_app_route(stripped);
    (!route.is_empty()).then_some(route)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_full_next_data() {
        let html = br#"<script id="__NEXT_DATA__" type="application/json">{"buildId":"b1","assetPrefix":"https://cdn.example.com","basePath":"/app","locales":["en","fr"],"defaultLocale":"en","locale":"fr","page":"/dashboard"}</script>"#;
        let cfg = parse_next_data(html).unwrap();
        assert_eq!(cfg.build_id.as_deref(), Some("b1"));
        assert_eq!(cfg.asset_prefix.as_deref(), Some("https://cdn.example.com"));
        assert_eq!(cfg.base_path.as_deref(), Some("/app"));
        assert_eq!(cfg.locales, vec!["en", "fr"]);
        assert_eq!(cfg.default_locale.as_deref(), Some("en"));
        assert_eq!(cfg.locale.as_deref(), Some("fr"));
    }

    #[test]
    fn strips_known_locale() {
        let locales = vec!["en".to_owned(), "fr".to_owned()];
        assert_eq!(strip_locale("/fr/dashboard", &locales), "/dashboard");
        assert_eq!(strip_locale("/en", &locales), "/");
        assert_eq!(strip_locale("/dashboard", &locales), "/dashboard");
        assert_eq!(strip_locale("/de/page", &locales), "/de/page");
    }

    #[test]
    fn normalizes_app_router_conventions() {
        assert_eq!(normalize_app_route("/(marketing)/about"), "/about");
        assert_eq!(
            normalize_app_route("/dashboard/@modal/login"),
            "/dashboard/login"
        );
        assert_eq!(normalize_app_route("/feed/(.)photo/42"), "/feed/photo/42");
        assert_eq!(normalize_app_route("/blog/[slug]"), "/blog/[slug]");
        assert_eq!(normalize_app_route("/docs/[...slug]"), "/docs/[...slug]");
        assert_eq!(normalize_app_route("/"), "/");
    }

    #[test]
    fn parses_build_manifest_js() {
        let src = br#"self.__BUILD_MANIFEST=function(s,c){return{"/":["static/chunks/a.js"],"/about":[s,c],"/_app":["static/chunks/_app.js"],sortedPages:["/","/about"]}}("x","y");self.__BUILD_MANIFEST_CB&&self.__BUILD_MANIFEST_CB();"#;
        let mut routes = parse_build_manifest_js(src);
        routes.sort();
        assert_eq!(routes, vec!["/", "/about"]);
    }

    #[test]
    fn parses_app_build_manifest() {
        let src = br#"{"pages":{"/dashboard/page":["chunks/a.js"],"/(marketing)/about/page":["chunks/b.js"]}}"#;
        let mut routes = parse_app_build_manifest(src);
        routes.sort();
        assert_eq!(routes, vec!["/about", "/dashboard"]);
    }

    #[test]
    fn flight_extracts_href_and_action_routes() {
        // The push string contains escaped JSON-like flight lines.
        let html = br#"<script>self.__next_f.push([1,"0:[\"$\",\"$L1\",null,{\"href\":\"/dashboard\",\"action\":\"/api/checkout\"}]\n2:{\"href\":\"/about\"}\n"])</script>"#;
        let mut routes = extract_flight_routes(html);
        routes.sort();
        assert_eq!(routes, vec!["/about", "/api/checkout", "/dashboard"]);
    }

    #[test]
    fn flight_ignores_garbage_strings() {
        let html = br#"<script>self.__next_f.push([1,"0:[\"$L1\",null,{\"foo\":\"not a route\",\"href\":\"http://other.example.com\"}]"])</script>"#;
        let routes = extract_flight_routes(html);
        assert!(routes.is_empty(), "got: {routes:?}");
    }
}
