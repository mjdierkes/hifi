//! Angular discovery policy.
//!
//! Angular ships compiled bundles (typically `runtime.<hash>.js`,
//! `polyfills.<hash>.js`, `main.<hash>.js`) and the routed app code lives in
//! `main`. Endpoints are commonly centralized in an object-literal "endpoint
//! map" — either inline (`this.APIs = { search: "/sgs/v1/search", ... }`) or
//! wrapped in `JSON.parse('{"J":{...}}')`. We anchor on those shapes and pull
//! the path-shaped string values out, tagged with `FrameworkId::Angular`.

use crate::framework::FrameworkId;
use crate::scan::findings::{Channel, Provenance};
use crate::scan::Shape;
use crate::source::{self, TemplateMode};
use crate::url::Url;

const HTML_MARKERS: &[&[u8]] = &[
    b"ng-version=\"",
    b"_nghost-",
    b"_ngcontent-",
    b"<app-root",
    b"ng-app=",
];

const BUNDLE_MARKERS: &[&[u8]] = &[
    b"@angular/core",
    b"\xc9\xb5\xc9\xb5defineComponent", // ɵɵdefineComponent
    b"\xc9\xb5\xc9\xb5defineNgModule",
    b"platformBrowser",
];

// Anchors that precede an Angular-style endpoint map. `APIs` is the convention
// in the sam.gov bundle; `endpoints`/`apis`/`urls`/`routes` cover the common
// variants. We accept either `key:{` or `key={` (object property vs class
// field assignment in compiled output).
const ENDPOINT_MAP_ANCHORS: &[&[u8]] = &[
    b"APIs",
    b"apis",
    b"Apis",
    b"endpoints",
    b"Endpoints",
    b"ENDPOINTS",
    b"urls",
    b"URLs",
    b"routes",
];

// Maximum bytes to scan after an anchor for the closing brace. Endpoint maps
// in practice are well under 16KB even uncompressed; this bounds work on
// false-positive matches (e.g. anchor keyword that isn't followed by `{`).
const MAP_WINDOW_BYTES: usize = 16 * 1024;

pub fn is_context(bytes: &[u8], _base: &Url) -> bool {
    HTML_MARKERS.iter().any(|m| source::contains(bytes, m))
        || BUNDLE_MARKERS.iter().any(|m| source::contains(bytes, m))
}

pub fn should_skip(_url: &Url) -> bool {
    false
}

pub fn is_payload(_raw: &str, _path: &str) -> bool {
    false
}

pub fn is_manifest(_path: &str) -> bool {
    false
}

pub fn resolve(_base: &Url, _raw: &str, _context: bool) -> Option<Url> {
    None
}

pub fn record_endpoint_maps(bytes: &[u8], findings: &mut crate::scan::FindingsBuilder) {
    let mut emitted = std::collections::HashSet::new();
    let mut emit = |path: String| {
        if emitted.insert(path.clone()) {
            findings.record_api(
                path,
                Shape::inferred(None, false),
                Provenance::framework(Channel::Literal, FrameworkId::Angular),
            );
        }
    };

    // Scan windows that follow APIs/endpoints/routes-style
    // identifiers and collect path-shaped string values from each window.
    for window in find_map_windows(bytes) {
        super::scan_quoted_strings(window, TemplateMode::ReplaceExpressions, |raw| {
            // Inside an explicit endpoint map the surrounding structure is
            // the signal — relax the prefix gate that filters bare API
            // candidates to only `/api`, `/graphql`, `/trpc`. Angular apps
            // routinely use vanity prefixes (`/sgs`, `/opps`, ...) that the
            // global filter would discard.
            if crate::scan::classify::is_url_like(raw) {
                emit(crate::scan::classify::normalize_api_url(raw));
            }
        });
    }
}

// Locate object-literal regions following an endpoint-map anchor. Returns
// borrowed slices spanning `{` through the matching `}` (or up to a bounded
// window) so callers can scan string values within.
fn find_map_windows(bytes: &[u8]) -> Vec<&[u8]> {
    let mut out = Vec::new();
    for anchor in ENDPOINT_MAP_ANCHORS {
        let mut offset = 0;
        while let Some(rel) = memchr::memmem::find(&bytes[offset..], anchor) {
            let pos = offset + rel;
            offset = pos + anchor.len();
            if !source::is_identifier_boundary(bytes, pos, anchor.len()) {
                continue;
            }
            if let Some(window) = locate_object_after(bytes, offset) {
                out.push(window);
            }
        }
    }
    out
}

// Given a position just past an identifier, look for `[:=]?\s*{` (with an
// optional quoted-string wrapping for the JSON.parse('{"J":{...}}') shape).
// Returns the slice from `{` through the matching `}`, bounded.
fn locate_object_after(bytes: &[u8], start: usize) -> Option<&[u8]> {
    let mut i = start;
    // Skip optional `"` if anchor was inside a JSON string key.
    while i < bytes.len() && matches!(bytes[i], b'"' | b'\'') {
        i += 1;
    }
    // Whitespace then `:` or `=`.
    while i < bytes.len() && bytes[i].is_ascii_whitespace() {
        i += 1;
    }
    if !matches!(bytes.get(i), Some(b':') | Some(b'=')) {
        return None;
    }
    i += 1;
    while i < bytes.len() && bytes[i].is_ascii_whitespace() {
        i += 1;
    }
    if bytes.get(i) != Some(&b'{') {
        return None;
    }
    let open = i;
    let limit = bytes.len().min(open + MAP_WINDOW_BYTES);
    let close = match_brace(&bytes[open..limit])?;
    Some(&bytes[open..=open + close])
}

// Returns the index of the `}` that closes the `{` at position 0 of `slice`,
// respecting nested braces and string-literal contents.
fn match_brace(slice: &[u8]) -> Option<usize> {
    debug_assert_eq!(slice.first(), Some(&b'{'));
    let mut depth: u32 = 0;
    let mut i = 0;
    while i < slice.len() {
        match slice[i] {
            b'{' => depth += 1,
            b'}' => {
                depth -= 1;
                if depth == 0 {
                    return Some(i);
                }
            }
            q @ (b'"' | b'\'' | b'`') => {
                i = source::quoted_end(slice, i + 1, q).map_or(slice.len(), |e| e + 1);
                continue;
            }
            _ => {}
        }
        i += 1;
    }
    None
}
