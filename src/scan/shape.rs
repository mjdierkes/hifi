use super::extract;
use crate::source;
use serde::{Deserialize, Serialize};

const METHOD_GET: u8 = 1 << 0;
const METHOD_POST: u8 = 1 << 1;
const METHOD_PUT: u8 = 1 << 2;
const METHOD_DELETE: u8 = 1 << 3;
const METHOD_PATCH: u8 = 1 << 4;
const METHOD_HEAD: u8 = 1 << 5;
const METHOD_OPTIONS: u8 = 1 << 6;
const CONTENT_JSON: u8 = 1 << 0;
const CONTENT_FORM: u8 = 1 << 1;
const CONTENT_URLENCODED: u8 = 1 << 2;
const CONTENT_TEXT: u8 = 1 << 3;

const METHODS: [(u8, &str); 7] = [
    (METHOD_GET, "GET"),
    (METHOD_POST, "POST"),
    (METHOD_PUT, "PUT"),
    (METHOD_DELETE, "DELETE"),
    (METHOD_PATCH, "PATCH"),
    (METHOD_HEAD, "HEAD"),
    (METHOD_OPTIONS, "OPTIONS"),
];
const CONTENT_FLAGS: [(u8, &str); 4] = [
    (CONTENT_JSON, "json"),
    (CONTENT_FORM, "form"),
    (CONTENT_URLENCODED, "urlencoded"),
    (CONTENT_TEXT, "text"),
];
const BODY_HINTS: &[&[u8]] = &[b"body", b"formdata("];
const HEADER_HINTS: &[&[u8]] = &[b"headers", b"content-type", b"authorization"];
const AUTH_HINTS: &[&[u8]] = &[b"authorization", b"bearer"];
const JSON_HINTS: &[&[u8]] = &[b"application/json"];
const FORM_HINTS: &[&[u8]] = &[b"multipart/form-data", b"formdata("];
const URLENCODED_HINTS: &[&[u8]] = &[b"application/x-www-form-urlencoded", b"urlsearchparams("];
const TEXT_HINTS: &[&[u8]] = &[b"text/plain"];
const CONTENT_HINTS: &[(&[&[u8]], u8)] = &[
    (JSON_HINTS, CONTENT_JSON),
    (FORM_HINTS, CONTENT_FORM),
    (URLENCODED_HINTS, CONTENT_URLENCODED),
    (TEXT_HINTS, CONTENT_TEXT),
];

// Request options are usually close to the URL literal in client bundles, but
// minified code can make "the current call expression" expensive to identify
// without a real parser. This window is intentionally local: broad enough to
// catch common fetch/axios options, narrow enough to avoid unrelated calls.
const SHAPE_WINDOW: usize = 400;

#[derive(Default, Clone, Serialize, Deserialize)]
pub struct Shape {
    methods: u8,
    has_body: bool,
    has_headers: bool,
    content_types: u8,
    auth: bool,
    #[serde(default, skip_serializing_if = "is_false")]
    next_server_action: bool,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    query_params: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    body_params: Vec<String>,
}

impl Shape {
    pub fn methods_csv(&self) -> String {
        METHODS
            .iter()
            .filter_map(|(bit, name)| (self.methods & bit != 0).then_some(*name))
            .collect::<Vec<_>>()
            .join(",")
    }

    pub fn flags_csv(&self) -> String {
        let mut flags = Vec::with_capacity(7);
        if self.has_body {
            flags.push("body");
        }
        if self.has_headers {
            flags.push("headers");
        }
        for (bit, flag) in CONTENT_FLAGS {
            if self.content_types & bit != 0 {
                flags.push(flag);
            }
        }
        if self.auth {
            flags.push("auth");
        }
        if !self.query_params.is_empty() {
            flags.push("query");
        }
        if !self.body_params.is_empty() {
            flags.push("body-shape");
        }
        if self.next_server_action {
            flags.push("next-action");
        }
        flags.join(",")
    }

    pub(crate) fn merge(&mut self, other: &Shape) {
        self.methods |= other.methods;
        self.has_body |= other.has_body;
        self.has_headers |= other.has_headers;
        self.content_types |= other.content_types;
        self.auth |= other.auth;
        self.next_server_action |= other.next_server_action;
        for key in &other.query_params {
            push_unique_sorted(&mut self.query_params, key);
        }
        for key in &other.body_params {
            push_unique_sorted(&mut self.body_params, key);
        }
    }

    pub(crate) fn ensure_default_method(&mut self) {
        if self.methods == 0 {
            self.methods = METHOD_GET;
        }
    }

    pub(crate) fn apply_query_params(&mut self, url: &str) {
        let Some(query_start) = url.find('?') else {
            return;
        };
        let query = url[query_start + 1..].split('#').next().unwrap_or("");
        for key in query
            .split('&')
            .filter_map(|pair| pair.split('=').next().map(str::trim))
            .filter(|key| !key.is_empty() && key.len() <= 128)
        {
            push_unique_sorted(&mut self.query_params, key);
        }
    }

    pub(crate) fn next_server_action() -> Self {
        Self {
            methods: METHOD_POST,
            has_body: true,
            next_server_action: true,
            ..Self::default()
        }
    }
}

fn is_false(value: &bool) -> bool {
    !*value
}

// Shape extraction is deliberately heuristic. It should capture useful request
// hints from nearby source without pretending to validate JavaScript semantics.
pub(crate) fn scan_call(
    bytes: &[u8],
    start: usize,
    after: usize,
    anchor: &str,
) -> Option<(String, Shape)> {
    let url = extract::url_arg(bytes, after)?;
    let lo = statement_start(bytes, start);
    let hi = statement_end(bytes, after);
    let mut shape = shape_from_window(&bytes[lo..hi]);
    let hint = method_hint(anchor);
    shape.methods |= hint;
    if method_allows_body(hint) {
        apply_second_arg_body_shape(bytes, after, &mut shape);
    }
    Some((url, shape))
}

fn shape_from_window(bytes: &[u8]) -> Shape {
    let lower = bytes.to_ascii_lowercase();
    let mut shape = Shape::default();
    for method in memchr::memmem::find_iter(&lower, b"method") {
        shape.methods |= parse_method(&lower[method + 6..]);
    }
    shape.has_body = contains_any(&lower, BODY_HINTS);
    shape.has_headers = contains_any(&lower, HEADER_HINTS);
    shape.auth = contains_any(&lower, AUTH_HINTS);
    for (hints, bit) in CONTENT_HINTS {
        if contains_any(&lower, hints) {
            shape.content_types |= *bit;
        }
    }
    shape
}

fn contains_any(haystack: &[u8], needles: &[&[u8]]) -> bool {
    needles
        .iter()
        .any(|needle| source::contains(haystack, needle))
}

fn parse_method(mut bytes: &[u8]) -> u8 {
    while bytes.first().is_some_and(|b| b.is_ascii_whitespace()) {
        bytes = &bytes[1..];
    }
    if bytes.first() == Some(&b':') {
        bytes = &bytes[1..];
    }
    while bytes.first().is_some_and(|b| b.is_ascii_whitespace()) {
        bytes = &bytes[1..];
    }
    if matches!(bytes.first(), Some(b'"' | b'\'' | b'`')) {
        bytes = &bytes[1..];
    }
    let end = bytes
        .iter()
        .position(|b| !b.is_ascii_alphabetic())
        .unwrap_or(bytes.len());
    match &bytes[..end] {
        b"get" => METHOD_GET,
        b"post" => METHOD_POST,
        b"put" => METHOD_PUT,
        b"delete" => METHOD_DELETE,
        b"patch" => METHOD_PATCH,
        b"head" => METHOD_HEAD,
        b"options" => METHOD_OPTIONS,
        _ => 0,
    }
}

fn apply_second_arg_body_shape(bytes: &[u8], start: usize, shape: &mut Shape) {
    let Some(first_end) = first_arg_end(bytes, start) else {
        return;
    };
    let mut i = source::skip_ws(bytes, first_end);
    if bytes.get(i) != Some(&b',') {
        return;
    }
    i = source::skip_ws(bytes, i + 1);
    if matches!(bytes.get(i), None | Some(b')')) {
        return;
    }
    shape.has_body = true;
    if let Some(keys) = object_keys(bytes, i) {
        shape.content_types |= CONTENT_JSON;
        for key in keys {
            push_unique_sorted(&mut shape.body_params, &key);
        }
    }
}

// Supported object forms are deliberately small: `{ key }`, `{ key: value }`,
// and quoted keys at the top level. Nested objects are skipped structurally so
// the result describes the request body surface, not every nested value.
fn object_keys(bytes: &[u8], start: usize) -> Option<Vec<String>> {
    if bytes.get(start) != Some(&b'{') {
        return None;
    }
    let mut keys = Vec::new();
    let mut i = start + 1;
    let mut depth = 1usize;
    let mut read_key = true;
    while i < bytes.len() && depth > 0 {
        match bytes[i] {
            b'{' | b'[' | b'(' => {
                depth += 1;
                i += 1;
            }
            b'}' | b']' | b')' => {
                depth -= 1;
                i += 1;
                read_key = depth == 1;
            }
            b'"' | b'\'' | b'`' => {
                if depth == 1 && read_key {
                    let quote = bytes[i];
                    if let Some(end) = source::quoted_end(bytes, i + 1, quote) {
                        let key = std::str::from_utf8(&bytes[i + 1..end]).ok()?.to_string();
                        let after = source::skip_ws(bytes, end + 1);
                        if bytes.get(after) == Some(&b':') {
                            keys.push(key);
                            read_key = false;
                        }
                        i = end + 1;
                    } else {
                        return Some(keys);
                    }
                } else {
                    i = source::quoted_end(bytes, i + 1, bytes[i])
                        .map(|end| end + 1)
                        .unwrap_or(bytes.len());
                }
            }
            b',' if depth == 1 => {
                read_key = true;
                i += 1;
            }
            b':' if depth == 1 => {
                read_key = false;
                i += 1;
            }
            b if depth == 1 && read_key && (b == b'_' || b == b'$' || b.is_ascii_alphabetic()) => {
                let key_start = i;
                i += 1;
                while bytes
                    .get(i)
                    .is_some_and(|b| *b == b'_' || *b == b'$' || b.is_ascii_alphanumeric())
                {
                    i += 1;
                }
                let key = std::str::from_utf8(&bytes[key_start..i]).ok()?.to_string();
                let after = source::skip_ws(bytes, i);
                if matches!(bytes.get(after), Some(b':' | b',' | b'}')) {
                    keys.push(key);
                    read_key = !matches!(bytes.get(after), Some(b':'));
                }
            }
            _ => i += 1,
        }
    }
    Some(keys)
}

fn statement_start(bytes: &[u8], pos: usize) -> usize {
    let start = pos.saturating_sub(SHAPE_WINDOW);
    bytes[start..pos]
        .iter()
        .rposition(|b| matches!(*b, b';' | b'\n' | b'\r'))
        .map(|rel| start + rel + 1)
        .unwrap_or(start)
}

fn statement_end(bytes: &[u8], pos: usize) -> usize {
    let end = (pos + SHAPE_WINDOW).min(bytes.len());
    bytes[pos..end]
        .iter()
        .position(|b| matches!(*b, b';' | b'\n' | b'\r'))
        .map(|rel| pos + rel)
        .unwrap_or(end)
}

fn method_hint(anchor: &str) -> u8 {
    match anchor {
        "axios.get(" | "ky.get(" | ".get(" => METHOD_GET,
        "axios.post(" | "ky.post(" | ".post(" => METHOD_POST,
        "axios.put(" | ".put(" => METHOD_PUT,
        "axios.delete(" | ".delete(" => METHOD_DELETE,
        "axios.patch(" | ".patch(" => METHOD_PATCH,
        _ => 0,
    }
}

fn method_allows_body(method: u8) -> bool {
    method & (METHOD_POST | METHOD_PUT | METHOD_PATCH) != 0
}

// The first argument to a `fetch`-style call may be a quoted URL or a bare
// identifier that holds a previously-built URL. Body-shape extraction only
// needs to skip past it to reach the options object.
fn first_arg_end(bytes: &[u8], start: usize) -> Option<usize> {
    if let Some(end) = source::quoted_arg_end(bytes, start) {
        return Some(end);
    }
    let i = source::skip_ws(bytes, start);
    let first = *bytes.get(i)?;
    if !(first == b'_' || first == b'$' || first.is_ascii_alphabetic()) {
        return None;
    }
    let end = bytes[i..]
        .iter()
        .position(|b| !(*b == b'_' || *b == b'$' || b.is_ascii_alphanumeric()))
        .map(|rel| i + rel)
        .unwrap_or(bytes.len());
    Some(end)
}

fn push_unique_sorted(dst: &mut Vec<String>, value: &str) {
    if !dst.iter().any(|existing| existing == value) {
        dst.push(value.to_owned());
        dst.sort_unstable();
    }
}
