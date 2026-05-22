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

#[derive(Default, Clone, Debug, Serialize, Deserialize)]
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
        let mut flags = Vec::with_capacity(6);
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

    pub(crate) fn inferred(method: Option<&str>, has_body: bool) -> Self {
        let mut shape = Self {
            has_body,
            ..Self::default()
        };
        if let Some(method) = method {
            shape.methods |= method_bit(method);
        }
        shape.ensure_default_method();
        shape
    }
}

fn is_false(value: &bool) -> bool {
    !*value
}

// Shape extraction is deliberately heuristic. It should capture useful request
// hints from nearby source without pretending to validate JavaScript semantics.
pub(crate) fn scan_call(
    bytes: &[u8],
    _start: usize,
    after: usize,
    anchor: &str,
) -> Option<(String, Shape)> {
    let url = extract::url_arg(bytes, after)?;
    let mut shape = Shape::default();
    let hint = method_hint(anchor);
    shape.methods |= hint;
    if is_fetch_style(anchor) {
        apply_fetch_options_shape(bytes, after, &mut shape);
    } else if method_allows_body(hint) {
        apply_second_arg_body_shape(bytes, after, &mut shape);
    }
    Some((url, shape))
}

fn apply_fetch_options_shape(bytes: &[u8], start: usize, shape: &mut Shape) {
    let Some(first_end) = first_arg_end(bytes, start) else {
        return;
    };
    let mut i = source::skip_ws(bytes, first_end);
    if bytes.get(i) != Some(&b',') {
        return;
    }
    i = source::skip_ws(bytes, i + 1);
    if bytes.get(i) != Some(&b'{') {
        return;
    }
    apply_options_object_shape(bytes, i, shape);
}

fn apply_options_object_shape(bytes: &[u8], start: usize, shape: &mut Shape) {
    let Some(end) = source::balanced_end(bytes, start) else {
        return;
    };
    let options = &bytes[start..=end];
    let parsed = shape_from_object(options);
    shape.methods |= parsed.methods;
    shape.has_body |= parsed.has_body;
    shape.has_headers |= parsed.has_headers;
    shape.content_types |= parsed.content_types;
    shape.auth |= parsed.auth;
}

fn shape_from_object(bytes: &[u8]) -> Shape {
    let mut shape = Shape::default();
    let mut offset = 0;
    while let Some(rel) = source::find_ascii_ignore_case(&bytes[offset..], b"method") {
        let method = offset + rel;
        shape.methods |= parse_method(&bytes[method + 6..]);
        offset = method + 6;
    }
    shape.has_body = contains_any_ignore_case(bytes, BODY_HINTS);
    shape.has_headers = contains_any_ignore_case(bytes, HEADER_HINTS);
    shape.auth = contains_any_ignore_case(bytes, AUTH_HINTS);
    for (hints, bit) in CONTENT_HINTS {
        if contains_any_ignore_case(bytes, hints) {
            shape.content_types |= *bit;
        }
    }
    shape
}

fn contains_any_ignore_case(haystack: &[u8], needles: &[&[u8]]) -> bool {
    needles
        .iter()
        .any(|needle| source::find_ascii_ignore_case(haystack, needle).is_some())
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
    let method = &bytes[..end];
    METHODS
        .iter()
        .find_map(|(bit, name)| method.eq_ignore_ascii_case(name.as_bytes()).then_some(*bit))
        .unwrap_or(0)
}

fn method_bit(method: &str) -> u8 {
    METHODS
        .iter()
        .find_map(|(bit, name)| method.eq_ignore_ascii_case(name).then_some(*bit))
        .unwrap_or(0)
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
    if bytes.get(i) == Some(&b'{') {
        shape.content_types |= CONTENT_JSON;
    }
}

fn method_hint(anchor: &str) -> u8 {
    match anchor {
        "axios.get(" | "ky.get(" => METHOD_GET,
        "axios.post(" | "ky.post(" => METHOD_POST,
        "axios.put(" | "ky.put(" => METHOD_PUT,
        "axios.delete(" | "ky.delete(" => METHOD_DELETE,
        "axios.patch(" | "ky.patch(" => METHOD_PATCH,
        _ => 0,
    }
}

fn is_fetch_style(anchor: &str) -> bool {
    matches!(anchor, "fetch(" | "fetch (")
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
    None
}

fn push_unique_sorted(dst: &mut Vec<String>, value: &str) {
    if !dst.iter().any(|existing| existing == value) {
        dst.push(value.to_owned());
        dst.sort_unstable();
    }
}
