//! HTTP client call-site analyzer ($fetch, axios, ky, etc.).

use super::{anchors::scan_anchor_bytes, extract, findings::Channel, shape, FindingsBuilder, Provenance};
use crate::generated::{CLIENT_METHODS, FIXED_CLIENT_PATTERNS};
use crate::hash::FxHashMap;
use crate::source;

pub(super) fn scan(bytes: &[u8], out: &mut FindingsBuilder) {
    let bindings = collect_string_bindings(bytes);
    for pattern in FIXED_CLIENT_PATTERNS {
        scan_pattern(
            bytes,
            pattern.anchor,
            pattern.method,
            ClientMode::from_tag(pattern.mode),
            &bindings,
            out,
        );
    }
    for m in CLIENT_METHODS {
        let dollar = format!("$api.${}(", m.to_lowercase());
        scan_pattern(bytes, dollar.as_bytes(), Some(*m), ClientMode::FirstArg, &bindings, out);
        let dot = format!("$api.{}(", m.to_lowercase());
        scan_pattern(bytes, dot.as_bytes(), Some(*m), ClientMode::FirstArg, &bindings, out);
        let axios = format!("$axios.${}(", m.to_lowercase());
        scan_pattern(bytes, axios.as_bytes(), Some(*m), ClientMode::FirstArg, &bindings, out);
        let generic = format!(".{}(", m.to_lowercase());
        scan_pattern(bytes, generic.as_bytes(), Some(*m), ClientMode::GenericMethod, &bindings, out);
    }
}

fn scan_pattern(
    bytes: &[u8],
    anchor: &[u8],
    method: Option<&str>,
    mode: ClientMode,
    bindings: &FxHashMap<String, String>,
    out: &mut FindingsBuilder,
) {
    scan_anchor_bytes(bytes, &[anchor], |pos, needle| {
        let after = pos + needle.len();
        match mode {
            ClientMode::FirstArg => record_first_arg_client_with_method(
                bytes,
                after,
                method.or_else(|| method_near(bytes, after)),
                bindings,
                out,
            ),
            ClientMode::Object => record_object_client(bytes, after, bindings, out),
            ClientMode::GenericMethod if apiish_receiver_context(bytes, pos) => {
                record_first_arg_client_with_method(bytes, after, method, bindings, out);
            }
            ClientMode::GenericMethod => {}
        }
    });
}

#[derive(Clone, Copy)]
enum ClientMode {
    FirstArg,
    Object,
    GenericMethod,
}

impl ClientMode {
    fn from_tag(tag: u8) -> Self {
        match tag {
            1 => Self::Object,
            2 => Self::GenericMethod,
            _ => Self::FirstArg,
        }
    }
}

fn record_first_arg_client_with_method(
    bytes: &[u8],
    after: usize,
    method: Option<&str>,
    bindings: &FxHashMap<String, String>,
    out: &mut FindingsBuilder,
) {
    let Some(url) = first_arg_url(bytes, after, bindings) else {
        return;
    };
    let shape = shape::Shape::inferred(method, false);
    out.try_record_api(url, shape, Provenance::channel(Channel::ApiClient));
}

fn record_object_client(
    bytes: &[u8],
    after: usize,
    bindings: &FxHashMap<String, String>,
    out: &mut FindingsBuilder,
) {
    let i = source::skip_ws(bytes, after);
    if bytes.get(i) != Some(&b'{') {
        return;
    }
    let end = source::balanced_end(bytes, i)
        .map(|end| end + 1)
        .unwrap_or_else(|| bytes.len().min(i + 1024));
    let obj = &bytes[i..end];
    let Some(url) = object_url_value(obj, &[b"url", b"URL", b"endpoint", b"path"], bindings) else {
        return;
    };
    let method = object_string_value(obj, &[b"method"])
        .or_else(|| method_near(bytes, i).map(str::to_string));
    let shape = shape::Shape::inferred(
        method.as_deref(),
        contains_key(obj, b"data") || contains_key(obj, b"body"),
    );
    out.try_record_api(url, shape, Provenance::channel(Channel::ApiClient));
}

fn collect_string_bindings(bytes: &[u8]) -> FxHashMap<String, String> {
    let mut out = FxHashMap::default();
    for keyword in [b"const ".as_slice(), b"let ".as_slice(), b"var ".as_slice()] {
        for pos in memchr::memmem::find_iter(bytes, keyword) {
            collect_decl_bindings(bytes, pos + keyword.len(), &mut out);
        }
    }
    out
}

fn collect_decl_bindings(bytes: &[u8], mut i: usize, out: &mut FxHashMap<String, String>) {
    let end = bytes.len().min(i + 2048);
    while i < end {
        i = source::skip_ws(bytes, i);
        let Some(name) = source::identifier_at(bytes, i) else {
            return;
        };
        let name_end = i + name.len();
        i = source::skip_ws(bytes, name_end);
        if bytes.get(i) != Some(&b'=') {
            return;
        }
        i = source::skip_ws(bytes, i + 1);
        if let Some((value, value_end)) = static_string_expr(bytes, i, out) {
            if useful_binding(&value) {
                out.insert(String::from_utf8_lossy(name).to_string(), value);
            }
            i = source::skip_ws(bytes, value_end);
        } else {
            return;
        }
        match bytes.get(i) {
            Some(b',') => i += 1,
            _ => return,
        }
    }
}

fn first_arg_url(
    bytes: &[u8],
    start: usize,
    bindings: &FxHashMap<String, String>,
) -> Option<String> {
    if let Some(url) = extract::url_arg(bytes, start) {
        return Some(url);
    }
    let i = source::skip_ws(bytes, start);
    static_string_expr(bytes, i, bindings).map(|(value, _)| value)
}

fn object_url_value(
    bytes: &[u8],
    keys: &[&[u8]],
    bindings: &FxHashMap<String, String>,
) -> Option<String> {
    object_string_value(bytes, keys).or_else(|| object_static_value(bytes, keys, bindings))
}

fn object_static_value(
    bytes: &[u8],
    keys: &[&[u8]],
    bindings: &FxHashMap<String, String>,
) -> Option<String> {
    find_object_key_values(bytes, keys, |i| {
        if let Some((value, _)) = static_string_expr(bytes, i, bindings) {
            return Some(value);
        }
        None
    })
}

fn static_string_expr(
    bytes: &[u8],
    start: usize,
    bindings: &FxHashMap<String, String>,
) -> Option<(String, usize)> {
    let mut i = source::skip_ws(bytes, start);
    let mut out = String::new();
    let mut saw_part = false;
    while i < bytes.len() {
        i = source::skip_ws(bytes, i);
        match bytes.get(i).copied()? {
            quote @ (b'"' | b'\'' | b'`') => {
                let part = if quote == b'`' {
                    template_with_bindings(bytes, i + 1, bindings)?
                } else {
                    source::quoted_string(bytes, i + 1, quote, source::TemplateMode::Preserve)?
                };
                out.push_str(&part);
                i = source::quoted_end(bytes, i + 1, quote)? + 1;
                saw_part = true;
            }
            b if source::is_identifier_continue(b) => {
                let ident = source::identifier_at(bytes, i)?;
                let name = std::str::from_utf8(ident).ok()?;
                let value = bindings.get(name)?;
                out.push_str(value);
                i += ident.len();
                saw_part = true;
            }
            _ => break,
        }
        i = source::skip_ws(bytes, i);
        if bytes.get(i) != Some(&b'+') {
            break;
        }
        i += 1;
    }
    if saw_part && !out.starts_with("{dynamic}") {
        Some((out, i))
    } else {
        None
    }
}

fn template_with_bindings(
    bytes: &[u8],
    start: usize,
    bindings: &FxHashMap<String, String>,
) -> Option<String> {
    let mut out = String::new();
    let mut i = start;
    while i < bytes.len() {
        if bytes[i] == b'\\' && i + 1 < bytes.len() {
            out.push(bytes[i + 1] as char);
            i += 2;
        } else if bytes.get(i..i + 2) == Some(b"${") {
            let expr = i + 2;
            let end = source::skip_template_expr(bytes, expr);
            let inner_end = end.saturating_sub(1);
            let ident_start = source::skip_ws(bytes, expr);
            let ident = source::identifier_at(bytes, ident_start)
                .and_then(|name| {
                    let name_end = ident_start + name.len();
                    (source::skip_ws(bytes, name_end) == inner_end).then_some(name)
                })
                .and_then(|name| std::str::from_utf8(name).ok());
            if let Some(value) = ident.and_then(|name| bindings.get(name)) {
                out.push_str(value);
            } else {
                out.push_str("{dynamic}");
            }
            i = end;
        } else if bytes[i] == b'`' {
            return Some(out);
        } else {
            out.push(bytes[i] as char);
            i += 1;
        }
    }
    Some(out)
}

fn useful_binding(value: &str) -> bool {
    super::classify::is_url_like(value)
        || value == "/api"
        || value.starts_with("/api/")
        || value.starts_with("/graphql")
        || value.starts_with("/trpc")
        || value.contains("/api/")
}

fn apiish_receiver_context(bytes: &[u8], dot: usize) -> bool {
    let start = dot.saturating_sub(64);
    let context = &bytes[start..dot];
    [
        b"api".as_slice(),
        b"Api".as_slice(),
        b"API".as_slice(),
        b"axios".as_slice(),
        b"http".as_slice(),
        b"client".as_slice(),
        b"Client".as_slice(),
        b"service".as_slice(),
        b"Service".as_slice(),
        b"repo".as_slice(),
        b"Repo".as_slice(),
        b"request".as_slice(),
        b"Request".as_slice(),
    ]
    .iter()
    .any(|needle| memchr::memmem::find(context, needle).is_some())
}

fn object_string_value(bytes: &[u8], keys: &[&[u8]]) -> Option<String> {
    find_object_key_values(bytes, keys, |i| {
        matches!(bytes.get(i), Some(b'"' | b'\'' | b'`')).then(|| extract::url_arg(bytes, i))?
    })
}

fn find_object_key_values<T>(
    bytes: &[u8],
    keys: &[&[u8]],
    mut found: impl FnMut(usize) -> Option<T>,
) -> Option<T> {
    for key in keys {
        let mut offset = 0;
        while let Some(rel) = memchr::memmem::find(&bytes[offset..], key) {
            let pos = offset + rel;
            if !source::is_identifier_boundary_before(bytes, pos) {
                offset = pos + 1;
                continue;
            }
            let mut i = source::skip_ws(bytes, pos + key.len());
            if bytes.get(i) != Some(&b':') {
                offset = pos + 1;
                continue;
            }
            i = source::skip_ws(bytes, i + 1);
            if let Some(value) = found(i) {
                return Some(value);
            }
            offset = pos + 1;
        }
    }
    None
}

fn method_near(bytes: &[u8], start: usize) -> Option<&'static str> {
    let end = memchr::memchr(b';', &bytes[start..])
        .map(|rel| start + rel)
        .unwrap_or_else(|| bytes.len().min(start + 256));
    ["DELETE", "PATCH", "POST", "PUT", "GET", "HEAD", "OPTIONS"]
        .into_iter()
        .find(|method| {
            source::find_ascii_ignore_case(&bytes[start..end], method.as_bytes()).is_some()
        })
}

fn contains_key(bytes: &[u8], key: &[u8]) -> bool {
    let mut offset = 0;
    while let Some(rel) = memchr::memmem::find(&bytes[offset..], key) {
        let pos = offset + rel;
        if source::is_identifier_boundary_before(bytes, pos) {
            return true;
        }
        offset = pos + 1;
    }
    false
}
