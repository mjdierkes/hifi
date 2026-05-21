//! Shared byte-level source helpers.
//!
//! hifi scans minified HTML and JavaScript without building a full JavaScript
//! AST. These helpers define the small, shared parsing contract used by both
//! endpoint scanning and asset discovery: quoted strings, URL-like tokens,
//! template-expression placeholders, and identifier boundaries.
//!
//! Keep this module conservative. It should expose primitives with predictable
//! behavior, not grow into a partial JavaScript parser hidden behind helpers.

/// How token extraction should treat JavaScript template expressions.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TemplateMode {
    /// Stop at template expression boundaries instead of inventing a static
    /// value. Asset discovery uses this because interpolated imports are not
    /// fetchable static files.
    Preserve,
    /// Replace `${...}` with a stable marker. Endpoint scanning uses this so
    /// humans can see route/API shape without depending on runtime values.
    ReplaceExpressions,
}

const DYNAMIC: &[u8] = b"{dynamic}";

pub fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    memchr::memmem::find(haystack, needle).is_some()
}

pub fn find_ascii_ignore_case(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() {
        return Some(0);
    }
    if needle.len() > haystack.len() {
        return None;
    }

    let mut offset = 0;
    while offset + needle.len() <= haystack.len() {
        let rel = find_first_ascii_ignore_case(&haystack[offset..], needle[0])?;
        let pos = offset + rel;
        if pos + needle.len() > haystack.len() {
            return None;
        }
        if haystack[pos..pos + needle.len()].eq_ignore_ascii_case(needle) {
            return Some(pos);
        }
        offset = pos + 1;
    }
    None
}

pub fn ends_with_ascii_ignore_case(haystack: &str, needle: &str) -> bool {
    haystack.len() >= needle.len()
        && haystack.as_bytes()[haystack.len() - needle.len()..]
            .eq_ignore_ascii_case(needle.as_bytes())
}

fn find_first_ascii_ignore_case(haystack: &[u8], needle: u8) -> Option<usize> {
    if needle.is_ascii_alphabetic() {
        memchr::memchr2(
            needle.to_ascii_lowercase(),
            needle.to_ascii_uppercase(),
            haystack,
        )
    } else {
        memchr::memchr(needle, haystack)
    }
}

pub fn find_token_delim(bytes: &[u8], include_equals: bool) -> Option<usize> {
    #[cfg(target_arch = "aarch64")]
    {
        unsafe { find_token_delim_neon(bytes, include_equals) }
    }
    #[cfg(not(target_arch = "aarch64"))]
    {
        find_token_delim_scalar(bytes, include_equals)
    }
}

pub fn rfind_token_delim(bytes: &[u8], include_equals: bool) -> Option<usize> {
    #[cfg(target_arch = "aarch64")]
    {
        unsafe { rfind_token_delim_neon(bytes, include_equals) }
    }
    #[cfg(not(target_arch = "aarch64"))]
    {
        rfind_token_delim_scalar(bytes, include_equals)
    }
}

fn find_token_delim_scalar(bytes: &[u8], include_equals: bool) -> Option<usize> {
    bytes
        .iter()
        .position(|b| is_token_delim(*b, include_equals))
}

fn rfind_token_delim_scalar(bytes: &[u8], include_equals: bool) -> Option<usize> {
    bytes
        .iter()
        .rposition(|b| is_token_delim(*b, include_equals))
}

#[cfg(target_arch = "aarch64")]
unsafe fn find_token_delim_neon(bytes: &[u8], include_equals: bool) -> Option<usize> {
    use std::arch::aarch64::*;

    let mut i = 0;
    while i + 16 <= bytes.len() {
        let m = token_delim_mask_neon(vld1q_u8(bytes.as_ptr().add(i)), include_equals);
        let mut out = [0u8; 16];
        vst1q_u8(out.as_mut_ptr(), m);
        if let Some(rel) = out.iter().position(|b| *b != 0) {
            return Some(i + rel);
        }
        i += 16;
    }
    find_token_delim_scalar(&bytes[i..], include_equals).map(|rel| i + rel)
}

#[cfg(target_arch = "aarch64")]
unsafe fn rfind_token_delim_neon(bytes: &[u8], include_equals: bool) -> Option<usize> {
    use std::arch::aarch64::*;

    let mut end = bytes.len();
    while end >= 16 {
        end -= 16;
        let m = token_delim_mask_neon(vld1q_u8(bytes.as_ptr().add(end)), include_equals);
        let mut out = [0u8; 16];
        vst1q_u8(out.as_mut_ptr(), m);
        if let Some(rel) = out.iter().rposition(|b| *b != 0) {
            return Some(end + rel);
        }
    }
    rfind_token_delim_scalar(&bytes[..end], include_equals)
}

#[cfg(target_arch = "aarch64")]
unsafe fn token_delim_mask_neon(
    v: std::arch::aarch64::uint8x16_t,
    include_equals: bool,
) -> std::arch::aarch64::uint8x16_t {
    use std::arch::aarch64::*;

    let mut m = vceqq_u8(v, vdupq_n_u8(b'"'));
    for b in [
        b'\'', b'`', b'<', b'>', b')', b'(', b',', b';', b'{', b'}', b'[', b']',
    ] {
        m = vorrq_u8(m, vceqq_u8(v, vdupq_n_u8(b)));
    }
    if include_equals {
        m = vorrq_u8(m, vceqq_u8(v, vdupq_n_u8(b'=')));
    }
    let ws_range = vandq_u8(vcgeq_u8(v, vdupq_n_u8(9)), vcleq_u8(v, vdupq_n_u8(13)));
    m = vorrq_u8(m, ws_range);
    vorrq_u8(m, vceqq_u8(v, vdupq_n_u8(b' ')))
}

pub fn skip_ws(bytes: &[u8], mut i: usize) -> usize {
    while bytes.get(i).is_some_and(|b| b.is_ascii_whitespace()) {
        i += 1;
    }
    i
}

pub fn quoted_arg(bytes: &[u8], start: usize) -> Option<&str> {
    let mut i = skip_ws(bytes, start);
    let quote = *bytes.get(i)?;
    if !matches!(quote, b'"' | b'\'' | b'`') {
        return None;
    }
    i += 1;
    let end = quoted_end(bytes, i, quote)?;
    std::str::from_utf8(&bytes[i..end]).ok()
}

pub fn quoted_arg_end(bytes: &[u8], start: usize) -> Option<usize> {
    let mut i = skip_ws(bytes, start);
    let quote = *bytes.get(i)?;
    if !matches!(quote, b'"' | b'\'' | b'`') {
        return None;
    }
    i += 1;
    while i < bytes.len() {
        if bytes[i] == b'\\' && i + 1 < bytes.len() {
            i += 2;
        } else if quote == b'`' && bytes.get(i..i + 2) == Some(b"${") {
            i = skip_template_expr(bytes, i + 2);
        } else if bytes[i] == quote {
            return Some(i + 1);
        } else {
            i += 1;
        }
    }
    Some(bytes.len())
}

pub fn quoted_string(
    bytes: &[u8],
    start: usize,
    quote: u8,
    template_mode: TemplateMode,
) -> Option<String> {
    let mut normalized = None;
    let mut i = start;
    while i < bytes.len() {
        if bytes[i] == b'\\' && i + 1 < bytes.len() {
            normalized
                .get_or_insert_with(|| bytes[start..i].to_vec())
                .push(bytes[i + 1]);
            i += 2;
        } else if template_mode == TemplateMode::ReplaceExpressions
            && quote == b'`'
            && bytes.get(i..i + 2) == Some(b"${")
        {
            normalized
                .get_or_insert_with(|| bytes[start..i].to_vec())
                .extend_from_slice(DYNAMIC);
            i = skip_template_expr(bytes, i + 2);
        } else if bytes[i] == quote {
            return string_from_parts(bytes, start, i, normalized);
        } else {
            if let Some(out) = normalized.as_mut() {
                out.push(bytes[i]);
            }
            i += 1;
        }
    }
    string_from_parts(bytes, start, bytes.len(), normalized)
}

pub fn quoted_end(bytes: &[u8], mut i: usize, quote: u8) -> Option<usize> {
    while i < bytes.len() {
        if bytes[i] == b'\\' && i + 1 < bytes.len() {
            i += 2;
        } else if bytes[i] == quote {
            return Some(i);
        } else {
            i += 1;
        }
    }
    None
}

pub fn token_string(bytes: &[u8], start: usize, template_mode: TemplateMode) -> Option<String> {
    let mut normalized = None;
    let end = token_end(bytes, start, template_mode, &mut normalized);
    string_from_parts(bytes, start, end, normalized)
}

pub fn walk_token_start(bytes: &[u8], pos: usize) -> usize {
    rfind_token_delim(&bytes[..pos], true).map_or(0, |idx| idx + 1)
}

pub fn identifier_at(bytes: &[u8], start: usize) -> Option<&[u8]> {
    let first = *bytes.get(start)?;
    if !is_identifier_start(first) {
        return None;
    }
    let end = bytes[start..]
        .iter()
        .position(|b| !is_identifier_continue(*b))
        .map(|rel| start + rel)
        .unwrap_or(bytes.len());
    Some(&bytes[start..end])
}

pub fn is_identifier_continue(b: u8) -> bool {
    b == b'_' || b == b'$' || b.is_ascii_alphanumeric()
}

pub fn skip_template_expr(bytes: &[u8], mut i: usize) -> usize {
    let mut depth = 1;
    while i < bytes.len() && depth > 0 {
        match bytes[i] {
            b'{' => depth += 1,
            b'}' => depth -= 1,
            b'\\' if i + 1 < bytes.len() => i += 1,
            _ => {}
        }
        i += 1;
    }
    i
}

pub fn is_identifier_boundary_before(bytes: &[u8], pos: usize) -> bool {
    pos == 0 || !is_identifier_continue(bytes[pos - 1])
}

fn token_end(
    bytes: &[u8],
    mut i: usize,
    template_mode: TemplateMode,
    normalized: &mut Option<Vec<u8>>,
) -> usize {
    let start = i;
    if template_mode == TemplateMode::Preserve {
        return i + find_token_delim(&bytes[i..], true).unwrap_or(bytes.len() - i);
    }
    while i < bytes.len() {
        if template_mode == TemplateMode::ReplaceExpressions && bytes[i..].starts_with(DYNAMIC) {
            normalized
                .get_or_insert_with(|| bytes[start..i].to_vec())
                .extend_from_slice(DYNAMIC);
            i += DYNAMIC.len();
        } else if template_mode == TemplateMode::ReplaceExpressions
            && bytes.get(i..i + 2) == Some(b"${")
        {
            normalized
                .get_or_insert_with(|| bytes[start..i].to_vec())
                .extend_from_slice(DYNAMIC);
            i = skip_template_expr(bytes, i + 2);
        } else if is_token_delim(bytes[i], true) {
            break;
        } else {
            if let Some(out) = normalized {
                out.push(bytes[i]);
            }
            i += 1;
        }
    }
    i
}

fn string_from_parts(
    bytes: &[u8],
    start: usize,
    end: usize,
    normalized: Option<Vec<u8>>,
) -> Option<String> {
    if let Some(out) = normalized {
        return String::from_utf8(out)
            .ok()
            .map(|s| s.trim_matches('\\').to_string());
    }
    std::str::from_utf8(&bytes[start..end])
        .ok()
        .map(|s| s.trim_matches('\\').to_string())
}

pub fn is_token_delim(b: u8, include_equals: bool) -> bool {
    b.is_ascii_whitespace()
        || (include_equals && b == b'=')
        || matches!(
            b,
            b'"' | b'\''
                | b'`'
                | b'<'
                | b'>'
                | b')'
                | b'('
                | b','
                | b';'
                | b'{'
                | b'}'
                | b'['
                | b']'
        )
}

fn is_identifier_start(b: u8) -> bool {
    b == b'_' || b == b'$' || b.is_ascii_alphabetic()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn template_tokens_can_preserve_or_replace_expressions() {
        let src = br#"/api/${team}/settings`"#;

        assert_eq!(
            token_string(src, 0, TemplateMode::ReplaceExpressions).as_deref(),
            Some("/api/{dynamic}/settings")
        );
        assert_eq!(
            token_string(src, 0, TemplateMode::Preserve).as_deref(),
            Some("/api/$")
        );
    }

    #[test]
    fn token_delim_search_matches_scalar_delimiters() {
        let src = b"alpha/beta/gamma,rest";
        assert_eq!(find_token_delim(src, true), Some(16));
        assert_eq!(find_token_delim(b"abc=def", true), Some(3));
        assert_eq!(find_token_delim(b"abc=def", false), None);
        assert_eq!(find_token_delim(b"abcdef", true), None);
    }
}
