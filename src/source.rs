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
    let mut start = pos;
    while start > 0 && !is_token_delim(bytes[start - 1]) {
        start -= 1;
    }
    start
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
    pos == 0
        || !matches!(
            bytes[pos - 1],
            b'a'..=b'z' | b'A'..=b'Z' | b'0'..=b'9' | b'_' | b'$'
        )
}

fn token_end(
    bytes: &[u8],
    mut i: usize,
    template_mode: TemplateMode,
    normalized: &mut Option<Vec<u8>>,
) -> usize {
    let start = i;
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
        } else if is_token_delim(bytes[i]) {
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

fn is_token_delim(b: u8) -> bool {
    b.is_ascii_whitespace()
        || matches!(
            b,
            b'"' | b'\''
                | b'`'
                | b'<'
                | b'>'
                | b'='
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
}
