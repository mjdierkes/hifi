use crate::source::{self, TemplateMode};

const LOOKBACK_WINDOW: usize = 2048;
const DYNAMIC: &str = "{dynamic}";

pub(crate) fn url_arg(bytes: &[u8], start: usize) -> Option<String> {
    if start > 0 && matches!(bytes[start - 1], b'"' | b'\'' | b'`') {
        return quoted_url_string(bytes, start, bytes[start - 1], start - 1);
    }

    let i = source::skip_ws(bytes, start);
    let next = *bytes.get(i)?;
    if matches!(next, b'"' | b'\'' | b'`') {
        return quoted_url_string(bytes, i + 1, next, i);
    }
    // Bundlers commonly hoist URLs into a local variable: `let t = `${base}/api/foo`; fetch(t, {...})`.
    // When the call argument is a bare identifier, look backward for its most
    // recent assignment so we can still attach the call shape to the URL.
    resolve_var_url(bytes, i)
}

fn resolve_var_url(bytes: &[u8], pos: usize) -> Option<String> {
    let ident = read_identifier(bytes, pos)?;
    if ident.is_empty() || !is_ident_continue(ident[0]) {
        return None;
    }

    let start = pos.saturating_sub(LOOKBACK_WINDOW);
    let mut search_from = start;
    let mut latest_url: Option<String> = None;
    while let Some(rel) = memchr::memmem::find(&bytes[search_from..pos], ident) {
        let match_pos = search_from + rel;
        let after = match_pos + ident.len();
        search_from = match_pos + 1;

        if match_pos > 0 && is_ident_continue(bytes[match_pos - 1]) {
            continue;
        }
        if bytes.get(after).is_some_and(|b| is_ident_continue(*b)) {
            continue;
        }

        let mut j = source::skip_ws(bytes, after);
        if bytes.get(j) != Some(&b'=') {
            continue;
        }
        // Skip `==` and `===`; those are comparisons, not assignments.
        if bytes.get(j + 1) == Some(&b'=') {
            continue;
        }
        j = source::skip_ws(bytes, j + 1);
        let quote = match bytes.get(j) {
            Some(&q) if matches!(q, b'"' | b'\'' | b'`') => q,
            _ => continue,
        };
        let mut value_start = j + 1;
        if quote == b'`' && bytes.get(value_start..value_start + 2) == Some(b"${") {
            value_start = source::skip_template_expr(bytes, value_start + 2);
        }
        if let Some(url) =
            source::quoted_string(bytes, value_start, quote, TemplateMode::ReplaceExpressions)
        {
            latest_url = Some(url);
        }
    }
    latest_url
}

fn quoted_url_string(bytes: &[u8], start: usize, quote: u8, quote_pos: usize) -> Option<String> {
    if quote != b'`' {
        return source::quoted_string(bytes, start, quote, TemplateMode::ReplaceExpressions);
    }

    let resolved = template_string_with_constants(bytes, start, quote_pos)?;
    if !resolved.starts_with(DYNAMIC) {
        return Some(resolved);
    }

    // Preserve the old behavior for templates like `${base}/api/foo`: when the
    // leading expression cannot be resolved, drop it and keep the useful path.
    if bytes.get(start..start + 2) == Some(b"${") {
        let after_expr = source::skip_template_expr(bytes, start + 2);
        let suffix =
            source::quoted_string(bytes, after_expr, quote, TemplateMode::ReplaceExpressions)?;
        return Some(promote_relative_path(suffix));
    }
    Some(resolved)
}

// SDK code routinely writes URLs as `${this.apiBase}v1/foo` — the base variable
// already includes the trailing slash, so the literal suffix is bare (`v1/foo`,
// no leading slash). After stripping the unresolved `${...}` prefix, we want
// to keep these as relative API paths instead of dropping them on the floor.
// Only promote when the suffix looks like a path (contains `/` and starts with
// an identifier character) — a bare word like `txt` could be anything.
fn promote_relative_path(suffix: String) -> String {
    if suffix.starts_with('/') || suffix.is_empty() {
        return suffix;
    }
    let first = suffix.as_bytes()[0];
    if !first.is_ascii_alphanumeric() || !suffix.contains('/') {
        return suffix;
    }
    format!("/{suffix}")
}

fn template_string_with_constants(bytes: &[u8], start: usize, quote_pos: usize) -> Option<String> {
    let mut out = Vec::new();
    let mut i = start;
    while i < bytes.len() {
        match bytes[i] {
            b'\\' if i + 1 < bytes.len() => {
                out.push(bytes[i + 1]);
                i += 2;
            }
            b'`' => return String::from_utf8(out).ok(),
            b'$' if bytes.get(i + 1) == Some(&b'{') => {
                let expr_start = i + 2;
                let after_expr = source::skip_template_expr(bytes, expr_start);
                let expr_end = after_expr.saturating_sub(1);
                if let Some(value) =
                    resolve_template_identifier(bytes, expr_start, expr_end, quote_pos)
                {
                    out.extend_from_slice(value.as_bytes());
                } else {
                    out.extend_from_slice(DYNAMIC.as_bytes());
                }
                i = after_expr;
            }
            b => {
                out.push(b);
                i += 1;
            }
        }
    }
    String::from_utf8(out).ok()
}

fn resolve_template_identifier(
    bytes: &[u8],
    expr_start: usize,
    expr_end: usize,
    before_pos: usize,
) -> Option<String> {
    let mut start = expr_start;
    while start < expr_end && bytes[start].is_ascii_whitespace() {
        start += 1;
    }
    let mut end = expr_end;
    while end > start && bytes[end - 1].is_ascii_whitespace() {
        end -= 1;
    }
    if start >= end {
        return None;
    }
    let ident = read_identifier(bytes, start)?;
    if start + ident.len() != end {
        return None;
    }
    resolve_const_string(bytes, ident, before_pos)
}

fn resolve_const_string(bytes: &[u8], ident: &[u8], before_pos: usize) -> Option<String> {
    let start = before_pos.saturating_sub(LOOKBACK_WINDOW);
    let mut search_from = start;
    let mut latest_value = None;
    while let Some(rel) = memchr::memmem::find(&bytes[search_from..before_pos], ident) {
        let match_pos = search_from + rel;
        let after = match_pos + ident.len();
        search_from = match_pos + 1;

        if match_pos > 0 && is_ident_continue(bytes[match_pos - 1]) {
            continue;
        }
        if bytes.get(after).is_some_and(|b| is_ident_continue(*b)) {
            continue;
        }

        let mut j = source::skip_ws(bytes, after);
        if bytes.get(j) != Some(&b'=') || bytes.get(j + 1) == Some(&b'=') {
            continue;
        }
        j = source::skip_ws(bytes, j + 1);
        let quote = match bytes.get(j) {
            Some(&q) if matches!(q, b'"' | b'\'' | b'`') => q,
            _ => continue,
        };
        let value_start = j + 1;
        let value =
            source::quoted_string(bytes, value_start, quote, TemplateMode::ReplaceExpressions)?;
        if value.contains(DYNAMIC) || value.contains("${") {
            continue;
        }
        latest_value = Some(value);
    }
    latest_value
}

fn read_identifier(bytes: &[u8], start: usize) -> Option<&[u8]> {
    let first = *bytes.get(start)?;
    if !is_ident_start(first) {
        return None;
    }
    let end = bytes[start..]
        .iter()
        .position(|b| !is_ident_continue(*b))
        .map(|rel| start + rel)
        .unwrap_or(bytes.len());
    Some(&bytes[start..end])
}

fn is_ident_start(b: u8) -> bool {
    b == b'_' || b == b'$' || b.is_ascii_alphabetic()
}

fn is_ident_continue(b: u8) -> bool {
    b == b'_' || b == b'$' || b.is_ascii_alphanumeric()
}

pub(crate) fn value_after_anchor(bytes: &[u8], mut i: usize) -> Option<String> {
    i = source::skip_ws(bytes, i);
    if matches!(bytes.get(i), Some(b'"' | b'\'' | b'`')) {
        let quote = bytes[i];
        i = source::skip_ws(bytes, i + 1);
        if bytes.get(i) == Some(&quote) {
            i += 1;
        }
    }
    i = source::skip_ws(bytes, i);
    if !matches!(bytes.get(i), Some(b':' | b'=')) {
        return None;
    }
    url_arg(bytes, i + 1)
}

pub(crate) fn token_before(bytes: &[u8], pos: usize) -> Option<String> {
    let start = source::walk_token_start(bytes, pos);
    token_at(bytes, start)
}

pub(crate) fn token_at(bytes: &[u8], pos: usize) -> Option<String> {
    source::token_string(bytes, pos, TemplateMode::ReplaceExpressions)
}
