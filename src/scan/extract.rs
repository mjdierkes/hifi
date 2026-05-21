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
    let ident = source::identifier_at(bytes, pos)?;
    source::latest_quoted_assignment(
        bytes,
        ident,
        pos,
        LOOKBACK_WINDOW,
        TemplateMode::ReplaceExpressions,
        true,
        false,
    )
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
    start = source::skip_ws(bytes, start);
    let mut end = expr_end;
    while end > start && bytes[end - 1].is_ascii_whitespace() {
        end -= 1;
    }
    if start >= end {
        return None;
    }
    let ident = source::identifier_at(bytes, start)?;
    if start + ident.len() != end {
        return None;
    }
    resolve_const_string(bytes, ident, before_pos)
}

fn resolve_const_string(bytes: &[u8], ident: &[u8], before_pos: usize) -> Option<String> {
    source::latest_quoted_assignment(
        bytes,
        ident,
        before_pos,
        LOOKBACK_WINDOW,
        TemplateMode::ReplaceExpressions,
        false,
        true,
    )
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
