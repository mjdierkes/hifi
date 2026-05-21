use crate::source::{self, TemplateMode};

pub(crate) fn url_arg(bytes: &[u8], start: usize) -> Option<String> {
    if start > 0 && matches!(bytes[start - 1], b'"' | b'\'' | b'`') {
        return source::quoted_string(
            bytes,
            start,
            bytes[start - 1],
            TemplateMode::ReplaceExpressions,
        );
    }

    let mut i = source::skip_ws(bytes, start);
    let quote = *bytes.get(i)?;
    if !matches!(quote, b'"' | b'\'' | b'`') {
        return None;
    }
    i += 1;
    if quote == b'`' && bytes.get(i..i + 2) == Some(b"${") {
        i = source::skip_template_expr(bytes, i + 2);
    }
    source::quoted_string(bytes, i, quote, TemplateMode::ReplaceExpressions)
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
