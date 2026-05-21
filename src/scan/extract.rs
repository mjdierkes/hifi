use crate::source::{self, TemplateMode};

pub(crate) fn url_arg(bytes: &[u8], start: usize) -> Option<String> {
    if start > 0 && matches!(bytes[start - 1], b'"' | b'\'' | b'`') {
        return quoted_url_string(bytes, start, bytes[start - 1], start - 1);
    }

    let i = source::skip_ws(bytes, start);
    let next = *bytes.get(i)?;
    if matches!(next, b'"' | b'\'' | b'`') {
        return quoted_url_string(bytes, i + 1, next, i);
    }
    None
}

fn quoted_url_string(bytes: &[u8], start: usize, quote: u8, _quote_pos: usize) -> Option<String> {
    let url = source::quoted_string(bytes, start, quote, TemplateMode::ReplaceExpressions)?;
    (!url.starts_with("{dynamic}")).then_some(url)
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
