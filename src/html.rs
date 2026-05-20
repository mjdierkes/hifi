use crate::literals::SKIPPED_CHUNK_FRAGMENTS;
use url::Url;

pub fn extract_chunks(html: &str, base: &Url) -> Vec<Url> {
    let mut out = Vec::new();
    let mut offset = 0;
    while let Some(rel) = find_ascii_ci(&html.as_bytes()[offset..], b"<script") {
        let start = offset + rel;
        let Some(end_rel) = html.as_bytes()[start..].iter().position(|&b| b == b'>') else {
            break;
        };
        let end = start + end_rel + 1;
        let tag = &html[start..end];

        if let Some(src) = attr_value(tag, "src") {
            if src.contains("/_next/") && !is_skipped_chunk(src) {
                if let Ok(u) = base.join(src) {
                    out.push(u);
                }
            }
        }

        offset = end;
    }
    out
}

pub fn extract_build_id(html: &str) -> Option<String> {
    let needle = "\"buildId\":\"";
    if let Some(i) = html.find(needle) {
        let rest = &html[i + needle.len()..];
        if let Some(end) = rest.find('"') {
            return Some(rest[..end].to_string());
        }
    }

    let marker = "/_next/static/";
    let i = html.find(marker)?;
    let rest = &html[i + marker.len()..];
    let end = rest.find('/')?;
    let candidate = &rest[..end];
    if matches!(candidate, "chunks" | "css" | "media" | "development") {
        return None;
    }
    Some(candidate.to_string())
}

fn attr_value<'a>(tag: &'a str, name: &str) -> Option<&'a str> {
    let bytes = tag.as_bytes();
    let needle = name.as_bytes();
    let mut offset = 0;

    while let Some(rel) = find_ascii_ci(&bytes[offset..], needle) {
        let name_start = offset + rel;
        let name_end = name_start + needle.len();

        if name_start > 0 && is_attr_char(bytes[name_start - 1]) {
            offset = name_end;
            continue;
        }

        let mut i = name_end;
        while i < bytes.len() && bytes[i].is_ascii_whitespace() {
            i += 1;
        }
        if i >= bytes.len() || bytes[i] != b'=' {
            offset = name_end;
            continue;
        }
        i += 1;
        while i < bytes.len() && bytes[i].is_ascii_whitespace() {
            i += 1;
        }
        if i >= bytes.len() {
            return None;
        }

        let value_start;
        let value_end;
        if matches!(bytes[i], b'"' | b'\'') {
            let quote = bytes[i];
            value_start = i + 1;
            value_end = bytes[value_start..]
                .iter()
                .position(|&b| b == quote)
                .map(|p| value_start + p)?;
        } else {
            value_start = i;
            value_end = bytes[value_start..]
                .iter()
                .position(|&b| b.is_ascii_whitespace() || b == b'>')
                .map(|p| value_start + p)
                .unwrap_or(bytes.len());
        }
        return Some(&tag[value_start..value_end]);
    }

    None
}

fn is_skipped_chunk(src: &str) -> bool {
    SKIPPED_CHUNK_FRAGMENTS
        .iter()
        .any(|f| contains_ascii_ci(src, f))
}

fn contains_ascii_ci(haystack: &str, needle: &str) -> bool {
    find_ascii_ci(haystack.as_bytes(), needle.as_bytes()).is_some()
}

fn find_ascii_ci(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() {
        return Some(0);
    }
    if needle.len() > haystack.len() {
        return None;
    }

    haystack
        .windows(needle.len())
        .position(|w| w.eq_ignore_ascii_case(needle))
}

fn is_attr_char(b: u8) -> bool {
    b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-' | b':')
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extracts_next_script_chunks_without_framework_noise() {
        let base = Url::parse("https://example.com/app/page").unwrap();
        let html = r#"
            <script src="/_next/static/chunks/framework-abc.js"></script>
            <script defer SRC='/_next/static/chunks/app/dashboard-123.js'></script>
            <script src="/assets/site.js"></script>
        "#;

        let chunks = extract_chunks(html, &base);

        assert_eq!(chunks.len(), 1);
        assert_eq!(
            chunks[0].as_str(),
            "https://example.com/_next/static/chunks/app/dashboard-123.js"
        );
    }

    #[test]
    fn reads_quoted_and_unquoted_attributes() {
        assert_eq!(
            attr_value(r#"<script defer src="/_next/a.js">"#, "src"),
            Some("/_next/a.js")
        );
        assert_eq!(
            attr_value("<script src=/_next/b.js async>", "src"),
            Some("/_next/b.js")
        );
        assert_eq!(
            attr_value(r#"<script data-src="/_next/wrong.js">"#, "src"),
            None
        );
    }
}
