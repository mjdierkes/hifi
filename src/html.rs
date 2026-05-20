use crate::literals::SKIPPED_CHUNK_FRAGMENTS;
use std::collections::HashSet;
use url::Url;

pub fn extract_chunks(html: &str, base: &Url) -> Vec<Url> {
    let mut out = Vec::new();
    let mut seen = HashSet::new();
    let mut offset = 0;
    let bytes = html.as_bytes();
    while let Some(rel) = html[offset..].find("/_next/") {
        let start = offset + rel;
        let end = bytes[start..]
            .iter()
            .position(|b| b.is_ascii_whitespace() || matches!(b, b'"' | b'\'' | b'<' | b'>'))
            .map(|n| start + n)
            .unwrap_or(bytes.len());
        let src = &html[start..end];
        if src.contains(".js") && !is_skipped_chunk(src) {
            if let Ok(u) = base.join(src) {
                if seen.insert(u.clone()) {
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

fn is_skipped_chunk(src: &str) -> bool {
    SKIPPED_CHUNK_FRAGMENTS.iter().any(|f| src.contains(f))
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
    fn reads_quoted_and_unquoted_chunk_urls() {
        let base = Url::parse("https://example.com").unwrap();
        let html = r#"<script src="/_next/a.js"></script><script src=/_next/b.js async>"#;
        let chunks = extract_chunks(html, &base);
        assert_eq!(chunks.len(), 2);
        assert_eq!(chunks[0].as_str(), "https://example.com/_next/a.js");
        assert_eq!(chunks[1].as_str(), "https://example.com/_next/b.js");
    }

    #[test]
    fn deduplicates_repeated_chunk_urls() {
        let base = Url::parse("https://example.com").unwrap();
        let html = r#"
            <script src="/_next/a.js"></script>
            <link rel="preload" href="/_next/a.js">
            <script src="/_next/b.js"></script>
        "#;

        let chunks = extract_chunks(html, &base);

        assert_eq!(chunks.len(), 2);
        assert_eq!(chunks[0].as_str(), "https://example.com/_next/a.js");
        assert_eq!(chunks[1].as_str(), "https://example.com/_next/b.js");
    }
}
