use crate::literals::SKIPPED_CHUNK_FRAGMENTS;
use memchr::memmem;
use rustc_hash::FxHashSet;
use url::Url;

pub fn extract_chunks(html: &[u8], base: &Url) -> Vec<Url> {
    let mut out = Vec::new();
    let mut seen = FxHashSet::default();
    let mut offset = 0;
    while let Some(rel) = memmem::find(&html[offset..], b"/_next/") {
        let start = offset + rel;
        let end = html[start..]
            .iter()
            .position(|b| b.is_ascii_whitespace() || matches!(b, b'"' | b'\'' | b'<' | b'>'))
            .map(|n| start + n)
            .unwrap_or(html.len());
        let src = &html[start..end];
        if memmem::find(src, b".js").is_some() && !is_skipped_chunk(src) {
            if let Ok(src) = std::str::from_utf8(src) {
                let Ok(u) = base.join(src) else {
                    offset = end;
                    continue;
                };
                if seen.insert(u.clone()) {
                    out.push(u);
                }
            }
        }
        offset = end;
    }
    out
}

pub fn extract_build_id(html: &[u8]) -> Option<String> {
    let needle = br#""buildId":""#;
    if let Some(i) = memmem::find(html, needle) {
        let rest = &html[i + needle.len()..];
        if let Some(end) = memchr::memchr(b'"', rest) {
            return std::str::from_utf8(&rest[..end]).ok().map(str::to_string);
        }
    }

    let marker = b"/_next/static/";
    let i = memmem::find(html, marker)?;
    let rest = &html[i + marker.len()..];
    let end = memchr::memchr(b'/', rest)?;
    let candidate = &rest[..end];
    if matches!(candidate, b"chunks" | b"css" | b"media" | b"development") {
        return None;
    }
    std::str::from_utf8(candidate).ok().map(str::to_string)
}

fn is_skipped_chunk(src: &[u8]) -> bool {
    SKIPPED_CHUNK_FRAGMENTS
        .iter()
        .any(|f| memmem::find(src, f.as_bytes()).is_some())
}
