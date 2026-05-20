use crate::literals::SKIPPED_CHUNK_FRAGMENTS;
use memchr::memmem;
use rustc_hash::FxHashSet;
use url::Url;

pub fn extract_chunks(html: &[u8], base: &Url) -> Vec<Url> {
    let mut out = Vec::new();
    let mut seen_src = FxHashSet::default();
    let mut seen = FxHashSet::default();
    let mut offset = 0;
    while let Some(rel) = memmem::find(&html[offset..], b"/_next/") {
        let needle_pos = offset + rel;
        let start = walk_url_start(html, needle_pos);
        let end = html[needle_pos..]
            .iter()
            .position(|b| b.is_ascii_whitespace() || matches!(b, b'"' | b'\'' | b'<' | b'>' | b')'))
            .map(|n| needle_pos + n)
            .unwrap_or(html.len());
        let src = &html[start..end];
        if memmem::find(src, b".js").is_some() && !is_skipped_chunk(src) {
            if seen_src.insert(src.to_vec()) {
                if let Ok(src_str) = std::str::from_utf8(src) {
                    if let Ok(u) = base.join(src_str) {
                        if seen.insert(u.clone()) {
                            out.push(u);
                        }
                    }
                }
            }
        }
        offset = end;
    }
    out
}

fn walk_url_start(html: &[u8], needle_pos: usize) -> usize {
    let mut s = needle_pos;
    while s > 0 {
        let b = html[s - 1];
        if b.is_ascii_whitespace()
            || matches!(
                b,
                b'"' | b'\'' | b'`' | b'<' | b'>' | b'=' | b'(' | b',' | b';' | b'['
            )
        {
            break;
        }
        s -= 1;
    }
    s
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

pub fn extract_chunk_refs(body: &[u8], base: &Url) -> Vec<Url> {
    let mut out = extract_chunks(body, base);
    let mut seen: FxHashSet<Url> = out.iter().cloned().collect();

    let needle = b"static/chunks/";
    let mut offset = 0;
    while let Some(rel) = memmem::find(&body[offset..], needle) {
        let pos = offset + rel;
        if pos >= 7 && &body[pos - 7..pos] == b"/_next/" {
            offset = pos + needle.len();
            continue;
        }
        let end = body[pos..]
            .iter()
            .position(|b| {
                b.is_ascii_whitespace()
                    || matches!(b, b'"' | b'\'' | b'`' | b'<' | b'>' | b')' | b',' | b';')
            })
            .map(|n| pos + n)
            .unwrap_or(body.len());
        let src = &body[pos..end];
        if src.ends_with(b".js") && !is_skipped_chunk(src) {
            if let Ok(src_str) = std::str::from_utf8(src) {
                let path = format!("/_next/{}", src_str);
                if let Ok(u) = base.join(&path) {
                    if seen.insert(u.clone()) {
                        out.push(u);
                    }
                }
            }
        }
        offset = end;
    }
    out
}

fn is_skipped_chunk(src: &[u8]) -> bool {
    SKIPPED_CHUNK_FRAGMENTS
        .iter()
        .any(|f| memmem::find(src, f.as_bytes()).is_some())
}
