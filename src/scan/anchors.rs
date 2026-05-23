use crate::literal::{LiteralMatch, LiteralSet};

pub fn scan_anchors<T: Copy>(
    bytes: &[u8],
    set: &LiteralSet<T>,
    mut handler: impl FnMut(LiteralMatch<T>),
) {
    for m in set.find_iter(bytes) {
        handler(m);
    }
}

pub fn scan_anchor_bytes(
    bytes: &[u8],
    needles: &[&[u8]],
    mut handler: impl FnMut(usize, &[u8]),
) {
    for &needle in needles {
        for pos in memchr::memmem::find_iter(bytes, needle) {
            handler(pos, needle);
        }
    }
}

pub fn anchor_bytes_is_match(bytes: &[u8], needles: &[&[u8]]) -> bool {
    needles
        .iter()
        .any(|needle| memchr::memmem::find(bytes, needle).is_some())
}
