use crate::runtime::bytes::{HiBuf, HiBytes};

/// Header collection that borrows name/value bytes from a single backing buffer.
///
/// For HTTP/1.1 the backing buffer is a slice of the received head bytes (truly
/// zero-copy). For HTTP/2 we materialize a single buffer from the HPACK output
/// so the same accessor shape works for both.
#[derive(Clone, Default)]
pub struct Headers {
    storage: HiBytes,
    entries: Vec<HeaderEntry>,
}

#[derive(Clone, Copy)]
struct HeaderEntry {
    name_start: u32,
    name_end: u32,
    value_start: u32,
    value_end: u32,
}

impl Headers {
    pub(super) fn builder() -> HeadersBuilder {
        HeadersBuilder {
            storage: HiBuf::new(),
            entries: Vec::new(),
        }
    }

    pub(super) fn from_borrowed(storage: HiBytes, entries: Vec<(u32, u32, u32, u32)>) -> Self {
        Self {
            storage,
            entries: entries
                .into_iter()
                .map(|(ns, ne, vs, ve)| HeaderEntry {
                    name_start: ns,
                    name_end: ne,
                    value_start: vs,
                    value_end: ve,
                })
                .collect(),
        }
    }

    pub fn iter(&self) -> HeadersIter<'_> {
        HeadersIter {
            headers: self,
            idx: 0,
        }
    }

    pub fn get(&self, name: &str) -> Option<&str> {
        self.iter()
            .find(|(key, _)| key.eq_ignore_ascii_case(name))
            .map(|(_, value)| value)
    }

    pub(super) fn connection_close(&self) -> bool {
        self.iter()
            .filter(|(name, _)| name.eq_ignore_ascii_case("connection"))
            .any(|(_, value)| value.eq_ignore_ascii_case("close"))
    }

    fn name_at(&self, idx: usize) -> &str {
        let e = &self.entries[idx];
        let bytes = &self.storage[e.name_start as usize..e.name_end as usize];
        std::str::from_utf8(bytes).expect("header names are validated before storage")
    }

    fn value_at(&self, idx: usize) -> &str {
        let e = &self.entries[idx];
        let bytes = &self.storage[e.value_start as usize..e.value_end as usize];
        std::str::from_utf8(bytes).expect("header values are validated before storage")
    }
}

pub(super) struct HeadersBuilder {
    storage: HiBuf,
    entries: Vec<HeaderEntry>,
}

impl HeadersBuilder {
    pub(super) fn push(&mut self, name: &str, value: &str) {
        let ns = self.storage.len() as u32;
        self.storage.extend_from_slice(name.as_bytes());
        let ne = self.storage.len() as u32;
        let vs = self.storage.len() as u32;
        self.storage.extend_from_slice(value.as_bytes());
        let ve = self.storage.len() as u32;
        self.entries.push(HeaderEntry {
            name_start: ns,
            name_end: ne,
            value_start: vs,
            value_end: ve,
        });
    }

    pub(super) fn finish(self) -> Headers {
        Headers {
            storage: self.storage.freeze(),
            entries: self.entries,
        }
    }
}

pub struct HeadersIter<'a> {
    headers: &'a Headers,
    idx: usize,
}

impl<'a> Iterator for HeadersIter<'a> {
    type Item = (&'a str, &'a str);
    fn next(&mut self) -> Option<Self::Item> {
        if self.idx >= self.headers.entries.len() {
            return None;
        }
        let i = self.idx;
        self.idx += 1;
        Some((self.headers.name_at(i), self.headers.value_at(i)))
    }
}
