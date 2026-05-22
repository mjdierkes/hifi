#[derive(Clone, Copy)]
pub(crate) struct Literal<T> {
    bytes: &'static [u8],
    value: T,
}

pub(crate) struct LiteralSet<T> {
    buckets: [Vec<Literal<T>>; 256],
    starts: [bool; 256],
}

#[derive(Clone, Copy)]
pub(crate) struct LiteralMatch<T> {
    pub(crate) start: usize,
    pub(crate) end: usize,
    pub(crate) value: T,
}

impl<T> LiteralMatch<T> {
    pub(crate) fn start(&self) -> usize {
        self.start
    }

    pub(crate) fn end(&self) -> usize {
        self.end
    }
}

impl<T: Copy> LiteralSet<T> {
    pub(crate) fn from_strs(items: impl IntoIterator<Item = (&'static str, T)>) -> Self {
        let mut buckets: [Vec<Literal<T>>; 256] = std::array::from_fn(|_| Vec::new());
        let mut starts = [false; 256];
        for (literal, value) in items {
            if literal.is_empty() {
                continue;
            }
            let bucket = literal.as_bytes()[0] as usize;
            starts[bucket] = true;
            buckets[bucket].push(Literal {
                bytes: literal.as_bytes(),
                value,
            });
        }
        for bucket in &mut buckets {
            bucket.sort_unstable_by_key(|literal| std::cmp::Reverse(literal.bytes.len()));
        }
        Self { buckets, starts }
    }

    pub(crate) fn is_match(&self, bytes: &[u8]) -> bool {
        self.find_iter(bytes).next().is_some()
    }

    pub(crate) fn find_iter<'a>(&'a self, bytes: &'a [u8]) -> LiteralIter<'a, T> {
        LiteralIter {
            set: self,
            bytes,
            pos: 0,
        }
    }

    fn find_at(&self, bytes: &[u8], pos: usize) -> Option<LiteralMatch<T>> {
        let bucket = &self.buckets[bytes[pos] as usize];
        bucket.iter().find_map(|literal| {
            let end = pos + literal.bytes.len();
            (bytes.get(pos..end) == Some(literal.bytes)).then_some(LiteralMatch {
                start: pos,
                end,
                value: literal.value,
            })
        })
    }
}

pub(crate) struct LiteralIter<'a, T> {
    set: &'a LiteralSet<T>,
    bytes: &'a [u8],
    pos: usize,
}

impl<T: Copy> Iterator for LiteralIter<'_, T> {
    type Item = LiteralMatch<T>;

    fn next(&mut self) -> Option<Self::Item> {
        while self.pos < self.bytes.len() {
            if self.set.starts[self.bytes[self.pos] as usize] {
                if let Some(found) = self.set.find_at(self.bytes, self.pos) {
                    self.pos = found.end;
                    return Some(found);
                }
            }
            self.pos += 1;
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn finds_leftmost_longest_non_overlapping_literals() {
        let set = LiteralSet::from_strs([("ab", 1), ("abc", 2), ("bc", 3)]);
        let found: Vec<_> = set
            .find_iter(b"xabcabc")
            .map(|m| (m.start, m.end, m.value))
            .collect();
        assert_eq!(found, vec![(1, 4, 2), (4, 7, 2)]);
    }
}
