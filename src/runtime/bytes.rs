use std::{
    ops::{Bound, Deref, DerefMut, Range, RangeBounds},
    sync::Arc,
};

#[derive(Clone)]
pub(crate) struct HiBytes {
    data: Arc<[u8]>,
    range: Range<usize>,
}

impl HiBytes {
    pub(crate) fn from_vec(bytes: Vec<u8>) -> Self {
        let len = bytes.len();
        Self {
            data: Arc::from(bytes),
            range: 0..len,
        }
    }

    #[cfg(test)]
    pub(crate) fn from_static(bytes: &'static [u8]) -> Self {
        Self::from_vec(bytes.to_vec())
    }

    pub(crate) fn slice<R: RangeBounds<usize>>(&self, range: R) -> Self {
        let len = self.len();
        let start = match range.start_bound() {
            Bound::Included(&idx) => idx,
            Bound::Excluded(&idx) => idx + 1,
            Bound::Unbounded => 0,
        };
        let end = match range.end_bound() {
            Bound::Included(&idx) => idx + 1,
            Bound::Excluded(&idx) => idx,
            Bound::Unbounded => len,
        };
        debug_assert!(start <= end && end <= len);
        Self {
            data: self.data.clone(),
            range: self.range.start + start..self.range.start + end,
        }
    }
}

impl Deref for HiBytes {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        &self.data[self.range.clone()]
    }
}

impl AsRef<[u8]> for HiBytes {
    fn as_ref(&self) -> &[u8] {
        self
    }
}

impl PartialEq for HiBytes {
    fn eq(&self, other: &Self) -> bool {
        self.as_ref() == other.as_ref()
    }
}

impl Eq for HiBytes {}

impl std::fmt::Debug for HiBytes {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.as_ref().fmt(f)
    }
}

#[derive(Clone, Default)]
pub(crate) struct HiBuf {
    bytes: Vec<u8>,
}

impl HiBuf {
    pub(crate) fn new() -> Self {
        Self { bytes: Vec::new() }
    }

    pub(crate) fn with_capacity(capacity: usize) -> Self {
        Self {
            bytes: Vec::with_capacity(capacity),
        }
    }

    pub(crate) fn zeroed(len: usize) -> Self {
        Self {
            bytes: vec![0; len],
        }
    }

    pub(crate) fn from_slice(bytes: &[u8]) -> Self {
        Self {
            bytes: bytes.to_vec(),
        }
    }

    pub(crate) fn len(&self) -> usize {
        self.bytes.len()
    }

    pub(crate) fn capacity(&self) -> usize {
        self.bytes.capacity()
    }

    pub(crate) fn reserve(&mut self, additional: usize) {
        self.bytes.reserve(additional);
    }

    pub(crate) fn push(&mut self, byte: u8) {
        self.bytes.push(byte);
    }

    pub(crate) fn extend_from_slice(&mut self, bytes: &[u8]) {
        self.bytes.extend_from_slice(bytes);
    }

    pub(crate) fn freeze(self) -> HiBytes {
        HiBytes::from_vec(self.bytes)
    }
}

impl Deref for HiBuf {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        &self.bytes
    }
}

impl DerefMut for HiBuf {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.bytes
    }
}

impl AsRef<[u8]> for HiBuf {
    fn as_ref(&self) -> &[u8] {
        &self.bytes
    }
}
