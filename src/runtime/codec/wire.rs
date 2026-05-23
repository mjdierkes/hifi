//! Length-prefixed binary primitives shared across cache and IPC encoders.
//!
//! All multi-byte integers are little-endian. Strings are `u32` length followed
//! by raw UTF-8 bytes. There is no schema; callers own the layout.

pub(crate) fn put_u32(out: &mut Vec<u8>, value: usize) {
    out.extend_from_slice(&(value.min(u32::MAX as usize) as u32).to_le_bytes());
}

pub(crate) fn put_string(out: &mut Vec<u8>, value: &str) {
    put_u32(out, value.len());
    out.extend_from_slice(value.as_bytes());
}

pub(crate) fn put_opt_string(out: &mut Vec<u8>, value: Option<&str>) {
    match value {
        Some(value) => {
            out.push(1);
            put_string(out, value);
        }
        None => out.push(0),
    }
}

pub(crate) fn put_string_vec(out: &mut Vec<u8>, values: &[String]) {
    put_u32(out, values.len());
    for value in values {
        put_string(out, value);
    }
}

pub(crate) struct Reader<'a> {
    bytes: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    pub(crate) fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, pos: 0 }
    }

    pub(crate) fn take_exact(&mut self, len: usize) -> Option<&'a [u8]> {
        let end = self.pos.checked_add(len)?;
        let out = self.bytes.get(self.pos..end)?;
        self.pos = end;
        Some(out)
    }

    pub(crate) fn u8(&mut self) -> Option<u8> {
        let value = *self.bytes.get(self.pos)?;
        self.pos += 1;
        Some(value)
    }

    pub(crate) fn u32(&mut self) -> Option<u32> {
        let bytes = self.take_exact(4)?;
        Some(u32::from_le_bytes(bytes.try_into().ok()?))
    }

    pub(crate) fn string(&mut self) -> Option<String> {
        let len = self.u32()? as usize;
        let bytes = self.take_exact(len)?;
        std::str::from_utf8(bytes).ok().map(str::to_string)
    }

    pub(crate) fn opt_string(&mut self) -> Option<Option<String>> {
        match self.u8()? {
            0 => Some(None),
            1 => self.string().map(Some),
            _ => None,
        }
    }

    pub(crate) fn string_vec(&mut self) -> Option<Vec<String>> {
        let len = self.u32()? as usize;
        let mut out = Vec::with_capacity(len);
        for _ in 0..len {
            out.push(self.string()?);
        }
        Some(out)
    }

    pub(crate) fn bool(&mut self) -> Option<bool> {
        match self.u8()? {
            0 => Some(false),
            1 => Some(true),
            _ => None,
        }
    }

    pub(crate) fn finish(&self) -> Option<()> {
        (self.pos == self.bytes.len()).then_some(())
    }
}
