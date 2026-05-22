use super::{origin::Origin, Error};
use crate::hash::FxHashMap;
use crate::url::Url;
use bytes::{BufMut, Bytes, BytesMut};
use std::{borrow::Cow, sync::OnceLock};

pub(super) fn encode_headers(
    url: &Url,
    origin: &Origin,
    extra: Vec<(String, String)>,
    defaults: &[(String, String)],
) -> Bytes {
    let mut out = BytesMut::new();
    let path = match url.query() {
        Some(query) => format!("{}?{query}", url.path()),
        None => {
            let path = url.path();
            if path.is_empty() {
                "/".to_string()
            } else {
                path.to_string()
            }
        }
    };
    literal_header(&mut out, ":method", "GET");
    literal_header(&mut out, ":scheme", url.scheme());
    literal_header(&mut out, ":authority", &origin.authority());
    literal_header(&mut out, ":path", &path);
    for (k, v) in defaults {
        literal_header(&mut out, &k.to_ascii_lowercase(), v);
    }
    for (k, v) in extra {
        literal_header(&mut out, &k.to_ascii_lowercase(), &v);
    }
    out.freeze()
}

pub(super) fn literal_header(out: &mut BytesMut, name: &str, value: &str) {
    out.put_u8(0x00);
    hpack_string(out, name);
    hpack_string(out, value);
}

pub(super) fn hpack_string(out: &mut BytesMut, value: &str) {
    hpack_int(out, value.len(), 7, 0);
    out.extend_from_slice(value.as_bytes());
}

pub(super) fn hpack_int(out: &mut BytesMut, mut value: usize, prefix: u8, marker: u8) {
    let max = (1usize << prefix) - 1;
    if value < max {
        out.put_u8(marker | value as u8);
        return;
    }
    out.put_u8(marker | max as u8);
    value -= max;
    while value >= 128 {
        out.put_u8((value as u8 & 0x7f) | 0x80);
        value >>= 7;
    }
    out.put_u8(value as u8);
}

pub(super) struct HpackDecoder {
    dynamic: Vec<(String, String)>,
    dynamic_size: usize,
    max_dynamic_size: usize,
    allowed_dynamic_size: usize,
}

impl HpackDecoder {
    pub(super) fn set_allowed_max_size(&mut self, size: usize) {
        self.allowed_dynamic_size = size;
        if self.max_dynamic_size > size {
            self.set_max_size(size);
        }
    }

    pub(super) fn set_max_size(&mut self, size: usize) {
        self.max_dynamic_size = size;
        self.evict_dynamic();
    }

    pub(super) fn decode(&mut self, bytes: &[u8]) -> Result<Vec<(String, String)>, Error> {
        let mut pos = 0;
        let mut out = Vec::new();
        let mut can_resize = true;
        while pos < bytes.len() {
            let b = bytes[pos];
            if b & 0x80 != 0 {
                can_resize = false;
                let idx = read_int(bytes, &mut pos, 7)?;
                let (name, value) = self.lookup(idx)?;
                out.push((name.into_owned(), value.into_owned()));
            } else if b & 0x40 != 0 {
                can_resize = false;
                let idx = read_int(bytes, &mut pos, 6)?;
                let name = if idx == 0 {
                    read_string(bytes, &mut pos)?
                } else {
                    self.lookup_name(idx)?.into_owned()
                };
                let value = read_string(bytes, &mut pos)?;
                self.insert_dynamic(name.clone(), value.clone());
                out.push((name, value));
            } else if b & 0x20 != 0 {
                let size = read_int(bytes, &mut pos, 5)?;
                if !can_resize || size > self.allowed_dynamic_size {
                    return Err(Error::H2("bad HPACK dynamic table size update"));
                }
                self.set_max_size(size);
            } else {
                can_resize = false;
                let idx = read_int(bytes, &mut pos, 4)?;
                let name = if idx == 0 {
                    read_string(bytes, &mut pos)?
                } else {
                    self.lookup_name(idx)?.into_owned()
                };
                let value = read_string(bytes, &mut pos)?;
                out.push((name, value));
            }
        }
        Ok(out)
    }

    fn insert_dynamic(&mut self, name: String, value: String) {
        let size = dynamic_entry_size(&name, &value);
        if size > self.max_dynamic_size {
            self.dynamic.clear();
            self.dynamic_size = 0;
            return;
        }
        self.dynamic_size += size;
        self.dynamic.insert(0, (name, value));
        self.evict_dynamic();
    }

    fn evict_dynamic(&mut self) {
        while self.dynamic_size > self.max_dynamic_size {
            let Some((name, value)) = self.dynamic.pop() else {
                self.dynamic_size = 0;
                break;
            };
            self.dynamic_size = self
                .dynamic_size
                .saturating_sub(dynamic_entry_size(&name, &value));
        }
    }

    fn lookup(&self, idx: usize) -> Result<(Cow<'static, str>, Cow<'static, str>), Error> {
        if idx == 0 {
            return Err(Error::H2("bad HPACK index"));
        }
        if let Some((name, value)) = STATIC_TABLE.get(idx - 1) {
            return Ok((Cow::Borrowed(*name), Cow::Borrowed(*value)));
        }
        let (name, value) = self
            .dynamic
            .get(idx - STATIC_TABLE.len() - 1)
            .ok_or(Error::H2("bad HPACK dynamic index"))?;
        Ok((Cow::Owned(name.clone()), Cow::Owned(value.clone())))
    }

    fn lookup_name(&self, idx: usize) -> Result<Cow<'static, str>, Error> {
        if idx == 0 {
            return Err(Error::H2("bad HPACK index"));
        }
        if let Some((name, _)) = STATIC_TABLE.get(idx - 1) {
            return Ok(Cow::Borrowed(*name));
        }
        self.dynamic
            .get(idx - STATIC_TABLE.len() - 1)
            .map(|(name, _)| Cow::Owned(name.clone()))
            .ok_or(Error::H2("bad HPACK dynamic index"))
    }
}

impl Default for HpackDecoder {
    fn default() -> Self {
        Self {
            dynamic: Vec::new(),
            dynamic_size: 0,
            max_dynamic_size: 4096,
            allowed_dynamic_size: 4096,
        }
    }
}

fn dynamic_entry_size(name: &str, value: &str) -> usize {
    name.len() + value.len() + 32
}

fn read_int(bytes: &[u8], pos: &mut usize, prefix: u8) -> Result<usize, Error> {
    let first = *bytes.get(*pos).ok_or(Error::H2("truncated HPACK int"))?;
    *pos += 1;
    let mask = (1usize << prefix) - 1;
    let mut value = (first as usize) & mask;
    if value < mask {
        return Ok(value);
    }
    let mut shift = 0;
    loop {
        let b = *bytes.get(*pos).ok_or(Error::H2("truncated HPACK int"))?;
        *pos += 1;
        value += ((b & 0x7f) as usize) << shift;
        if b & 0x80 == 0 {
            return Ok(value);
        }
        shift += 7;
    }
}

fn read_string(bytes: &[u8], pos: &mut usize) -> Result<String, Error> {
    let huffman = bytes.get(*pos).map(|b| b & 0x80 != 0).unwrap_or(false);
    let len = read_int(bytes, pos, 7)?;
    let end = pos.checked_add(len).ok_or(Error::H2("bad HPACK string"))?;
    let raw = bytes
        .get(*pos..end)
        .ok_or(Error::H2("truncated HPACK string"))?;
    *pos = end;
    if huffman {
        let decoded = hpack_huffman_decode(raw)?;
        return String::from_utf8(decoded).map_err(|_| Error::H2("bad HPACK string utf8"));
    }
    std::str::from_utf8(raw)
        .map(str::to_string)
        .map_err(|_| Error::H2("bad HPACK string utf8"))
}

pub(super) fn hpack_huffman_decode(raw: &[u8]) -> Result<Vec<u8>, Error> {
    let mut out = Vec::with_capacity(raw.len() * 2);
    let mut code = 0u32;
    let mut len = 0usize;
    for byte in raw {
        for shift in (0..8).rev() {
            code = (code << 1) | (((byte >> shift) & 1) as u32);
            len += 1;
            if let Some(symbol) = huffman_symbol(code, len) {
                if symbol == 256 {
                    return Err(Error::H2("HPACK Huffman EOS in string"));
                }
                out.push(symbol as u8);
                code = 0;
                len = 0;
            } else if len > 30 {
                return Err(Error::H2("bad HPACK Huffman code"));
            }
        }
    }
    if len > 7 || (len > 0 && code != ((1u32 << len) - 1)) {
        return Err(Error::H2("bad HPACK Huffman padding"));
    }
    Ok(out)
}

fn huffman_symbol(code: u32, len: usize) -> Option<u16> {
    static LOOKUP: OnceLock<FxHashMap<u64, u16>> = OnceLock::new();
    LOOKUP
        .get_or_init(|| {
            HUFFMAN_CODES
                .iter()
                .enumerate()
                .map(|(idx, &(bits, value))| (huffman_key(value, bits), idx as u16))
                .collect()
        })
        .get(&huffman_key(code, len))
        .copied()
}

fn huffman_key(code: u32, len: usize) -> u64 {
    ((len as u64) << 32) | code as u64
}

const HUFFMAN_CODES: &[(usize, u32)] = &[
    (13, 0x1ff8),
    (23, 0x007f_ffd8),
    (28, 0x0fff_ffe2),
    (28, 0x0fff_ffe3),
    (28, 0x0fff_ffe4),
    (28, 0x0fff_ffe5),
    (28, 0x0fff_ffe6),
    (28, 0x0fff_ffe7),
    (28, 0x0fff_ffe8),
    (24, 0x00ff_ffea),
    (30, 0x3fff_fffc),
    (28, 0x0fff_ffe9),
    (28, 0x0fff_ffea),
    (30, 0x3fff_fffd),
    (28, 0x0fff_ffeb),
    (28, 0x0fff_ffec),
    (28, 0x0fff_ffed),
    (28, 0x0fff_ffee),
    (28, 0x0fff_ffef),
    (28, 0x0fff_fff0),
    (28, 0x0fff_fff1),
    (28, 0x0fff_fff2),
    (30, 0x3fff_fffe),
    (28, 0x0fff_fff3),
    (28, 0x0fff_fff4),
    (28, 0x0fff_fff5),
    (28, 0x0fff_fff6),
    (28, 0x0fff_fff7),
    (28, 0x0fff_fff8),
    (28, 0x0fff_fff9),
    (28, 0x0fff_fffa),
    (28, 0x0fff_fffb),
    (6, 0x14),
    (10, 0x3f8),
    (10, 0x3f9),
    (12, 0xffa),
    (13, 0x1ff9),
    (6, 0x15),
    (8, 0xf8),
    (11, 0x7fa),
    (10, 0x3fa),
    (10, 0x3fb),
    (8, 0xf9),
    (11, 0x7fb),
    (8, 0xfa),
    (6, 0x16),
    (6, 0x17),
    (6, 0x18),
    (5, 0x0),
    (5, 0x1),
    (5, 0x2),
    (6, 0x19),
    (6, 0x1a),
    (6, 0x1b),
    (6, 0x1c),
    (6, 0x1d),
    (6, 0x1e),
    (6, 0x1f),
    (7, 0x5c),
    (8, 0xfb),
    (15, 0x7ffc),
    (6, 0x20),
    (12, 0xffb),
    (10, 0x3fc),
    (13, 0x1ffa),
    (6, 0x21),
    (7, 0x5d),
    (7, 0x5e),
    (7, 0x5f),
    (7, 0x60),
    (7, 0x61),
    (7, 0x62),
    (7, 0x63),
    (7, 0x64),
    (7, 0x65),
    (7, 0x66),
    (7, 0x67),
    (7, 0x68),
    (7, 0x69),
    (7, 0x6a),
    (7, 0x6b),
    (7, 0x6c),
    (7, 0x6d),
    (7, 0x6e),
    (7, 0x6f),
    (7, 0x70),
    (7, 0x71),
    (7, 0x72),
    (8, 0xfc),
    (7, 0x73),
    (8, 0xfd),
    (13, 0x1ffb),
    (19, 0x7fff0),
    (13, 0x1ffc),
    (14, 0x3ffc),
    (6, 0x22),
    (15, 0x7ffd),
    (5, 0x3),
    (6, 0x23),
    (5, 0x4),
    (6, 0x24),
    (5, 0x5),
    (6, 0x25),
    (6, 0x26),
    (6, 0x27),
    (5, 0x6),
    (7, 0x74),
    (7, 0x75),
    (6, 0x28),
    (6, 0x29),
    (6, 0x2a),
    (5, 0x7),
    (6, 0x2b),
    (7, 0x76),
    (6, 0x2c),
    (5, 0x8),
    (5, 0x9),
    (6, 0x2d),
    (7, 0x77),
    (7, 0x78),
    (7, 0x79),
    (7, 0x7a),
    (7, 0x7b),
    (15, 0x7ffe),
    (11, 0x7fc),
    (14, 0x3ffd),
    (13, 0x1ffd),
    (28, 0x0fff_fffc),
    (20, 0xfffe6),
    (22, 0x003f_ffd2),
    (20, 0xfffe7),
    (20, 0xfffe8),
    (22, 0x003f_ffd3),
    (22, 0x003f_ffd4),
    (22, 0x003f_ffd5),
    (23, 0x007f_ffd9),
    (22, 0x003f_ffd6),
    (23, 0x007f_ffda),
    (23, 0x007f_ffdb),
    (23, 0x007f_ffdc),
    (23, 0x007f_ffdd),
    (23, 0x007f_ffde),
    (24, 0x00ff_ffeb),
    (23, 0x007f_ffdf),
    (24, 0x00ff_ffec),
    (24, 0x00ff_ffed),
    (22, 0x003f_ffd7),
    (23, 0x007f_ffe0),
    (24, 0x00ff_ffee),
    (23, 0x007f_ffe1),
    (23, 0x007f_ffe2),
    (23, 0x007f_ffe3),
    (23, 0x007f_ffe4),
    (21, 0x001f_ffdc),
    (22, 0x003f_ffd8),
    (23, 0x007f_ffe5),
    (22, 0x003f_ffd9),
    (23, 0x007f_ffe6),
    (23, 0x007f_ffe7),
    (24, 0x00ff_ffef),
    (22, 0x003f_ffda),
    (21, 0x001f_ffdd),
    (20, 0xfffe9),
    (22, 0x003f_ffdb),
    (22, 0x003f_ffdc),
    (23, 0x007f_ffe8),
    (23, 0x007f_ffe9),
    (21, 0x001f_ffde),
    (23, 0x007f_ffea),
    (22, 0x003f_ffdd),
    (22, 0x003f_ffde),
    (24, 0x00ff_fff0),
    (21, 0x001f_ffdf),
    (22, 0x003f_ffdf),
    (23, 0x007f_ffeb),
    (23, 0x007f_ffec),
    (21, 0x001f_ffe0),
    (21, 0x001f_ffe1),
    (22, 0x003f_ffe0),
    (21, 0x001f_ffe2),
    (23, 0x007f_ffed),
    (22, 0x003f_ffe1),
    (23, 0x007f_ffee),
    (23, 0x007f_ffef),
    (20, 0xfffea),
    (22, 0x003f_ffe2),
    (22, 0x003f_ffe3),
    (22, 0x003f_ffe4),
    (23, 0x007f_fff0),
    (22, 0x003f_ffe5),
    (22, 0x003f_ffe6),
    (23, 0x007f_fff1),
    (26, 0x03ff_ffe0),
    (26, 0x03ff_ffe1),
    (20, 0xfffeb),
    (19, 0x7fff1),
    (22, 0x003f_ffe7),
    (23, 0x007f_fff2),
    (22, 0x003f_ffe8),
    (25, 0x01ff_ffec),
    (26, 0x03ff_ffe2),
    (26, 0x03ff_ffe3),
    (26, 0x03ff_ffe4),
    (27, 0x07ff_ffde),
    (27, 0x07ff_ffdf),
    (26, 0x03ff_ffe5),
    (24, 0x00ff_fff1),
    (25, 0x01ff_ffed),
    (19, 0x7fff2),
    (21, 0x001f_ffe3),
    (26, 0x03ff_ffe6),
    (27, 0x07ff_ffe0),
    (27, 0x07ff_ffe1),
    (26, 0x03ff_ffe7),
    (27, 0x07ff_ffe2),
    (24, 0x00ff_fff2),
    (21, 0x001f_ffe4),
    (21, 0x001f_ffe5),
    (26, 0x03ff_ffe8),
    (26, 0x03ff_ffe9),
    (28, 0x0fff_fffd),
    (27, 0x07ff_ffe3),
    (27, 0x07ff_ffe4),
    (27, 0x07ff_ffe5),
    (20, 0xfffec),
    (24, 0x00ff_fff3),
    (20, 0xfffed),
    (21, 0x001f_ffe6),
    (22, 0x003f_ffe9),
    (21, 0x001f_ffe7),
    (21, 0x001f_ffe8),
    (23, 0x007f_fff3),
    (22, 0x003f_ffea),
    (22, 0x003f_ffeb),
    (25, 0x01ff_ffee),
    (25, 0x01ff_ffef),
    (24, 0x00ff_fff4),
    (24, 0x00ff_fff5),
    (26, 0x03ff_ffea),
    (23, 0x007f_fff4),
    (26, 0x03ff_ffeb),
    (27, 0x07ff_ffe6),
    (26, 0x03ff_ffec),
    (26, 0x03ff_ffed),
    (27, 0x07ff_ffe7),
    (27, 0x07ff_ffe8),
    (27, 0x07ff_ffe9),
    (27, 0x07ff_ffea),
    (27, 0x07ff_ffeb),
    (28, 0x0fff_fffe),
    (27, 0x07ff_ffec),
    (27, 0x07ff_ffed),
    (27, 0x07ff_ffee),
    (27, 0x07ff_ffef),
    (27, 0x07ff_fff0),
    (26, 0x03ff_ffee),
    (30, 0x3fff_ffff),
];

pub(super) const STATIC_TABLE: &[(&str, &str)] = &[
    (":authority", ""),
    (":method", "GET"),
    (":method", "POST"),
    (":path", "/"),
    (":path", "/index.html"),
    (":scheme", "http"),
    (":scheme", "https"),
    (":status", "200"),
    (":status", "204"),
    (":status", "206"),
    (":status", "304"),
    (":status", "400"),
    (":status", "404"),
    (":status", "500"),
    ("accept-charset", ""),
    ("accept-encoding", "gzip, deflate"),
    ("accept-language", ""),
    ("accept-ranges", ""),
    ("accept", ""),
    ("access-control-allow-origin", ""),
    ("age", ""),
    ("allow", ""),
    ("authorization", ""),
    ("cache-control", ""),
    ("content-disposition", ""),
    ("content-encoding", ""),
    ("content-language", ""),
    ("content-length", ""),
    ("content-location", ""),
    ("content-range", ""),
    ("content-type", ""),
    ("cookie", ""),
    ("date", ""),
    ("etag", ""),
    ("expect", ""),
    ("expires", ""),
    ("from", ""),
    ("host", ""),
    ("if-match", ""),
    ("if-modified-since", ""),
    ("if-none-match", ""),
    ("if-range", ""),
    ("if-unmodified-since", ""),
    ("last-modified", ""),
    ("link", ""),
    ("location", ""),
    ("max-forwards", ""),
    ("proxy-authenticate", ""),
    ("proxy-authorization", ""),
    ("range", ""),
    ("referer", ""),
    ("refresh", ""),
    ("retry-after", ""),
    ("server", ""),
    ("set-cookie", ""),
    ("strict-transport-security", ""),
    ("transfer-encoding", ""),
    ("user-agent", ""),
    ("vary", ""),
    ("via", ""),
    ("www-authenticate", ""),
];

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::{BufMut, BytesMut};

    #[test]
    fn huffman_decodes_reference_samples() {
        assert_eq!(hpack_huffman_decode(&[0b0011_1111]).unwrap(), b"o");
        assert_eq!(hpack_huffman_decode(&[7]).unwrap(), b"0");
        assert_eq!(hpack_huffman_decode(&[(0x21 << 2) + 3]).unwrap(), b"A");
        assert_eq!(
            hpack_huffman_decode(&[0b0101_0011, 0b1111_1000]).unwrap(),
            b" !"
        );
    }

    #[test]
    fn dynamic_table_indexes_and_evicts() {
        let mut decoder = HpackDecoder::default();
        let mut block = BytesMut::new();
        block.put_u8(0x40);
        hpack_string(&mut block, "x-a");
        hpack_string(&mut block, "one");
        assert_eq!(
            decoder.decode(&block).unwrap(),
            vec![("x-a".to_string(), "one".to_string())]
        );

        assert_eq!(
            decoder
                .decode(&[(STATIC_TABLE.len() as u8 + 1) | 0x80])
                .unwrap(),
            vec![("x-a".to_string(), "one".to_string())]
        );

        decoder.set_max_size(1);
        assert!(decoder
            .decode(&[(STATIC_TABLE.len() as u8 + 1) | 0x80])
            .is_err());
    }

    #[test]
    fn rejects_late_or_oversized_table_updates() {
        let mut decoder = HpackDecoder::default();
        let mut late = BytesMut::new();
        literal_header(&mut late, "x-a", "one");
        late.put_u8(0x20);
        assert!(decoder.decode(&late).is_err());

        let mut decoder = HpackDecoder::default();
        decoder.set_allowed_max_size(8);
        let mut oversized = BytesMut::new();
        hpack_int(&mut oversized, 9, 5, 0x20);
        assert!(decoder.decode(&oversized).is_err());
    }
}
