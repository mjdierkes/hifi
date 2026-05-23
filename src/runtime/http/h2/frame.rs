use crate::runtime::bytes::HiBytes;

pub(crate) const H2_PREFACE: &[u8] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
pub(crate) const DEFAULT_H2_WINDOW: u32 = 65_535;
pub(crate) const SCANNER_INITIAL_WINDOW: u32 = 16 * 1024 * 1024;
pub(crate) const MAX_FRAME_SIZE: usize = 16_384;
pub(crate) const MAX_FRAME_PAYLOAD: u32 = 16 * 1024 * 1024;
pub(crate) const END_STREAM: u8 = 0x01;
pub(crate) const END_HEADERS: u8 = 0x04;
pub(crate) const PADDED: u8 = 0x08;
pub(crate) const PRIORITY: u8 = 0x20;

#[derive(Clone)]
pub(crate) struct Frame {
    pub header: FrameHeader,
    pub payload: HiBytes,
}

#[derive(Clone, Copy)]
pub(crate) struct FrameHeader {
    pub len: u32,
    pub kind: u8,
    pub flags: u8,
    pub stream_id: u32,
}

#[repr(u8)]
pub(crate) enum FrameType {
    Data = 0,
    Headers = 1,
    RstStream = 3,
    Settings = 4,
    Ping = 6,
    GoAway = 7,
    WindowUpdate = 8,
    Continuation = 9,
}

pub(crate) fn settings_payload(initial_window: u32) -> [u8; 12] {
    let mut out = [0u8; 12];
    out[1] = 0x04;
    out[2..6].copy_from_slice(&initial_window.to_be_bytes());
    out[7] = 0x05;
    out[8..12].copy_from_slice(&(MAX_FRAME_SIZE as u32).to_be_bytes());
    out
}

pub(crate) fn encode_frame(header: FrameHeader, payload: &[u8]) -> HiBytes {
    let mut out = crate::runtime::bytes::HiBuf::with_capacity(9 + payload.len());
    out.push(((header.len >> 16) & 0xff) as u8);
    out.push(((header.len >> 8) & 0xff) as u8);
    out.push((header.len & 0xff) as u8);
    out.push(header.kind);
    out.push(header.flags);
    out.extend_from_slice(&(header.stream_id & 0x7fff_ffff).to_be_bytes());
    out.extend_from_slice(payload);
    out.freeze()
}

pub(crate) fn header_block_payload(frame: &Frame) -> Option<&[u8]> {
    let mut start = 0usize;
    let mut end = frame.payload.len();
    if frame.header.flags & PADDED != 0 {
        let pad = *frame.payload.first()? as usize;
        start += 1;
        end = end.checked_sub(pad)?;
    }
    if frame.header.flags & PRIORITY != 0 {
        start += 5;
    }
    frame.payload.get(start..end)
}

pub(crate) fn data_payload(frame: &Frame) -> Option<HiBytes> {
    let mut start = 0usize;
    let mut end = frame.payload.len();
    if frame.header.flags & PADDED != 0 {
        let pad = *frame.payload.first()? as usize;
        start += 1;
        end = end.checked_sub(pad)?;
    }
    frame.payload.get(start..end)?;
    Some(frame.payload.slice(start..end))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frame_payload_helpers_strip_padding_and_priority() {
        let frame = Frame {
            header: FrameHeader {
                len: 10,
                kind: FrameType::Headers as u8,
                flags: PADDED | PRIORITY,
                stream_id: 1,
            },
            payload: HiBytes::from_static(&[2, 0, 0, 0, 0, 0, b'a', b'b', 0, 0]),
        };
        assert_eq!(header_block_payload(&frame).unwrap(), b"ab");

        let frame = Frame {
            header: FrameHeader {
                len: 5,
                kind: FrameType::Data as u8,
                flags: PADDED,
                stream_id: 1,
            },
            payload: HiBytes::from_static(&[1, b'x', b'y', b'z', 0]),
        };
        assert_eq!(data_payload(&frame).unwrap(), HiBytes::from_static(b"xyz"));
    }
}
