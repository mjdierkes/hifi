use super::frame::{
    encode_frame, FrameHeader, FrameType, DEFAULT_H2_WINDOW, END_HEADERS, END_STREAM,
    MAX_FRAME_SIZE, SCANNER_INITIAL_WINDOW,
};
use super::session::H2Session;
use crate::runtime::bytes::HiBytes;
use crate::runtime::http::backpressure::Backpressure;
use std::sync::{
    atomic::{AtomicU32, Ordering},
    Arc,
};

pub(crate) fn scaled_initial_window(backpressure: &Backpressure) -> u32 {
    let scaled = (SCANNER_INITIAL_WINDOW as f32 * backpressure.generosity()) as u32;
    scaled.max(DEFAULT_H2_WINDOW * 4)
}

pub(crate) fn header_block_frames(stream_id: u32, block: &[u8]) -> Result<Vec<HiBytes>, crate::runtime::http::Error> {
    let mut chunks = block.chunks(MAX_FRAME_SIZE).peekable();
    let Some(first) = chunks.next() else {
        return Err(crate::runtime::http::Error::H2("empty request header block"));
    };
    let mut frames = Vec::with_capacity(1 + chunks.size_hint().0);
    let first_is_last = chunks.peek().is_none();
    frames.push(encode_frame(
        FrameHeader {
            len: first.len() as u32,
            kind: FrameType::Headers as u8,
            flags: END_STREAM | if first_is_last { END_HEADERS } else { 0 },
            stream_id,
        },
        first,
    ));
    while let Some(chunk) = chunks.next() {
        let is_last = chunks.peek().is_none();
        frames.push(encode_frame(
            FrameHeader {
                len: chunk.len() as u32,
                kind: FrameType::Continuation as u8,
                flags: if is_last { END_HEADERS } else { 0 },
                stream_id,
            },
            chunk,
        ));
    }
    Ok(frames)
}

pub(crate) fn release_window(session: &H2Session, stream_id: u32, len: usize) {
    let Ok(increment) = u32::try_from(len) else {
        return;
    };
    if increment == 0 {
        return;
    }
    let stream_bytes = increment.to_be_bytes();
    let mut frames = vec![encode_frame(
        FrameHeader {
            len: 4,
            kind: FrameType::WindowUpdate as u8,
            flags: 0,
            stream_id,
        },
        &stream_bytes,
    )];

    let pending = session
        .conn_pending_credit
        .fetch_add(increment, Ordering::Relaxed)
        + increment;
    let threshold = ((SCANNER_INITIAL_WINDOW as f32 / 4.0) * session.backpressure.generosity())
        .max(4096.0) as u32;
    if pending >= threshold {
        let flush = session.conn_pending_credit.swap(0, Ordering::Relaxed);
        if flush > 0 {
            frames.push(encode_frame(
                FrameHeader {
                    len: 4,
                    kind: FrameType::WindowUpdate as u8,
                    flags: 0,
                    stream_id: 0,
                },
                &flush.to_be_bytes(),
            ));
        }
    }

    let _ = session.writer.send(frames);
}
