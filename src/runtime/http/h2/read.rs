use super::frame::{
    data_payload, encode_frame, header_block_payload, Frame, FrameHeader, FrameType, END_HEADERS,
    END_STREAM, MAX_FRAME_PAYLOAD,
};
use super::session::{H2Session, PendingHeaders, StreamMessage};
use super::window::release_window;
use crate::runtime::bytes::{HiBuf, HiBytes};
use crate::runtime::http::Error;
use std::sync::Arc;
use tokio::io::{AsyncRead, AsyncReadExt};

pub(crate) async fn read_frame<R: AsyncRead + Unpin>(reader: &mut R) -> Result<Frame, Error> {
    let mut head = [0u8; 9];
    reader.read_exact(&mut head).await?;
    let len = ((head[0] as u32) << 16) | ((head[1] as u32) << 8) | head[2] as u32;
    if len > MAX_FRAME_PAYLOAD {
        return Err(Error::H2("frame payload too large"));
    }
    let mut payload = HiBuf::zeroed(len as usize);
    reader.read_exact(&mut payload).await?;
    Ok(Frame {
        header: FrameHeader {
            len,
            kind: head[3],
            flags: head[4],
            stream_id: u32::from_be_bytes([head[5] & 0x7f, head[6], head[7], head[8]]),
        },
        payload: payload.freeze(),
    })
}

pub(crate) async fn read_h2(session: Arc<H2Session>, mut reader: tokio::io::ReadHalf<tokio_rustls::client::TlsStream<tokio::net::TcpStream>>) {
    let mut pending_headers: Option<PendingHeaders> = None;
    while let Ok(frame) = read_frame(&mut reader).await {
        if frame.header.kind == FrameType::Settings as u8 && frame.header.flags & 0x01 == 0 {
            apply_settings(&session, &frame.payload).await;
            let _ = session.writer.send(vec![encode_frame(
                FrameHeader {
                    len: 0,
                    kind: FrameType::Settings as u8,
                    flags: 0x01,
                    stream_id: 0,
                },
                &[],
            )]);
            continue;
        }
        if frame.header.kind == FrameType::Ping as u8 && frame.header.flags & 0x01 == 0 {
            let _ = session.writer.send(vec![encode_frame(
                FrameHeader {
                    len: frame.payload.len() as u32,
                    kind: FrameType::Ping as u8,
                    flags: 0x01,
                    stream_id: 0,
                },
                &frame.payload,
            )]);
            continue;
        }
        if frame.header.kind == FrameType::GoAway as u8 {
            break;
        }
        if frame.header.stream_id == 0 {
            continue;
        }
        if pending_headers.is_some() && frame.header.kind != FrameType::Continuation as u8 {
            break;
        }
        let message = match frame.header.kind {
            x if x == FrameType::Headers as u8 => {
                let Some(block) = header_block_payload(&frame) else {
                    break;
                };
                if frame.header.flags & END_HEADERS == 0 {
                    pending_headers = Some(PendingHeaders {
                        stream_id: frame.header.stream_id,
                        end_stream: frame.header.flags & END_STREAM != 0,
                        block: HiBuf::from_slice(block),
                    });
                    continue;
                }
                let headers = match session.decoder.lock().await.decode(block) {
                    Ok(headers) => headers,
                    Err(_) => break,
                };
                StreamMessage::Headers {
                    headers,
                    end_stream: frame.header.flags & END_STREAM != 0,
                }
            }
            x if x == FrameType::Continuation as u8 => {
                let Some(pending) = pending_headers.as_mut() else {
                    break;
                };
                if pending.stream_id != frame.header.stream_id {
                    break;
                }
                pending.block.extend_from_slice(&frame.payload);
                if frame.header.flags & END_HEADERS == 0 {
                    continue;
                }
                let pending = pending_headers.take().expect("pending headers");
                let headers = match session.decoder.lock().await.decode(&pending.block) {
                    Ok(headers) => headers,
                    Err(_) => break,
                };
                StreamMessage::Headers {
                    headers,
                    end_stream: pending.end_stream,
                }
            }
            x if x == FrameType::Data as u8 => StreamMessage::Data {
                payload: match data_payload(&frame) {
                    Some(payload) => {
                        release_window(&session, frame.header.stream_id, payload.len());
                        payload
                    }
                    None => break,
                },
                end_stream: frame.header.flags & END_STREAM != 0,
            },
            x if x == FrameType::RstStream as u8 => {
                let code = u32::from_be_bytes([
                    frame.payload[0],
                    frame.payload[1],
                    frame.payload[2],
                    frame.payload[3],
                ]);
                StreamMessage::Reset(code)
            }
            _ => continue,
        };
        let tx = {
            let streams = session.streams.lock().await;
            streams.get(&frame.header.stream_id).cloned()
        };
        if let Some(tx) = tx {
            let _ = tx.send(message);
        }
    }
    let streams = std::mem::take(&mut *session.streams.lock().await);
    for (_, tx) in streams {
        let _ = tx.send(StreamMessage::ConnectionClosed);
    }
}

async fn apply_settings(session: &H2Session, payload: &[u8]) {
    if !payload.len().is_multiple_of(6) {
        return;
    }
    for setting in payload.chunks_exact(6) {
        let id = u16::from_be_bytes([setting[0], setting[1]]);
        let value = u32::from_be_bytes([setting[2], setting[3], setting[4], setting[5]]);
        if id == 0x01 {
            session
                .decoder
                .lock()
                .await
                .set_allowed_max_size(value as usize);
        }
    }
}
