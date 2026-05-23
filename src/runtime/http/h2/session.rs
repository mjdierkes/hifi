use super::frame::{encode_frame, settings_payload, FrameHeader, FrameType, H2_PREFACE, DEFAULT_H2_WINDOW};
use super::read::read_h2;
use super::window::{header_block_frames, scaled_initial_window};
use super::write::write_h2;
use crate::hash::FxHashMap;
use crate::runtime::bytes::{HiBuf, HiBytes};
use crate::runtime::http::backpressure::Backpressure;
use crate::runtime::http::headers::Headers;
use crate::runtime::http::hpack::{encode_headers, HpackDecoder};
use crate::runtime::http::origin::{connect_tcp, Origin};
use crate::runtime::http::{Error, Response, Version};
use crate::url::Url;
use rustls_pki_types::ServerName;
use std::sync::{
    atomic::{AtomicU32, Ordering},
    Arc,
};
use tokio::{
    io::{AsyncReadExt, AsyncWrite, AsyncWriteExt},
    sync::{mpsc, Mutex},
};
use tokio_rustls::{client::TlsStream, TlsConnector};

pub(crate) struct H2Session {
    pub(crate) origin: Origin,
    pub(crate) writer: mpsc::UnboundedSender<Vec<HiBytes>>,
    pub(crate) streams: Mutex<FxHashMap<u32, mpsc::UnboundedSender<StreamMessage>>>,
    pub(crate) decoder: Mutex<HpackDecoder>,
    pub(crate) next_stream_id: AtomicU32,
    pub(crate) backpressure: Arc<Backpressure>,
    pub(crate) conn_pending_credit: AtomicU32,
}

pub(crate) enum StreamMessage {
    Headers {
        headers: Vec<(String, String)>,
        end_stream: bool,
    },
    Data {
        payload: HiBytes,
        end_stream: bool,
    },
    Reset(u32),
    ConnectionClosed,
}

pub(crate) struct PendingHeaders {
    pub stream_id: u32,
    pub end_stream: bool,
    pub block: HiBuf,
}

pub(crate) async fn connect_h2(
    origin: Origin,
    tls: TlsConnector,
    backpressure: Arc<Backpressure>,
) -> Result<Arc<H2Session>, Error> {
    let tcp = connect_tcp(&origin).await?;
    let name = ServerName::try_from(origin.host.clone())
        .map_err(|_| Error::BadDnsName(origin.host.clone()))?;
    let mut stream = tls.connect(name, tcp).await?;
    if stream
        .get_ref()
        .1
        .alpn_protocol()
        .map(|proto| proto != b"h2")
        .unwrap_or(true)
    {
        return Err(Error::H2("TLS origin did not negotiate h2"));
    }

    stream.write_all(H2_PREFACE).await?;
    let initial_window = scaled_initial_window(&backpressure);
    write_frame(
        &mut stream,
        FrameHeader {
            len: 12,
            kind: FrameType::Settings as u8,
            flags: 0,
            stream_id: 0,
        },
        &settings_payload(initial_window),
    )
    .await?;
    if initial_window > DEFAULT_H2_WINDOW {
        write_frame(
            &mut stream,
            FrameHeader {
                len: 4,
                kind: FrameType::WindowUpdate as u8,
                flags: 0,
                stream_id: 0,
            },
            &(initial_window - DEFAULT_H2_WINDOW).to_be_bytes(),
        )
        .await?;
    }
    let (reader, writer) = tokio::io::split(stream);
    let (writer_tx, writer_rx) = mpsc::unbounded_channel();
    let session = Arc::new(H2Session {
        origin,
        writer: writer_tx,
        streams: Mutex::new(FxHashMap::default()),
        decoder: Mutex::new(HpackDecoder::default()),
        next_stream_id: AtomicU32::new(1),
        backpressure,
        conn_pending_credit: AtomicU32::new(0),
    });
    tokio::spawn(write_h2(writer, writer_rx));
    tokio::spawn(read_h2(session.clone(), reader));
    Ok(session)
}

impl H2Session {
    pub(crate) async fn request(
        &self,
        url: Url,
        headers: Vec<(String, String)>,
        defaults: &[(String, String)],
    ) -> Result<Response, Error> {
        let stream_id = self.next_stream_id.fetch_add(2, Ordering::Relaxed);
        let (tx, mut rx) = mpsc::unbounded_channel();
        self.streams.lock().await.insert(stream_id, tx);

        let block = encode_headers(&url, &self.origin, headers, defaults);
        let frames = header_block_frames(stream_id, &block)?;
        if self.writer.send(frames).is_err() {
            self.streams.lock().await.remove(&stream_id);
            return Err(Error::H2Closed);
        }

        let mut status = None;
        let mut response_headers = Headers::builder();
        let mut body = HiBuf::new();
        while let Some(message) = rx.recv().await {
            match message {
                StreamMessage::Headers {
                    headers,
                    end_stream,
                } => {
                    for (name, value) in headers {
                        if name == ":status" {
                            status = value.parse::<u16>().ok();
                        } else {
                            if body.capacity() == 0 && name.eq_ignore_ascii_case("content-length") {
                                if let Ok(len) = value.trim().parse::<usize>() {
                                    body.reserve(len);
                                }
                            }
                            response_headers.push(&name, &value);
                        }
                    }
                    if end_stream {
                        break;
                    }
                }
                StreamMessage::Data {
                    payload,
                    end_stream,
                } => {
                    body.extend_from_slice(&payload);
                    if end_stream {
                        break;
                    }
                }
                StreamMessage::Reset(code) => return Err(Error::H2Code(code)),
                StreamMessage::ConnectionClosed => return Err(Error::H2Closed),
            }
        }
        self.streams.lock().await.remove(&stream_id);
        Ok(Response {
            status: status.ok_or(Error::H2("response had no :status"))?,
            version: Version::Http2,
            url,
            headers: response_headers.finish(),
            body: body.freeze(),
        })
    }
}

async fn write_frame<W: AsyncWriteExt + Unpin>(
    writer: &mut W,
    header: FrameHeader,
    payload: &[u8],
) -> Result<(), Error> {
    writer.write_all(&encode_frame(header, payload)).await?;
    writer.flush().await?;
    Ok(())
}
