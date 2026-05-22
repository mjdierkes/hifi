//! Small HTTP client tailored to hifi's scanner workload.
//!
//! The client owns just enough HTTP/2 to multiplex many GET requests over one
//! TLS connection per origin. HTTP/1.1 remains as a compatibility path for
//! plain HTTP test servers and TLS origins that do not negotiate `h2`.

use crate::url::Url;
use bytes::{Buf, BufMut, Bytes, BytesMut};
use rustc_hash::FxHashMap;
use rustls::{client::Resumption, RootCertStore};
use rustls_pki_types::ServerName;
use std::{
    fmt, io,
    io::IoSlice,
    sync::{
        atomic::{AtomicU32, Ordering},
        Arc,
    },
};
use thiserror::Error;
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadHalf, WriteHalf},
    net::TcpStream,
    sync::{mpsc, Mutex},
};
use tokio_rustls::{client::TlsStream, TlsConnector};

mod headers;
mod hpack;
mod origin;

use headers::{http1_content_length, reserve_body};
use hpack::{encode_headers, HpackDecoder};
use origin::{connect_tcp, Origin};

const H2_PREFACE: &[u8] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
const DEFAULT_H2_WINDOW: u32 = 65_535;
const SCANNER_INITIAL_WINDOW: u32 = 16 * 1024 * 1024;
const MAX_FRAME_SIZE: usize = 16_384;
const MAX_FRAME_PAYLOAD: u32 = 16 * 1024 * 1024;
const END_STREAM: u8 = 0x01;
const END_HEADERS: u8 = 0x04;
const PADDED: u8 = 0x08;
const PRIORITY: u8 = 0x20;

#[derive(Clone)]
pub struct Client {
    inner: Arc<ClientInner>,
}

struct ClientInner {
    tls_h2: TlsConnector,
    tls_h1: TlsConnector,
    default_headers: Vec<(String, String)>,
    h2: Mutex<FxHashMap<Origin, Arc<H2Session>>>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Version {
    Http11,
    Http2,
}

pub struct Response {
    status: u16,
    version: Version,
    url: Url,
    headers: Vec<(String, String)>,
    body: Bytes,
}

pub struct Request {
    client: Client,
    url: Url,
    headers: Vec<(String, String)>,
}

#[derive(Debug, Error)]
pub enum Error {
    #[error("unsupported URL scheme '{0}'")]
    BadScheme(String),
    #[error("URL has no host")]
    MissingHost,
    #[error("invalid TLS server name '{0}'")]
    BadDnsName(String),
    #[error("HTTP/2 protocol error: {0}")]
    H2(&'static str),
    #[error("HTTP/2 peer error code {0}")]
    H2Code(u32),
    #[error("HTTP/2 connection closed")]
    H2Closed,
    #[error("HTTP/1.1 response parse error")]
    BadHttp1,
    #[error(transparent)]
    Io(#[from] io::Error),
}

impl Client {
    pub fn new() -> Self {
        Self::builder().build()
    }

    pub fn builder() -> ClientBuilder {
        ClientBuilder::default()
    }

    pub fn get(&self, url: Url) -> Request {
        Request {
            client: self.clone(),
            url,
            headers: Vec::new(),
        }
    }

    pub async fn prewarm(&self, url: &Url) -> Result<(), Error> {
        if url.scheme() != "https" {
            return Ok(());
        }
        let origin = Origin::for_url(url)?;
        if self.inner.h2.lock().await.contains_key(&origin) {
            return Ok(());
        }
        let session = connect_h2(origin.clone(), self.inner.tls_h2.clone()).await?;
        let mut sessions = self.inner.h2.lock().await;
        if sessions.contains_key(&origin) {
            return Ok(());
        }
        sessions.insert(origin, session);
        Ok(())
    }

    async fn execute(&self, url: Url, headers: Vec<(String, String)>) -> Result<Response, Error> {
        match url.scheme() {
            "https" => self.execute_https(url, headers).await,
            "http" => http1_request(url, headers, &self.inner.default_headers).await,
            other => Err(Error::BadScheme(other.to_string())),
        }
    }

    async fn execute_https(
        &self,
        url: Url,
        headers: Vec<(String, String)>,
    ) -> Result<Response, Error> {
        let origin = Origin::for_url(&url)?;
        let session = {
            let mut sessions = self.inner.h2.lock().await;
            if let Some(session) = sessions.get(&origin) {
                session.clone()
            } else {
                match connect_h2(origin.clone(), self.inner.tls_h2.clone()).await {
                    Ok(session) => {
                        sessions.insert(origin, session.clone());
                        session
                    }
                    Err(err) => {
                        trace_http_fallback(&url, &err);
                        drop(sessions);
                        return http1_tls_request(
                            url,
                            headers,
                            &self.inner.default_headers,
                            self.inner.tls_h1.clone(),
                        )
                        .await;
                    }
                }
            }
        };

        match session
            .request(url.clone(), headers.clone(), &self.inner.default_headers)
            .await
        {
            Ok(response) => Ok(response),
            Err(err) => {
                trace_http_fallback(&url, &err);
                let mut sessions = self.inner.h2.lock().await;
                sessions.remove(&Origin::for_url(&url)?);
                drop(sessions);
                http1_tls_request(
                    url,
                    headers,
                    &self.inner.default_headers,
                    self.inner.tls_h1.clone(),
                )
                .await
            }
        }
    }
}

impl Default for Client {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Default)]
pub struct ClientBuilder {
    default_headers: Vec<(String, String)>,
}

impl ClientBuilder {
    pub fn default_headers(mut self, headers: Vec<(String, String)>) -> Self {
        self.default_headers = headers;
        self
    }

    pub fn build(self) -> Client {
        let mut roots = RootCertStore::empty();
        roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        let mut h2_config = rustls::ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth();
        h2_config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
        h2_config.resumption = Resumption::in_memory_sessions(1024);
        h2_config.enable_early_data = true;

        let mut roots = RootCertStore::empty();
        roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        let mut h1_config = rustls::ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth();
        h1_config.alpn_protocols = vec![b"http/1.1".to_vec()];
        h1_config.resumption = Resumption::in_memory_sessions(1024);
        h1_config.enable_early_data = true;

        Client {
            inner: Arc::new(ClientInner {
                tls_h2: TlsConnector::from(Arc::new(h2_config)),
                tls_h1: TlsConnector::from(Arc::new(h1_config)),
                default_headers: self.default_headers,
                h2: Mutex::new(FxHashMap::default()),
            }),
        }
    }
}

impl Request {
    pub fn header(mut self, name: impl Into<String>, value: impl Into<String>) -> Self {
        self.headers.push((name.into(), value.into()));
        self
    }

    pub async fn send(self) -> Result<Response, Error> {
        self.client.execute(self.url, self.headers).await
    }
}

impl Response {
    pub fn status(&self) -> u16 {
        self.status
    }

    pub fn is_success(&self) -> bool {
        (200..300).contains(&self.status)
    }

    pub fn is_redirection(&self) -> bool {
        (300..400).contains(&self.status)
    }

    pub fn version(&self) -> Version {
        self.version
    }

    pub fn url(&self) -> &Url {
        &self.url
    }

    pub fn headers(&self) -> &[(String, String)] {
        &self.headers
    }

    pub fn header(&self, name: &str) -> Option<&str> {
        headers::value(&self.headers, name)
    }

    pub fn content_length(&self) -> Option<u64> {
        self.header("content-length")?.parse().ok()
    }

    pub fn body(self) -> Bytes {
        self.body
    }
}

struct H2Session {
    origin: Origin,
    writer: mpsc::UnboundedSender<H2Write>,
    streams: Mutex<FxHashMap<u32, mpsc::UnboundedSender<StreamMessage>>>,
    decoder: Mutex<HpackDecoder>,
    next_stream_id: AtomicU32,
}

enum H2Write {
    Frames(Vec<Bytes>),
}

async fn connect_h2(origin: Origin, tls: TlsConnector) -> Result<Arc<H2Session>, Error> {
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
    write_frame(
        &mut stream,
        FrameHeader {
            len: 12,
            kind: FrameType::Settings as u8,
            flags: 0,
            stream_id: 0,
        },
        &settings_payload(),
    )
    .await?;
    write_frame(
        &mut stream,
        FrameHeader {
            len: 4,
            kind: FrameType::WindowUpdate as u8,
            flags: 0,
            stream_id: 0,
        },
        &(SCANNER_INITIAL_WINDOW - DEFAULT_H2_WINDOW).to_be_bytes(),
    )
    .await?;
    let (reader, writer) = tokio::io::split(stream);
    let (writer_tx, writer_rx) = mpsc::unbounded_channel();
    let session = Arc::new(H2Session {
        origin,
        writer: writer_tx,
        streams: Mutex::new(FxHashMap::default()),
        decoder: Mutex::new(HpackDecoder::default()),
        next_stream_id: AtomicU32::new(1),
    });
    tokio::spawn(write_h2(writer, writer_rx));
    tokio::spawn(read_h2(session.clone(), reader));
    Ok(session)
}

impl H2Session {
    async fn request(
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
        if self.writer.send(H2Write::Frames(frames)).is_err() {
            self.streams.lock().await.remove(&stream_id);
            return Err(Error::H2Closed);
        }

        let mut status = None;
        let mut response_headers = Vec::new();
        let mut body = BytesMut::new();
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
                            response_headers.push((name, value));
                        }
                    }
                    reserve_body(&response_headers, &mut body);
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
            headers: response_headers,
            body: body.freeze(),
        })
    }
}

fn header_block_frames(stream_id: u32, block: &[u8]) -> Result<Vec<Bytes>, Error> {
    let mut chunks = block.chunks(MAX_FRAME_SIZE).peekable();
    let Some(first) = chunks.next() else {
        return Err(Error::H2("empty request header block"));
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

async fn write_h2(
    mut writer: WriteHalf<TlsStream<TcpStream>>,
    mut rx: mpsc::UnboundedReceiver<H2Write>,
) {
    let mut pending = Vec::new();
    while let Some(command) = rx.recv().await {
        append_write(command, &mut pending);
        while let Ok(command) = rx.try_recv() {
            append_write(command, &mut pending);
        }
        if write_vectored_all(&mut writer, &pending).await.is_err() {
            break;
        }
        pending.clear();
    }
}

fn append_write(command: H2Write, pending: &mut Vec<Bytes>) {
    match command {
        H2Write::Frames(mut frames) => pending.append(&mut frames),
    }
}

async fn write_vectored_all<W: AsyncWrite + Unpin>(
    writer: &mut W,
    frames: &[Bytes],
) -> io::Result<()> {
    let mut frame_index = 0usize;
    let mut offset = 0usize;
    while frame_index < frames.len() {
        let ios: Vec<IoSlice<'_>> = frames[frame_index..]
            .iter()
            .take(64)
            .enumerate()
            .map(|(idx, frame)| {
                if idx == 0 {
                    IoSlice::new(&frame[offset..])
                } else {
                    IoSlice::new(frame)
                }
            })
            .collect();
        let mut written = writer.write_vectored(&ios).await?;
        if written == 0 {
            return Err(io::ErrorKind::WriteZero.into());
        }
        while frame_index < frames.len() {
            let remaining = frames[frame_index].len() - offset;
            if written < remaining {
                offset += written;
                break;
            }
            written -= remaining;
            frame_index += 1;
            offset = 0;
            if written == 0 {
                break;
            }
        }
    }
    writer.flush().await
}

async fn read_h2(session: Arc<H2Session>, mut reader: ReadHalf<TlsStream<TcpStream>>) {
    let mut pending_headers: Option<PendingHeaders> = None;
    while let Ok(frame) = read_frame(&mut reader).await {
        if frame.header.kind == FrameType::Settings as u8 && frame.header.flags & 0x01 == 0 {
            apply_settings(&session, &frame.payload).await;
            let _ = session.writer.send(H2Write::Frames(vec![encode_frame(
                FrameHeader {
                    len: 0,
                    kind: FrameType::Settings as u8,
                    flags: 0x01,
                    stream_id: 0,
                },
                &[],
            )]));
            continue;
        }
        if frame.header.kind == FrameType::Ping as u8 && frame.header.flags & 0x01 == 0 {
            let _ = session.writer.send(H2Write::Frames(vec![encode_frame(
                FrameHeader {
                    len: frame.payload.len() as u32,
                    kind: FrameType::Ping as u8,
                    flags: 0x01,
                    stream_id: 0,
                },
                &frame.payload,
            )]));
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
                        block: BytesMut::from(block),
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
                let code = frame.payload.as_ref().get_u32();
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

enum StreamMessage {
    Headers {
        headers: Vec<(String, String)>,
        end_stream: bool,
    },
    Data {
        payload: Bytes,
        end_stream: bool,
    },
    Reset(u32),
    ConnectionClosed,
}

struct PendingHeaders {
    stream_id: u32,
    end_stream: bool,
    block: BytesMut,
}

#[derive(Clone)]
struct Frame {
    header: FrameHeader,
    payload: Bytes,
}

#[derive(Clone, Copy)]
struct FrameHeader {
    len: u32,
    kind: u8,
    flags: u8,
    stream_id: u32,
}

#[repr(u8)]
enum FrameType {
    Data = 0,
    Headers = 1,
    Settings = 4,
    Ping = 6,
    RstStream = 3,
    GoAway = 7,
    WindowUpdate = 8,
    Continuation = 9,
}

fn settings_payload() -> [u8; 12] {
    let mut out = [0u8; 12];
    out[1] = 0x04;
    (&mut out[2..6]).put_u32(SCANNER_INITIAL_WINDOW);
    out[7] = 0x05;
    (&mut out[8..12]).put_u32(MAX_FRAME_SIZE as u32);
    out
}

async fn read_frame<R: AsyncRead + Unpin>(reader: &mut R) -> Result<Frame, Error> {
    let mut head = [0u8; 9];
    reader.read_exact(&mut head).await?;
    let len = ((head[0] as u32) << 16) | ((head[1] as u32) << 8) | head[2] as u32;
    if len > MAX_FRAME_PAYLOAD {
        return Err(Error::H2("frame payload too large"));
    }
    let mut payload = BytesMut::zeroed(len as usize);
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

async fn apply_settings(session: &H2Session, payload: &[u8]) {
    if payload.len() % 6 != 0 {
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

fn release_window(session: &H2Session, stream_id: u32, len: usize) {
    let Ok(increment) = u32::try_from(len) else {
        return;
    };
    if increment == 0 {
        return;
    }
    let bytes = increment.to_be_bytes();
    let _ = session.writer.send(H2Write::Frames(vec![
        encode_frame(
            FrameHeader {
                len: 4,
                kind: FrameType::WindowUpdate as u8,
                flags: 0,
                stream_id: 0,
            },
            &bytes,
        ),
        encode_frame(
            FrameHeader {
                len: 4,
                kind: FrameType::WindowUpdate as u8,
                flags: 0,
                stream_id,
            },
            &bytes,
        ),
    ]));
}

fn encode_frame(header: FrameHeader, payload: &[u8]) -> Bytes {
    let mut out = BytesMut::with_capacity(9 + payload.len());
    out.put_u8(((header.len >> 16) & 0xff) as u8);
    out.put_u8(((header.len >> 8) & 0xff) as u8);
    out.put_u8((header.len & 0xff) as u8);
    out.put_u8(header.kind);
    out.put_u8(header.flags);
    out.extend_from_slice(&(header.stream_id & 0x7fff_ffff).to_be_bytes());
    out.extend_from_slice(payload);
    out.freeze()
}

async fn read_http1_bytes<S: AsyncRead + Unpin>(stream: &mut S) -> Result<Bytes, Error> {
    let mut bytes = BytesMut::with_capacity(16 * 1024);
    let mut buf = [0u8; 16 * 1024];
    let mut reserved_body = false;
    loop {
        match stream.read(&mut buf).await {
            Ok(0) => break,
            Ok(n) => {
                bytes.extend_from_slice(&buf[..n]);
                if !reserved_body {
                    if let Some(split) = bytes.windows(4).position(|w| w == b"\r\n\r\n") {
                        if let Ok(head) = std::str::from_utf8(&bytes[..split]) {
                            if let Some(len) = http1_content_length(head) {
                                let target = split + 4 + len;
                                if target > bytes.capacity() {
                                    bytes.reserve(target - bytes.len());
                                }
                            }
                        }
                        reserved_body = true;
                    }
                }
            }
            Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => break,
            Err(e) => return Err(e.into()),
        }
    }
    Ok(bytes.freeze())
}

fn header_block_payload(frame: &Frame) -> Option<&[u8]> {
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

fn data_payload(frame: &Frame) -> Option<Bytes> {
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

async fn write_frame<W: AsyncWrite + Unpin>(
    writer: &mut W,
    header: FrameHeader,
    payload: &[u8],
) -> Result<(), Error> {
    writer.write_all(&encode_frame(header, payload)).await?;
    writer.flush().await?;
    Ok(())
}

async fn http1_tls_request(
    url: Url,
    headers: Vec<(String, String)>,
    defaults: &[(String, String)],
    tls: TlsConnector,
) -> Result<Response, Error> {
    let origin = Origin::for_url(&url)?;
    let tcp = connect_tcp(&origin).await?;
    let name = ServerName::try_from(origin.host.clone())
        .map_err(|_| Error::BadDnsName(origin.host.clone()))?;
    let stream = tls.connect(name, tcp).await?;
    http1_exchange(stream, url, origin, headers, defaults, Version::Http11).await
}

async fn http1_request(
    url: Url,
    headers: Vec<(String, String)>,
    defaults: &[(String, String)],
) -> Result<Response, Error> {
    let origin = Origin::for_url(&url)?;
    let stream = connect_tcp(&origin).await?;
    http1_exchange(stream, url, origin, headers, defaults, Version::Http11).await
}

async fn http1_exchange<S: AsyncRead + AsyncWrite + Unpin>(
    mut stream: S,
    url: Url,
    origin: Origin,
    extra: Vec<(String, String)>,
    defaults: &[(String, String)],
    version: Version,
) -> Result<Response, Error> {
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
    let mut req = format!(
        "GET {path} HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n",
        origin.authority()
    );
    for (k, v) in defaults {
        req.push_str(k);
        req.push_str(": ");
        req.push_str(v);
        req.push_str("\r\n");
    }
    for (k, v) in extra {
        req.push_str(&k);
        req.push_str(": ");
        req.push_str(&v);
        req.push_str("\r\n");
    }
    req.push_str("\r\n");
    stream.write_all(req.as_bytes()).await?;

    let bytes = read_http1_bytes(&mut stream).await?;
    parse_http1(url, version, bytes)
}

fn parse_http1(url: Url, version: Version, bytes: Bytes) -> Result<Response, Error> {
    let split = bytes
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .ok_or(Error::BadHttp1)?;
    let head = std::str::from_utf8(&bytes[..split]).map_err(|_| Error::BadHttp1)?;
    let mut lines = head.split("\r\n");
    let status_line = lines.next().ok_or(Error::BadHttp1)?;
    let status = status_line
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse::<u16>().ok())
        .ok_or(Error::BadHttp1)?;
    let mut headers = Vec::new();
    let mut chunked = false;
    for line in lines {
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        let value = value.trim().to_string();
        if name.eq_ignore_ascii_case("transfer-encoding") && value.eq_ignore_ascii_case("chunked") {
            chunked = true;
        }
        headers.push((name.to_ascii_lowercase(), value));
    }
    let body = bytes.slice(split + 4..);
    let body = if chunked { decode_chunks(&body)? } else { body };
    Ok(Response {
        status,
        version,
        url,
        headers,
        body,
    })
}

fn decode_chunks(bytes: &[u8]) -> Result<Bytes, Error> {
    let mut pos = 0;
    let mut out = BytesMut::new();
    loop {
        let line_end = find_crlf(bytes, pos).ok_or(Error::BadHttp1)?;
        let size_text = std::str::from_utf8(&bytes[pos..line_end]).map_err(|_| Error::BadHttp1)?;
        let size = usize::from_str_radix(size_text.split(';').next().unwrap_or(""), 16)
            .map_err(|_| Error::BadHttp1)?;
        pos = line_end + 2;
        if size == 0 {
            break;
        }
        let end = pos.checked_add(size).ok_or(Error::BadHttp1)?;
        out.extend_from_slice(bytes.get(pos..end).ok_or(Error::BadHttp1)?);
        pos = end + 2;
    }
    Ok(out.freeze())
}

fn find_crlf(bytes: &[u8], start: usize) -> Option<usize> {
    bytes
        .get(start..)?
        .windows(2)
        .position(|w| w == b"\r\n")
        .map(|idx| start + idx)
}

impl fmt::Debug for Client {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Client").finish_non_exhaustive()
    }
}

fn trace_http_fallback(url: &Url, err: &Error) {
    if std::env::var_os("HIFI_TRACE_HTTP").is_some() {
        eprintln!("hifi: trace: h2 fallback {} {err}", url.as_str());
    }
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
            payload: Bytes::from_static(&[2, 0, 0, 0, 0, 0, b'a', b'b', 0, 0]),
        };
        assert_eq!(header_block_payload(&frame).unwrap(), b"ab");

        let frame = Frame {
            header: FrameHeader {
                len: 5,
                kind: FrameType::Data as u8,
                flags: PADDED,
                stream_id: 1,
            },
            payload: Bytes::from_static(&[1, b'x', b'y', b'z', 0]),
        };
        assert_eq!(data_payload(&frame).unwrap(), Bytes::from_static(b"xyz"));
    }

    #[test]
    fn http1_chunked_body_is_decoded() {
        let body = decode_chunks(b"4\r\nWiki\r\n5\r\npedia\r\n0\r\n\r\n").unwrap();
        assert_eq!(body, Bytes::from_static(b"Wikipedia"));
    }
}
