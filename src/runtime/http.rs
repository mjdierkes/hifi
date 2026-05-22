//! Small HTTP client tailored to hifi's scanner workload.
//!
//! The client owns just enough HTTP/2 to multiplex many GET requests over one
//! TLS connection per origin. HTTP/1.1 remains as a compatibility path for
//! plain HTTP test servers and TLS origins that do not negotiate `h2`.

use bytes::{Buf, BufMut, Bytes, BytesMut};
use rustls::RootCertStore;
use rustls_pki_types::ServerName;
use std::{
    collections::HashMap,
    fmt, io,
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
use url::Url;

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
    h2: Mutex<HashMap<Origin, Arc<H2Session>>>,
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
struct Origin {
    scheme: String,
    host: String,
    port: u16,
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

        let mut roots = RootCertStore::empty();
        roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        let mut h1_config = rustls::ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth();
        h1_config.alpn_protocols = vec![b"http/1.1".to_vec()];

        Client {
            inner: Arc::new(ClientInner {
                tls_h2: TlsConnector::from(Arc::new(h2_config)),
                tls_h1: TlsConnector::from(Arc::new(h1_config)),
                default_headers: self.default_headers,
                h2: Mutex::new(HashMap::new()),
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
        self.headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }

    pub fn content_length(&self) -> Option<u64> {
        self.header("content-length")?.parse().ok()
    }

    pub fn body(self) -> Bytes {
        self.body
    }
}

impl Origin {
    fn for_url(url: &Url) -> Result<Self, Error> {
        let host = url
            .host_str()
            .ok_or(Error::MissingHost)?
            .to_ascii_lowercase();
        let port = url.port_or_known_default().ok_or(Error::MissingHost)?;
        Ok(Self {
            scheme: url.scheme().to_string(),
            host,
            port,
        })
    }

    fn authority(&self) -> String {
        let default_port = (self.scheme == "https" && self.port == 443)
            || (self.scheme == "http" && self.port == 80);
        if default_port {
            self.host.clone()
        } else {
            format!("{}:{}", self.host, self.port)
        }
    }
}

struct H2Session {
    origin: Origin,
    writer: Mutex<WriteHalf<TlsStream<TcpStream>>>,
    streams: Mutex<HashMap<u32, mpsc::UnboundedSender<StreamMessage>>>,
    decoder: Mutex<HpackDecoder>,
    next_stream_id: AtomicU32,
}

async fn connect_h2(origin: Origin, tls: TlsConnector) -> Result<Arc<H2Session>, Error> {
    let tcp = TcpStream::connect((origin.host.as_str(), origin.port)).await?;
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
    let session = Arc::new(H2Session {
        origin,
        writer: Mutex::new(writer),
        streams: Mutex::new(HashMap::new()),
        decoder: Mutex::new(HpackDecoder::default()),
        next_stream_id: AtomicU32::new(1),
    });
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
        {
            let mut writer = self.writer.lock().await;
            if let Err(err) = write_header_block(&mut *writer, stream_id, &block).await {
                self.streams.lock().await.remove(&stream_id);
                return Err(err);
            }
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

async fn write_header_block<W: AsyncWrite + Unpin>(
    writer: &mut W,
    stream_id: u32,
    block: &[u8],
) -> Result<(), Error> {
    let mut chunks = block.chunks(MAX_FRAME_SIZE).peekable();
    let Some(first) = chunks.next() else {
        return Err(Error::H2("empty request header block"));
    };
    let first_is_last = chunks.peek().is_none();
    write_frame(
        writer,
        FrameHeader {
            len: first.len() as u32,
            kind: FrameType::Headers as u8,
            flags: END_STREAM | if first_is_last { END_HEADERS } else { 0 },
            stream_id,
        },
        first,
    )
    .await?;
    while let Some(chunk) = chunks.next() {
        let is_last = chunks.peek().is_none();
        write_frame(
            writer,
            FrameHeader {
                len: chunk.len() as u32,
                kind: FrameType::Continuation as u8,
                flags: if is_last { END_HEADERS } else { 0 },
                stream_id,
            },
            chunk,
        )
        .await?;
    }
    Ok(())
}

async fn read_h2(session: Arc<H2Session>, mut reader: ReadHalf<TlsStream<TcpStream>>) {
    let mut pending_headers: Option<PendingHeaders> = None;
    while let Ok(frame) = read_frame(&mut reader).await {
        if frame.header.kind == FrameType::Settings as u8 && frame.header.flags & 0x01 == 0 {
            apply_settings(&session, &frame.payload).await;
            let mut writer = session.writer.lock().await;
            let _ = write_frame(
                &mut *writer,
                FrameHeader {
                    len: 0,
                    kind: FrameType::Settings as u8,
                    flags: 0x01,
                    stream_id: 0,
                },
                &[],
            )
            .await;
            continue;
        }
        if frame.header.kind == FrameType::Ping as u8 && frame.header.flags & 0x01 == 0 {
            let mut writer = session.writer.lock().await;
            let _ = write_frame(
                &mut *writer,
                FrameHeader {
                    len: frame.payload.len() as u32,
                    kind: FrameType::Ping as u8,
                    flags: 0x01,
                    stream_id: 0,
                },
                &frame.payload,
            )
            .await;
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
                        release_window(&session, frame.header.stream_id, payload.len()).await;
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

async fn release_window(session: &H2Session, stream_id: u32, len: usize) {
    let Ok(increment) = u32::try_from(len) else {
        return;
    };
    if increment == 0 {
        return;
    }
    let mut writer = session.writer.lock().await;
    let bytes = increment.to_be_bytes();
    let _ = write_frame(
        &mut *writer,
        FrameHeader {
            len: 4,
            kind: FrameType::WindowUpdate as u8,
            flags: 0,
            stream_id: 0,
        },
        &bytes,
    )
    .await;
    let _ = write_frame(
        &mut *writer,
        FrameHeader {
            len: 4,
            kind: FrameType::WindowUpdate as u8,
            flags: 0,
            stream_id,
        },
        &bytes,
    )
    .await;
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
    let mut head = [0u8; 9];
    head[0] = ((header.len >> 16) & 0xff) as u8;
    head[1] = ((header.len >> 8) & 0xff) as u8;
    head[2] = (header.len & 0xff) as u8;
    head[3] = header.kind;
    head[4] = header.flags;
    head[5..9].copy_from_slice(&(header.stream_id & 0x7fff_ffff).to_be_bytes());
    writer.write_all(&head).await?;
    writer.write_all(payload).await?;
    writer.flush().await?;
    Ok(())
}

fn encode_headers(
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

fn literal_header(out: &mut BytesMut, name: &str, value: &str) {
    out.put_u8(0x00);
    hpack_string(out, name);
    hpack_string(out, value);
}

fn hpack_string(out: &mut BytesMut, value: &str) {
    hpack_int(out, value.len(), 7, 0);
    out.extend_from_slice(value.as_bytes());
}

fn hpack_int(out: &mut BytesMut, mut value: usize, prefix: u8, marker: u8) {
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

struct HpackDecoder {
    dynamic: Vec<(String, String)>,
    dynamic_size: usize,
    max_dynamic_size: usize,
    allowed_dynamic_size: usize,
}

impl HpackDecoder {
    fn set_allowed_max_size(&mut self, size: usize) {
        self.allowed_dynamic_size = size;
        if self.max_dynamic_size > size {
            self.set_max_size(size);
        }
    }

    fn set_max_size(&mut self, size: usize) {
        self.max_dynamic_size = size;
        self.evict_dynamic();
    }

    fn decode(&mut self, bytes: &[u8]) -> Result<Vec<(String, String)>, Error> {
        let mut pos = 0;
        let mut out = Vec::new();
        let mut can_resize = true;
        while pos < bytes.len() {
            let b = bytes[pos];
            if b & 0x80 != 0 {
                can_resize = false;
                let idx = read_int(bytes, &mut pos, 7)?;
                out.push(self.lookup(idx)?);
            } else if b & 0x40 != 0 {
                can_resize = false;
                let idx = read_int(bytes, &mut pos, 6)?;
                let name = if idx == 0 {
                    read_string(bytes, &mut pos)?
                } else {
                    self.lookup(idx)?.0
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
                    self.lookup(idx)?.0
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

    fn lookup(&self, idx: usize) -> Result<(String, String), Error> {
        if idx == 0 {
            return Err(Error::H2("bad HPACK index"));
        }
        if let Some((name, value)) = STATIC_TABLE.get(idx - 1) {
            return Ok((name.to_string(), value.to_string()));
        }
        self.dynamic
            .get(idx - STATIC_TABLE.len() - 1)
            .cloned()
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

fn hpack_huffman_decode(raw: &[u8]) -> Result<Vec<u8>, Error> {
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
    HUFFMAN_CODES
        .iter()
        .position(|&(bits, value)| bits == len && value == code)
        .map(|idx| idx as u16)
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

const STATIC_TABLE: &[(&str, &str)] = &[
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

async fn http1_tls_request(
    url: Url,
    headers: Vec<(String, String)>,
    defaults: &[(String, String)],
    tls: TlsConnector,
) -> Result<Response, Error> {
    let origin = Origin::for_url(&url)?;
    let tcp = TcpStream::connect((origin.host.as_str(), origin.port)).await?;
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
    let stream = TcpStream::connect((origin.host.as_str(), origin.port)).await?;
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

    let mut bytes = Vec::new();
    let mut buf = [0u8; 16 * 1024];
    loop {
        match stream.read(&mut buf).await {
            Ok(0) => break,
            Ok(n) => bytes.extend_from_slice(&buf[..n]),
            Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => break,
            Err(e) => return Err(e.into()),
        }
    }
    parse_http1(url, version, Bytes::from(bytes))
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
    fn hpack_huffman_decodes_reference_samples() {
        assert_eq!(hpack_huffman_decode(&[0b0011_1111]).unwrap(), b"o");
        assert_eq!(hpack_huffman_decode(&[7]).unwrap(), b"0");
        assert_eq!(hpack_huffman_decode(&[(0x21 << 2) + 3]).unwrap(), b"A");
        assert_eq!(
            hpack_huffman_decode(&[0b0101_0011, 0b1111_1000]).unwrap(),
            b" !"
        );
    }

    #[test]
    fn hpack_dynamic_table_indexes_and_evicts() {
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
                .decode(&[STATIC_TABLE.len() as u8 + 1 | 0x80])
                .unwrap(),
            vec![("x-a".to_string(), "one".to_string())]
        );

        decoder.set_max_size(1);
        assert!(decoder
            .decode(&[STATIC_TABLE.len() as u8 + 1 | 0x80])
            .is_err());
    }

    #[test]
    fn hpack_rejects_late_or_oversized_table_updates() {
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
