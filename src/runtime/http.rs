//! Small HTTP client tailored to hifi's scanner workload.
//!
//! HTTPS uses the `h2` crate for one multiplexed HTTP/2 connection per origin.
//! Plain HTTP uses a small HTTP/1.1 path.

use crate::hash::FxHashMap;
use crate::url::Url;
use bytes::{Bytes, BytesMut};
use rustls::{client::Resumption, RootCertStore};
use rustls_pki_types::ServerName;
use std::{fmt, io, sync::Arc};
use thiserror::Error;
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    sync::Mutex,
};
use tokio_rustls::TlsConnector;

mod headers;
mod origin;

use headers::{http1_content_length, reserve_body};
use origin::{connect_tcp, Origin};

const SCANNER_INITIAL_WINDOW: u32 = 16 * 1024 * 1024;

#[derive(Clone)]
pub struct Client {
    inner: Arc<ClientInner>,
}

struct ClientInner {
    tls_h2: TlsConnector,
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
    #[error("invalid HTTP/2 request header")]
    BadHeader,
    #[error(transparent)]
    H2Client(#[from] h2::Error),
    #[error(transparent)]
    Http(#[from] http::Error),
    #[error(transparent)]
    InvalidUri(#[from] http::uri::InvalidUri),
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
                    Err(err) => return Err(err),
                }
            }
        };

        match session
            .request(url.clone(), headers.clone(), &self.inner.default_headers)
            .await
        {
            Ok(response) => Ok(response),
            Err(err) => {
                let mut sessions = self.inner.h2.lock().await;
                sessions.remove(&Origin::for_url(&url)?);
                Err(err)
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
        h2_config.alpn_protocols = vec![b"h2".to_vec()];
        h2_config.resumption = Resumption::in_memory_sessions(1024);
        h2_config.enable_early_data = true;

        Client {
            inner: Arc::new(ClientInner {
                tls_h2: TlsConnector::from(Arc::new(h2_config)),
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
    sender: h2::client::SendRequest<Bytes>,
}

async fn connect_h2(origin: Origin, tls: TlsConnector) -> Result<Arc<H2Session>, Error> {
    let tcp = connect_tcp(&origin).await?;
    let name = ServerName::try_from(origin.host.clone())
        .map_err(|_| Error::BadDnsName(origin.host.clone()))?;
    let stream = tls.connect(name, tcp).await?;
    if stream
        .get_ref()
        .1
        .alpn_protocol()
        .map(|proto| proto != b"h2")
        .unwrap_or(true)
    {
        return Err(Error::H2("TLS origin did not negotiate h2"));
    }

    let (sender, connection) = h2::client::Builder::new()
        .initial_window_size(SCANNER_INITIAL_WINDOW)
        .initial_connection_window_size(SCANNER_INITIAL_WINDOW)
        .handshake(stream)
        .await?;
    tokio::spawn(async move {
        let _ = connection.await;
    });
    Ok(Arc::new(H2Session { origin, sender }))
}

impl H2Session {
    async fn request(
        &self,
        url: Url,
        headers: Vec<(String, String)>,
        defaults: &[(String, String)],
    ) -> Result<Response, Error> {
        let request = h2_request(&url, &self.origin, headers, defaults)?;
        let mut sender = self.sender.clone().ready().await?;
        let (response, _stream) = sender.send_request(request, true)?;
        let response = response.await?;

        let status = response.status().as_u16();
        let response_headers = response
            .headers()
            .iter()
            .filter_map(|(name, value)| {
                let value = value.to_str().ok()?;
                Some((name.as_str().to_ascii_lowercase(), value.to_string()))
            })
            .collect::<Vec<_>>();
        let mut body = BytesMut::new();
        reserve_body(&response_headers, &mut body);
        let mut stream = response.into_body();
        while let Some(chunk) = stream.data().await {
            let chunk = chunk?;
            body.extend_from_slice(&chunk);
        }
        Ok(Response {
            status,
            version: Version::Http2,
            url,
            headers: response_headers,
            body: body.freeze(),
        })
    }
}

fn h2_request(
    url: &Url,
    origin: &Origin,
    extra: Vec<(String, String)>,
    defaults: &[(String, String)],
) -> Result<http::Request<()>, Error> {
    let mut builder = http::Request::builder()
        .method(http::Method::GET)
        .version(http::Version::HTTP_2)
        .uri(
            format!(
                "{}://{}{}",
                url.scheme(),
                origin.authority(),
                request_path(url)
            )
            .parse::<http::Uri>()?,
        );
    let headers = builder.headers_mut().ok_or(Error::BadHeader)?;
    for (k, v) in defaults {
        append_header(headers, k, v)?;
    }
    for (k, v) in extra {
        append_header(headers, &k, &v)?;
    }
    Ok(builder.body(())?)
}

fn append_header(headers: &mut http::HeaderMap, name: &str, value: &str) -> Result<(), Error> {
    let name = http::HeaderName::from_bytes(name.to_ascii_lowercase().as_bytes())
        .map_err(|_| Error::BadHeader)?;
    let value = http::HeaderValue::from_str(value).map_err(|_| Error::BadHeader)?;
    headers.append(name, value);
    Ok(())
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
    let path = request_path(&url);
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

fn request_path(url: &Url) -> String {
    let path = if url.path().is_empty() {
        "/"
    } else {
        url.path()
    };
    match url.query() {
        Some(query) => format!("{path}?{query}"),
        None => path.to_string(),
    }
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn http1_chunked_body_is_decoded() {
        let body = decode_chunks(b"4\r\nWiki\r\n5\r\npedia\r\n0\r\n\r\n").unwrap();
        assert_eq!(body, Bytes::from_static(b"Wikipedia"));
    }
}
