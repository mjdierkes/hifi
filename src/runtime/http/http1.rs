use super::{headers::Headers, origin::connect_tcp, origin::Origin, Error, Response, Version};
use crate::hash::FxHashMap;
use crate::runtime::bytes::{HiBuf, HiBytes};
use crate::url::Url;
use std::{
    io,
    time::{Duration, Instant},
};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
    sync::Mutex,
};

const POOL_MAX_IDLE_PER_ORIGIN: usize = 8;
const POOL_IDLE_TIMEOUT: Duration = Duration::from_secs(30);
const HEAD_LIMIT: usize = 64 * 1024;

pub(super) struct Pool {
    idle: Mutex<FxHashMap<Origin, Vec<IdleConn>>>,
}

struct IdleConn {
    stream: TcpStream,
    idle_since: Instant,
}

impl Default for Pool {
    fn default() -> Self {
        Self {
            idle: Mutex::new(FxHashMap::default()),
        }
    }
}

impl Pool {
    pub(super) async fn execute(
        &self,
        url: Url,
        headers: Vec<(String, String)>,
        defaults: &[(String, String)],
    ) -> Result<Response, Error> {
        let origin = Origin::for_url(&url)?;
        while let Some(stream) = self.checkout(&origin).await {
            match exchange(
                stream,
                url.clone(),
                origin.clone(),
                headers.clone(),
                defaults,
                Version::Http11,
            )
            .await
            {
                Ok((response, keep)) => {
                    if let Some(stream) = keep {
                        self.return_idle(origin, stream).await;
                    }
                    return Ok(response);
                }
                Err(_) => continue,
            }
        }

        let stream = connect_tcp(&origin).await?;
        let (response, keep) = exchange(
            stream,
            url,
            origin.clone(),
            headers,
            defaults,
            Version::Http11,
        )
        .await?;
        if let Some(stream) = keep {
            self.return_idle(origin, stream).await;
        }
        Ok(response)
    }

    async fn checkout(&self, origin: &Origin) -> Option<TcpStream> {
        let mut pool = self.idle.lock().await;
        let bucket = pool.get_mut(origin)?;
        let now = Instant::now();
        while let Some(idle) = bucket.pop() {
            if now.duration_since(idle.idle_since) <= POOL_IDLE_TIMEOUT {
                return Some(idle.stream);
            }
        }
        None
    }

    async fn return_idle(&self, origin: Origin, stream: TcpStream) {
        let mut pool = self.idle.lock().await;
        let bucket = pool.entry(origin).or_default();
        if bucket.len() >= POOL_MAX_IDLE_PER_ORIGIN {
            return;
        }
        bucket.push(IdleConn {
            stream,
            idle_since: Instant::now(),
        });
    }
}

async fn exchange(
    mut stream: TcpStream,
    url: Url,
    origin: Origin,
    extra: Vec<(String, String)>,
    defaults: &[(String, String)],
    version: Version,
) -> Result<(Response, Option<TcpStream>), Error> {
    let path = request_path(&url);
    let mut req = format!("GET {path} HTTP/1.1\r\nHost: {}\r\n", origin.authority());
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

    let (response, reusable) = read_response(&mut stream, url, version).await?;
    let pooled = reusable
        .then_some(stream)
        .filter(|_| !response.headers.connection_close());
    Ok((response, pooled))
}

fn request_path(url: &Url) -> String {
    match url.query() {
        Some(query) => format!("{}?{query}", url.path()),
        None => {
            let path = url.path();
            if path.is_empty() {
                "/".to_string()
            } else {
                path.to_string()
            }
        }
    }
}

async fn read_response<S: AsyncRead + Unpin>(
    stream: &mut S,
    url: Url,
    version: Version,
) -> Result<(Response, bool), Error> {
    let mut bytes = HiBuf::with_capacity(8 * 1024);
    let mut buf = [0u8; 16 * 1024];
    let head_end = loop {
        if let Some(idx) = find_sub(&bytes, b"\r\n\r\n") {
            break idx;
        }
        if bytes.len() > HEAD_LIMIT {
            return Err(Error::BadHttp1);
        }
        match stream.read(&mut buf).await {
            Ok(0) => return Err(Error::BadHttp1),
            Ok(n) => bytes.extend_from_slice(&buf[..n]),
            Err(e) => return Err(e.into()),
        }
    };

    let head = parse_head(&bytes, head_end)?;
    let body_start = head_end + 4;
    match head.body {
        BodyShape::Length(len) => {
            read_exact_body(stream, &mut bytes, body_start + len).await?;
        }
        BodyShape::Chunked => {
            read_chunked_body(stream, &mut bytes, body_start).await?;
        }
        BodyShape::Empty => {}
        BodyShape::UntilClose => {
            read_until_close(stream, &mut bytes).await?;
        }
    }

    let bytes = bytes.freeze();
    let body = bytes.slice(body_start..);
    let body = match head.body {
        BodyShape::Chunked => decode_chunks(&body)?,
        _ => body,
    };
    let response = Response {
        status: head.status,
        version,
        url,
        headers: Headers::from_borrowed(bytes.slice(0..head_end), head.headers),
        body,
    };
    Ok((response, head.body != BodyShape::UntilClose))
}

async fn read_exact_body<S: AsyncRead + Unpin>(
    stream: &mut S,
    bytes: &mut HiBuf,
    target: usize,
) -> Result<(), Error> {
    let mut buf = [0u8; 16 * 1024];
    if target > bytes.capacity() {
        bytes.reserve(target - bytes.capacity());
    }
    while bytes.len() < target {
        let n = stream.read(&mut buf).await?;
        if n == 0 {
            return Err(Error::BadHttp1);
        }
        bytes.extend_from_slice(&buf[..n]);
    }
    Ok(())
}

async fn read_chunked_body<S: AsyncRead + Unpin>(
    stream: &mut S,
    bytes: &mut HiBuf,
    body_start: usize,
) -> Result<(), Error> {
    let mut buf = [0u8; 16 * 1024];
    loop {
        if chunked_complete(&bytes[body_start..]) {
            return Ok(());
        }
        let n = stream.read(&mut buf).await?;
        if n == 0 {
            return Err(Error::BadHttp1);
        }
        bytes.extend_from_slice(&buf[..n]);
    }
}

async fn read_until_close<S: AsyncRead + Unpin>(
    stream: &mut S,
    bytes: &mut HiBuf,
) -> Result<(), Error> {
    let mut buf = [0u8; 16 * 1024];
    loop {
        match stream.read(&mut buf).await {
            Ok(0) => return Ok(()),
            Ok(n) => bytes.extend_from_slice(&buf[..n]),
            Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => return Ok(()),
            Err(e) => return Err(e.into()),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum BodyShape {
    Length(usize),
    Chunked,
    Empty,
    UntilClose,
}

struct ParsedHead {
    status: u16,
    body: BodyShape,
    headers: Vec<(u32, u32, u32, u32)>,
}

fn parse_head(bytes: &[u8], head_end: usize) -> Result<ParsedHead, Error> {
    let head = bytes.get(..head_end).ok_or(Error::BadHttp1)?;
    std::str::from_utf8(head).map_err(|_| Error::BadHttp1)?;

    let status_line_end = find_crlf(bytes, 0).unwrap_or(head_end);
    let status = parse_status(&bytes[..status_line_end])?;
    let mut headers = Vec::new();
    let mut content_length = None;
    let mut chunked = false;
    let mut line_start = if status_line_end < head_end {
        status_line_end + 2
    } else {
        head_end
    };

    while line_start < head_end {
        let line_end = find_crlf(bytes, line_start).unwrap_or(head_end);
        if let Some(colon) = bytes[line_start..line_end].iter().position(|&b| b == b':') {
            let name_start = line_start;
            let name_end = line_start + colon;
            let mut value_start = name_end + 1;
            while value_start < line_end
                && (bytes[value_start] == b' ' || bytes[value_start] == b'\t')
            {
                value_start += 1;
            }
            let mut value_end = line_end;
            while value_end > value_start
                && (bytes[value_end - 1] == b' ' || bytes[value_end - 1] == b'\t')
            {
                value_end -= 1;
            }

            let name = &bytes[name_start..name_end];
            let value = &bytes[value_start..value_end];
            if eq_ignore_ascii_case(name, b"content-length") {
                content_length = std::str::from_utf8(value)
                    .ok()
                    .and_then(|value| value.parse().ok());
            } else if eq_ignore_ascii_case(name, b"transfer-encoding")
                && transfer_encoding_is_chunked(value)
            {
                chunked = true;
            }
            headers.push((
                name_start as u32,
                name_end as u32,
                value_start as u32,
                value_end as u32,
            ));
        }
        line_start = line_end + 2;
    }

    let body = if status == 204 || status == 304 || (100..200).contains(&status) {
        BodyShape::Empty
    } else if chunked {
        BodyShape::Chunked
    } else if let Some(len) = content_length {
        BodyShape::Length(len)
    } else {
        BodyShape::UntilClose
    };
    Ok(ParsedHead {
        status,
        body,
        headers,
    })
}

fn parse_status(line: &[u8]) -> Result<u16, Error> {
    let line = std::str::from_utf8(line).map_err(|_| Error::BadHttp1)?;
    line.split_whitespace()
        .nth(1)
        .and_then(|status| status.parse().ok())
        .ok_or(Error::BadHttp1)
}

fn transfer_encoding_is_chunked(value: &[u8]) -> bool {
    value
        .split(|&b| b == b',')
        .any(|part| eq_ignore_ascii_case(trim_ascii(part), b"chunked"))
}

fn trim_ascii(bytes: &[u8]) -> &[u8] {
    let mut start = 0;
    let mut end = bytes.len();
    while start < end && (bytes[start] == b' ' || bytes[start] == b'\t') {
        start += 1;
    }
    while end > start && (bytes[end - 1] == b' ' || bytes[end - 1] == b'\t') {
        end -= 1;
    }
    &bytes[start..end]
}

fn eq_ignore_ascii_case(a: &[u8], b: &[u8]) -> bool {
    a.eq_ignore_ascii_case(b)
}

fn chunked_complete(body: &[u8]) -> bool {
    let mut pos = 0;
    while pos < body.len() {
        let Some(line_end) = find_crlf(body, pos) else {
            return false;
        };
        let size_text = match std::str::from_utf8(&body[pos..line_end]) {
            Ok(s) => s,
            Err(_) => return false,
        };
        let Ok(size) = usize::from_str_radix(size_text.split(';').next().unwrap_or(""), 16) else {
            return false;
        };
        let after_size_crlf = line_end + 2;
        if size == 0 {
            return find_sub(&body[after_size_crlf.saturating_sub(2)..], b"\r\n\r\n").is_some();
        }
        let chunk_end = after_size_crlf + size + 2;
        if chunk_end > body.len() {
            return false;
        }
        pos = chunk_end;
    }
    false
}

fn decode_chunks(bytes: &[u8]) -> Result<HiBytes, Error> {
    let mut pos = 0;
    let mut out = HiBuf::new();
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

fn find_sub(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    memchr::memmem::find(haystack, needle)
}

fn find_crlf(bytes: &[u8], start: usize) -> Option<usize> {
    memchr::memmem::find(bytes.get(start..)?, b"\r\n").map(|idx| start + idx)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{
        atomic::{AtomicU32, Ordering},
        Arc,
    };

    #[test]
    fn chunked_body_is_decoded() {
        let body = decode_chunks(b"4\r\nWiki\r\n5\r\npedia\r\n0\r\n\r\n").unwrap();
        assert_eq!(body, HiBytes::from_static(b"Wikipedia"));
    }

    #[test]
    fn header_ranges_borrow_from_head_buffer() {
        let raw = b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\nETag: \"abc\"\r\n\r\nhello";
        let parsed = parse_head(raw, raw.len() - 5 - 4).unwrap();
        let bytes = HiBytes::from_vec(raw.to_vec());
        let headers = Headers::from_borrowed(bytes.slice(0..raw.len() - 5 - 4), parsed.headers);
        assert_eq!(parsed.status, 200);
        assert_eq!(headers.get("etag"), Some("\"abc\""));
        assert_eq!(headers.get("content-length"), Some("5"));
        assert_eq!(parsed.body, BodyShape::Length(5));
    }

    #[test]
    fn chunked_complete_detects_terminator() {
        assert!(chunked_complete(b"4\r\nWiki\r\n5\r\npedia\r\n0\r\n\r\n"));
        assert!(!chunked_complete(b"4\r\nWiki\r\n5\r\npedia\r\n0\r\n"));
        assert!(!chunked_complete(b"4\r\nWiki\r\n"));
    }

    #[test]
    fn parse_head_picks_body_shape() {
        let length = b"HTTP/1.1 200 OK\r\nContent-Length: 42";
        assert_eq!(
            parse_head(length, length.len()).unwrap().body,
            BodyShape::Length(42)
        );
        let chunked = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: gzip, chunked";
        assert_eq!(
            parse_head(chunked, chunked.len()).unwrap().body,
            BodyShape::Chunked
        );
        let empty = b"HTTP/1.1 204 No Content";
        assert_eq!(
            parse_head(empty, empty.len()).unwrap().body,
            BodyShape::Empty
        );
        let until_close = b"HTTP/1.1 200 OK";
        assert_eq!(
            parse_head(until_close, until_close.len()).unwrap().body,
            BodyShape::UntilClose
        );
    }

    #[tokio::test]
    async fn pool_reuses_connection_across_requests() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::TcpListener;

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let port = addr.port();
        let accepted = Arc::new(AtomicU32::new(0));
        let accepted_for_task = accepted.clone();
        tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.unwrap();
            accepted_for_task.fetch_add(1, Ordering::Relaxed);
            let mut buf = vec![0u8; 1024];
            for _ in 0..2 {
                let mut total = 0;
                loop {
                    let n = sock.read(&mut buf[total..]).await.unwrap();
                    total += n;
                    if buf[..total].windows(4).any(|w| w == b"\r\n\r\n") {
                        break;
                    }
                }
                sock.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nhi")
                    .await
                    .unwrap();
            }
        });

        let pool = Pool::default();
        let url = Url::parse(&format!("http://127.0.0.1:{port}/")).unwrap();
        let r1 = pool.execute(url.clone(), Vec::new(), &[]).await.unwrap();
        assert_eq!(r1.status(), 200);
        let r2 = pool.execute(url, Vec::new(), &[]).await.unwrap();
        assert_eq!(r2.status(), 200);
        assert_eq!(accepted.load(Ordering::Relaxed), 1);
    }
}
