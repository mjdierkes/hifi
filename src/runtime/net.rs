use bytes::{Bytes, BytesMut};
use futures_util::StreamExt;
use reqwest::{Client, Response};
use std::net::IpAddr;
use thiserror::Error;
use url::{Host, Url};

pub const MAX_RESPONSE_BYTES: u64 = 50 * 1024 * 1024;

#[derive(Debug, Error)]
pub enum NetError {
    #[error("unsupported URL scheme '{0}'")]
    BadScheme(String),
    #[error(
        "private or local addresses are blocked for '{0}' (set HIFI_ALLOW_PRIVATE=1 to allow)"
    )]
    PrivateAddress(String),
    #[error("response too large: {actual} bytes exceeds {limit} bytes")]
    ResponseTooLarge { actual: u64, limit: u64 },
    #[error(transparent)]
    Http(#[from] reqwest::Error),
}

pub fn allow_private_networks() -> bool {
    std::env::var("HIFI_ALLOW_PRIVATE")
        .map(|v| matches!(v.as_str(), "1" | "true" | "TRUE" | "yes" | "YES"))
        .unwrap_or(false)
}

pub fn validate_url(url: &Url, allow_private: bool) -> Result<(), NetError> {
    if !matches!(url.scheme(), "http" | "https") {
        return Err(NetError::BadScheme(url.scheme().to_string()));
    }
    if allow_private {
        return Ok(());
    }
    let Some(host) = url.host() else {
        return Err(NetError::PrivateAddress(url.to_string()));
    };
    match host {
        Host::Ipv4(ip) if is_private_ip(IpAddr::V4(ip)) => {
            Err(NetError::PrivateAddress(url.to_string()))
        }
        Host::Ipv6(ip) if is_private_ip(IpAddr::V6(ip)) => {
            Err(NetError::PrivateAddress(url.to_string()))
        }
        Host::Domain(name) if is_local_name(name) => Err(NetError::PrivateAddress(url.to_string())),
        _ => Ok(()),
    }
}

pub async fn get_limited(
    client: &Client,
    url: Url,
    allow_private: bool,
) -> Result<Response, NetError> {
    validate_url(&url, allow_private)?;
    Ok(client.get(url).send().await?.error_for_status()?)
}

pub async fn read_limited(response: Response) -> Result<Bytes, NetError> {
    let content_length = response.content_length();
    if let Some(len) = content_length {
        if len > MAX_RESPONSE_BYTES {
            return Err(NetError::ResponseTooLarge {
                actual: len,
                limit: MAX_RESPONSE_BYTES,
            });
        }
    }

    let mut body =
        BytesMut::with_capacity(content_length.unwrap_or(0).min(MAX_RESPONSE_BYTES) as usize);
    let mut stream = response.bytes_stream();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk?;
        let next_len = body.len() as u64 + chunk.len() as u64;
        if next_len > MAX_RESPONSE_BYTES {
            return Err(NetError::ResponseTooLarge {
                actual: next_len,
                limit: MAX_RESPONSE_BYTES,
            });
        }
        body.extend_from_slice(&chunk);
    }
    Ok(body.freeze())
}

pub async fn get_bytes_limited(
    client: &Client,
    url: Url,
    allow_private: bool,
) -> Result<Bytes, NetError> {
    read_limited(get_limited(client, url, allow_private).await?).await
}

pub async fn prewarm_connection(client: Client, url: Url, allow_private: bool) {
    if validate_url(&url, allow_private).is_err() {
        return;
    }
    let _ = client.head(url).send().await;
}

pub fn trace_response_version(label: &str, url: &Url, response: &Response) {
    if std::env::var_os("HIFI_TRACE_HTTP").is_some() {
        eprintln!(
            "hifi: trace: {label} {} {:?}",
            url.as_str(),
            response.version()
        );
    }
}

pub fn is_private_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => {
            ip.is_private()
                || ip.is_loopback()
                || ip.is_link_local()
                || ip.is_broadcast()
                || ip.is_documentation()
                || ip.octets()[0] == 0
                || ip.octets()[0] >= 224
        }
        IpAddr::V6(ip) => {
            ip.is_loopback()
                || ip.is_unspecified()
                || ip.is_unique_local()
                || ip.is_unicast_link_local()
                || ip.segments()[0] & 0xffc0 == 0xff80
        }
    }
}

fn is_local_name(name: &str) -> bool {
    let name = name.trim_end_matches('.').to_ascii_lowercase();
    name == "localhost" || name.ends_with(".localhost") || name.ends_with(".local")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn blocks_private_and_local_urls_by_default() {
        let private = Url::parse("http://169.254.169.254/latest").unwrap();
        let localhost = Url::parse("http://localhost:3000").unwrap();
        let public = Url::parse("https://example.com").unwrap();

        assert!(validate_url(&private, false).is_err());
        assert!(validate_url(&localhost, false).is_err());
        assert!(validate_url(&public, false).is_ok());
        assert!(validate_url(&private, true).is_ok());
    }
}
