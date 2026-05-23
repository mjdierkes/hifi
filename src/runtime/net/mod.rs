//! Network policy and bounded response reads.

mod fetch;

pub use fetch::{
    fetch, fetch_bytes, get_bytes_limited, get_limited, read_limited, FetchOptions,
};

use crate::runtime::http::Response;
use crate::url::{Host, Url};
use std::{fmt, io, net::IpAddr};

pub const MAX_RESPONSE_BYTES: u64 = 50 * 1024 * 1024;
pub const MAX_REDIRECTS: usize = 10;

#[derive(Debug)]
pub enum NetError {
    BadScheme(String),
    PrivateAddress(String),
    ResponseTooLarge { actual: u64, limit: u64 },
    Resolve(String, io::Error),
    TooManyRedirects(String),
    Http(crate::runtime::http::Error),
}

impl fmt::Display for NetError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BadScheme(s) => write!(f, "unsupported URL scheme '{s}'"),
            Self::PrivateAddress(u) => write!(
                f,
                "private or local addresses are blocked for '{u}' (set HIFI_ALLOW_PRIVATE=1 to allow)"
            ),
            Self::ResponseTooLarge { actual, limit } => {
                write!(f, "response too large: {actual} bytes exceeds {limit} bytes")
            }
            Self::Resolve(u, e) => write!(f, "failed to resolve '{u}': {e}"),
            Self::TooManyRedirects(u) => write!(f, "too many redirects for '{u}'"),
            Self::Http(e) => e.fmt(f),
        }
    }
}

impl std::error::Error for NetError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Resolve(_, e) => Some(e),
            Self::Http(e) => Some(e),
            _ => None,
        }
    }
}

impl From<crate::runtime::http::Error> for NetError {
    fn from(e: crate::runtime::http::Error) -> Self {
        Self::Http(e)
    }
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

pub async fn validate_request_url(url: &Url, allow_private: bool) -> Result<(), NetError> {
    validate_url(url, allow_private)?;
    if allow_private {
        return Ok(());
    }

    let Some(Host::Domain(host)) = url.host() else {
        return Ok(());
    };
    let port = url.port_or_known_default().unwrap_or(80);
    let addrs = tokio::net::lookup_host((host, port))
        .await
        .map_err(|e| NetError::Resolve(url.to_string(), e))?;
    for addr in addrs {
        if is_private_ip(addr.ip()) {
            return Err(NetError::PrivateAddress(url.to_string()));
        }
    }
    Ok(())
}

pub fn redirect_target(response: &Response) -> Option<Url> {
    let location = response.header("location")?;
    response.url().join(location).ok()
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
