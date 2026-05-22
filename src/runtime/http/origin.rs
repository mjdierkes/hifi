use super::Error;
use crate::hash::FxHashMap;
use crate::url::Url;
use std::{
    io,
    net::SocketAddr,
    sync::OnceLock,
    time::{Duration, Instant},
};
use tokio::{net::TcpStream, sync::Mutex};

const DNS_TTL: Duration = Duration::from_secs(5);

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub(super) struct Origin {
    pub(super) scheme: String,
    pub(super) host: String,
    pub(super) port: u16,
}

impl Origin {
    pub(super) fn for_url(url: &Url) -> Result<Self, Error> {
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

    pub(super) fn authority(&self) -> String {
        let default_port = (self.scheme == "https" && self.port == 443)
            || (self.scheme == "http" && self.port == 80);
        if default_port {
            self.host.clone()
        } else {
            format!("{}:{}", self.host, self.port)
        }
    }
}

#[derive(Clone, Copy)]
struct DnsEntry {
    addr: SocketAddr,
    expires_at: Instant,
}

fn dns_cache() -> &'static Mutex<FxHashMap<(String, u16), DnsEntry>> {
    static CACHE: OnceLock<Mutex<FxHashMap<(String, u16), DnsEntry>>> = OnceLock::new();
    CACHE.get_or_init(|| Mutex::new(FxHashMap::default()))
}

pub(super) async fn connect_tcp(origin: &Origin) -> Result<TcpStream, Error> {
    let key = (origin.host.clone(), origin.port);
    if let Some(addr) = cached_addr(&key).await {
        match TcpStream::connect(addr).await {
            Ok(stream) => {
                stream.set_nodelay(true)?;
                return Ok(stream);
            }
            Err(_) => {
                dns_cache().lock().await.remove(&key);
            }
        }
    }

    let mut last_err = None;
    let addrs = tokio::net::lookup_host((origin.host.as_str(), origin.port)).await?;
    for addr in addrs {
        match TcpStream::connect(addr).await {
            Ok(stream) => {
                stream.set_nodelay(true)?;
                dns_cache().lock().await.insert(
                    key,
                    DnsEntry {
                        addr,
                        expires_at: Instant::now() + DNS_TTL,
                    },
                );
                return Ok(stream);
            }
            Err(err) => last_err = Some(err),
        }
    }
    Err(last_err
        .unwrap_or_else(|| io::Error::new(io::ErrorKind::NotFound, "DNS returned no addresses"))
        .into())
}

async fn cached_addr(key: &(String, u16)) -> Option<SocketAddr> {
    let now = Instant::now();
    let mut cache = dns_cache().lock().await;
    let entry = cache.get(key).copied()?;
    if entry.expires_at > now {
        Some(entry.addr)
    } else {
        cache.remove(key);
        None
    }
}
