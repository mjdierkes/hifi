use super::backpressure::Backpressure;
use super::error::Error;
use super::h2::{connect_h2, H2Session};
use super::http1;
use super::origin::Origin;
use super::request::Request;
use super::response::{Response, Version};
use crate::hash::FxHashMap;
use crate::url::Url;
use rustls::{client::Resumption, RootCertStore};
use std::{fmt, sync::Arc};
use tokio::sync::Mutex as AsyncMutex;
use tokio_rustls::TlsConnector;

#[derive(Clone)]
pub struct Client {
    pub(crate) inner: Arc<ClientInner>,
}

pub(crate) struct ClientInner {
    pub tls_h2: TlsConnector,
    pub default_headers: Vec<(String, String)>,
    pub h2: AsyncMutex<FxHashMap<Origin, Arc<H2Session>>>,
    pub http1_pool: http1::Pool,
    pub backpressure: Arc<Backpressure>,
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
        let _ = self.h2_session(origin).await?;
        Ok(())
    }

    pub(crate) async fn execute(
        &self,
        url: Url,
        headers: Vec<(String, String)>,
    ) -> Result<Response, Error> {
        match url.scheme() {
            "https" => self.execute_https(url, headers).await,
            "http" => self.execute_http1(url, headers).await,
            other => Err(Error::BadScheme(other.to_string())),
        }
    }

    async fn execute_http1(
        &self,
        url: Url,
        headers: Vec<(String, String)>,
    ) -> Result<Response, Error> {
        self.inner
            .http1_pool
            .execute(url, headers, &self.inner.default_headers)
            .await
    }

    async fn execute_https(
        &self,
        url: Url,
        headers: Vec<(String, String)>,
    ) -> Result<Response, Error> {
        let origin = Origin::for_url(&url)?;
        let session = self.h2_session(origin.clone()).await?;
        match session
            .request(url, headers, &self.inner.default_headers)
            .await
        {
            Ok(response) => Ok(response),
            Err(err) => {
                let mut sessions = self.inner.h2.lock().await;
                sessions.remove(&origin);
                Err(err)
            }
        }
    }

    async fn h2_session(&self, origin: Origin) -> Result<Arc<H2Session>, Error> {
        if let Some(session) = self.inner.h2.lock().await.get(&origin).cloned() {
            return Ok(session);
        }
        let session = connect_h2(
            origin.clone(),
            self.inner.tls_h2.clone(),
            self.inner.backpressure.clone(),
        )
        .await?;
        let mut sessions = self.inner.h2.lock().await;
        Ok(sessions.entry(origin).or_insert(session).clone())
    }

    pub fn backpressure(&self) -> Arc<Backpressure> {
        self.inner.backpressure.clone()
    }
}

impl Default for Client {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Debug for Client {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Client").finish_non_exhaustive()
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
                h2: AsyncMutex::new(FxHashMap::default()),
                http1_pool: http1::Pool::default(),
                backpressure: Arc::new(Backpressure::default()),
            }),
        }
    }
}
