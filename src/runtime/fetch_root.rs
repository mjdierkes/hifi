//! Shared root-document fetch for scan and grep pipelines.

use super::bytes::HiBytes;
use super::http::Client;
use super::net::{self, FetchOptions};

pub struct FetchedDocument {
    pub url: crate::url::Url,
    pub body: HiBytes,
}

pub async fn fetch_root_document(
    client: &Client,
    url: &str,
    allow_private: bool,
) -> Result<FetchedDocument, net::NetError> {
    let base = crate::url::Url::parse(url).map_err(|_| {
        net::NetError::BadScheme("invalid URL".to_string())
    })?;
    let response = net::fetch(client, base, FetchOptions::page(allow_private)).await?;
    let final_url = response.url().clone();
    let body = net::read_limited(response).await?;
    Ok(FetchedDocument {
        url: final_url,
        body,
    })
}
