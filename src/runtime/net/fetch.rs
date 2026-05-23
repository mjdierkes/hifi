//! Unified HTTP fetch with redirect following and size limits.

use crate::runtime::bytes::HiBytes;
use crate::runtime::cache::AssetValidators;
use crate::runtime::http::{Client, Response};
use crate::url::Url;

use super::{redirect_target, validate_request_url, NetError, MAX_REDIRECTS, MAX_RESPONSE_BYTES};

pub struct FetchOptions<'a> {
    pub allow_private: bool,
    pub validators: Option<&'a AssetValidators>,
    pub extra_headers: &'a [(&'static str, &'static str)],
    pub accept_status: fn(u16) -> bool,
}

impl<'a> FetchOptions<'a> {
    pub fn page(allow_private: bool) -> Self {
        Self {
            allow_private,
            validators: None,
            extra_headers: &[],
            accept_status: |s| (200..300).contains(&s),
        }
    }

    pub fn asset(allow_private: bool, validators: Option<&'a AssetValidators>, headers: &'a [(&'static str, &'static str)]) -> Self {
        Self {
            allow_private,
            validators,
            extra_headers: headers,
            accept_status: |s| s == 304 || (200..300).contains(&s),
        }
    }
}

pub async fn fetch(client: &Client, url: Url, opts: FetchOptions<'_>) -> Result<Response, NetError> {
    let mut current = url;
    for _ in 0..MAX_REDIRECTS {
        validate_request_url(&current, opts.allow_private).await?;
        let mut request = client.get(current.clone());
        for (name, value) in opts.extra_headers {
            request = request.header(*name, *value);
        }
        if let Some(validators) = opts.validators {
            if let Some(etag) = &validators.etag {
                request = request.header("if-none-match", etag);
            }
            if let Some(last_modified) = &validators.last_modified {
                request = request.header("if-modified-since", last_modified);
            }
        }
        let response = request.send().await?;
        if response.is_redirection() {
            if let Some(next) = redirect_target(&response) {
                current = next;
                continue;
            }
        }
        if (opts.accept_status)(response.status()) {
            return Ok(response);
        }
        return Err(NetError::Http(crate::runtime::http::Error::H2(
            "HTTP status was not successful",
        )));
    }
    Err(NetError::TooManyRedirects(current.to_string()))
}

pub async fn fetch_bytes(client: &Client, url: Url, opts: FetchOptions<'_>) -> Result<HiBytes, NetError> {
    read_limited(fetch(client, url, opts).await?).await
}

pub async fn read_limited(response: Response) -> Result<HiBytes, NetError> {
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
        crate::runtime::bytes::HiBuf::with_capacity(content_length.unwrap_or(0).min(MAX_RESPONSE_BYTES) as usize);
    let bytes = response.body();
    for chunk in bytes.chunks(16 * 1024) {
        let next_len = body.len() as u64 + chunk.len() as u64;
        if next_len > MAX_RESPONSE_BYTES {
            return Err(NetError::ResponseTooLarge {
                actual: next_len,
                limit: MAX_RESPONSE_BYTES,
            });
        }
        body.extend_from_slice(chunk);
    }
    Ok(body.freeze())
}

pub async fn get_bytes_limited(
    client: &Client,
    url: Url,
    allow_private: bool,
) -> Result<HiBytes, NetError> {
    fetch_bytes(client, url, FetchOptions::page(allow_private)).await
}
