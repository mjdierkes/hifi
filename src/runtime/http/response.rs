use super::headers::Headers;
use crate::runtime::bytes::HiBytes;
use crate::url::Url;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Version {
    Http11,
    Http2,
}

pub struct Response {
    pub(crate) status: u16,
    pub(crate) version: Version,
    pub(crate) url: Url,
    pub(crate) headers: Headers,
    pub(crate) body: HiBytes,
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

    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers.get(name)
    }

    pub fn content_length(&self) -> Option<u64> {
        self.header("content-length")?.parse().ok()
    }

    pub fn body(self) -> HiBytes {
        self.body
    }
}
