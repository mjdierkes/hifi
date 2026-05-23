use super::{client::Client, Error, Response};
use crate::url::Url;

pub struct Request {
    pub(crate) client: Client,
    pub(crate) url: Url,
    pub(crate) headers: Vec<(String, String)>,
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
