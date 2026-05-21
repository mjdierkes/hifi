use crate::scan::next::NextConfig;
use serde::{Deserialize, Serialize};
use url::Url;

pub mod next;

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "kind", content = "config")]
pub enum FrameworkConfig {
    #[default]
    None,
    Next(NextConfig),
}

impl FrameworkConfig {
    pub fn is_none(&self) -> bool {
        matches!(self, Self::None)
    }

    pub fn as_next(&self) -> Option<&NextConfig> {
        match self {
            Self::Next(config) => Some(config),
            Self::None => None,
        }
    }
}

impl From<Option<NextConfig>> for FrameworkConfig {
    fn from(value: Option<NextConfig>) -> Self {
        value.map(Self::Next).unwrap_or_default()
    }
}

pub fn request_headers(url: &Url) -> Vec<(&'static str, &'static str)> {
    if next::is_rsc_payload(url) {
        vec![("RSC", "1")]
    } else {
        Vec::new()
    }
}
