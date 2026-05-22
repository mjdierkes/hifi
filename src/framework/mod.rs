use crate::scan::next::NextConfig;
use serde::{Deserialize, Serialize};
use url::Url;

pub mod astro;
pub mod next;
pub mod nuxt;
pub mod remix;
pub mod sveltekit;

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "kind", content = "config")]
pub enum FrameworkConfig {
    #[default]
    None,
    Next(NextConfig),
    Nuxt,
    SvelteKit,
    Astro,
    Remix,
}

impl FrameworkConfig {
    pub fn is_none(&self) -> bool {
        matches!(self, Self::None)
    }

    pub fn as_next(&self) -> Option<&NextConfig> {
        match self {
            Self::Next(config) => Some(config),
            _ => None,
        }
    }

    pub fn label(&self) -> Option<String> {
        match self {
            Self::None => None,
            Self::Next(cfg) => Some(match cfg.build_id.as_deref() {
                Some(build) if !build.is_empty() => format!("Next.js (build {build})"),
                _ => "Next.js".to_string(),
            }),
            Self::Nuxt => Some("Nuxt".to_string()),
            Self::SvelteKit => Some("SvelteKit".to_string()),
            Self::Astro => Some("Astro".to_string()),
            Self::Remix => Some("Remix".to_string()),
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
