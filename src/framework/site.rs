use crate::framework::next::NextConfig;
use crate::generated::{ASTRO_IS_CONTEXT_MARKERS, REMIX_IS_CONTEXT_MARKERS};
use crate::source;
use crate::url::Url;

use super::{next, nuxt, sveltekit};

pub(crate) fn is_astro_context(bytes: &[u8], base: &Url) -> bool {
    base.path().contains("/_astro/")
        || base.path().contains("/_actions/")
        || source::bytes_contain_any_str(bytes, ASTRO_IS_CONTEXT_MARKERS)
}

pub(crate) fn is_remix_context(bytes: &[u8], base: &Url) -> bool {
    base.path().contains("/build/")
        || base.query().is_some_and(|q| q.contains("_data="))
        || source::bytes_contain_any_str(bytes, REMIX_IS_CONTEXT_MARKERS)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash, PartialOrd, Ord)]
pub enum FrameworkId {
    Next,
    Nuxt,
    SvelteKit,
    Astro,
    Remix,
}

impl FrameworkId {
    pub const ALL: [Self; 5] = [
        Self::Next,
        Self::Nuxt,
        Self::SvelteKit,
        Self::Astro,
        Self::Remix,
    ];

    pub fn index(self) -> usize {
        match self {
            Self::Next => 0,
            Self::Nuxt => 1,
            Self::SvelteKit => 2,
            Self::Astro => 3,
            Self::Remix => 4,
        }
    }

    pub fn name(self) -> &'static str {
        match self {
            Self::Next => "Next.js",
            Self::Nuxt => "Nuxt",
            Self::SvelteKit => "SvelteKit",
            Self::Astro => "Astro",
            Self::Remix => "Remix",
        }
    }
}

#[derive(Clone, Debug)]
pub struct DetectedSite {
    pub active: [bool; 5],
    pub primary: FrameworkId,
    pub next: Option<NextConfig>,
    pub sveltekit_immutable_root: Option<String>,
}

impl Default for DetectedSite {
    fn default() -> Self {
        Self {
            active: [false; 5],
            primary: FrameworkId::Next,
            next: None,
            sveltekit_immutable_root: None,
        }
    }
}

impl DetectedSite {
    pub fn detect(bytes: &[u8], base: &Url, next_config: Option<&NextConfig>) -> Self {
        let next_active = next::is_context(bytes, base, next_config);
        let nuxt = nuxt::is_context(bytes, base);
        let sveltekit = sveltekit::is_context(bytes, base);
        let astro = is_astro_context(bytes, base);
        let remix = is_remix_context(bytes, base);
        let active = [next_active, nuxt, sveltekit, astro, remix];
        let primary = if next_active {
            FrameworkId::Next
        } else if nuxt {
            FrameworkId::Nuxt
        } else if sveltekit {
            FrameworkId::SvelteKit
        } else if astro {
            FrameworkId::Astro
        } else if remix {
            FrameworkId::Remix
        } else {
            FrameworkId::Next
        };
        Self {
            active,
            primary,
            next: next_config.cloned().or_else(|| next_active.then(NextConfig::default)),
            sveltekit_immutable_root: sveltekit
                .then(|| sveltekit::primary_immutable_root(bytes, base))
                .flatten(),
        }
    }

    pub fn has(&self, id: FrameworkId) -> bool {
        self.active[id.index()]
    }

    pub fn label(&self) -> Option<String> {
        if !self.active.iter().any(|&v| v) {
            return None;
        }
        Some(match self.primary {
            FrameworkId::Next => match self.next.as_ref().and_then(|c| c.build_id.as_deref()) {
                Some(build) if !build.is_empty() => format!("Next.js (build {build})"),
                _ => "Next.js".to_string(),
            },
            id => id.name().to_string(),
        })
    }
}
