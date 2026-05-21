//! Runtime settings derived from environment variables.
//!
//! Keep env reads here so request handling, daemon state, and network policy can
//! receive explicit values instead of reaching back into process-global state.

const DEFAULT_CHUNK_CONCURRENCY: usize = 32;
const HARD_MAX_CHUNK_CONCURRENCY: usize = 128;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RuntimeConfig {
    pub chunk_concurrency: usize,
    pub allow_private: bool,
}

impl RuntimeConfig {
    pub fn from_env() -> Self {
        Self {
            chunk_concurrency: chunk_concurrency_from_env(),
            allow_private: allow_private_from_env(),
        }
    }
}

fn chunk_concurrency_from_env() -> usize {
    std::env::var("HIFI_CHUNK_CONCURRENCY")
        .ok()
        .and_then(|v| v.parse::<usize>().ok())
        .filter(|v| *v > 0)
        .map(|v| v.min(HARD_MAX_CHUNK_CONCURRENCY))
        .unwrap_or(DEFAULT_CHUNK_CONCURRENCY)
}

fn allow_private_from_env() -> bool {
    std::env::var("HIFI_ALLOW_PRIVATE")
        .map(|v| matches!(v.as_str(), "1" | "true" | "TRUE" | "yes" | "YES"))
        .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_config_is_conservative() {
        let config = RuntimeConfig {
            chunk_concurrency: DEFAULT_CHUNK_CONCURRENCY,
            allow_private: false,
        };

        assert_eq!(config.chunk_concurrency, 32);
        assert!(!config.allow_private);
    }
}
