use super::AppError;
use crate::runtime::cache::CACHE_FRESH_SECS;
use crate::runtime::config::RuntimeConfig;
use crate::runtime::net;
use reqwest::header::{HeaderMap, HeaderValue};
use reqwest::Client;
use std::time::Duration;

// Many CDNs (notably Cloudflare) block obvious bot UAs with 403 before we ever
// see the page. hifi crawls publicly-served content the way a browser does, so
// presenting as one removes a class of "site unreachable" failures.
const DEFAULT_USER_AGENT: &str = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) \
    AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36";

pub fn runtime_client() -> Result<(RuntimeConfig, Client), AppError> {
    let config = RuntimeConfig::from_env();
    let client = make_client(config)?;
    Ok((config, client))
}

fn make_client(config: RuntimeConfig) -> reqwest::Result<Client> {
    Client::builder()
        .pool_max_idle_per_host(config.chunk_concurrency)
        .pool_idle_timeout(Duration::from_secs(CACHE_FRESH_SECS))
        .tcp_keepalive(Duration::from_secs(30))
        .connect_timeout(Duration::from_secs(5))
        .timeout(Duration::from_secs(12))
        .redirect(reqwest::redirect::Policy::custom(move |attempt| {
            if net::validate_url(attempt.url(), config.allow_private).is_ok() {
                attempt.follow()
            } else {
                attempt.error("blocked redirect to private or unsupported URL")
            }
        }))
        .user_agent(DEFAULT_USER_AGENT)
        .default_headers(browser_default_headers())
        .build()
}

// Cloudflare bot-management 403s any request that looks programmatic; UA alone
// isn't enough. Real browsers always send Accept, Accept-Language, and the
// Sec-Fetch-* hints; sending the same set lets us through without TLS
// fingerprinting tricks.
fn browser_default_headers() -> HeaderMap {
    let mut headers = HeaderMap::new();
    headers.insert(
        reqwest::header::ACCEPT,
        HeaderValue::from_static(
            "text/html,application/xhtml+xml,application/xml;q=0.9,\
             image/avif,image/webp,*/*;q=0.8",
        ),
    );
    headers.insert(
        reqwest::header::ACCEPT_LANGUAGE,
        HeaderValue::from_static("en-US,en;q=0.9"),
    );
    headers.insert("Sec-Fetch-Site", HeaderValue::from_static("none"));
    headers.insert("Sec-Fetch-Mode", HeaderValue::from_static("navigate"));
    headers.insert("Sec-Fetch-User", HeaderValue::from_static("?1"));
    headers.insert("Sec-Fetch-Dest", HeaderValue::from_static("document"));
    headers.insert("Upgrade-Insecure-Requests", HeaderValue::from_static("1"));
    headers
}
