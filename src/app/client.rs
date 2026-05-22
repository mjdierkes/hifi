use super::AppError;
use crate::runtime::config::RuntimeConfig;
use crate::runtime::http::Client;

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

fn make_client(_config: RuntimeConfig) -> Result<Client, crate::runtime::http::Error> {
    Ok(Client::builder()
        .default_headers(browser_default_headers())
        .build())
}

// Cloudflare bot-management 403s any request that looks programmatic; UA alone
// isn't enough. Real browsers always send Accept, Accept-Language, and the
// Sec-Fetch-* hints; sending the same set lets us through without TLS
// fingerprinting tricks.
fn browser_default_headers() -> Vec<(String, String)> {
    vec![
        ("user-agent".into(), DEFAULT_USER_AGENT.into()),
        (
            "accept".into(),
            "text/html,application/xhtml+xml,application/xml;q=0.9,\
             image/avif,image/webp,*/*;q=0.8"
                .into(),
        ),
        ("accept-language".into(), "en-US,en;q=0.9".into()),
        ("sec-fetch-site".into(), "none".into()),
        ("sec-fetch-mode".into(), "navigate".into()),
        ("sec-fetch-user".into(), "?1".into()),
        ("sec-fetch-dest".into(), "document".into()),
        ("upgrade-insecure-requests".into(), "1".into()),
    ]
}
