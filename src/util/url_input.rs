use crate::url::Url;

pub fn normalize_url(url: &str) -> Result<String, crate::url::ParseError> {
    if url.contains("://") {
        let parsed = Url::parse(url)?;
        if !matches!(parsed.scheme(), "http" | "https") {
            return Err(crate::url::ParseError::InvalidScheme);
        }
        Ok(parsed.to_string())
    } else {
        Ok(Url::parse(&format!("https://{url}"))?.to_string())
    }
}
