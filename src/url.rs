use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::{
    borrow::Cow,
    error, fmt,
    hash::{Hash, Hasher},
    net::{Ipv4Addr, Ipv6Addr},
    ops::Range,
    str::FromStr,
};

#[derive(Clone, Debug, Eq)]
pub struct Url {
    raw: String,
    parts: Parts,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct Parts {
    scheme: Range<usize>,
    host: Option<Range<usize>>,
    port: Option<Port>,
    path: Range<usize>,
    query: Option<Range<usize>>,
    fragment: Option<Range<usize>>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct Port {
    value: u16,
    range: Range<usize>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Host<'a> {
    Domain(&'a str),
    Ipv4(Ipv4Addr),
    Ipv6(Ipv6Addr),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ParseError {
    EmptyHost,
    InvalidPort,
    InvalidIpv6Address,
    RelativeUrlWithoutBase,
    RelativeUrlWithCannotBeABaseBase,
    SetHostOnCannotBeABaseUrl,
    InvalidIpv4Address,
    InvalidDomainCharacter,
    IdnaError,
    MissingScheme,
    InvalidScheme,
}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::EmptyHost => "empty host",
            Self::InvalidPort => "invalid port",
            Self::InvalidIpv6Address => "invalid IPv6 address",
            Self::RelativeUrlWithoutBase => "relative URL without a base",
            Self::RelativeUrlWithCannotBeABaseBase => "relative URL with cannot-be-a-base base",
            Self::SetHostOnCannotBeABaseUrl => "cannot set host on cannot-be-a-base URL",
            Self::InvalidIpv4Address => "invalid IPv4 address",
            Self::InvalidDomainCharacter => "invalid domain character",
            Self::IdnaError => "IDNA error",
            Self::MissingScheme => "missing scheme",
            Self::InvalidScheme => "invalid scheme",
        })
    }
}

impl error::Error for ParseError {}

impl Url {
    pub fn parse(input: &str) -> Result<Self, ParseError> {
        if input.is_ascii() {
            parse_ascii(input)
        } else {
            parse_ascii(&encode_non_ascii(input))
        }
    }

    pub fn join(&self, input: &str) -> Result<Self, ParseError> {
        if has_scheme(input) {
            return Self::parse(input);
        }

        let mut rest = input;
        let mut fragment = None;
        if let Some(idx) = rest.find('#') {
            fragment = Some(&rest[idx + 1..]);
            rest = &rest[..idx];
        }

        let mut query = None;
        if let Some(idx) = rest.find('?') {
            query = Some(&rest[idx + 1..]);
            rest = &rest[..idx];
        }

        let mut out = String::new();
        out.push_str(self.scheme());
        out.push(':');

        if let Some(stripped) = rest.strip_prefix("//") {
            out.push_str("//");
            out.push_str(stripped);
            if let Some(query) = query {
                out.push('?');
                out.push_str(query);
            }
            if let Some(fragment) = fragment {
                out.push('#');
                out.push_str(fragment);
            }
            return Self::parse(&out);
        }

        if let Some(authority) = self.serialized_authority() {
            out.push_str("//");
            out.push_str(authority);
        }

        let path = if rest.is_empty() {
            self.path().to_string()
        } else if rest.starts_with('/') {
            remove_dot_segments(rest)
        } else {
            let base = self.path();
            let base_dir = match base.rfind('/') {
                Some(idx) => &base[..idx + 1],
                None => "",
            };
            remove_dot_segments(&format!("{base_dir}{rest}"))
        };
        out.push_str(if path.is_empty() { "/" } else { &path });
        if let Some(query) = query.or_else(|| rest.is_empty().then(|| self.query()).flatten()) {
            out.push('?');
            out.push_str(query);
        }
        if let Some(fragment) = fragment {
            out.push('#');
            out.push_str(fragment);
        }
        Self::parse(&out)
    }

    pub fn as_str(&self) -> &str {
        &self.raw
    }

    pub fn scheme(&self) -> &str {
        &self.raw[self.parts.scheme.clone()]
    }

    pub fn host_str(&self) -> Option<&str> {
        self.parts.host.clone().map(|range| &self.raw[range])
    }

    pub fn host(&self) -> Option<Host<'_>> {
        let host = self.host_str()?;
        if let Some(inner) = host.strip_prefix('[').and_then(|s| s.strip_suffix(']')) {
            if let Ok(ip) = inner.parse::<Ipv6Addr>() {
                return Some(Host::Ipv6(ip));
            }
        }
        if let Ok(ip) = host.parse::<Ipv4Addr>() {
            return Some(Host::Ipv4(ip));
        }
        if let Ok(ip) = host.parse::<Ipv6Addr>() {
            return Some(Host::Ipv6(ip));
        }
        Some(Host::Domain(host))
    }

    pub fn port(&self) -> Option<u16> {
        self.parts.port.as_ref().map(|port| port.value)
    }

    pub fn port_or_known_default(&self) -> Option<u16> {
        self.port().or_else(|| match self.scheme() {
            "http" => Some(80),
            "https" => Some(443),
            _ => None,
        })
    }

    pub fn path(&self) -> &str {
        &self.raw[self.parts.path.clone()]
    }

    pub fn query(&self) -> Option<&str> {
        self.parts.query.clone().map(|range| &self.raw[range])
    }

    pub fn fragment(&self) -> Option<&str> {
        self.parts.fragment.clone().map(|range| &self.raw[range])
    }

    pub fn set_path(&mut self, path: &str) {
        let query = self.query().map(str::to_owned);
        let fragment = self.fragment().map(str::to_owned);
        self.rebuild(path, query.as_deref(), fragment.as_deref());
    }

    pub fn set_query(&mut self, query: Option<&str>) {
        let path = self.path().to_owned();
        let fragment = self.fragment().map(str::to_owned);
        self.rebuild(&path, query, fragment.as_deref());
    }

    pub fn set_fragment(&mut self, fragment: Option<&str>) {
        let path = self.path().to_owned();
        let query = self.query().map(str::to_owned);
        self.rebuild(&path, query.as_deref(), fragment);
    }

    pub fn query_pairs(&self) -> QueryPairs<'_> {
        QueryPairs {
            query: self.query(),
            offset: 0,
        }
    }

    fn serialized_authority(&self) -> Option<&str> {
        self.parts.host.as_ref()?;
        Some(&self.raw[self.parts.scheme.end + 3..self.parts.path.start])
    }

    fn rebuild(&mut self, path: &str, query: Option<&str>, fragment: Option<&str>) {
        let mut raw = String::new();
        raw.push_str(self.scheme());
        raw.push(':');
        if let Some(authority) = self.serialized_authority() {
            raw.push_str("//");
            raw.push_str(authority);
        }
        raw.push_str(if path.is_empty() { "/" } else { path });
        if let Some(query) = query {
            raw.push('?');
            raw.push_str(query);
        }
        if let Some(fragment) = fragment {
            raw.push('#');
            raw.push_str(fragment);
        }
        *self = Self::parse(&raw).expect("rebuilt URL remains valid");
    }
}

impl PartialEq for Url {
    fn eq(&self, other: &Self) -> bool {
        self.raw == other.raw
    }
}

impl Hash for Url {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.raw.hash(state);
    }
}

impl fmt::Display for Url {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.raw)
    }
}

impl FromStr for Url {
    type Err = ParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::parse(s)
    }
}

impl Serialize for Url {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for Url {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let raw = String::deserialize(deserializer)?;
        Self::parse(&raw).map_err(serde::de::Error::custom)
    }
}

pub struct QueryPairs<'a> {
    query: Option<&'a str>,
    offset: usize,
}

impl<'a> Iterator for QueryPairs<'a> {
    type Item = (Cow<'a, str>, Cow<'a, str>);

    fn next(&mut self) -> Option<Self::Item> {
        let query = self.query?;
        if self.offset > query.len() {
            return None;
        }
        let tail = &query[self.offset..];
        let (field, next_offset) = match tail.find('&') {
            Some(idx) => (&tail[..idx], self.offset + idx + 1),
            None => (tail, query.len() + 1),
        };
        self.offset = next_offset;
        let (key, value) = field.split_once('=').unwrap_or((field, ""));
        Some((decode_query_component(key), decode_query_component(value)))
    }
}

fn parse_ascii(input: &str) -> Result<Url, ParseError> {
    let scheme_end = input.find(':').ok_or(ParseError::MissingScheme)?;
    let scheme = &input[..scheme_end];
    if !valid_scheme(scheme) {
        return Err(ParseError::InvalidScheme);
    }

    let scheme_lower = scheme.to_ascii_lowercase();
    let mut raw = String::with_capacity(input.len());
    raw.push_str(&scheme_lower);
    raw.push(':');

    let mut rest = &input[scheme_end + 1..];
    let mut host = None;
    let mut port = None;

    if rest.starts_with("//") {
        rest = &rest[2..];
        let authority_end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
        let authority = &rest[..authority_end];
        rest = &rest[authority_end..];
        let (userinfo, authority) = authority
            .rsplit_once('@')
            .map(|(userinfo, host)| (Some(userinfo), host))
            .unwrap_or((None, authority));
        if authority.is_empty() {
            return Err(ParseError::EmptyHost);
        }

        raw.push_str("//");
        if let Some(userinfo) = userinfo {
            raw.push_str(userinfo);
            raw.push('@');
        }
        let host_start = raw.len();
        let (host_raw, parsed_port, bracketed) = split_host_port(authority)?;
        if host_raw.is_empty() {
            return Err(ParseError::EmptyHost);
        }
        if bracketed {
            host_raw
                .parse::<Ipv6Addr>()
                .map_err(|_| ParseError::InvalidIpv6Address)?;
            raw.push('[');
            raw.push_str(&host_raw.to_ascii_lowercase());
            raw.push(']');
            host = Some(host_start..host_start + host_raw.len() + 2);
        } else {
            validate_domain(host_raw)?;
            raw.push_str(&host_raw.to_ascii_lowercase());
            host = Some(host_start..host_start + host_raw.len());
        }

        if let Some(value) = parsed_port {
            if !is_default_port(&scheme_lower, value) {
                let port_start = raw.len() + 1;
                raw.push(':');
                raw.push_str(&value.to_string());
                port = Some(Port {
                    value,
                    range: port_start..raw.len(),
                });
            }
        }
    } else if matches!(scheme_lower.as_str(), "http" | "https") {
        return Err(ParseError::EmptyHost);
    }

    let mut fragment = None;
    if let Some(idx) = rest.find('#') {
        fragment = Some(&rest[idx + 1..]);
        rest = &rest[..idx];
    }

    let mut query = None;
    if let Some(idx) = rest.find('?') {
        query = Some(&rest[idx + 1..]);
        rest = &rest[..idx];
    }

    let path_start = raw.len();
    if rest.is_empty() && host.is_some() {
        raw.push('/');
    } else if host.is_some() {
        raw.push_str(&remove_dot_segments(rest));
    } else {
        raw.push_str(rest);
    }
    let path = path_start..raw.len();

    let query = query.map(|query| {
        raw.push('?');
        let start = raw.len();
        raw.push_str(query);
        start..raw.len()
    });

    let fragment = fragment.map(|fragment| {
        raw.push('#');
        let start = raw.len();
        raw.push_str(fragment);
        start..raw.len()
    });

    Ok(Url {
        raw,
        parts: Parts {
            scheme: 0..scheme_lower.len(),
            host,
            port,
            path,
            query,
            fragment,
        },
    })
}

fn split_host_port(authority: &str) -> Result<(&str, Option<u16>, bool), ParseError> {
    if let Some(rest) = authority.strip_prefix('[') {
        let end = rest.find(']').ok_or(ParseError::InvalidIpv6Address)?;
        let host = &rest[..end];
        let after = &rest[end + 1..];
        let port = if after.is_empty() {
            None
        } else {
            let raw_port = after.strip_prefix(':').ok_or(ParseError::InvalidPort)?;
            Some(parse_port(raw_port)?)
        };
        return Ok((host, port, true));
    }

    if authority.matches(':').count() == 1 {
        let (host, raw_port) = authority.rsplit_once(':').expect("one colon");
        if !raw_port.is_empty() && raw_port.bytes().all(|b| b.is_ascii_digit()) {
            return Ok((host, Some(parse_port(raw_port)?), false));
        }
    }
    Ok((authority, None, false))
}

fn parse_port(raw: &str) -> Result<u16, ParseError> {
    if raw.is_empty() {
        return Err(ParseError::InvalidPort);
    }
    raw.parse::<u16>().map_err(|_| ParseError::InvalidPort)
}

fn valid_scheme(scheme: &str) -> bool {
    let mut bytes = scheme.bytes();
    matches!(bytes.next(), Some(b'a'..=b'z' | b'A'..=b'Z'))
        && bytes.all(|b| b.is_ascii_alphanumeric() || matches!(b, b'+' | b'-' | b'.'))
}

fn has_scheme(input: &str) -> bool {
    match input.find(':') {
        Some(idx) => valid_scheme(&input[..idx]),
        None => false,
    }
}

fn validate_domain(host: &str) -> Result<(), ParseError> {
    if host.bytes().any(|b| {
        matches!(
            b,
            0x00..=0x20
                | b'"'
                | b'#'
                | b'%'
                | b'/'
                | b':'
                | b'<'
                | b'>'
                | b'?'
                | b'@'
                | b'['
                | b'\\'
                | b']'
                | b'^'
                | b'|'
                | 0x7f
        )
    }) {
        return Err(ParseError::InvalidDomainCharacter);
    }
    Ok(())
}

fn is_default_port(scheme: &str, port: u16) -> bool {
    (scheme == "http" && port == 80) || (scheme == "https" && port == 443)
}

fn remove_dot_segments(path: &str) -> String {
    let absolute = path.starts_with('/');
    let trailing = path.ends_with('/') || path.ends_with("/.") || path.ends_with("/..");
    let mut stack: Vec<&str> = Vec::new();
    for part in path.split('/') {
        match part {
            "" | "." => {}
            ".." => {
                stack.pop();
            }
            _ => stack.push(part),
        }
    }
    let mut out = String::new();
    if absolute {
        out.push('/');
    }
    out.push_str(&stack.join("/"));
    if trailing && !out.ends_with('/') {
        out.push('/');
    }
    if out.is_empty() && absolute {
        out.push('/');
    }
    out
}

fn decode_query_component(input: &str) -> Cow<'_, str> {
    if !input.as_bytes().iter().any(|&b| b == b'%' || b == b'+') {
        return Cow::Borrowed(input);
    }
    let mut out = Vec::with_capacity(input.len());
    let bytes = input.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'+' => {
                out.push(b' ');
                i += 1;
            }
            b'%' if i + 2 < bytes.len() => {
                if let (Some(hi), Some(lo)) = (hex(bytes[i + 1]), hex(bytes[i + 2])) {
                    out.push((hi << 4) | lo);
                    i += 3;
                } else {
                    out.push(bytes[i]);
                    i += 1;
                }
            }
            b => {
                out.push(b);
                i += 1;
            }
        }
    }
    match String::from_utf8(out) {
        Ok(decoded) => Cow::Owned(decoded),
        Err(_) => Cow::Borrowed(input),
    }
}

fn hex(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

fn encode_non_ascii(input: &str) -> String {
    let Some(scheme_end) = input.find(':') else {
        return encode_non_ascii_component(input);
    };
    let mut out = String::with_capacity(input.len());
    out.push_str(&input[..scheme_end + 1]);
    let mut rest = &input[scheme_end + 1..];
    if let Some(after_slashes) = rest.strip_prefix("//") {
        out.push_str("//");
        let authority_end = after_slashes
            .find(['/', '?', '#'])
            .unwrap_or(after_slashes.len());
        let authority = &after_slashes[..authority_end];
        let (userinfo, host_port) = authority
            .rsplit_once('@')
            .map(|(userinfo, host)| (Some(userinfo), host))
            .unwrap_or((None, authority));
        if let Some(userinfo) = userinfo {
            out.push_str(&encode_non_ascii_component(userinfo));
            out.push('@');
        }
        match split_host_port(host_port) {
            Ok((host, port, bracketed)) if !bracketed => {
                let ascii_host = if host.is_ascii() {
                    host.to_string()
                } else {
                    encode_non_ascii_component(host)
                };
                out.push_str(&ascii_host);
                if let Some(port) = port {
                    out.push(':');
                    out.push_str(&port.to_string());
                }
            }
            _ => out.push_str(host_port),
        }
        rest = &after_slashes[authority_end..];
    }
    out.push_str(&encode_non_ascii_component(rest));
    out
}

fn encode_non_ascii_component(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    for ch in input.chars() {
        if ch.is_ascii() {
            out.push(ch);
        } else {
            let mut buf = [0u8; 4];
            for byte in ch.encode_utf8(&mut buf).bytes() {
                out.push('%');
                out.push_str(&format!("{byte:02X}"));
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_and_normalizes_http_urls() {
        let url = Url::parse("HTTPS://User:Pass@Example.COM:443/a/b?x=1#top").unwrap();
        assert_eq!(url.as_str(), "https://User:Pass@example.com/a/b?x=1#top");
        assert_eq!(url.scheme(), "https");
        assert_eq!(url.host_str(), Some("example.com"));
        assert_eq!(url.port(), None);
        assert_eq!(url.port_or_known_default(), Some(443));
        assert_eq!(url.path(), "/a/b");
        assert_eq!(url.query(), Some("x=1"));
        assert_eq!(url.fragment(), Some("top"));
    }

    #[test]
    fn joins_relative_paths() {
        let base = Url::parse("https://example.com/a/b/c?old=1#frag").unwrap();
        assert_eq!(
            base.join("../d.js?x=1").unwrap().as_str(),
            "https://example.com/a/d.js?x=1"
        );
        assert_eq!(
            base.join("/root").unwrap().as_str(),
            "https://example.com/root"
        );
        assert_eq!(
            base.join("?new=1").unwrap().as_str(),
            "https://example.com/a/b/c?new=1"
        );
        assert_eq!(
            base.join("#next").unwrap().as_str(),
            "https://example.com/a/b/c?old=1#next"
        );
    }

    #[test]
    fn handles_ipv6_hosts() {
        let url = Url::parse("http://[::1]:8080/").unwrap();
        assert_eq!(url.host_str(), Some("[::1]"));
        assert_eq!(url.host(), Some(Host::Ipv6(Ipv6Addr::LOCALHOST)));
        assert_eq!(url.port(), Some(8080));
        assert_eq!(url.as_str(), "http://[::1]:8080/");
    }

    #[test]
    fn decodes_query_pairs() {
        let url = Url::parse("https://example.com/?a=b+c&x=%7B1%7D").unwrap();
        let pairs = url.query_pairs().collect::<Vec<_>>();
        assert_eq!(
            pairs[0],
            (Cow::Borrowed("a"), Cow::Owned("b c".to_string()))
        );
        assert_eq!(
            pairs[1],
            (Cow::Borrowed("x"), Cow::Owned("{1}".to_string()))
        );
    }
}
