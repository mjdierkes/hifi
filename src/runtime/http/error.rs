use std::{error, fmt, io};

#[derive(Debug)]
pub enum Error {
    BadScheme(String),
    MissingHost,
    BadDnsName(String),
    H2(&'static str),
    H2Code(u32),
    H2Closed,
    BadHttp1,
    Io(io::Error),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BadScheme(scheme) => write!(f, "unsupported URL scheme '{scheme}'"),
            Self::MissingHost => f.write_str("URL has no host"),
            Self::BadDnsName(name) => write!(f, "invalid TLS server name '{name}'"),
            Self::H2(message) => write!(f, "HTTP/2 protocol error: {message}"),
            Self::H2Code(code) => write!(f, "HTTP/2 peer error code {code}"),
            Self::H2Closed => f.write_str("HTTP/2 connection closed"),
            Self::BadHttp1 => f.write_str("HTTP/1.1 response parse error"),
            Self::Io(err) => err.fmt(f),
        }
    }
}

impl error::Error for Error {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        match self {
            Self::Io(err) => Some(err),
            _ => None,
        }
    }
}

impl From<io::Error> for Error {
    fn from(err: io::Error) -> Self {
        Self::Io(err)
    }
}
