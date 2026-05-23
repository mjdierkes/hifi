//! Internal scan/runtime errors converted to [`crate::app::AppError`] at the CLI boundary.

use super::net;
use std::fmt;

#[derive(Debug)]
pub enum RuntimeError {
    Net(net::NetError),
    Url(crate::url::ParseError),
    Join(tokio::task::JoinError),
}

impl fmt::Display for RuntimeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Net(err) => err.fmt(f),
            Self::Url(err) => err.fmt(f),
            Self::Join(err) => err.fmt(f),
        }
    }
}

impl std::error::Error for RuntimeError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Net(err) => Some(err),
            Self::Url(err) => Some(err),
            Self::Join(err) => Some(err),
        }
    }
}

impl From<net::NetError> for RuntimeError {
    fn from(err: net::NetError) -> Self {
        Self::Net(err)
    }
}

impl From<crate::url::ParseError> for RuntimeError {
    fn from(err: crate::url::ParseError) -> Self {
        Self::Url(err)
    }
}

impl From<tokio::task::JoinError> for RuntimeError {
    fn from(err: tokio::task::JoinError) -> Self {
        Self::Join(err)
    }
}
