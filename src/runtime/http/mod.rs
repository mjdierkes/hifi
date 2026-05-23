//! Small HTTP client tailored to hifi's scanner workload.
//!
//! The client owns just enough HTTP/2 to multiplex many HTTPS GET requests over
//! one TLS connection per origin. Plain HTTP uses HTTP/1.1.

mod backpressure;
mod client;
mod error;
mod h2;
mod headers;
mod hpack;
mod http1;
mod origin;
mod request;
mod response;

pub use backpressure::Backpressure;
pub use client::{Client, ClientBuilder};
pub use error::Error;
pub use headers::Headers;
pub use response::{Response, Version};
