//! A strict, resumable, zero-copy, sans-IO HTTP/1.1 parser.
//!
//! - [`RequestParser`] and [`ResponseParser`] parse heads. They are state machines that scan
//!   each byte once and stop exactly where the input ends, so a head that arrives in pieces
//!   costs no more than one that arrives whole. They store offsets, not pointers, so the
//!   caller's buffer may grow or move between calls; the parsed [`Request`] / [`Response`] hands
//!   out `&str` views into it.
//! - Validation is fused into the scans (SSE2/AVX2 on x86-64, SWAR elsewhere): controls, bare
//!   LF, invalid UTF-8, malformed targets, `Host`, `Content-Length` and `Transfer-Encoding` are
//!   checked while the head is read, following RFC 9112 and RFC 9110 strictly.
//! - [`BodyDecoder`] decodes `Content-Length`, chunked and until-close bodies incrementally,
//!   returning payload as slices of the input.
//!
//! No allocation, `no_std`. Every rejection is an [`Error`] with the status code a server
//! answers with ([`Error::status`]).
//!
//! ```
//! use rimu_http1::{BodyKind, Config, Method, RequestParser, Status};
//!
//! let mut parser = RequestParser::<64>::new(Config::DEFAULT);
//! let buf = b"GET /search?q=rust HTTP/1.1\r\nHost: example.com\r\nAccept: */*\r\n\r\n";
//! match parser.parse(buf) {
//!   Ok(Status::Complete(req)) => {
//!     assert_eq!(req.method, Method::Get);
//!     assert_eq!((req.path, req.query), ("/search", "q=rust"));
//!     assert_eq!(req.headers.find("accept"), Some("*/*"));
//!     assert_eq!(req.body, BodyKind::None);
//!     assert!(req.keep_alive);
//!   }
//!   Ok(Status::Partial) => { /* read more, call again with the grown buffer */ }
//!   Err(err) => { /* answer err.status() and close */ }
//! }
//! ```
#![no_std]

#[cfg(any(feature = "std", test))]
extern crate std;

mod body;
mod config;
mod error;
mod headers;
mod method;
mod parser;
mod request;
mod response;
mod scan;

pub use body::{BodyDecoder, BodyStatus, Decoded};
pub use config::Config;
pub use error::Error;
pub use headers::{Header, Headers, HeadersIter};
pub use method::{Method, Version};
pub use parser::BodyKind;
pub use request::{Request, RequestParser};
pub use response::{Response, ResponseParser};

/// Outcome of a parse call that did not fail.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Status<T> {
  /// The head is complete.
  Complete(T),
  /// More bytes are needed; call again once they arrived.
  Partial,
}

impl<T> Status<T> {
  /// If the head is complete.
  #[inline]
  pub const fn is_complete(&self) -> bool {
    matches!(self, Self::Complete(_))
  }
}
