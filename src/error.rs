//! Parse errors and the status codes they map to.

use core::fmt;

/// Why a message was rejected.
///
/// There is one variant per rule, so that tests and logs can tell them apart; [`Error::status`]
/// gives the status code a server answers a rejected request with.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[non_exhaustive]
pub enum Error {
  /// The method is empty or not a token (RFC 9110 §9.1).
  InvalidMethod,
  /// The request target holds a control, DEL, space, raw non-ASCII byte or `#`, is empty, or
  /// has a form the method does not allow (RFC 9112 §3.2).
  InvalidTarget,
  /// The version is not `HTTP/<digit>.<digit>` followed by the line end (RFC 9112 §2.3).
  InvalidVersion,
  /// A line ends in a bare LF, or a CR is not followed by LF (RFC 9112 §2.2).
  InvalidLineEnding,
  /// A field name is empty or not a token, or whitespace precedes the colon (RFC 9112 §5.1).
  InvalidHeaderName,
  /// A field value holds a control (other than HTAB), DEL, or invalid UTF-8 (RFC 9110 §5.5).
  InvalidHeaderValue,
  /// A field line starts with whitespace: obs-fold (RFC 9112 §5.2) or whitespace between the
  /// start line and the first field (RFC 9112 §2.2).
  WhitespaceBeforeName,
  /// An HTTP/1.1 request has no `Host` (RFC 9112 §3.2).
  MissingHost,
  /// A request has more than one `Host` (RFC 9112 §3.2).
  DuplicateHost,
  /// `Host` (or the authority of an absolute-form or CONNECT target) is not
  /// `host [":" port]` (RFC 9112 §3.2, RFC 3986 §3.2.2).
  InvalidHost,
  /// `Content-Length` is not a decimal number that fits in a `u64` (RFC 9110 §8.6).
  InvalidContentLength,
  /// More than one `Content-Length` field (RFC 9110 §8.6, RFC 9112 §6.3).
  DuplicateContentLength,
  /// Both `Content-Length` and `Transfer-Encoding` (RFC 9112 §6.3; request smuggling).
  ContentLengthWithTransferEncoding,
  /// `Transfer-Encoding` is not a list of tokens with `chunked` once and last (RFC 9112 §6.1).
  InvalidTransferEncoding,
  /// A response status code is not three digits from 100 to 599 followed by a space
  /// (RFC 9112 §4, RFC 9110 §15).
  InvalidStatus,
  /// The request line is longer than the line or head limit.
  UriTooLong,
  /// A field line or the head is longer than its limit.
  HeadTooLarge,
  /// More fields than the limit.
  TooManyHeaders,
  /// A well-formed method this parser does not know (RFC 9110 §9.1).
  UnknownMethod,
  /// A transfer coding other than `chunked` is applied to a request (RFC 9112 §6.1).
  UnsupportedTransferCoding,
  /// A major version other than 1 (RFC 9112 §2.5).
  VersionNotSupported,
  /// A chunk size is not hexadecimal digits, or overflows a `u64` (RFC 9112 §7.1).
  InvalidChunkSize,
  /// A chunk extension does not follow the RFC 9112 §7.1.1 grammar.
  InvalidChunkExtension,
  /// The chunk-size line is longer than the line limit.
  ChunkLineTooLong,
  /// Chunk data is not followed by CRLF (RFC 9112 §7.1).
  InvalidChunkEnd,
  /// A trailer field is malformed (RFC 9112 §7.1.2).
  InvalidTrailer,
  /// The trailer section has more fields or bytes than the limits.
  TrailersTooLarge,
  /// The connection ended before the body did.
  UnexpectedEof,
  /// API misuse: the buffer passed to resume a message is shorter than what was already
  /// consumed, or bytes consumed by an earlier call have changed.
  InvalidResume,
}

impl Error {
  /// The status code a server answers a request rejected with this error: 400, 414, 431, 501
  /// or 505. A client that rejects a response would answer its own caller with 502 instead.
  #[inline]
  pub const fn status(self) -> u16 {
    match self {
      Self::UriTooLong => 414,
      Self::HeadTooLarge | Self::TooManyHeaders | Self::TrailersTooLarge => 431,
      Self::UnknownMethod | Self::UnsupportedTransferCoding => 501,
      Self::VersionNotSupported => 505,
      _ => 400,
    }
  }

  /// A short description.
  #[inline]
  pub const fn as_str(self) -> &'static str {
    match self {
      Self::InvalidMethod => "invalid method",
      Self::InvalidTarget => "invalid request target",
      Self::InvalidVersion => "invalid HTTP version",
      Self::InvalidLineEnding => "line not ended by CRLF",
      Self::InvalidHeaderName => "invalid field name",
      Self::InvalidHeaderValue => "invalid field value",
      Self::WhitespaceBeforeName => "whitespace before a field name",
      Self::MissingHost => "missing Host",
      Self::DuplicateHost => "more than one Host",
      Self::InvalidHost => "invalid Host",
      Self::InvalidContentLength => "invalid Content-Length",
      Self::DuplicateContentLength => "more than one Content-Length",
      Self::ContentLengthWithTransferEncoding => "both Content-Length and Transfer-Encoding",
      Self::InvalidTransferEncoding => "invalid Transfer-Encoding",
      Self::InvalidStatus => "invalid status code",
      Self::UriTooLong => "request line too long",
      Self::HeadTooLarge => "head too large",
      Self::TooManyHeaders => "too many fields",
      Self::UnknownMethod => "unknown method",
      Self::UnsupportedTransferCoding => "unsupported transfer coding",
      Self::VersionNotSupported => "HTTP version not supported",
      Self::InvalidChunkSize => "invalid chunk size",
      Self::InvalidChunkExtension => "invalid chunk extension",
      Self::ChunkLineTooLong => "chunk-size line too long",
      Self::InvalidChunkEnd => "chunk data not followed by CRLF",
      Self::InvalidTrailer => "invalid trailer field",
      Self::TrailersTooLarge => "trailer section too large",
      Self::UnexpectedEof => "connection closed before the end of the body",
      Self::InvalidResume => "resumed with a different buffer",
    }
  }
}

impl fmt::Display for Error {
  #[inline]
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    f.write_str(self.as_str())
  }
}

impl core::error::Error for Error {}
