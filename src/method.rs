//! Request methods and versions.

/// A request method.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum Method {
  /// `CONNECT`
  Connect,
  /// `DELETE`
  Delete,
  /// `GET`
  Get,
  /// `HEAD`
  Head,
  /// `OPTIONS`
  Options,
  /// `PATCH`
  Patch,
  /// `POST`
  Post,
  /// `PUT`
  Put,
  /// `TRACE`
  Trace,
  /// Any other token, only with
  /// [`Config::allow_extension_methods`](crate::Config::allow_extension_methods). The name is
  /// [`Request::method_str`](crate::Request::method_str).
  Other,
}

impl Method {
  /// The method named exactly (methods are case-sensitive) by `bytes`, if it is one of the
  /// RFC 9110 methods or `PATCH`.
  #[inline]
  pub const fn from_bytes(bytes: &[u8]) -> Option<Self> {
    Some(match bytes {
      b"GET" => Self::Get,
      b"POST" => Self::Post,
      b"PUT" => Self::Put,
      b"HEAD" => Self::Head,
      b"DELETE" => Self::Delete,
      b"OPTIONS" => Self::Options,
      b"PATCH" => Self::Patch,
      b"CONNECT" => Self::Connect,
      b"TRACE" => Self::Trace,
      _ => return None,
    })
  }

  /// The name, or `""` for [`Method::Other`].
  #[inline]
  pub const fn as_str(self) -> &'static str {
    match self {
      Self::Connect => "CONNECT",
      Self::Delete => "DELETE",
      Self::Get => "GET",
      Self::Head => "HEAD",
      Self::Options => "OPTIONS",
      Self::Patch => "PATCH",
      Self::Post => "POST",
      Self::Put => "PUT",
      Self::Trace => "TRACE",
      Self::Other => "",
    }
  }
}

/// The protocol version of a message.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum Version {
  /// HTTP/1.0
  Http10,
  /// HTTP/1.1, also reported for a higher minor version (RFC 9112 §2.5).
  Http11,
}
