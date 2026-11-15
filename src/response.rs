//! Response heads.

use crate::{
  BodyKind, Config, Error, Headers, Method, Status, Version,
  parser::{Core, Framing, Slot, State},
  request::head_str,
};

/// Resumable parser of response heads with `N` header slots (default 64).
///
/// Used like [`RequestParser`](crate::RequestParser). The framing of a response depends on the
/// request it answers (RFC 9112 §6.3), so [`parse`](Self::parse) takes the request's method.
/// After a 1xx response (other than 101) the next head on the connection is the final response:
/// call `parse` again with the bytes after `head_len`.
///
/// ```
/// use nyseion_http1::{BodyKind, Config, Method, ResponseParser, Status};
///
/// let mut parser = ResponseParser::<16>::new(Config::DEFAULT);
/// let buf = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n";
/// let Ok(Status::Complete(res)) = parser.parse(buf, Method::Get) else { panic!() };
/// assert_eq!((res.status, res.reason), (200, "OK"));
/// assert_eq!(res.body, BodyKind::Chunked);
/// ```
#[derive(Clone, Debug)]
pub struct ResponseParser<const N: usize = 64> {
  core: Core<N, false>,
}

/// A parsed response head: views into the caller's buffer.
#[derive(Clone, Copy, Debug)]
pub struct Response<'b> {
  /// The version.
  pub version: Version,
  /// The status code, 100 to 599.
  pub status: u16,
  /// The reason phrase (possibly empty).
  pub reason: &'b str,
  /// The fields.
  pub headers: Headers<'b>,
  /// How the body is framed. [`BodyKind::None`] for 1xx, 204, 304, responses to HEAD and
  /// successful responses to CONNECT.
  pub body: BodyKind,
  /// If the connection may carry another request after this response.
  pub keep_alive: bool,
  /// A 101 (Switching Protocols), or a 2xx to CONNECT: the bytes after the head belong to the
  /// new protocol or the tunnel.
  pub upgrade: bool,
  /// Length of the head in the buffer, including the final empty line.
  pub head_len: usize,
}

impl<const N: usize> ResponseParser<N> {
  /// A parser with the given limits.
  #[inline]
  pub const fn new(config: Config) -> Self {
    Self { core: Core::new(config) }
  }

  /// The limits.
  #[inline]
  pub const fn config(&self) -> &Config {
    &self.core.config
  }

  /// Abandons the current message; the next call starts a new one.
  #[inline]
  pub fn reset(&mut self) {
    self.core.reset();
  }

  /// Parses `buf`, the bytes of the response received so far, answering a request with
  /// `request_method`. See [`RequestParser::parse`](crate::RequestParser::parse).
  #[inline]
  pub fn parse<'p, 'b: 'p>(
    &'p mut self,
    buf: &'b [u8],
    request_method: Method,
  ) -> Result<Status<Response<'p>>, Error> {
    if !self.core.advance(buf)? {
      return Ok(Status::Partial);
    }
    let checked = self
      .core
      .response_framing(request_method)
      .and_then(|framing| Ok((framing, head_str(buf, self.core.pos as usize, self.core.resumed)?)));
    match checked {
      Ok((framing, head)) => Ok(Status::Complete(self.response(head, framing))),
      Err(err) => {
        self.core.state = State::Failed(err);
        Err(err)
      }
    }
  }

  fn response<'p>(&'p self, head: &'p str, framing: Framing) -> Response<'p> {
    let core = &self.core;
    let slots: &[Slot] = core.slots.get(..usize::from(core.count)).unwrap_or_default();
    Response {
      version: if core.http10 { Version::Http10 } else { Version::Http11 },
      status: core.status,
      reason: head.get(core.reason_start as usize..core.reason_end as usize).unwrap_or_default(),
      headers: Headers::new(head, slots),
      body: framing.body,
      keep_alive: framing.keep_alive,
      upgrade: framing.upgrade,
      head_len: core.pos as usize,
    }
  }
}

impl<const N: usize> Default for ResponseParser<N> {
  #[inline]
  fn default() -> Self {
    Self::new(Config::DEFAULT)
  }
}
