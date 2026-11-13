//! Request heads.

use crate::{
  BodyKind, Config, Error, Headers, Method, Status, Version,
  parser::{Core, Slot},
};

/// Resumable parser of request heads with `N` header slots (default 64).
///
/// Call [`parse`](Self::parse) whenever bytes arrive, each time with the whole message received
/// so far (its first byte first; the buffer may have grown or moved). The parser continues where
/// the previous call stopped, so the total work is linear in the bytes received however they are
/// split. After [`Status::Complete`] the next call starts a new message.
///
/// ```
/// use rimu_http1::{BodyKind, Config, Method, RequestParser, Status};
///
/// let mut parser = RequestParser::<16>::new(Config::DEFAULT);
/// let mut buf = b"POST /orders?id=7 HTTP/1.1\r\nHost: shop\r\nCont".to_vec();
/// assert!(matches!(parser.parse(&buf), Ok(Status::Partial)));
/// buf.extend_from_slice(b"ent-Length: 2\r\n\r\n{}");
/// let Ok(Status::Complete(req)) = parser.parse(&buf) else { panic!() };
/// assert_eq!((req.method, req.path, req.query), (Method::Post, "/orders", "id=7"));
/// assert_eq!(req.headers.find("host"), Some("shop"));
/// assert_eq!(req.body, BodyKind::ContentLength(2));
/// assert_eq!(&buf[req.head_len..], b"{}");
/// ```
#[derive(Clone, Debug)]
pub struct RequestParser<const N: usize = 64> {
  core: Core<N, true>,
}

/// A parsed request head: views into the caller's buffer.
#[derive(Clone, Copy, Debug)]
pub struct Request<'b> {
  /// The method.
  pub method: Method,
  /// The method as sent (useful for [`Method::Other`]).
  pub method_str: &'b str,
  /// The version.
  pub version: Version,
  /// The request target as sent.
  pub target: &'b str,
  /// The percent-encoded path, without the query: for an absolute-form target the part after
  /// the authority (`/` if empty), for CONNECT the authority, for asterisk-form `*`.
  pub path: &'b str,
  /// Everything after the first `?`, or an empty string.
  pub query: &'b str,
  /// The fields. For an absolute-form target the value of `Host` is the target's authority
  /// (RFC 9112 §3.2.3).
  pub headers: Headers<'b>,
  /// How the body is framed: never [`BodyKind::UntilClose`].
  pub body: BodyKind,
  /// If the connection may serve another request after this one (RFC 9112 §9.3).
  pub keep_alive: bool,
  /// `Expect: 100-continue` on HTTP/1.1: send a `100 Continue` before reading the body.
  pub expect_continue: bool,
  /// HTTP/1.1 with `Upgrade` and `upgrade` in `Connection`. If the server switches protocols,
  /// the bytes after the body belong to the new protocol.
  pub upgrade: bool,
  /// Length of the head in the buffer, including a skipped leading CRLF and the final empty
  /// line. The body (or the next message) starts here.
  pub head_len: usize,
}

impl<const N: usize> RequestParser<N> {
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

  /// Parses `buf`, the bytes of the message received so far.
  ///
  /// Returns [`Status::Partial`] while the head is incomplete (errors are reported as soon as
  /// the bytes that cause them arrive), or the request once the final empty line arrived. An
  /// error is repeated by later calls until [`reset`](Self::reset);
  /// [`Error::status`] is the status to answer with.
  #[inline]
  pub fn parse<'p, 'b: 'p>(&'p mut self, buf: &'b [u8]) -> Result<Status<Request<'p>>, Error> {
    if !self.core.advance(buf)? {
      return Ok(Status::Partial);
    }
    let head = match head_str(buf, self.core.pos as usize, self.core.resumed) {
      Ok(head) => head,
      Err(err) => {
        self.core.state = crate::parser::State::Failed(err);
        return Err(err);
      }
    };
    Ok(Status::Complete(self.request(head)))
  }

  /// The request of the completed head again, as views into `buf` (the bytes that were parsed,
  /// possibly moved to another allocation), without parsing it again: one UTF-8 check of the
  /// head, no scan, and no change of state.
  ///
  /// Returns [`Error::InvalidResume`] if no head is complete (before the final empty line, after
  /// an error) or if `buf` does not hold a head of the parsed length.
  #[inline]
  pub fn view<'p, 'b: 'p>(&'p self, buf: &'b [u8]) -> Result<Request<'p>, Error> {
    if !matches!(self.core.state, crate::parser::State::Done) {
      return Err(Error::InvalidResume);
    }
    let head = head_str(buf, self.core.pos as usize, true)?;
    Ok(self.request(head))
  }

  fn request<'p>(&'p self, head: &'p str) -> Request<'p> {
    let core = &self.core;
    let span = |start: u32, end: u32| head.get(start as usize..end as usize).unwrap_or_default();
    let framing = core.request_framing();
    let target = span(core.target_start, core.target_end);
    let method = core.method.unwrap_or(Method::Other);
    let slots: &[Slot] = core.slots.get(..usize::from(core.count)).unwrap_or_default();
    Request {
      method,
      method_str: span(core.method_start, core.method_end),
      version: if core.http10 { Version::Http10 } else { Version::Http11 },
      target,
      path: if core.root_path() { "/" } else { span(core.path_start, core.path_end) },
      query: span(core.query_start, core.query_end),
      headers: Headers::new(head, slots),
      body: framing.body,
      keep_alive: framing.keep_alive,
      expect_continue: framing.expect_continue,
      upgrade: framing.upgrade,
      head_len: core.pos as usize,
    }
  }
}

impl<const N: usize> Default for RequestParser<N> {
  #[inline]
  fn default() -> Self {
    Self::new(Config::DEFAULT)
  }
}

/// The head as a `str`. Bytes scanned in this call were validated as they were scanned; if an
/// earlier call scanned some, the caller could have changed them since, so they are checked
/// again (once per message, so the total stays linear).
pub(crate) fn head_str(buf: &[u8], len: usize, resumed: bool) -> Result<&str, Error> {
  let bytes = buf.get(..len).ok_or(Error::InvalidResume)?;
  if resumed {
    return core::str::from_utf8(bytes).map_err(|_| Error::InvalidResume);
  }
  // SAFETY: this call scanned every byte of the head, and every byte the parser accepts in a
  // head is ASCII except inside field values and reason phrases, which were validated as UTF-8
  // sequence by sequence (`scan::utf8_len`), so the head is valid UTF-8.
  Ok(unsafe { core::str::from_utf8_unchecked(bytes) })
}
