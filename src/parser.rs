//! The resumable head state machine shared by [`RequestParser`](crate::RequestParser) and
//! [`ResponseParser`](crate::ResponseParser).
//!
//! The parser keeps offsets into the message, never pointers, and `pos`, the first byte it has
//! not scanned yet. A call continues from `pos` in whatever state the previous call stopped in,
//! so every byte is scanned once however the input is split. See `docs/design.md`.

use crate::{
  Config, Error, Method,
  scan::{NO_QUERY, TCHAR, Utf8Error, is_tchar, target_stop, utf8_len, value_stop},
};

/// Offsets of one field line in the head: the name and the value without surrounding
/// whitespace.
#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct Slot {
  pub(crate) name_start: u32,
  pub(crate) name_end: u32,
  pub(crate) value_start: u32,
  pub(crate) value_end: u32,
}

impl Slot {
  const EMPTY: Self = Self { name_start: 0, name_end: 0, value_start: 0, value_end: 0 };
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum State {
  /// Before the first byte (requests may skip one CRLF here).
  Start,
  /// Saw the CR of a leading CRLF.
  StartLf,
  /// In the method.
  Method,
  /// In the request target.
  Target,
  /// Waiting for `HTTP/d.d\r\n` after a request target.
  Version,
  /// Waiting for `HTTP/d.d ` at the start of a status line.
  ResponseVersion,
  /// Waiting for `ddd ` in a status line.
  Status,
  /// In a reason phrase.
  Reason,
  /// Saw the CR that ends the status line.
  ReasonLf,
  /// At the start of a field line or of the final empty line.
  LineStart,
  /// In a field name.
  Name,
  /// In a field value.
  Value,
  /// Saw the CR that ends a field line.
  ValueLf,
  /// Saw the CR of the final empty line.
  EndLf,
  /// The head is complete; the next call starts a new message.
  Done,
  /// The message was rejected; calls repeat the error until `reset`.
  Failed(Error),
}

// Bits of `Core::flags`.
const HAS_HOST: u16 = 1 << 0;
const HAS_CL: u16 = 1 << 1;
const TE: u16 = 1 << 2;
const CHUNKED: u16 = 1 << 3;
const TE_LAST_CHUNKED: u16 = 1 << 4;
const CONN_CLOSE: u16 = 1 << 5;
const CONN_KEEP_ALIVE: u16 = 1 << 6;
const CONN_UPGRADE: u16 = 1 << 7;
const UPGRADE: u16 = 1 << 8;
const EXPECT_CONTINUE: u16 = 1 << 9;
const METHOD_NOT_TOKEN: u16 = 1 << 10;
const ROOT_PATH: u16 = 1 << 11;

/// How a request's body is framed, or a response's (RFC 9112 §6.3).
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum BodyKind {
  /// No body.
  None,
  /// `Content-Length` bytes.
  ContentLength(u64),
  /// `Transfer-Encoding: chunked`.
  Chunked,
  /// Responses only: the body runs until the connection closes.
  UntilClose,
}

/// The parser state; `REQ` selects the request or the response start line.
#[derive(Clone, Debug)]
pub(crate) struct Core<const N: usize, const REQ: bool> {
  pub(crate) config: Config,
  pub(crate) state: State,
  /// First byte not scanned yet.
  pub(crate) pos: u32,
  /// If an earlier call for this message consumed bytes, which must be checked again before
  /// views of them are handed out (the caller could have changed them).
  pub(crate) resumed: bool,
  /// Start of the current line.
  line_start: u32,
  /// Request: end of the method; field lines: end of the name.
  mark: u32,
  pub(crate) method: Option<Method>,
  pub(crate) method_start: u32,
  pub(crate) method_end: u32,
  pub(crate) target_start: u32,
  pub(crate) target_end: u32,
  /// Index of the first `?` of the target, or [`NO_QUERY`].
  query: usize,
  pub(crate) path_start: u32,
  pub(crate) path_end: u32,
  pub(crate) query_start: u32,
  pub(crate) query_end: u32,
  /// Authority of an absolute-form target, if `authority_end != 0`.
  authority_start: u32,
  authority_end: u32,
  pub(crate) http10: bool,
  pub(crate) status: u16,
  pub(crate) reason_start: u32,
  pub(crate) reason_end: u32,
  flags: u16,
  content_length: u64,
  pub(crate) count: u16,
  pub(crate) slots: [Slot; N],
}

/// What [`Core::finish`] computes at the end of a head.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Framing {
  pub(crate) body: BodyKind,
  pub(crate) keep_alive: bool,
  pub(crate) expect_continue: bool,
  pub(crate) upgrade: bool,
}

impl<const N: usize, const REQ: bool> Core<N, REQ> {
  pub(crate) const fn new(config: Config) -> Self {
    Self {
      config,
      state: State::Start,
      pos: 0,
      resumed: false,
      line_start: 0,
      mark: 0,
      method: None,
      method_start: 0,
      method_end: 0,
      target_start: 0,
      target_end: 0,
      query: NO_QUERY,
      path_start: 0,
      path_end: 0,
      query_start: 0,
      query_end: 0,
      authority_start: 0,
      authority_end: 0,
      http10: false,
      status: 0,
      reason_start: 0,
      reason_end: 0,
      flags: 0,
      content_length: 0,
      count: 0,
      slots: [Slot::EMPTY; N],
    }
  }

  /// Forgets the current message. Slots are not cleared: only the first `count` are read.
  #[inline]
  pub(crate) fn reset(&mut self) {
    self.state = State::Start;
    self.pos = 0;
    self.resumed = false;
    self.method = None;
    self.query = NO_QUERY;
    self.authority_end = 0;
    self.flags = 0;
    self.count = 0;
  }

  #[inline]
  pub(crate) fn root_path(&self) -> bool {
    self.flags & ROOT_PATH != 0
  }

  #[inline]
  fn max_headers(&self) -> usize {
    usize::from(self.config.max_headers).min(N)
  }

  /// The error for reaching a limit in the current state.
  #[inline]
  fn limit_error(&self) -> Error {
    match self.state {
      State::Start | State::StartLf | State::Method | State::Target | State::Version if REQ => {
        Error::UriTooLong
      }
      _ => Error::HeadTooLarge,
    }
  }

  /// The scan of the current state reached `at` without finding its delimiter. If `at` is a
  /// limit (`line_limit` or the head limit) the head is rejected, else the parser waits there.
  #[cold]
  fn wait_or_limit(&mut self, at: usize, line_limit: usize, len: usize) -> Result<bool, Error> {
    let head_limit = self.config.max_head_len as usize;
    if at >= line_limit || at >= head_limit {
      return Err(self.limit_error());
    }
    debug_assert!(at >= len);
    self.wait(at)
  }

  /// Stops at `at` until more bytes arrive.
  #[inline]
  fn wait(&mut self, at: usize) -> Result<bool, Error> {
    // `at` is below the head limit, a `u32`.
    self.pos = at as u32;
    if at > 0 {
      self.resumed = true;
    }
    Ok(false)
  }

  /// End of the line window for a line starting at `line_start`: a line of `max_line_len` bytes
  /// has its CR at index `line_start + max_line_len`.
  #[inline]
  fn line_limit(&self) -> usize {
    (self.line_start as usize).saturating_add(self.config.max_line_len as usize).saturating_add(1)
  }

  /// Runs the state machine over `buf`. `Ok(true)`: the head ends at `self.pos`.
  #[inline]
  pub(crate) fn advance(&mut self, buf: &[u8]) -> Result<bool, Error> {
    match self.state {
      State::Done => self.reset(),
      State::Failed(err) => return Err(err),
      _ => {}
    }
    match self.run(buf) {
      Ok(done) => Ok(done),
      Err(err) => {
        self.state = State::Failed(err);
        Err(err)
      }
    }
  }

  #[inline]
  fn run(&mut self, buf: &[u8]) -> Result<bool, Error> {
    let len = buf.len();
    let mut i = self.pos as usize;
    if len < i {
      return Err(Error::InvalidResume);
    }
    let head_limit = self.config.max_head_len as usize;
    // Bytes that may be looked at: those received, up to the head limit.
    let end = len.min(head_limit);
    loop {
      match self.state {
        State::Start => {
          if !REQ {
            self.line_start = i as u32;
            self.state = State::ResponseVersion;
            continue;
          }
          let Some(&byte) = buf.get(i).filter(|_| i < end) else {
            return self.wait_or_limit(i, usize::MAX, len);
          };
          if byte == b'\r' {
            // RFC 9112 §2.2: one empty line before the request line is ignored.
            i += 1;
            self.state = State::StartLf;
          } else {
            self.line_start = i as u32;
            self.state = State::Method;
          }
        }
        State::StartLf => {
          let Some(&byte) = buf.get(i).filter(|_| i < end) else {
            return self.wait_or_limit(i, usize::MAX, len);
          };
          if byte != b'\n' {
            return Err(Error::InvalidLineEnding);
          }
          i += 1;
          self.line_start = i as u32;
          self.state = State::Method;
        }
        State::Method => {
          // `GET ` and `POST ` in one compare each.
          if i == self.line_start as usize
            && let Some(word) = buf.get(i..i + 5).filter(|_| i + 5 <= end)
          {
            let n = match word {
              [b'G', b'E', b'T', b' ', _] => Some((Method::Get, 3)),
              [b'P', b'O', b'S', b'T', b' '] => Some((Method::Post, 4)),
              _ => None,
            };
            if let Some((method, n)) = n {
              self.method = Some(method);
              self.method_start = i as u32;
              self.method_end = (i + n) as u32;
              i += n + 1;
              self.target_start = i as u32;
              self.query = NO_QUERY;
              self.state = State::Target;
              continue;
            }
          }
          let wend = end.min(self.line_limit());
          let mut j = i;
          loop {
            let Some(&byte) = buf.get(j).filter(|_| j < wend) else {
              return self.wait_or_limit(j, self.line_limit(), len);
            };
            if is_tchar(byte) {
              j += 1;
            } else if byte == b' ' {
              break;
            } else if (0x21..=0x7e).contains(&byte) {
              // Not a token, but judged once the line is known to be well formed.
              self.flags |= METHOD_NOT_TOKEN;
              j += 1;
            } else {
              return Err(Error::InvalidMethod);
            }
          }
          let start = self.line_start as usize;
          self.method = buf.get(start..j).and_then(Method::from_bytes);
          self.method_start = start as u32;
          self.method_end = j as u32;
          i = j + 1;
          self.target_start = i as u32;
          self.query = NO_QUERY;
          self.state = State::Target;
        }
        State::Target => {
          let wend = end.min(self.line_limit());
          let j = target_stop(buf, i, wend, &mut self.query);
          if j >= wend {
            return self.wait_or_limit(j, self.line_limit(), len);
          }
          if buf.get(j) != Some(&b' ') {
            // A control, DEL, raw non-ASCII byte, or a fragment (RFC 9112 §3.2, RFC 9110 §7.1).
            return Err(Error::InvalidTarget);
          }
          self.target_end = j as u32;
          i = j + 1;
          self.state = State::Version;
        }
        State::Version => {
          // The 10 bytes `HTTP/d.d\r\n`, all at once; limits are judged first, by position.
          if i + 8 > self.line_limit() - 1 || i + 10 > head_limit {
            return Err(Error::UriTooLong);
          }
          let Some(v) = buf.get(i..i + 10) else {
            return self.wait(i);
          };
          if !(v.starts_with(b"HTTP/") && v[5].is_ascii_digit() && v[6] == b'.')
            || !v[7].is_ascii_digit()
          {
            return Err(Error::InvalidVersion);
          }
          match (v[8], v[9]) {
            (b'\r', b'\n') => {}
            (b'\r' | b'\n', _) => return Err(Error::InvalidLineEnding),
            _ => return Err(Error::InvalidVersion),
          }
          if v[5] != b'1' {
            return Err(Error::VersionNotSupported);
          }
          self.http10 = v[7] == b'0';
          self.request_line(buf)?;
          i += 10;
          self.state = State::LineStart;
        }
        State::ResponseVersion => {
          if i + 9 > self.line_limit() - 1 || i + 9 > head_limit {
            return Err(Error::HeadTooLarge);
          }
          let Some(v) = buf.get(i..i + 9) else {
            return self.wait(i);
          };
          if !(v.starts_with(b"HTTP/") && v[5].is_ascii_digit() && v[6] == b'.')
            || !v[7].is_ascii_digit()
          {
            return Err(Error::InvalidVersion);
          }
          match v[8] {
            b' ' => {}
            b'\r' | b'\n' => return Err(Error::InvalidLineEnding),
            _ => return Err(Error::InvalidVersion),
          }
          if v[5] != b'1' {
            return Err(Error::VersionNotSupported);
          }
          self.http10 = v[7] == b'0';
          i += 9;
          self.state = State::Status;
        }
        State::Status => {
          if i + 4 > self.line_limit() - 1 || i + 4 > head_limit {
            return Err(Error::HeadTooLarge);
          }
          let Some(v) = buf.get(i..i + 4) else {
            return self.wait(i);
          };
          // RFC 9112 §4: `status-code SP`, the space even before an empty reason.
          if !v[..3].iter().all(u8::is_ascii_digit) || v[3] != b' ' {
            return Err(Error::InvalidStatus);
          }
          let status =
            u16::from(v[0] - b'0') * 100 + u16::from(v[1] - b'0') * 10 + u16::from(v[2] - b'0');
          // RFC 9110 §15: all valid status codes are 100 to 599.
          if !(100..=599).contains(&status) {
            return Err(Error::InvalidStatus);
          }
          self.status = status;
          i += 4;
          self.reason_start = i as u32;
          self.state = State::Reason;
        }
        State::Reason | State::Value => {
          let wend = end.min(self.line_limit());
          let mut j = i;
          loop {
            j = value_stop(buf, j, wend);
            let Some(&byte) = buf.get(j).filter(|_| j < wend) else {
              return self.wait_or_limit(j, self.line_limit(), len);
            };
            if byte == b'\r' {
              break;
            } else if byte == b'\t' {
              j += 1;
            } else if byte >= 0x80 {
              match utf8_len(buf, j, wend) {
                Ok(n) => j += n,
                // Resume at the start of the sequence.
                Err(Utf8Error::Incomplete) => {
                  if wend >= self.line_limit() || wend >= head_limit {
                    return Err(self.limit_error());
                  }
                  return self.wait(j);
                }
                Err(Utf8Error::Invalid) => return Err(Error::InvalidHeaderValue),
              }
            } else if byte == b'\n' {
              return Err(Error::InvalidLineEnding);
            } else {
              return Err(Error::InvalidHeaderValue);
            }
          }
          if self.state == State::Reason {
            self.reason_end = j as u32;
            self.state = State::ReasonLf;
          } else {
            self.field(buf, j)?;
            self.state = State::ValueLf;
          }
          i = j + 1;
        }
        State::ReasonLf | State::ValueLf => {
          let Some(&byte) = buf.get(i).filter(|_| i < end) else {
            return self.wait_or_limit(i, usize::MAX, len);
          };
          if byte != b'\n' {
            return Err(Error::InvalidLineEnding);
          }
          i += 1;
          self.state = State::LineStart;
        }
        State::LineStart => {
          let Some(&byte) = buf.get(i).filter(|_| i < end) else {
            return self.wait_or_limit(i, usize::MAX, len);
          };
          self.line_start = i as u32;
          i += 1;
          if is_tchar(byte) {
            self.state = State::Name;
          } else if byte == b'\r' {
            self.state = State::EndLf;
          } else if byte == b' ' || byte == b'\t' {
            return Err(Error::WhitespaceBeforeName);
          } else if byte == b'\n' {
            return Err(Error::InvalidLineEnding);
          } else {
            return Err(Error::InvalidHeaderName);
          }
        }
        State::Name => {
          let wend = end.min(self.line_limit());
          let mut j = i;
          let name = buf.get(..wend).unwrap_or_default();
          while let Some(&byte) = name.get(j) {
            if !TCHAR[usize::from(byte)] {
              break;
            }
            j += 1;
          }
          let Some(&byte) = name.get(j) else {
            return self.wait_or_limit(j, self.line_limit(), len);
          };
          // No whitespace before the colon (RFC 9112 §5.1).
          if byte != b':' {
            return Err(Error::InvalidHeaderName);
          }
          self.mark = j as u32;
          i = j + 1;
          self.state = State::Value;
        }
        State::EndLf => {
          let Some(&byte) = buf.get(i).filter(|_| i < end) else {
            return self.wait_or_limit(i, usize::MAX, len);
          };
          if byte != b'\n' {
            return Err(Error::InvalidLineEnding);
          }
          i += 1;
          self.pos = i as u32;
          if REQ {
            self.request_head_end()?;
          }
          self.state = State::Done;
          return Ok(true);
        }
        State::Done | State::Failed(_) => return Err(Error::InvalidResume),
      }
    }
  }

  /// End of the request line: verdicts on the target and the method, which rimu-ws takes once
  /// the whole line is known to be well formed (so a bad version wins over a bad target).
  fn request_line(&mut self, buf: &[u8]) -> Result<(), Error> {
    let ts = self.target_start as usize;
    let te = self.target_end as usize;
    let target = buf.get(ts..te).unwrap_or_default();
    if target.is_empty() {
      return Err(Error::InvalidTarget);
    }
    let method = self.method;
    let scheme = if target.len() >= 7 && target[..7].eq_ignore_ascii_case(b"http://") {
      7
    } else if target.len() >= 8 && target[..8].eq_ignore_ascii_case(b"https://") {
      8
    } else {
      0
    };
    let (path_start, path_end) = (ts, if self.query == NO_QUERY { te } else { self.query });
    self.path_start = path_start as u32;
    self.path_end = path_end as u32;
    if self.query == NO_QUERY {
      self.query_start = te as u32;
    } else {
      self.query_start = (self.query + 1) as u32;
    }
    self.query_end = te as u32;
    if scheme != 0 {
      // Absolute-form (RFC 9112 §3.2.2): the authority replaces `Host` (§3.2.3); it has no
      // userinfo (RFC 9110 §4.2.4) and is not empty.
      let rest = &target[scheme..];
      let alen = rest.iter().position(|b| *b == b'/' || *b == b'?').unwrap_or(rest.len());
      let authority = &rest[..alen];
      if authority.is_empty() || authority.contains(&b'@') {
        return Err(Error::InvalidTarget);
      }
      if method == Some(Method::Connect) {
        return Err(Error::InvalidTarget);
      }
      self.authority_start = (ts + scheme) as u32;
      self.authority_end = (ts + scheme + alen) as u32;
      self.path_start = self.authority_end;
      if self.path_start == self.path_end {
        self.flags |= ROOT_PATH;
      }
    } else if target[0] == b'/' {
      // Origin-form
      if method == Some(Method::Connect) {
        return Err(Error::InvalidTarget);
      }
    } else if target == b"*" {
      // Asterisk-form, OPTIONS only (RFC 9112 §3.2.4).
      if method.is_some_and(|m| m != Method::Options) {
        return Err(Error::InvalidTarget);
      }
    } else {
      // Authority-form, CONNECT only, `host:port` (RFC 9112 §3.2.3).
      if method != Some(Method::Connect) {
        return Err(Error::InvalidTarget);
      }
      check_host(target, true).map_err(|_| Error::InvalidTarget)?;
      self.query_start = te as u32;
    }
    if method.is_none() {
      let name = buf.get(self.method_start as usize..self.method_end as usize).unwrap_or_default();
      if name.is_empty() || self.flags & METHOD_NOT_TOKEN != 0 {
        return Err(Error::InvalidMethod);
      }
      if self.config.allow_extension_methods {
        if target == b"*" {
          return Err(Error::InvalidTarget);
        }
        self.method = Some(Method::Other);
      } else if name.iter().all(u8::is_ascii_uppercase) {
        // nginx and httpd: a well-formed method that is not known is not implemented.
        return Err(Error::UnknownMethod);
      } else {
        return Err(Error::InvalidMethod);
      }
    }
    Ok(())
  }

  /// A field line whose value ends at the CR at `cr`: semantic checks, then a slot.
  #[inline]
  fn field(&mut self, buf: &[u8], cr: usize) -> Result<(), Error> {
    let name_start = self.line_start as usize;
    let name_end = self.mark as usize;
    let mut vs = name_end + 1;
    let mut ve = cr;
    while vs < ve && matches!(buf.get(vs), Some(b' ' | b'\t')) {
      vs += 1;
    }
    while ve > vs && matches!(buf.get(ve - 1), Some(b' ' | b'\t')) {
      ve -= 1;
    }
    let name = buf.get(name_start..name_end).unwrap_or_default();
    match name.len() {
      4 if REQ && eq_lower(name, b"host") => {
        // RFC 9112 §3.2: at most one, and a valid value.
        if self.flags & HAS_HOST != 0 {
          return Err(Error::DuplicateHost);
        }
        self.flags |= HAS_HOST;
        if self.authority_end != 0 {
          // RFC 9112 §3.2.3: an absolute-form target's authority replaces `Host`.
          vs = self.authority_start as usize;
          ve = self.authority_end as usize;
        }
        check_host(buf.get(vs..ve).unwrap_or_default(), false)?;
      }
      6 if REQ && eq_lower(name, b"expect") => {
        if buf.get(vs..ve).is_some_and(|v| v.eq_ignore_ascii_case(b"100-continue")) {
          self.flags |= EXPECT_CONTINUE;
        }
      }
      7 if REQ && eq_lower(name, b"upgrade") => self.flags |= UPGRADE,
      10 if eq_lower(name, b"connection") => {
        for token in buf.get(vs..ve).unwrap_or_default().split(|b| *b == b',') {
          let token = trim_ows(token);
          if token.eq_ignore_ascii_case(b"close") {
            self.flags |= CONN_CLOSE;
          } else if token.eq_ignore_ascii_case(b"keep-alive") {
            self.flags |= CONN_KEEP_ALIVE;
          } else if token.eq_ignore_ascii_case(b"upgrade") {
            self.flags |= CONN_UPGRADE;
          }
        }
      }
      14 if eq_lower(name, b"content-length") => {
        if self.flags & HAS_CL != 0 {
          return Err(Error::DuplicateContentLength);
        }
        self.flags |= HAS_CL;
        self.content_length = parse_decimal(buf.get(vs..ve).unwrap_or_default())?;
      }
      17 if eq_lower(name, b"transfer-encoding") => {
        self.transfer_encoding(buf.get(vs..ve).unwrap_or_default())?;
      }
      _ => {}
    }
    let count = usize::from(self.count);
    if count >= self.max_headers() {
      return Err(Error::TooManyHeaders);
    }
    let Some(slot) = self.slots.get_mut(count) else {
      return Err(Error::TooManyHeaders);
    };
    // All offsets are below the head limit, a `u32`.
    *slot = Slot {
      name_start: name_start as u32,
      name_end: name_end as u32,
      value_start: vs as u32,
      value_end: ve as u32,
    };
    self.count += 1;
    Ok(())
  }

  /// One `Transfer-Encoding` field: a list of tokens with `chunked` at most once and, if
  /// present, last (RFC 9112 §6.1). Several fields form one list.
  fn transfer_encoding(&mut self, value: &[u8]) -> Result<(), Error> {
    if REQ && self.flags & TE != 0 {
      // A second field is refused like `chunked` listed twice.
      return Err(Error::InvalidTransferEncoding);
    }
    self.flags |= TE;
    let mut others = false;
    for token in value.split(|b| *b == b',') {
      let token = trim_ows(token);
      if token.is_empty() || !token.iter().all(|b| is_tchar(*b)) {
        return Err(Error::InvalidTransferEncoding);
      }
      if token.eq_ignore_ascii_case(b"chunked") {
        if self.flags & CHUNKED != 0 {
          return Err(Error::InvalidTransferEncoding);
        }
        self.flags |= CHUNKED | TE_LAST_CHUNKED;
      } else {
        // A coding after `chunked`.
        if self.flags & CHUNKED != 0 {
          return Err(Error::InvalidTransferEncoding);
        }
        self.flags &= !TE_LAST_CHUNKED;
        others = true;
      }
    }
    if REQ {
      // RFC 9112 §6.3: without `chunked` last the length of a request is unknown (400); other
      // codings before it are not implemented (501, RFC 9112 §6.1).
      if self.flags & TE_LAST_CHUNKED == 0 {
        return Err(Error::InvalidTransferEncoding);
      }
      if others {
        return Err(Error::UnsupportedTransferCoding);
      }
    }
    Ok(())
  }

  /// End of a request head: rules that need every field.
  fn request_head_end(&mut self) -> Result<(), Error> {
    if self.flags & TE != 0 && self.flags & HAS_CL != 0 {
      return Err(Error::ContentLengthWithTransferEncoding);
    }
    if !self.http10 && self.flags & HAS_HOST == 0 {
      return Err(Error::MissingHost);
    }
    Ok(())
  }

  /// Framing and connection semantics of a complete request head.
  pub(crate) fn request_framing(&self) -> Framing {
    let chunked = self.flags & CHUNKED != 0;
    let body = if chunked {
      BodyKind::Chunked
    } else if self.flags & HAS_CL != 0 {
      BodyKind::ContentLength(self.content_length)
    } else {
      BodyKind::None
    };
    let http10 = self.http10;
    // RFC 9112 §6.1: chunked framing in HTTP/1.0 is faulty, the connection closes after it.
    let keep_alive = if self.flags & CONN_CLOSE != 0 || (http10 && chunked) {
      false
    } else {
      !http10 || self.flags & CONN_KEEP_ALIVE != 0
    };
    Framing {
      body,
      keep_alive,
      // RFC 9110 §10.1.1 and §7.8: both are ignored in HTTP/1.0 requests.
      expect_continue: !http10 && self.flags & EXPECT_CONTINUE != 0,
      upgrade: !http10 && self.flags & UPGRADE != 0 && self.flags & CONN_UPGRADE != 0,
    }
  }

  /// Framing of a complete response head to a request with `request_method` (RFC 9112 §6.3).
  pub(crate) fn response_framing(&self, request_method: Method) -> Result<Framing, Error> {
    if self.flags & TE != 0 && self.flags & HAS_CL != 0 {
      return Err(Error::ContentLengthWithTransferEncoding);
    }
    let status = self.status;
    let tunnel = request_method == Method::Connect && (200..300).contains(&status);
    let body = if (100..200).contains(&status)
      || status == 204
      || status == 304
      || request_method == Method::Head
      || tunnel
    {
      BodyKind::None
    } else if self.flags & TE != 0 {
      if self.flags & TE_LAST_CHUNKED != 0 { BodyKind::Chunked } else { BodyKind::UntilClose }
    } else if self.flags & HAS_CL != 0 {
      BodyKind::ContentLength(self.content_length)
    } else {
      BodyKind::UntilClose
    };
    let http10 = self.http10;
    let keep_alive = if self.flags & CONN_CLOSE != 0
      || body == BodyKind::UntilClose
      || (http10 && self.flags & TE != 0)
    {
      false
    } else {
      !http10 || self.flags & CONN_KEEP_ALIVE != 0
    };
    Ok(Framing { body, keep_alive, expect_continue: false, upgrade: status == 101 || tunnel })
  }
}

/// `bytes` (`tchar`s) equal to the lowercase `lit`, ignoring ASCII case. OR-ing `0x20` maps an
/// uppercase letter to lowercase and leaves the other `tchar`s that can match a literal byte
/// (digits, `-`) unchanged.
#[inline(always)]
fn eq_lower<const L: usize>(bytes: &[u8], lit: &[u8; L]) -> bool {
  bytes.len() == L && bytes.iter().zip(lit).all(|(b, l)| b | 0x20 == *l)
}

#[inline]
fn trim_ows(mut s: &[u8]) -> &[u8] {
  while let [b' ' | b'\t', rest @ ..] = s {
    s = rest;
  }
  while let [rest @ .., b' ' | b'\t'] = s {
    s = rest;
  }
  s
}

/// Digits only, no sign, no overflow (RFC 9110 §8.6).
#[inline]
fn parse_decimal(bytes: &[u8]) -> Result<u64, Error> {
  if bytes.is_empty() {
    return Err(Error::InvalidContentLength);
  }
  let mut n: u64 = 0;
  for byte in bytes {
    let digit = byte.wrapping_sub(b'0');
    if digit > 9 {
      return Err(Error::InvalidContentLength);
    }
    n = n
      .checked_mul(10)
      .and_then(|v| v.checked_add(u64::from(digit)))
      .ok_or(Error::InvalidContentLength)?;
  }
  Ok(n)
}

/// Accepts `host [":" port]` (RFC 3986 §3.2.2): a registered name or IPv4 address, or a
/// bracketed IPv6 literal, and a port of at most 65535; `require_port` for CONNECT's
/// authority-form. Userinfo, a path or extra colons are refused, as h2o does. An empty value is
/// allowed when no port is required (RFC 9110 §7.2).
fn check_host(value: &[u8], require_port: bool) -> Result<(), Error> {
  let port = if let Some(rest) = value.strip_prefix(b"[") {
    let end = rest.iter().position(|b| *b == b']').ok_or(Error::InvalidHost)?;
    let literal = &rest[..end];
    if literal.is_empty()
      || !literal.iter().all(|byte| byte.is_ascii_hexdigit() || matches!(byte, b':' | b'.'))
    {
      return Err(Error::InvalidHost);
    }
    match &rest[end + 1..] {
      [] => None,
      [b':', port @ ..] => Some(port),
      _ => return Err(Error::InvalidHost),
    }
  } else {
    let (name, port) = match value.iter().position(|b| *b == b':') {
      Some(idx) => (&value[..idx], Some(&value[idx + 1..])),
      None => (value, None),
    };
    if !name.iter().all(|byte| is_reg_name_byte(*byte)) {
      return Err(Error::InvalidHost);
    }
    if require_port && name.is_empty() {
      return Err(Error::InvalidHost);
    }
    port
  };
  match port {
    Some(port) => {
      if require_port && port.is_empty() {
        return Err(Error::InvalidHost);
      }
      let mut number: u32 = 0;
      for byte in port {
        let digit = byte.wrapping_sub(b'0');
        if digit > 9 {
          return Err(Error::InvalidHost);
        }
        number = number.saturating_mul(10).saturating_add(u32::from(digit));
      }
      if number > 65535 {
        return Err(Error::InvalidHost);
      }
    }
    None if require_port => return Err(Error::InvalidHost),
    None => {}
  }
  Ok(())
}

/// RFC 3986 `reg-name` bytes: unreserved, `%` of a percent-encoding, and sub-delims.
#[inline]
const fn is_reg_name_byte(byte: u8) -> bool {
  byte.is_ascii_alphanumeric()
    || matches!(
      byte,
      b'-'
        | b'.'
        | b'_'
        | b'~'
        | b'%'
        | b'!'
        | b'$'
        | b'&'
        | b'\''
        | b'('
        | b')'
        | b'*'
        | b'+'
        | b','
        | b';'
        | b'='
    )
}
