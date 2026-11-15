//! Helpers shared by the integration tests: owned snapshots of parse outcomes, and feeding a
//! message whole or in pieces (each call gets a freshly allocated copy of the prefix, so the
//! buffer really moves between calls).
#![allow(dead_code, reason = "each test file uses a subset")]

pub mod corpus;
pub mod ported_inputs;

use nyseion_http1::{
  BodyDecoder, BodyKind, BodyStatus, Config, Error, Method, Request, RequestParser, Response,
  ResponseParser, Status, Version,
};

/// Everything a parsed request exposes, owned.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Req {
  pub method: Method,
  pub method_str: String,
  pub version: Version,
  pub target: String,
  pub path: String,
  pub query: String,
  pub headers: Vec<(String, String)>,
  pub body: BodyKind,
  pub keep_alive: bool,
  pub expect_continue: bool,
  pub upgrade: bool,
  pub head_len: usize,
}

impl Req {
  pub fn of(r: &Request<'_>) -> Self {
    Self {
      method: r.method,
      method_str: r.method_str.into(),
      version: r.version,
      target: r.target.into(),
      path: r.path.into(),
      query: r.query.into(),
      headers: r.headers.iter().map(|h| (h.name.into(), h.value.into())).collect(),
      body: r.body,
      keep_alive: r.keep_alive,
      expect_continue: r.expect_continue,
      upgrade: r.upgrade,
      head_len: r.head_len,
    }
  }
}

/// Everything a parsed response exposes, owned.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Res {
  pub version: Version,
  pub status: u16,
  pub reason: String,
  pub headers: Vec<(String, String)>,
  pub body: BodyKind,
  pub keep_alive: bool,
  pub upgrade: bool,
  pub head_len: usize,
}

impl Res {
  pub fn of(r: &Response<'_>) -> Self {
    Self {
      version: r.version,
      status: r.status,
      reason: r.reason.into(),
      headers: r.headers.iter().map(|h| (h.name.into(), h.value.into())).collect(),
      body: r.body,
      keep_alive: r.keep_alive,
      upgrade: r.upgrade,
      head_len: r.head_len,
    }
  }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Outcome<T> {
  Complete(T),
  Partial,
  Error(Error),
}

impl<T> Outcome<T> {
  pub fn unwrap(self) -> T {
    match self {
      Self::Complete(t) => t,
      Self::Partial => panic!("partial"),
      Self::Error(e) => panic!("error {e:?}"),
    }
  }

  pub fn err(&self) -> Option<Error> {
    match self {
      Self::Error(e) => Some(*e),
      _ => None,
    }
  }
}

pub fn req_step(parser: &mut RequestParser, buf: &[u8]) -> Outcome<Req> {
  match parser.parse(buf) {
    Ok(Status::Complete(r)) => Outcome::Complete(Req::of(&r)),
    Ok(Status::Partial) => Outcome::Partial,
    Err(e) => Outcome::Error(e),
  }
}

pub fn res_step(parser: &mut ResponseParser, buf: &[u8], method: Method) -> Outcome<Res> {
  match parser.parse(buf, method) {
    Ok(Status::Complete(r)) => Outcome::Complete(Res::of(&r)),
    Ok(Status::Partial) => Outcome::Partial,
    Err(e) => Outcome::Error(e),
  }
}

pub fn req_whole_with(buf: &[u8], config: Config) -> Outcome<Req> {
  req_step(&mut RequestParser::new(config), buf)
}

pub fn req_whole(buf: &[u8]) -> Outcome<Req> {
  req_whole_with(buf, Config::DEFAULT)
}

/// Feeds the prefixes `buf[..cut]` for each cut (increasing), then `buf`, each as a new
/// allocation. Stops at the first non-partial outcome.
pub fn req_split_with(buf: &[u8], cuts: &[usize], config: Config) -> Outcome<Req> {
  let mut parser = RequestParser::new(config);
  for &cut in cuts.iter().chain(core::iter::once(&buf.len())) {
    let copy = buf[..cut].to_vec();
    let out = req_step(&mut parser, &copy);
    if out != Outcome::Partial {
      return out;
    }
  }
  Outcome::Partial
}

pub fn res_whole(buf: &[u8], method: Method) -> Outcome<Res> {
  res_step(&mut ResponseParser::new(Config::DEFAULT), buf, method)
}

pub fn res_split(buf: &[u8], cuts: &[usize], method: Method) -> Outcome<Res> {
  let mut parser = ResponseParser::new(Config::DEFAULT);
  for &cut in cuts.iter().chain(core::iter::once(&buf.len())) {
    let copy = buf[..cut].to_vec();
    let out = res_step(&mut parser, &copy, method);
    if out != Outcome::Partial {
      return out;
    }
  }
  Outcome::Partial
}

/// The status code `buf` is rejected with (panics if accepted).
pub fn err_status(buf: &[u8]) -> u16 {
  match req_whole(buf) {
    Outcome::Error(e) => e.status(),
    other => panic!("not rejected: {other:?}"),
  }
}

pub fn is_err(buf: &[u8]) -> bool {
  matches!(req_whole(buf), Outcome::Error(_))
}

/// Decoded body: payload, bytes of the input that belong to the body, or the error.
pub type BodyOutcome = Result<(Vec<u8>, Option<usize>), Error>;

/// Decodes `input` fed in pieces cut at `cuts`. `Some(consumed)` once complete.
pub fn body_split(kind: BodyKind, input: &[u8], cuts: &[usize], config: Config) -> BodyOutcome {
  let mut decoder = BodyDecoder::with_config(kind, &config);
  let mut out = Vec::new();
  let mut start = 0;
  for &cut in cuts.iter().chain(core::iter::once(&input.len())) {
    if cut < start {
      continue;
    }
    let piece = input[start..cut].to_vec();
    match decoder.feed(&piece, |d| out.extend_from_slice(d))? {
      BodyStatus::NeedMore => start = cut,
      BodyStatus::Complete { consumed } => return Ok((out, Some(start + consumed))),
    }
  }
  Ok((out, None))
}

/// A small deterministic generator (xorshift64*), so the randomized tests need no dependency.
pub struct Rng(pub u64);

impl Rng {
  pub fn next(&mut self) -> u64 {
    let mut x = self.0;
    x ^= x >> 12;
    x ^= x << 25;
    x ^= x >> 27;
    self.0 = x;
    x.wrapping_mul(0x2545_f491_4f6c_dd1d)
  }

  pub fn below(&mut self, n: usize) -> usize {
    (self.next() % n as u64) as usize
  }

  pub fn pick<'a, T>(&mut self, items: &'a [T]) -> &'a T {
    &items[self.below(items.len())]
  }

  /// Sorted random cut points in `1..len`.
  pub fn cuts(&mut self, len: usize, n: usize) -> Vec<usize> {
    if len < 2 {
      return Vec::new();
    }
    let mut cuts: Vec<usize> = (0..n).map(|_| 1 + self.below(len - 1)).collect();
    cuts.sort_unstable();
    cuts.dedup();
    cuts
  }
}
