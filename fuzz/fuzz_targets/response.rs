//! Responses: no panics, and whole equals split.
#![no_main]

use libfuzzer_sys::fuzz_target;
use rimu_http1::{Config, Error, Method, ResponseParser, Status};

#[derive(Debug, PartialEq)]
enum Out {
  Complete(String),
  Partial,
  Error(Error),
}

fn step(p: &mut ResponseParser<16>, buf: &[u8], m: Method) -> Out {
  match p.parse(buf, m) {
    Ok(Status::Complete(r)) => Out::Complete(format!("{r:?}")),
    Ok(Status::Partial) => Out::Partial,
    Err(e) => Out::Error(e),
  }
}

fuzz_target!(|data: &[u8]| {
  let Some((&[a, b], buf)) = data.split_first_chunk::<2>() else { return };
  let method = [Method::Get, Method::Head, Method::Connect, Method::Post][usize::from(a & 3)];
  let whole = step(&mut ResponseParser::new(Config::DEFAULT), buf, method);
  let mut p = ResponseParser::new(Config::DEFAULT);
  let stride = usize::from(b % 13) + 1;
  let mut out = Out::Partial;
  let mut end = 0;
  while end < buf.len() {
    end = (end + stride).min(buf.len());
    out = step(&mut p, &buf[..end], method);
    if out != Out::Partial {
      break;
    }
  }
  if buf.is_empty() {
    out = step(&mut p, buf, method);
  }
  assert_eq!(out, whole);
});
