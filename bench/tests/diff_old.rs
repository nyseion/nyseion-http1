//! Differential test against the rimu-ws parser that rimu-http1 replaces
//! (`rimu_ws::http1::parse_request`), on its test corpus (the ported inputs), the realistic
//! corpus, generated requests and mutated ones.
//!
//! - When both accept: method, version, path, query, every field, framing, keep-alive and head
//!   length agree exactly.
//! - Accept/reject disagreements must be one of the intended changes:
//!   CONNECT only with authority-form `host:port` and asterisk-form only for OPTIONS
//!   (RFC 9112 §3.2.3–3.2.4), and the 8 KiB line limit (rimu-ws: 16 KiB for the head only).
//! - When both reject, the status codes agree, except where rimu-ws checks the whole head
//!   before the request line (UTF-8, head size, bare LF) and rimu-http1 reports the first
//!   problem in byte order.
//!
//! Run with `--nocapture` to see the tallies.

#[path = "../../tests/common/mod.rs"]
mod common;

use common::{
  Outcome, Req, Rng,
  corpus::{gen_request, mutate, requests},
  ported_inputs::{PORTED, ported_generated},
  req_whole,
};
use rimu_http1::{BodyKind, Error};
use rimu_ws::http1::{
  BodyKind as OldKind, ParseOutcome, ParseScratch, error_status, parse_request,
};
use std::collections::BTreeMap;

#[derive(Debug, PartialEq)]
struct Old {
  method: String,
  http10: bool,
  path: String,
  query: String,
  headers: Vec<(String, String)>,
  body: BodyKind,
  keep_alive: bool,
  head_len: usize,
}

fn old(buf: &[u8]) -> Result<Option<Old>, u16> {
  let mut scratch = ParseScratch::new();
  match parse_request(buf, &mut scratch) {
    Err(e) => Err(u16::from(error_status(&e))),
    Ok(ParseOutcome::Partial) => Ok(None),
    Ok(ParseOutcome::Complete { request, head_len }) => Ok(Some(Old {
      method: format!("{:?}", request.method).to_uppercase(),
      http10: request.version == rimu_ws::http::Version::Http1,
      path: request.path.into(),
      query: request.query.into(),
      headers: request.headers.iter().map(|(n, v)| ((*n).into(), (*v).into())).collect(),
      body: match request.body_kind {
        OldKind::None => BodyKind::None,
        OldKind::ContentLength(n) => BodyKind::ContentLength(n as u64),
        OldKind::Chunked => BodyKind::Chunked,
      },
      keep_alive: request.keep_alive,
      head_len,
    })),
  }
}

fn show(buf: &[u8]) -> String {
  format!("{:?}", String::from_utf8_lossy(&buf[..buf.len().min(300)]))
}

fn has_bare_lf(buf: &[u8]) -> bool {
  buf.iter().enumerate().any(|(i, b)| *b == b'\n' && (i == 0 || buf[i - 1] != b'\r'))
}

fn head_of(buf: &[u8]) -> &[u8] {
  let skip = if buf.starts_with(b"\r\n") { 2 } else { 0 };
  let b = &buf[skip..];
  match b.windows(4).position(|w| w == b"\r\n\r\n") {
    Some(p) => &b[..p + 4],
    None => b,
  }
}

fn compare(buf: &[u8], tally: &mut BTreeMap<String, usize>) {
  let new = req_whole(buf);
  let theirs = old(buf);
  let key = match (&new, &theirs) {
    (Outcome::Complete(r), Ok(Some(o))) => {
      let r: &Req = r;
      let mine = Old {
        method: r.method_str.clone(),
        http10: r.version == rimu_http1::Version::Http10,
        path: r.path.clone(),
        query: r.query.clone(),
        headers: r.headers.clone(),
        body: r.body,
        keep_alive: r.keep_alive,
        head_len: r.head_len,
      };
      assert_eq!(&mine, o, "{}", show(buf));
      "both accept: all fields agree".to_string()
    }
    (Outcome::Error(e), Ok(Some(o))) => {
      let c = match e {
        Error::InvalidTarget if o.method == "CONNECT" => {
          "CONNECT target not authority-form host:port (RFC 9112 §3.2.3)"
        }
        Error::InvalidTarget if o.path == "*" => {
          "asterisk-form for a method other than OPTIONS (RFC 9112 §3.2.4)"
        }
        Error::HeadTooLarge | Error::UriTooLong
          if buf.split(|b| *b == b'\n').any(|l| l.len() > 8193) =>
        {
          "line over the 8 KiB line limit"
        }
        _ => panic!("unexplained: rimu-http1 {e:?}, rimu-ws accepts {}", show(buf)),
      };
      format!("rimu-http1 rejects, rimu-ws accepts: {c}")
    }
    (Outcome::Complete(_), Err(s)) => panic!("rimu-ws {s}, rimu-http1 accepts {}", show(buf)),
    (Outcome::Error(e), Err(s)) if e.status() == *s => "both reject, same status".to_string(),
    (Outcome::Error(e), Err(s)) => {
      let head = head_of(buf);
      let c = if std::str::from_utf8(head).is_err() {
        "rimu-ws checks UTF-8 of the whole head first"
      } else if *s == 431 || *s == 414 {
        "rimu-ws checks the head size first"
      } else if has_bare_lf(head) {
        "rimu-ws checks bare LF in the whole head first"
      } else if *e == Error::InvalidTarget
        && (buf.starts_with(b"CONNECT ") || buf.windows(3).any(|w| w == b" * "))
      {
        "CONNECT / asterisk-form rule, judged before a later error"
      } else {
        panic!("statuses differ: rimu-http1 {e:?} ({}), rimu-ws {s}: {}", e.status(), show(buf))
      };
      format!("both reject, status differs: {c}")
    }
    (Outcome::Partial, Ok(None)) => "both partial".to_string(),
    // rimu-http1 reports an error as soon as its bytes arrive; rimu-ws once the head is whole.
    (Outcome::Error(_), Ok(None)) => "rimu-http1 rejects early, rimu-ws partial".to_string(),
    (Outcome::Partial, Err(s)) => {
      // rimu-ws rejects a bare LF or an oversized buffer before the head is complete.
      assert!(
        has_bare_lf(buf) || *s == 431 || *s == 414,
        "rimu-ws {s}, rimu-http1 partial {}",
        show(buf)
      );
      "rimu-ws rejects early (bare LF / size), rimu-http1 partial".to_string()
    }
    (Outcome::Partial, Ok(Some(_))) | (Outcome::Complete(_), Ok(None)) => {
      panic!("completion differs {new:?} {theirs:?} {}", show(buf))
    }
  };
  *tally.entry(key).or_insert(0) += 1;
}

#[test]
fn agrees_with_rimu_ws() {
  let mut rng = Rng(21);
  let mut tally = BTreeMap::new();
  let mut seeds: Vec<Vec<u8>> = PORTED.iter().map(|b| b.to_vec()).collect();
  seeds.extend(ported_generated());
  seeds.extend(requests());
  for _ in 0..5000 {
    seeds.push(gen_request(&mut rng));
  }
  for buf in &seeds {
    compare(buf, &mut tally);
  }
  for seed in &seeds {
    for _ in 0..6 {
      compare(&mutate(&mut rng, seed), &mut tally);
    }
  }
  for (k, n) in &tally {
    println!("{n:>7}  {k}");
  }
  assert!(tally["both accept: all fields agree"] > 5000);
}
