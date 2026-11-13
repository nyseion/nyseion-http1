//! Differential tests against httparse on corpus, ported, generated and mutated messages.
//!
//! - When both accept, method, target, version, status, reason, head length and every field
//!   (name, and value after OWS trimming) agree exactly. (One documented difference: for an
//!   absolute-form target rimu-http1 reports the target's authority as `Host`.)
//! - Every input that one accepts and the other rejects must fall in a category of the README's
//!   strictness table; an unexplained disagreement fails the test.
//!
//! Run with `--nocapture` to see how often each category occurred.

mod common;

use common::{
  Outcome, Req, Res, Rng,
  corpus::{gen_request, gen_response, mutate, requests, responses},
  ported_inputs::{PORTED, ported_generated},
  req_whole, res_whole,
};
use rimu_http1::{Error, Method, Version};
use std::collections::BTreeMap;

#[derive(Debug)]
struct HReq {
  method: String,
  target: String,
  version: u8,
  headers: Vec<(String, Vec<u8>)>,
  len: usize,
}

/// The input for a failure message, cut to 300 bytes.
fn show(buf: &[u8]) -> String {
  let s = String::from_utf8_lossy(&buf[..buf.len().min(300)]).into_owned();
  if buf.len() > 300 { format!("{s:?}... ({} bytes)", buf.len()) } else { format!("{s:?}") }
}

fn trim(v: &[u8]) -> &[u8] {
  let s = v.iter().position(|b| *b != b' ' && *b != b'\t').unwrap_or(v.len());
  let e = v.iter().rposition(|b| *b != b' ' && *b != b'\t').map_or(s, |e| e + 1);
  &v[s..e]
}

fn httparse_req(buf: &[u8]) -> Result<Option<HReq>, httparse::Error> {
  let mut headers = [httparse::EMPTY_HEADER; 64];
  let mut req = httparse::Request::new(&mut headers);
  Ok(match req.parse(buf)? {
    httparse::Status::Partial => None,
    httparse::Status::Complete(len) => Some(HReq {
      method: req.method.unwrap().into(),
      target: req.path.unwrap().into(),
      version: req.version.unwrap(),
      headers: req.headers.iter().map(|h| (h.name.into(), trim(h.value).to_vec())).collect(),
      len,
    }),
  })
}

/// The README category of an input rimu-http1 rejects and httparse accepts, from rimu-http1's
/// error and the bytes. `None`: unexplained.
fn reject_category(err: Error, buf: &[u8], h: &HReq) -> Option<&'static str> {
  let target = h.target.as_bytes();
  Some(match err {
    Error::InvalidLineEnding => "bare LF line ending (RFC 9112 §2.2 allows rejecting it)",
    Error::UriTooLong | Error::HeadTooLarge | Error::TooManyHeaders => {
      "over the configured line, head or field-count limit (414/431)"
    }
    Error::InvalidMethod
      if buf.starts_with(b"\r\n\r\n") || buf.starts_with(b"\r\n\n") || buf.starts_with(b"\n") =>
    {
      "more than one empty line, or a bare LF, before the request line (RFC 9112 §2.2: one is skipped)"
    }
    Error::UnknownMethod | Error::InvalidMethod => {
      "method not one of the RFC 9110 methods (RFC 9110 §9.1: 501; opt-in `allow_extension_methods`)"
    }
    Error::InvalidTarget if target.contains(&b'#') => {
      "fragment in the target (RFC 9110 §7.1, RFC 9112 §3.2)"
    }
    Error::InvalidTarget if target.iter().any(|b| *b >= 0x80) => {
      "raw non-ASCII in the target (RFC 9112 §3.2, RFC 3986 §2)"
    }
    Error::InvalidTarget => {
      "target form not allowed for the method, or bad absolute-form authority (RFC 9112 §3.2, RFC 9110 §4.2.4)"
    }
    Error::InvalidHeaderValue => "field value not UTF-8 (obs-text is obsolete, RFC 9110 §5.5)",
    Error::MissingHost => "HTTP/1.1 request without Host (RFC 9112 §3.2)",
    Error::DuplicateHost => "more than one Host (RFC 9112 §3.2)",
    Error::InvalidHost => "Host not host[:port] (RFC 9112 §3.2, RFC 3986 §3.2.2)",
    Error::InvalidContentLength => "Content-Length not a decimal number (RFC 9110 §8.6)",
    Error::DuplicateContentLength => "more than one Content-Length (RFC 9110 §8.6, RFC 9112 §6.3)",
    Error::ContentLengthWithTransferEncoding => {
      "both Content-Length and Transfer-Encoding (RFC 9112 §6.3)"
    }
    Error::InvalidTransferEncoding => {
      "Transfer-Encoding not ending in chunked once (RFC 9112 §6.1, §6.3)"
    }
    Error::UnsupportedTransferCoding => {
      "transfer coding other than chunked in a request (RFC 9112 §6.1: 501)"
    }
    _ => return None,
  })
}

/// Category of an input rimu-http1 accepts and httparse rejects.
fn accept_category(req: &Req, err: httparse::Error) -> Option<&'static str> {
  match err {
    httparse::Error::Version if req.version == Version::Http11 => {
      Some("httparse rejects HTTP/1.2..1.9; RFC 9112 §2.5 treats them as 1.1")
    }
    _ => None,
  }
}

fn compare_request(buf: &[u8], tally: &mut BTreeMap<String, usize>) {
  let ours = req_whole(buf);
  let theirs = httparse_req(buf);
  let key = match (&ours, &theirs) {
    (Outcome::Complete(r), Ok(Some(h))) => {
      assert_eq!(r.method_str, h.method, "{buf:?}");
      assert_eq!(r.target, h.target, "{buf:?}");
      assert_eq!(r.version, if h.version == 0 { Version::Http10 } else { Version::Http11 });
      assert_eq!(r.head_len, h.len, "{:?}", show(buf));
      assert_eq!(r.headers.len(), h.headers.len());
      let absolute =
        r.target.starts_with("http://") || r.target.to_ascii_lowercase().starts_with("http");
      for ((name, value), (hname, hvalue)) in r.headers.iter().zip(&h.headers) {
        assert_eq!(name, hname);
        if absolute && name.eq_ignore_ascii_case("host") {
          continue;
        }
        assert_eq!(value.as_bytes(), hvalue.as_slice(), "{:?}", show(buf));
      }
      "both accept: fields agree".to_string()
    }
    (Outcome::Error(e), Ok(Some(h))) => match reject_category(*e, buf, h) {
      Some(c) => format!("rimu-http1 rejects: {c}"),
      None => {
        panic!("unexplained: rimu-http1 {e:?}, httparse accepts {:?}", show(buf))
      }
    },
    (Outcome::Complete(r), Err(e)) => match accept_category(r, *e) {
      Some(c) => format!("httparse rejects: {c}"),
      None => {
        panic!("unexplained: httparse {e:?}, rimu-http1 accepts {:?}", show(buf))
      }
    },
    (Outcome::Error(_), Err(_)) => "both reject".to_string(),
    (Outcome::Partial, Ok(None)) => "both partial".to_string(),
    // rimu-http1 reports errors as soon as they arrive; httparse may still wait.
    (Outcome::Error(_), Ok(None)) => "rimu-http1 rejects early, httparse partial".to_string(),
    // rimu-http1 judges a method that is not a token once the request line is complete (as
    // rimu-ws does, so a bad version still answers 505); httparse rejects at the byte.
    (Outcome::Partial, Err(httparse::Error::Token)) if !buf.contains(&b'\n') => {
      "httparse rejects a bad method byte early, rimu-http1 at the end of the line".to_string()
    }
    (Outcome::Partial, Err(e)) => {
      panic!("httparse {e:?}, rimu-http1 partial {:?}", show(buf))
    }
    (Outcome::Partial, Ok(Some(_))) | (Outcome::Complete(_), Ok(None)) => {
      panic!("completion differs {ours:?} {theirs:?} {:?}", show(buf))
    }
  };
  *tally.entry(key).or_insert(0) += 1;
}

fn print(tally: &BTreeMap<String, usize>) {
  for (k, n) in tally {
    println!("{n:>7}  {k}");
  }
}

#[test]
fn requests_agree_with_httparse() {
  let mut rng = Rng(11);
  let mut tally = BTreeMap::new();
  let mut seeds: Vec<Vec<u8>> = requests();
  seeds.extend(PORTED.iter().map(|b| b.to_vec()));
  seeds.extend(ported_generated());
  for buf in &seeds {
    compare_request(buf, &mut tally);
  }
  let mut generated = Vec::new();
  for _ in 0..4000 {
    let buf = gen_request(&mut rng);
    compare_request(&buf, &mut tally);
    generated.push(buf);
  }
  seeds.extend(generated);
  for seed in &seeds {
    for _ in 0..5 {
      compare_request(&mutate(&mut rng, seed), &mut tally);
    }
  }
  print(&tally);
  assert!(tally.get("both accept: fields agree").copied().unwrap_or(0) > 4000);
}

#[derive(Debug)]
struct HRes {
  version: u8,
  code: u16,
  reason: String,
  headers: Vec<(String, Vec<u8>)>,
  len: usize,
}

fn httparse_res(buf: &[u8]) -> Result<Option<HRes>, httparse::Error> {
  let mut headers = [httparse::EMPTY_HEADER; 64];
  let mut res = httparse::Response::new(&mut headers);
  Ok(match res.parse(buf)? {
    httparse::Status::Partial => None,
    httparse::Status::Complete(len) => Some(HRes {
      version: res.version.unwrap(),
      code: res.code.unwrap(),
      reason: res.reason.unwrap_or("").into(),
      headers: res.headers.iter().map(|h| (h.name.into(), trim(h.value).to_vec())).collect(),
      len,
    }),
  })
}

fn compare_response(method: Method, buf: &[u8], tally: &mut BTreeMap<String, usize>) {
  let ours = res_whole(buf, method);
  let theirs = httparse_res(buf);
  let key = match (&ours, &theirs) {
    (Outcome::Complete(r), Ok(Some(h))) => {
      let r: &Res = r;
      assert_eq!(r.version, if h.version == 0 { Version::Http10 } else { Version::Http11 });
      assert_eq!((r.status, r.head_len), (h.code, h.len), "{:?}", show(buf));
      // httparse reports a reason phrase with non-ASCII bytes as empty.
      if !(h.reason.is_empty() && !r.reason.is_ascii()) {
        assert_eq!(r.reason, h.reason, "{:?}", show(buf));
      }
      let ours: Vec<(&str, &[u8])> =
        r.headers.iter().map(|(n, v)| (n.as_str(), v.as_bytes())).collect();
      let theirs: Vec<(&str, &[u8])> =
        h.headers.iter().map(|(n, v)| (n.as_str(), v.as_slice())).collect();
      assert_eq!(ours, theirs, "{:?}", show(buf));
      "both accept: fields agree".to_string()
    }
    (Outcome::Error(e), Ok(Some(h))) => {
      let c = match e {
        Error::InvalidLineEnding => "bare LF line ending (RFC 9112 §2.2 allows rejecting it)",
        Error::InvalidVersion if buf.starts_with(b"\r\n") || buf.starts_with(b"\n") => {
          "empty line before the status line (RFC 9112 §2.2 skips them before request lines only)"
        }
        Error::HeadTooLarge | Error::TooManyHeaders => "over the configured limits (431)",
        Error::InvalidStatus if !(100..=599).contains(&h.code) => {
          "status code outside 100-599 (RFC 9110 §15)"
        }
        Error::InvalidStatus => "no space after the status code (RFC 9112 §4)",
        Error::InvalidHeaderValue => {
          "field value or reason phrase not UTF-8 (obs-text is obsolete, RFC 9110 §5.5)"
        }
        Error::InvalidContentLength => "Content-Length not a decimal number (RFC 9110 §8.6)",
        Error::DuplicateContentLength => {
          "more than one Content-Length (RFC 9110 §8.6, RFC 9112 §6.3)"
        }
        Error::ContentLengthWithTransferEncoding => {
          "both Content-Length and Transfer-Encoding (RFC 9112 §6.3)"
        }
        Error::InvalidTransferEncoding => {
          "Transfer-Encoding with chunked twice or not last (RFC 9112 §6.1)"
        }
        _ => panic!("unexplained: rimu-http1 {e:?}, httparse accepts {:?}", show(buf)),
      };
      format!("rimu-http1 rejects: {c}")
    }
    (Outcome::Complete(r), Err(e)) => match e {
      httparse::Error::Version if r.version == Version::Http11 => {
        "httparse rejects: HTTP/1.2..1.9 (RFC 9112 §2.5 treats them as 1.1)".to_string()
      }
      _ => {
        panic!("unexplained: httparse {e:?}, rimu-http1 accepts {:?}", show(buf))
      }
    },
    (Outcome::Error(_), Err(_)) => "both reject".to_string(),
    (Outcome::Partial, Ok(None)) => "both partial".to_string(),
    (Outcome::Error(_), Ok(None)) => "rimu-http1 rejects early, httparse partial".to_string(),
    (a, b) => panic!("outcomes differ {a:?} {b:?} {:?}", show(buf)),
  };
  *tally.entry(key).or_insert(0) += 1;
}

#[test]
fn responses_agree_with_httparse() {
  let mut rng = Rng(12);
  let mut tally = BTreeMap::new();
  let mut seeds = responses();
  for _ in 0..4000 {
    seeds.push(gen_response(&mut rng));
  }
  for (method, buf) in &seeds {
    compare_response(*method, buf, &mut tally);
    for _ in 0..4 {
      compare_response(*method, &mutate(&mut rng, buf), &mut tally);
    }
  }
  print(&tally);
  assert!(tally.get("both accept: fields agree").copied().unwrap_or(0) > 3000);
}
