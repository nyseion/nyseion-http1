//! Seeded randomized tests on arbitrary bytes: no panics, invariants hold, results do not depend
//! on the split, and the work of feeding a head byte by byte is linear.
//!
//! `RIMU_HTTP1_RANDOM_ITERS` scales the number of inputs (default 20 000 per test).

mod common;

use common::{Outcome, Rng, body_split, req_split_with, req_whole_with, res_split, res_whole};
use rimu_http1::{BodyDecoder, BodyKind, Config, Method, RequestParser, Status};
use std::time::Instant;

fn iters() -> usize {
  std::env::var("RIMU_HTTP1_RANDOM_ITERS").ok().and_then(|s| s.parse().ok()).unwrap_or(20_000)
}

/// Random bytes, biased towards the bytes HTTP heads are made of so that parsing gets deep.
fn random_input(rng: &mut Rng) -> Vec<u8> {
  const PIECES: &[&[u8]] = &[
    b"GET ",
    b"POST ",
    b"CONNECT ",
    b"OPTIONS ",
    b"HTTP/1.1",
    b"HTTP/1.0",
    b"HTTP/1.1 200 OK",
    b"\r\n",
    b"\r\n\r\n",
    b"Host: a",
    b": ",
    b"Content-Length: 5",
    b"Transfer-Encoding: chunked",
    b"Connection: close",
    b"/",
    b"?",
    b"http://h",
    b"*",
    b" ",
    b"\t",
    b"\n",
    b"\r",
    b"\xc3\xa9",
    b"\xff",
    b"\0",
    b"#",
    b"@",
    b":",
    b"0",
    b"9",
    b"a",
    b"Z",
    b"-",
  ];
  let mut v = Vec::new();
  let n = rng.below(40);
  for _ in 0..n {
    if rng.below(4) == 0 {
      v.push(rng.next() as u8);
    } else {
      v.extend_from_slice(rng.pick(PIECES));
    }
  }
  v
}

const CONFIGS: [Config; 2] = [
  Config::DEFAULT,
  Config { max_head_len: 64, max_line_len: 24, max_headers: 2, allow_extension_methods: true },
];

#[test]
fn random_requests() {
  let mut rng = Rng(31);
  for k in 0..iters() {
    let buf = random_input(&mut rng);
    let config = CONFIGS[k % 2];
    let whole = req_whole_with(&buf, config);
    if let Outcome::Complete(r) = &whole {
      assert!(r.head_len <= buf.len());
      assert!(r.headers.len() <= usize::from(config.max_headers));
    }
    let n = 1 + rng.below(6);
    let cuts = rng.cuts(buf.len(), n);
    assert_eq!(req_split_with(&buf, &cuts, config), whole, "{buf:?} {cuts:?}");
  }
}

#[test]
fn random_responses() {
  let mut rng = Rng(32);
  for _ in 0..iters() {
    let mut buf = random_input(&mut rng);
    if rng.below(2) == 0 {
      buf.splice(0..0, b"HTTP/1.1 ".iter().copied());
    }
    let method = *rng.pick(&[Method::Get, Method::Head, Method::Connect]);
    let whole = res_whole(&buf, method);
    let n = 1 + rng.below(6);
    let cuts = rng.cuts(buf.len(), n);
    assert_eq!(res_split(&buf, &cuts, method), whole, "{buf:?} {cuts:?}");
  }
}

#[test]
fn random_bodies() {
  let mut rng = Rng(33);
  for _ in 0..iters() {
    let mut buf = Vec::new();
    for _ in 0..rng.below(30) {
      buf.extend_from_slice(rng.pick(&[
        &b"1"[..],
        b"a",
        b"F",
        b"0",
        b"\r\n",
        b";",
        b"=",
        b"\"",
        b"\\",
        b" ",
        b"x",
        b":",
        b"\xff",
        b"\n",
      ]));
    }
    let kind = *rng.pick(&[
      BodyKind::Chunked,
      BodyKind::Chunked,
      BodyKind::ContentLength(7),
      BodyKind::UntilClose,
    ]);
    let config = CONFIGS[rng.below(2)];
    let whole = body_split(kind, &buf, &[], config);
    if let Ok((data, consumed)) = &whole {
      assert!(data.len() <= buf.len());
      assert!(consumed.is_none_or(|c| c <= buf.len()));
    }
    let n = 1 + rng.below(6);
    let cuts = rng.cuts(buf.len(), n);
    assert_eq!(body_split(kind, &buf, &cuts, config), whole);
    // `finish` never panics either.
    let mut d = BodyDecoder::with_config(kind, &config);
    let _ = d.feed(&buf, |_| {});
    let _ = d.finish();
  }
}

/// Feeding a 16 KiB head byte by byte costs a constant factor more than parsing it whole, not a
/// factor proportional to its length (which a re-scanning parser pays: about 8000 here).
#[test]
fn byte_by_byte_work_is_linear() {
  let mut head = String::from("GET /x HTTP/1.1\r\nHost: a\r\n");
  let mut i = 0;
  while head.len() < 15_000 {
    head.push_str(&format!("X-Field-{i}: some value of moderate length {i}\r\n"));
    i += 1;
  }
  head.push_str("\r\n");
  let buf = head.as_bytes();
  let config = Config { max_headers: 1000, ..Config::DEFAULT };
  let mut parser = RequestParser::<1024>::new(config);
  let time = |f: &mut dyn FnMut()| {
    (0..5)
      .map(|_| {
        let t = Instant::now();
        f();
        t.elapsed().as_nanos()
      })
      .min()
      .unwrap()
  };
  let whole = time(&mut || assert!(matches!(parser.parse(buf), Ok(Status::Complete(_)))));
  let bytewise = time(&mut || {
    for n in 1..buf.len() {
      assert!(matches!(parser.parse(&buf[..n]), Ok(Status::Partial)));
    }
    assert!(matches!(parser.parse(buf), Ok(Status::Complete(_))));
  });
  let ratio = bytewise as f64 / whole as f64;
  println!("byte by byte / whole = {ratio:.0} for {} bytes", buf.len());
  assert!(ratio < 1000.0, "{ratio}");
}
