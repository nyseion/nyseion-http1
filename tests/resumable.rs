//! Resumability: feeding a message in pieces — cut at every offset, at random multi-splits, and
//! byte by byte, each piece in a freshly allocated buffer — gives exactly the outcome of
//! feeding it whole (every field, or the same error), for every ported test input, a corpus of
//! realistic messages, generated messages and mutated (mostly invalid) ones, with the default
//! and with tight limits.

mod common;

use common::{
  BodyOutcome, Outcome, Rng, body_split,
  corpus::{gen_request, gen_response, mutate, requests, responses},
  ported_inputs::{PORTED, ported_generated},
  req_split_with, req_whole_with, res_split, res_whole,
};
use nyseion_http1::{BodyKind, Config, Method, RequestParser};

const TIGHT: Config =
  Config { max_head_len: 300, max_line_len: 70, max_headers: 5, allow_extension_methods: false };
const LENIENT: Config = Config { allow_extension_methods: true, ..Config::DEFAULT };

/// Every single cut for small inputs (a sample for large ones), byte by byte, and random
/// multi-splits.
fn check_request(buf: &[u8], config: Config, rng: &mut Rng) {
  let whole = req_whole_with(buf, config);
  let len = buf.len();
  let single: Vec<usize> = if len <= 2048 {
    (1..len).collect()
  } else {
    (0..64).map(|_| 1 + rng.below(len - 1)).collect()
  };
  for cut in single {
    assert_eq!(
      req_split_with(buf, &[cut], config),
      whole,
      "cut {cut} of {:?}",
      String::from_utf8_lossy(buf)
    );
  }
  for _ in 0..8 {
    let n = 1 + rng.below(12);
    let cuts = rng.cuts(len, n);
    assert_eq!(
      req_split_with(buf, &cuts, config),
      whole,
      "cuts {cuts:?} of {:?}",
      String::from_utf8_lossy(buf)
    );
  }
  // Byte by byte: copies for small inputs, the same buffer for large ones (linear total work).
  if len <= 4096 {
    let all: Vec<usize> = (1..len).collect();
    assert_eq!(
      req_split_with(buf, &all, config),
      whole,
      "byte by byte {:?}",
      String::from_utf8_lossy(buf)
    );
  } else {
    let mut parser = RequestParser::new(config);
    let mut out = Outcome::Partial;
    for n in 1..=len {
      out = common::req_step(&mut parser, &buf[..n]);
      if out != Outcome::Partial {
        break;
      }
    }
    assert_eq!(out, whole, "byte by byte (large)");
  }
}

fn check_response(method: Method, buf: &[u8], rng: &mut Rng) {
  let whole = res_whole(buf, method);
  let len = buf.len();
  for cut in 1..len {
    assert_eq!(
      res_split(buf, &[cut], method),
      whole,
      "cut {cut} of {:?}",
      String::from_utf8_lossy(buf)
    );
  }
  for _ in 0..8 {
    let n = 1 + rng.below(12);
    let cuts = rng.cuts(len, n);
    assert_eq!(res_split(buf, &cuts, method), whole, "cuts {cuts:?}");
  }
  let all: Vec<usize> = (1..len).collect();
  assert_eq!(
    res_split(buf, &all, method),
    whole,
    "byte by byte {:?}",
    String::from_utf8_lossy(buf)
  );
}

#[test]
fn ported_inputs_any_split() {
  let mut rng = Rng(1);
  let mut inputs: Vec<Vec<u8>> = PORTED.iter().map(|b| b.to_vec()).collect();
  inputs.extend(ported_generated());
  for buf in &inputs {
    for config in [Config::DEFAULT, TIGHT, LENIENT] {
      check_request(buf, config, &mut rng);
    }
  }
}

#[test]
fn corpus_requests_any_split() {
  let mut rng = Rng(2);
  for buf in requests() {
    assert!(
      matches!(req_whole_with(&buf, Config::DEFAULT), Outcome::Complete(_)),
      "{:?}",
      String::from_utf8_lossy(&buf)
    );
    for config in [Config::DEFAULT, TIGHT] {
      check_request(&buf, config, &mut rng);
    }
  }
}

#[test]
fn corpus_responses_any_split() {
  let mut rng = Rng(3);
  for (method, buf) in responses() {
    assert!(
      matches!(res_whole(&buf, method), Outcome::Complete(_)),
      "{:?}",
      String::from_utf8_lossy(&buf)
    );
    check_response(method, &buf, &mut rng);
  }
}

#[test]
fn generated_and_mutated_requests_any_split() {
  let mut rng = Rng(4);
  let mut seeds = requests();
  seeds.extend(PORTED.iter().map(|b| b.to_vec()));
  for _ in 0..150 {
    seeds.push(gen_request(&mut rng));
  }
  let mut kinds = std::collections::BTreeMap::new();
  for seed in &seeds {
    for _ in 0..6 {
      let buf = mutate(&mut rng, seed);
      if buf.len() > 3000 {
        continue;
      }
      let whole = req_whole_with(&buf, Config::DEFAULT);
      *kinds.entry(format!("{:?}", whole.err())).or_insert(0usize) += 1;
      check_request(&buf, Config::DEFAULT, &mut rng);
      if rng.below(4) == 0 {
        check_request(&buf, TIGHT, &mut rng);
      }
    }
  }
  // The mutations reach many different rules.
  assert!(kinds.len() >= 15, "{kinds:?}");
}

#[test]
fn generated_and_mutated_responses_any_split() {
  let mut rng = Rng(5);
  let mut seeds = responses();
  for _ in 0..150 {
    seeds.push(gen_response(&mut rng));
  }
  for (method, seed) in &seeds {
    check_response(*method, seed, &mut rng);
    for _ in 0..4 {
      check_response(*method, &mutate(&mut rng, seed), &mut rng);
    }
  }
}

/// A random valid chunked body: sizes, extensions, trailers.
fn gen_chunked(rng: &mut Rng) -> Vec<u8> {
  let mut s = Vec::new();
  for _ in 0..rng.below(5) {
    let n = 1 + rng.below(40);
    s.extend_from_slice(format!("{n:x}").as_bytes());
    match rng.below(5) {
      0 => s.extend_from_slice(b";a=b"),
      1 => s.extend_from_slice(b" ; name = \"quoted \\\" value\" ;flag"),
      _ => {}
    }
    s.extend_from_slice(b"\r\n");
    s.extend((0..n).map(|k| b'a' + (k % 26) as u8));
    s.extend_from_slice(b"\r\n");
  }
  s.extend_from_slice(b"0\r\n");
  for _ in 0..rng.below(3) {
    s.extend_from_slice(b"X-Trailer: v\r\n");
  }
  s.extend_from_slice(b"\r\nNEXT");
  s
}

fn check_body(kind: BodyKind, input: &[u8], config: Config, rng: &mut Rng) {
  let whole: BodyOutcome = body_split(kind, input, &[], config);
  for cut in 1..input.len() {
    assert_eq!(
      body_split(kind, input, &[cut], config),
      whole,
      "{kind:?} cut {cut} {:?}",
      String::from_utf8_lossy(input)
    );
  }
  for _ in 0..8 {
    let n = 1 + rng.below(10);
    let cuts = rng.cuts(input.len(), n);
    assert_eq!(body_split(kind, input, &cuts, config), whole);
  }
  let all: Vec<usize> = (1..input.len()).collect();
  assert_eq!(body_split(kind, input, &all, config), whole, "byte by byte");
}

#[test]
fn bodies_any_split() {
  let mut rng = Rng(6);
  let small = Config { max_line_len: 20, max_head_len: 30, max_headers: 2, ..Config::DEFAULT };
  for _ in 0..200 {
    let body = gen_chunked(&mut rng);
    let (data, consumed) = body_split(BodyKind::Chunked, &body, &[], Config::DEFAULT).unwrap();
    assert_eq!(consumed, Some(body.len() - 4));
    assert!(data.iter().all(u8::is_ascii_lowercase));
    check_body(BodyKind::Chunked, &body, Config::DEFAULT, &mut rng);
    check_body(BodyKind::Chunked, &body, small, &mut rng);
    for _ in 0..4 {
      check_body(BodyKind::Chunked, &mutate(&mut rng, &body), Config::DEFAULT, &mut rng);
    }
    let n = rng.below(body.len() + 3) as u64;
    check_body(BodyKind::ContentLength(n), &body, Config::DEFAULT, &mut rng);
    check_body(BodyKind::UntilClose, &body, Config::DEFAULT, &mut rng);
  }
}
