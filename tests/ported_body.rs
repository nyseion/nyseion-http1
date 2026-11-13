//! Every test of the rimu-ws body decoder (`wtx/src/http1/body.rs`), adapted to this API: the
//! `feed(input, &mut Vec)` of rimu-ws is `feed(input, |data| out.extend_from_slice(data))`.

use rimu_http1::{BodyDecoder, BodyKind, BodyStatus};

fn feed(
  decoder: &mut BodyDecoder,
  input: &[u8],
  out: &mut Vec<u8>,
) -> Result<BodyStatus, rimu_http1::Error> {
  decoder.feed(input, |d| out.extend_from_slice(d))
}

fn byte_wise(input: &[u8]) -> (Vec<u8>, usize) {
  let mut decoder = BodyDecoder::new(BodyKind::Chunked);
  let mut out = Vec::new();
  let mut total = 0;
  for (idx, byte) in input.iter().enumerate() {
    match feed(&mut decoder, core::slice::from_ref(byte), &mut out).unwrap() {
      BodyStatus::NeedMore => {
        assert!(idx + 1 < input.len());
        total += 1;
      }
      BodyStatus::Complete { consumed } => {
        assert_eq!(idx + 1, input.len());
        total += consumed;
      }
    }
  }
  (out, total)
}

fn rejects(input: &[u8]) -> bool {
  BodyDecoder::new(BodyKind::Chunked).feed(input, |_| {}).is_err()
}

#[test]
fn content_length_exact() {
  let mut decoder = BodyDecoder::new(BodyKind::ContentLength(2));
  let mut out = Vec::new();
  assert_eq!(feed(&mut decoder, b"20", &mut out).unwrap(), BodyStatus::Complete { consumed: 2 });
  assert_eq!(out, b"20");
}

#[test]
fn content_length_split() {
  let mut decoder = BodyDecoder::new(BodyKind::ContentLength(2));
  let mut out = Vec::new();
  assert_eq!(feed(&mut decoder, b"2", &mut out).unwrap(), BodyStatus::NeedMore);
  assert_eq!(feed(&mut decoder, b"0", &mut out).unwrap(), BodyStatus::Complete { consumed: 1 });
  assert_eq!(out, b"20");
}

#[test]
fn content_length_leaves_pipelined_bytes() {
  let mut decoder = BodyDecoder::new(BodyKind::ContentLength(2));
  let mut out = Vec::new();
  assert_eq!(feed(&mut decoder, b"20GET", &mut out).unwrap(), BodyStatus::Complete { consumed: 2 });
  assert_eq!(out, b"20");
}

#[test]
fn empty_bodies_complete_at_once() {
  let mut out = Vec::new();
  let mut decoder = BodyDecoder::new(BodyKind::None);
  assert_eq!(feed(&mut decoder, b"GET", &mut out).unwrap(), BodyStatus::Complete { consumed: 0 });
  let mut decoder = BodyDecoder::new(BodyKind::ContentLength(0));
  assert_eq!(feed(&mut decoder, b"", &mut out).unwrap(), BodyStatus::Complete { consumed: 0 });
  assert!(out.is_empty());
}

#[test]
fn chunked_single() {
  let mut decoder = BodyDecoder::new(BodyKind::Chunked);
  let mut out = Vec::new();
  let input = b"2\r\n20\r\n0\r\n\r\n";
  assert_eq!(
    feed(&mut decoder, input, &mut out).unwrap(),
    BodyStatus::Complete { consumed: input.len() }
  );
  assert_eq!(out, b"20");
}

#[test]
fn chunked_split_mid_size() {
  let (out, total) = byte_wise(b"a\r\n0123456789\r\n0\r\n\r\n");
  assert_eq!(out, b"0123456789");
  assert_eq!(total, 20);
}

#[test]
fn chunked_split_mid_terminator() {
  let input = b"2\r\n20\r\n0\r\n\r\n";
  let (out, total) = byte_wise(input);
  assert_eq!(out, b"20");
  assert_eq!(total, input.len());
}

#[test]
fn chunked_zero_only() {
  let mut decoder = BodyDecoder::new(BodyKind::Chunked);
  let mut out = Vec::new();
  assert_eq!(
    feed(&mut decoder, b"0\r\n\r\n", &mut out).unwrap(),
    BodyStatus::Complete { consumed: 5 }
  );
  assert!(out.is_empty());
}

#[test]
fn chunked_multi_chunk_extension_trailer_and_pipelined() {
  let mut decoder = BodyDecoder::new(BodyKind::Chunked);
  let mut out = Vec::new();
  let input = b"3;ext=1\r\nabc\r\nA\r\n0123456789\r\n0\r\nX-T: v\r\n\r\nGET /";
  assert_eq!(
    feed(&mut decoder, input, &mut out).unwrap(),
    BodyStatus::Complete { consumed: input.len() - 5 }
  );
  assert_eq!(out, b"abc0123456789");
}

#[test]
fn chunked_split_multidigit_size() {
  let input = b"10\r\n0123456789abcdef\r\n0\r\n\r\n";
  let (out, total) = byte_wise(input);
  assert_eq!(out, b"0123456789abcdef");
  assert_eq!(total, input.len());
}

#[test]
fn rejects_bare_lf_in_chunk_ext() {
  assert!(rejects(b"2;ext\n=1\r\n20\r\n0\r\n\r\n"));
}

#[test]
fn rejects_bare_lf_in_trailer() {
  assert!(rejects(b"0\r\nX: a\nY: b\r\n\r\n"));
}

#[test]
fn rejects_bare_lf_at_trailer_start() {
  assert!(rejects(b"0\r\n\n"));
}

#[test]
fn rejects_bad_chunk_size() {
  assert!(rejects(b"zz\r\n"));
  assert!(rejects(b"\r\n"));
}

#[test]
fn rejects_chunk_size_overflow() {
  assert!(rejects(b"fffffffffffffffffffffffff\r\n"));
}

#[test]
fn rejects_missing_chunk_terminator() {
  assert!(rejects(b"2\r\n20XX"));
}

// ---- Chunked shapes from lighttpd and llhttp ----

// lighttpd answers uppercase hex chunk sizes; the decoder takes `A` for 10.
#[test]
fn chunked_uppercase_hex_size() {
  let mut decoder = BodyDecoder::new(BodyKind::Chunked);
  let mut out = Vec::new();
  let input = b"A\r\n0123456789\r\n0\r\n\r\n";
  assert_eq!(
    feed(&mut decoder, input, &mut out).unwrap(),
    BodyStatus::Complete { consumed: input.len() }
  );
  assert_eq!(out, b"0123456789");
}

// llhttp refuses a space after the chunk size (httpd tolerates up to ten) and the `0x`
// prefix some clients send.
#[test]
fn chunked_size_junk_is_rejected() {
  assert!(rejects(b"a \r\n0123456789\r\n0\r\n\r\n"));
  assert!(rejects(b"0x10\r\n\r\n"));
}

// A bare CR inside chunk extensions derails the terminator: lighttpd answers 400 to `2;a\rb`.
#[test]
fn chunked_extension_bare_cr_is_rejected() {
  assert!(rejects(b"2;a\rb\r\n20\r\n0\r\n\r\n"));
}

// The final chunk may carry extensions: lighttpd answers 200 to `0; comment`.
#[test]
fn chunked_final_chunk_extensions() {
  let mut decoder = BodyDecoder::new(BodyKind::Chunked);
  let mut out = Vec::new();
  let input = b"2\r\n20\r\n0; comment\r\n\r\n";
  assert_eq!(
    feed(&mut decoder, input, &mut out).unwrap(),
    BodyStatus::Complete { consumed: input.len() }
  );
  assert_eq!(out, b"20");
}

// ---- Trailer limits ----

// Envoy bounds the trailer-field count like the header count; 150 of them must not complete
// a body.
#[test]
fn trailer_count_is_bounded() {
  let mut input = b"0\r\n".to_vec();
  for _ in 0..150 {
    input.extend_from_slice(b"X-Many: v\r\n");
  }
  input.extend_from_slice(b"\r\n");
  assert!(rejects(&input), "150 trailer fields were accepted");
}

// Trailer fields are HTTP fields (RFC 9112 §7.1): llhttp and Envoy validate their names and
// values.
#[test]
fn trailer_fields_are_validated() {
  for case in
    [b"0\r\nX-T\x01: v\r\n\r\n".as_slice(), b"0\r\n: v\r\n\r\n", b"0\r\nX-T: \x7f\r\n\r\n"]
  {
    assert!(rejects(case), "{case:?}");
  }
}
