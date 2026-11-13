//! Behaviour beyond the ported rimu-ws tests: responses, the rules added here, the API, and the
//! body decoder's zero-copy and end-of-input handling.

mod common;

use common::{Outcome, req_whole, req_whole_with, res_whole};
use rimu_http1::{
  BodyDecoder, BodyKind, Config, Decoded, Error, Method, RequestParser, Status, Version,
};

fn req_err(raw: &[u8]) -> Error {
  req_whole(raw).err().unwrap_or_else(|| panic!("accepted {:?}", String::from_utf8_lossy(raw)))
}

fn res_err(raw: &[u8], method: Method) -> Error {
  res_whole(raw, method)
    .err()
    .unwrap_or_else(|| panic!("accepted {:?}", String::from_utf8_lossy(raw)))
}

// ---- Request target forms (RFC 9112 §3.2) ----

#[test]
fn connect_takes_only_authority_form_with_a_port() {
  assert_eq!(req_err(b"CONNECT /x HTTP/1.1\r\nHost: a\r\n\r\n"), Error::InvalidTarget);
  assert_eq!(req_err(b"CONNECT http://h:1/ HTTP/1.1\r\nHost: a\r\n\r\n"), Error::InvalidTarget);
  assert_eq!(req_err(b"CONNECT * HTTP/1.1\r\nHost: a\r\n\r\n"), Error::InvalidTarget);
  assert_eq!(req_err(b"CONNECT example.com HTTP/1.1\r\nHost: a\r\n\r\n"), Error::InvalidTarget);
  assert_eq!(req_err(b"CONNECT example.com: HTTP/1.1\r\nHost: a\r\n\r\n"), Error::InvalidTarget);
  assert_eq!(req_err(b"CONNECT :443 HTTP/1.1\r\nHost: a\r\n\r\n"), Error::InvalidTarget);
  assert_eq!(req_err(b"CONNECT u@h:443 HTTP/1.1\r\nHost: a\r\n\r\n"), Error::InvalidTarget);
  let r = req_whole(b"CONNECT [::1]:443 HTTP/1.1\r\nHost: [::1]:443\r\n\r\n").unwrap();
  assert_eq!((r.method, r.path.as_str(), r.query.as_str()), (Method::Connect, "[::1]:443", ""));
}

#[test]
fn asterisk_form_is_for_options_only() {
  assert_eq!(req_err(b"GET * HTTP/1.1\r\nHost: a\r\n\r\n"), Error::InvalidTarget);
  assert_eq!(req_err(b"POST * HTTP/1.1\r\nHost: a\r\n\r\n"), Error::InvalidTarget);
  assert_eq!(req_err(b"OPTIONS *x HTTP/1.1\r\nHost: a\r\n\r\n"), Error::InvalidTarget);
  assert_eq!(req_whole(b"OPTIONS * HTTP/1.1\r\nHost: a\r\n\r\n").unwrap().target, "*");
}

#[test]
fn target_bytes() {
  for bad in ["/a\tb", "/a\x7fb", "/a\x01", "/caf\u{e9}", "/x#y"] {
    let raw = format!("GET {bad} HTTP/1.1\r\nHost: a\r\n\r\n");
    assert_eq!(req_err(raw.as_bytes()), Error::InvalidTarget, "{bad:?}");
  }
  // Every other visible ASCII byte is passed through for the application to judge.
  let r = req_whole(b"GET /a|b{c}\"d<e>^`[]?q=\\ HTTP/1.1\r\nHost: a\r\n\r\n").unwrap();
  assert_eq!((r.path.as_str(), r.query.as_str()), ("/a|b{c}\"d<e>^`[]", "q=\\"));
  // Only the first `?` splits.
  let r = req_whole(b"GET /p?a?b=c HTTP/1.1\r\nHost: a\r\n\r\n").unwrap();
  assert_eq!((r.path.as_str(), r.query.as_str()), ("/p", "a?b=c"));
}

#[test]
fn version_errors_win_over_target_errors() {
  // As in rimu-ws: the request line is judged once complete, version first.
  assert_eq!(req_err(b"GET www.x HTTP/9.1\r\n\r\n"), Error::VersionNotSupported);
  assert_eq!(req_err(b"BREW / HTTP/9.1\r\n\r\n"), Error::VersionNotSupported);
  assert_eq!(req_err(b"GET  HTTP/9.1\r\n\r\n"), Error::VersionNotSupported);
  assert_eq!(req_err(b"BREW www.x HTTP/1.1\r\n\r\n"), Error::InvalidTarget);
}

// ---- Methods ----

#[test]
fn extension_methods_are_an_option() {
  let lenient = Config { allow_extension_methods: true, ..Config::DEFAULT };
  for (raw, method) in [
    (&b"PROPFIND /dav HTTP/1.1\r\nHost: a\r\n\r\n"[..], "PROPFIND"),
    (b"get / HTTP/1.1\r\nHost: a\r\n\r\n", "get"),
    (b"M-SEARCH / HTTP/1.1\r\nHost: a\r\n\r\n", "M-SEARCH"),
  ] {
    let r = req_whole_with(raw, lenient).unwrap();
    assert_eq!((r.method, r.method_str.as_str()), (Method::Other, method));
  }
  assert_eq!(req_err(b"PROPFIND /dav HTTP/1.1\r\nHost: a\r\n\r\n").status(), 501);
  // Still a token, still no asterisk-form.
  assert!(req_whole_with(b"G(T / HTTP/1.1\r\nHost: a\r\n\r\n", lenient).err().is_some());
  assert_eq!(
    req_whole_with(b"FOO * HTTP/1.1\r\nHost: a\r\n\r\n", lenient).err(),
    Some(Error::InvalidTarget)
  );
  // Known methods keep their variant and name.
  let r = req_whole_with(b"DELETE /x HTTP/1.1\r\nHost: a\r\n\r\n", lenient).unwrap();
  assert_eq!((r.method, r.method_str.as_str()), (Method::Delete, "DELETE"));
}

// ---- Expect and Upgrade ----

#[test]
fn expect_continue() {
  assert!(
    req_whole(b"PUT / HTTP/1.1\r\nHost: a\r\nExpect: 100-Continue\r\nContent-Length: 5\r\n\r\n")
      .unwrap()
      .expect_continue
  );
  // RFC 9110 §10.1.1: ignored on HTTP/1.0.
  assert!(!req_whole(b"PUT / HTTP/1.0\r\nExpect: 100-continue\r\n\r\n").unwrap().expect_continue);
  assert!(
    !req_whole(b"PUT / HTTP/1.1\r\nHost: a\r\nExpect: something\r\n\r\n").unwrap().expect_continue
  );
}

#[test]
fn upgrade_needs_both_fields_and_http11() {
  let up = |raw: &[u8]| req_whole(raw).unwrap().upgrade;
  assert!(up(
    b"GET / HTTP/1.1\r\nHost: a\r\nConnection: keep-alive, Upgrade\r\nUpgrade: websocket\r\n\r\n"
  ));
  assert!(!up(b"GET / HTTP/1.1\r\nHost: a\r\nUpgrade: websocket\r\n\r\n"));
  assert!(!up(b"GET / HTTP/1.1\r\nHost: a\r\nConnection: upgrade\r\n\r\n"));
  // RFC 9110 §7.8: ignored on HTTP/1.0.
  assert!(!up(b"GET / HTTP/1.0\r\nConnection: upgrade\r\nUpgrade: websocket\r\n\r\n"));
}

// ---- Field rules ----

#[test]
fn field_values_must_be_utf8() {
  assert_eq!(
    req_err(b"GET / HTTP/1.1\r\nHost: a\r\nX: caf\xe9\r\n\r\n"),
    Error::InvalidHeaderValue
  );
  assert_eq!(
    req_err(b"GET / HTTP/1.1\r\nHost: a\r\nX: \xed\xa0\x80\r\n\r\n"),
    Error::InvalidHeaderValue
  );
  let r = req_whole("GET / HTTP/1.1\r\nHost: a\r\nX: 日本語 🦀\r\n\r\n".as_bytes()).unwrap();
  assert_eq!(r.headers[1].1, "日本語 🦀");
}

#[test]
fn multiple_connection_fields_combine() {
  let r =
    req_whole(b"GET / HTTP/1.1\r\nHost: a\r\nConnection: keep-alive\r\nConnection: close\r\n\r\n")
      .unwrap();
  assert!(!r.keep_alive);
}

#[test]
fn errors_are_reported_before_the_head_ends() {
  // A bare LF, a bad field byte or a bad target is reported as soon as it arrives.
  assert_eq!(req_whole(b"GET / HTTP/1.1\r\nHost: a\n").err(), Some(Error::InvalidLineEnding));
  assert_eq!(req_whole(b"GET / HTTP/1.1\r\nX: \x01").err(), Some(Error::InvalidHeaderValue));
  assert_eq!(req_whole(b"GET /#").err(), Some(Error::InvalidTarget));
  // ...and repeated until reset.
  let mut parser = RequestParser::<8>::default();
  assert_eq!(parser.parse(b"GET /# HT").err(), Some(Error::InvalidTarget));
  assert_eq!(parser.parse(b"GET /# HTTP/1.1\r\n\r\n").err(), Some(Error::InvalidTarget));
  parser.reset();
  assert!(matches!(parser.parse(b"GET / HTTP/1.0\r\n\r\n"), Ok(Status::Complete(_))));
}

// ---- Limits ----

#[test]
fn limits_are_configurable_and_positional() {
  let c =
    Config { max_head_len: 64, max_line_len: 32, max_headers: 2, allow_extension_methods: false };
  // A request line of exactly 32 bytes passes, 33 does not.
  let line32 = b"GET /aaaaaaaaaaaaaaaaaa HTTP/1.1\r\n";
  assert_eq!(line32.len(), 34);
  let mut raw = line32.to_vec();
  raw.extend_from_slice(b"Host: a\r\n\r\n");
  assert!(matches!(req_whole_with(&raw, c), Outcome::Complete(_)));
  let raw = b"GET /aaaaaaaaaaaaaaaaaaa HTTP/1.1\r\nHost: a\r\n\r\n";
  assert_eq!(req_whole_with(raw, c).err(), Some(Error::UriTooLong));
  // Field line over the line limit, head over the head limit, too many fields.
  let raw = b"GET / HTTP/1.1\r\nHost: a\r\nX: 0123456789012345678901234567890\r\n\r\n";
  assert_eq!(req_whole_with(raw, c).err(), Some(Error::HeadTooLarge));
  let raw = b"GET / HTTP/1.1\r\nHost: a\r\nX: 01234567890123456789\r\nY: 0123456789\r\n\r\n";
  let more = Config { max_headers: 8, ..c };
  assert_eq!(req_whole_with(raw, more).err(), Some(Error::HeadTooLarge));
  let raw = b"GET / HTTP/1.1\r\nHost: a\r\nX: 1\r\nY: 2\r\n\r\n";
  assert_eq!(req_whole_with(raw, c).err(), Some(Error::TooManyHeaders));
  // The slot count caps `max_headers`.
  let mut p = RequestParser::<1>::new(Config::DEFAULT);
  assert_eq!(
    p.parse(b"GET / HTTP/1.1\r\nHost: a\r\nX: 1\r\n\r\n").err(),
    Some(Error::TooManyHeaders)
  );
  // A head exactly at the head limit passes.
  let raw = b"GET / HTTP/1.1\r\nHost: a\r\n\r\n";
  let c = Config { max_head_len: raw.len() as u32, ..Config::DEFAULT };
  assert!(matches!(req_whole_with(raw, c), Outcome::Complete(_)));
  let c = Config { max_head_len: raw.len() as u32 - 1, ..Config::DEFAULT };
  assert_eq!(req_whole_with(raw, c).err(), Some(Error::HeadTooLarge));
}

#[test]
fn error_statuses() {
  assert_eq!(Error::UriTooLong.status(), 414);
  assert_eq!(Error::HeadTooLarge.status(), 431);
  assert_eq!(Error::TooManyHeaders.status(), 431);
  assert_eq!(Error::UnknownMethod.status(), 501);
  assert_eq!(Error::UnsupportedTransferCoding.status(), 501);
  assert_eq!(Error::VersionNotSupported.status(), 505);
  assert_eq!(Error::MissingHost.status(), 400);
  assert_eq!(Error::InvalidLineEnding.to_string(), "line not ended by CRLF");
}

// ---- API ----

#[test]
fn headers_view() {
  let buf = b"GET / HTTP/1.1\r\nHost: a\r\nAccept: x\r\naccept: y\r\n\r\n";
  let mut p = RequestParser::<8>::default();
  let Ok(Status::Complete(r)) = p.parse(buf) else { panic!() };
  assert_eq!(r.headers.len(), 3);
  assert_eq!(r.headers.find("ACCEPT"), Some("x"));
  assert_eq!(r.headers.find("missing"), None);
  assert_eq!(r.headers.get(2).map(|h| (h.name, h.value)), Some(("accept", "y")));
  assert_eq!(r.headers.iter().next_back().map(|h| h.value), Some("y"));
  assert_eq!(r.headers.iter().filter(|h| h.name.eq_ignore_ascii_case("accept")).count(), 2);
  assert_eq!(format!("{:?}", r.headers), r#"[("Host", "a"), ("Accept", "x"), ("accept", "y")]"#);
}

#[test]
fn next_message_after_complete_and_pipelining() {
  let two = b"GET /1 HTTP/1.1\r\nHost: a\r\n\r\nGET /2 HTTP/1.1\r\nHost: a\r\n\r\n";
  let mut p = RequestParser::<8>::default();
  let n = match p.parse(two) {
    Ok(Status::Complete(r)) => {
      assert_eq!(r.path, "/1");
      r.head_len
    }
    other => panic!("{other:?}"),
  };
  let Ok(Status::Complete(r)) = p.parse(&two[n..]) else { panic!() };
  assert_eq!((r.path, r.head_len), ("/2", n));
}

#[test]
fn changed_bytes_are_caught_on_resume() {
  // API misuse must not produce invalid `str`s: bytes consumed by an earlier call are checked
  // again when the head completes.
  let mut p = RequestParser::<8>::default();
  let mut buf = b"GET / HTTP/1.1\r\nX: abc".to_vec();
  assert!(matches!(p.parse(&buf), Ok(Status::Partial)));
  buf[19] = 0xff;
  buf.extend_from_slice(b"\r\nHost: a\r\n\r\n");
  assert_eq!(p.parse(&buf).err(), Some(Error::InvalidResume));
  // A shorter buffer than what was consumed is misuse too.
  let mut p = RequestParser::<8>::default();
  assert!(matches!(p.parse(b"GET / HTTP/1.1\r\nX: abc"), Ok(Status::Partial)));
  assert_eq!(p.parse(b"GET").err(), Some(Error::InvalidResume));
}

// ---- Responses ----

#[test]
fn response_framing() {
  let body = |raw: &[u8], m: Method| res_whole(raw, m).unwrap().body;
  assert_eq!(
    body(b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\n", Method::Get),
    BodyKind::ContentLength(5)
  );
  assert_eq!(
    body(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n", Method::Get),
    BodyKind::Chunked
  );
  assert_eq!(
    body(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: gzip, chunked\r\n\r\n", Method::Get),
    BodyKind::Chunked
  );
  assert_eq!(
    body(
      b"HTTP/1.1 200 OK\r\nTransfer-Encoding: gzip\r\nTransfer-Encoding: chunked\r\n\r\n",
      Method::Get
    ),
    BodyKind::Chunked
  );
  assert_eq!(
    body(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: gzip\r\n\r\n", Method::Get),
    BodyKind::UntilClose
  );
  assert_eq!(body(b"HTTP/1.1 200 OK\r\n\r\n", Method::Get), BodyKind::UntilClose);
  assert_eq!(body(b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\n", Method::Head), BodyKind::None);
  assert_eq!(body(b"HTTP/1.1 204 No Content\r\n\r\n", Method::Get), BodyKind::None);
  assert_eq!(
    body(b"HTTP/1.1 304 Not Modified\r\nContent-Length: 9\r\n\r\n", Method::Get),
    BodyKind::None
  );
  assert_eq!(body(b"HTTP/1.1 100 Continue\r\n\r\n", Method::Post), BodyKind::None);
  let r = res_whole(b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n\r\n", Method::Get)
    .unwrap();
  assert!(r.upgrade && r.body == BodyKind::None);
  let r = res_whole(b"HTTP/1.1 200 OK\r\n\r\n", Method::Connect).unwrap();
  assert!(r.upgrade && r.body == BodyKind::None);
  let r =
    res_whole(b"HTTP/1.1 407 Proxy Auth\r\nContent-Length: 0\r\n\r\n", Method::Connect).unwrap();
  assert!(!r.upgrade && r.body == BodyKind::ContentLength(0));
}

#[test]
fn response_keep_alive() {
  let ka = |raw: &[u8]| res_whole(raw, Method::Get).unwrap().keep_alive;
  assert!(ka(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"));
  assert!(!ka(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"));
  assert!(!ka(b"HTTP/1.1 200 OK\r\n\r\n"));
  assert!(!ka(b"HTTP/1.0 200 OK\r\nContent-Length: 0\r\n\r\n"));
  assert!(ka(b"HTTP/1.0 200 OK\r\nContent-Length: 0\r\nConnection: keep-alive\r\n\r\n"));
  assert!(!ka(b"HTTP/1.0 200 OK\r\nTransfer-Encoding: chunked\r\nConnection: keep-alive\r\n\r\n"));
}

#[test]
fn status_line_rules() {
  let r = res_whole(b"HTTP/1.1 404 \r\n\r\n", Method::Get).unwrap();
  assert_eq!((r.status, r.reason.as_str(), r.version), (404, "", Version::Http11));
  let r = res_whole("HTTP/1.0 200 Très\tbien\r\n\r\n".as_bytes(), Method::Get).unwrap();
  assert_eq!((r.reason.as_str(), r.version), ("Très\tbien", Version::Http10));
  assert_eq!(res_whole(b"HTTP/1.2 200 OK\r\n\r\n", Method::Get).unwrap().version, Version::Http11);
  for (raw, err) in [
    (&b"HTTP/1.1 200\r\n\r\n"[..], Error::InvalidStatus),
    (b"HTTP/1.1 99 X\r\n\r\n", Error::InvalidStatus),
    (b"HTTP/1.1 600 X\r\n\r\n", Error::InvalidStatus),
    (b"HTTP/1.1 099 X\r\n\r\n", Error::InvalidStatus),
    (b"HTTP/1.1 2000 X\r\n\r\n", Error::InvalidStatus),
    (b"HTTP/2.0 200 X\r\n\r\n", Error::VersionNotSupported),
    (b"HTTP/1.1  200 X\r\n\r\n", Error::InvalidStatus),
    (b"HTTP/1.1 200 X\n\r\n", Error::InvalidLineEnding),
    (b"HTTP/1.1 200 X\x01\r\n\r\n", Error::InvalidHeaderValue),
    (b"HTTP/1.1 200 \xff\r\n\r\n", Error::InvalidHeaderValue),
    (b"http/1.1 200 OK\r\n\r\n", Error::InvalidVersion),
    (b"\r\nHTTP/1.1 200 OK\r\n\r\n", Error::InvalidVersion),
    (
      b"HTTP/1.1 200 OK\r\nContent-Length: 1\r\nTransfer-Encoding: chunked\r\n\r\n",
      Error::ContentLengthWithTransferEncoding,
    ),
    (
      b"HTTP/1.1 200 OK\r\nContent-Length: 1\r\nContent-Length: 1\r\n\r\n",
      Error::DuplicateContentLength,
    ),
    (
      b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked, gzip\r\n\r\n",
      Error::InvalidTransferEncoding,
    ),
    (
      b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nTransfer-Encoding: chunked\r\n\r\n",
      Error::InvalidTransferEncoding,
    ),
    (b"HTTP/1.1 200 OK\r\n folded: x\r\n\r\n", Error::WhitespaceBeforeName),
  ] {
    assert_eq!(res_err(raw, Method::Get), err, "{:?}", String::from_utf8_lossy(raw));
  }
}

// ---- Body decoder ----

#[test]
fn decode_returns_slices_of_the_input() {
  let input = b"5\r\nhello\r\n6\r\n world\r\n0\r\n\r\n";
  let mut d = BodyDecoder::new(BodyKind::Chunked);
  let mut rest = &input[..];
  let mut pieces = Vec::new();
  loop {
    let Decoded { consumed, data, done } = d.decode(rest).unwrap();
    if !data.is_empty() {
      // Zero-copy: the payload points into the input.
      let offset = data.as_ptr() as usize - input.as_ptr() as usize;
      assert_eq!(&input[offset..offset + data.len()], data);
      pieces.push(data);
    }
    rest = &rest[consumed..];
    if done {
      break;
    }
  }
  assert_eq!(pieces, [&b"hello"[..], b" world"]);
  assert!(d.is_done());
}

#[test]
fn chunk_extension_grammar() {
  let ok = |s: &[u8]| {
    let mut raw = s.to_vec();
    raw.extend_from_slice(b"\r\nab\r\n0\r\n\r\n");
    BodyDecoder::new(BodyKind::Chunked).feed(&raw, |_| {}).map(|_| ())
  };
  for good in [
    &b"2"[..],
    b"2;a",
    b"2;a=b",
    b"2 ;a",
    b"2; a",
    b"2;a = b",
    b"2;a=\"q \\\" t\"",
    b"2;a;b=c;d",
    b"02",
    b"2;a=\"\"",
  ] {
    assert_eq!(ok(good), Ok(()), "{:?}", String::from_utf8_lossy(good));
  }
  for bad in [
    &b"2;"[..],
    b"2;=b",
    b"2;a=",
    b"2;a b",
    b"2;a=b c",
    b"2;a=\"open",
    b"2;a=b ",
    b"2 ",
    b"2;a,b",
    b"2;a=\"\x01\"",
    b"2;\xff",
  ] {
    assert!(ok(bad).is_err(), "{:?}", String::from_utf8_lossy(bad));
  }
}

#[test]
fn chunk_size_line_is_bounded() {
  let c = Config { max_line_len: 16, ..Config::DEFAULT };
  let mut d = BodyDecoder::with_config(BodyKind::Chunked, &c);
  assert_eq!(d.feed(b"2;aaaaaaaaaaaaaaaaaaaaa\r\n", |_| {}), Err(Error::ChunkLineTooLong));
  let mut d = BodyDecoder::with_config(BodyKind::Chunked, &c);
  assert!(d.feed(b"2;aaaaaaaaaaaaa\r\nab\r\n0\r\n\r\n", |_| {}).is_ok());
}

#[test]
fn finish_at_end_of_input() {
  let mut d = BodyDecoder::new(BodyKind::UntilClose);
  let mut out = Vec::new();
  assert_eq!(
    d.feed(b"all of it", |x| out.extend_from_slice(x)),
    Ok(rimu_http1::BodyStatus::NeedMore)
  );
  assert_eq!((d.finish(), out.as_slice()), (Ok(()), &b"all of it"[..]));
  let mut d = BodyDecoder::new(BodyKind::ContentLength(10));
  d.feed(b"short", |_| {}).unwrap();
  assert_eq!(d.finish(), Err(Error::UnexpectedEof));
  let mut d = BodyDecoder::new(BodyKind::Chunked);
  d.feed(b"5\r\nhel", |_| {}).unwrap();
  assert_eq!(d.finish(), Err(Error::UnexpectedEof));
  assert_eq!(BodyDecoder::new(BodyKind::None).finish(), Ok(()));
}

#[test]
fn large_content_length() {
  let r = req_whole(b"POST / HTTP/1.1\r\nHost: a\r\nContent-Length: 18446744073709551615\r\n\r\n")
    .unwrap();
  assert_eq!(r.body, BodyKind::ContentLength(u64::MAX));
  assert_eq!(
    req_err(b"POST / HTTP/1.1\r\nHost: a\r\nContent-Length: 18446744073709551616\r\n\r\n"),
    Error::InvalidContentLength
  );
}
