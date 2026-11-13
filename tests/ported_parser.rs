//! Every test of the rimu-ws request parser (`wtx/src/http1/parser.rs`), adapted to this API.
//! The rules they encode are this crate's strictness baseline. (`simd_scans_match_scalar` is
//! the unit test `scan::tests::kernels_match_scalar`.)

mod common;

use common::{Outcome, err_status, is_err, req_whole};
use rimu_http1::{BodyKind, Config, Method, RequestParser, Status, Version};

const GET: &[u8] = b"GET /baseline11?a=13&b=42 HTTP/1.1\r\nHost: localhost:8080\r\n\r\n";
const POST_CL: &[u8] =
  b"POST /baseline11?a=13&b=42 HTTP/1.1\r\nHost: localhost:8080\r\nContent-Length: 2\r\n\r\n20";
const POST_CHUNKED: &[u8] = b"POST /baseline11?a=13&b=42 HTTP/1.1\r\nHost: localhost:8080\r\nTransfer-Encoding: chunked\r\n\r\n2\r\n20\r\n0\r\n\r\n";

type Fields = (Method, String, String, Vec<(String, String)>, BodyKind, bool, usize);

fn complete(buf: &[u8]) -> Fields {
  let r = req_whole(buf).unwrap();
  (r.method, r.path, r.query, r.headers, r.body, r.keep_alive, r.head_len)
}

const MAX_HEADERS: usize = 64;

#[test]
fn parses_get_baseline() {
  let (method, path, query, headers, body_kind, keep_alive, head_len) = complete(GET);
  assert_eq!(method, Method::Get);
  assert_eq!(path, "/baseline11");
  assert_eq!(query, "a=13&b=42");
  assert_eq!(headers, [("Host".into(), "localhost:8080".into())]);
  assert_eq!(body_kind, BodyKind::None);
  assert!(keep_alive);
  assert_eq!(head_len, 60);
}

#[test]
fn parses_post_content_length() {
  let (method, _, _, _, body_kind, _, head_len) = complete(POST_CL);
  assert_eq!(method, Method::Post);
  assert_eq!(body_kind, BodyKind::ContentLength(2));
  assert_eq!(head_len, 80);
}

#[test]
fn parses_post_chunked() {
  let (method, _, _, _, body_kind, _, head_len) = complete(POST_CHUNKED);
  assert_eq!(method, Method::Post);
  assert_eq!(body_kind, BodyKind::Chunked);
  assert_eq!(head_len, 89);
}

#[test]
fn partial_returns_partial_at_every_split() {
  let mut parser = RequestParser::<64>::default();
  for n in 1..GET.len() {
    assert!(matches!(parser.parse(&GET[..n]), Ok(Status::Partial)), "{n}");
  }
  assert!(matches!(parser.parse(GET), Ok(Status::Complete(r)) if r.head_len == 60));
}

#[test]
fn partial_at_every_split_with_body_bytes_trailing() {
  let mut parser = RequestParser::<64>::default();
  for n in 1..80 {
    assert!(matches!(parser.parse(&POST_CL[..n]), Ok(Status::Partial)), "{n}");
  }
  // After a complete head, each call parses a new message from the buffer's start.
  for n in 80..=POST_CL.len() {
    assert!(matches!(parser.parse(&POST_CL[..n]), Ok(Status::Complete(r)) if r.head_len == 80));
  }
}

#[test]
fn lowercase_header_names_match() {
  let (_, _, _, headers, body_kind, _, _) =
    complete(b"POST /x HTTP/1.1\r\nhost: a\r\ncontent-length: 7\r\n\r\n");
  assert_eq!(headers.len(), 2);
  assert_eq!(body_kind, BodyKind::ContentLength(7));
  let (_, _, _, _, body_kind, keep_alive, _) = complete(
    b"POST /x HTTP/1.1\r\nHost: a\r\nTRANSFER-ENCODING: Chunked\r\nCONNECTION: Close\r\n\r\n",
  );
  assert_eq!(body_kind, BodyKind::Chunked);
  assert!(!keep_alive);
}

#[test]
fn rejects_cl_and_te() {
  assert!(is_err(
    b"POST / HTTP/1.1\r\nHost: a\r\nContent-Length: 1\r\nTransfer-Encoding: chunked\r\n\r\n"
  ));
  assert!(is_err(
    b"POST / HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: chunked\r\nContent-Length: 1\r\n\r\n"
  ));
}

#[test]
fn rejects_double_cl() {
  assert!(is_err(b"POST / HTTP/1.1\r\nHost: a\r\nContent-Length: 1\r\nContent-Length: 1\r\n\r\n"));
  assert!(is_err(b"POST / HTTP/1.1\r\nHost: a\r\nContent-Length: 1\r\nContent-Length: 2\r\n\r\n"));
}

#[test]
fn rejects_too_many_headers() {
  let build = |n: usize| {
    let mut buf = b"GET / HTTP/1.1\r\nHost: a\r\n".to_vec();
    for i in 1..n {
      buf.extend_from_slice(format!("X-H{i}: v\r\n").as_bytes());
    }
    buf.extend_from_slice(b"\r\n");
    buf
  };
  assert!(!is_err(&build(MAX_HEADERS)));
  assert_eq!(err_status(&build(MAX_HEADERS + 1)), 431);
}

#[test]
fn rejects_oversized_head() {
  let mut buf = b"GET / HTTP/1.1\r\nHost: a\r\nX: ".to_vec();
  buf.resize(20_000, b'a');
  assert_eq!(err_status(&buf), 431);
  buf.extend_from_slice(b"\r\n\r\n");
  assert_eq!(err_status(&buf), 431);
  assert_eq!(err_status(b"GET  / HTTP/1.1\r\n\r\n"), 400);
}

#[test]
fn rejects_malformed() {
  assert!(is_err(b"GET / HTTP/2.0\r\n\r\n"));
  assert!(is_err(b"GET /\r\n\r\n"));
  assert!(is_err(b"GET  / HTTP/1.1\r\nHost: a\r\n\r\n"));
  assert!(is_err(b"BREW / HTTP/1.1\r\nHost: a\r\n\r\n"));
  assert!(is_err(b"get / HTTP/1.1\r\nHost: a\r\n\r\n"));
  assert!(is_err(b"GET / HTTP/1.1\r\nHost: a\r\nBad Name: v\r\n\r\n"));
  assert!(is_err(b"GET / HTTP/1.1\r\nHost: a\r\nNoColon\r\n\r\n"));
  assert!(is_err(b"GET / HTTP/1.1\r\nHost: a\r\n folded: v\r\n\r\n"));
  assert!(is_err(b"GET / HTTP/1.1\r\nHost: a\r\nA: b\rc\r\n\r\n"));
  assert!(is_err(b"GET / HTTP/1.1\r\nHost: a\r\nA: b\0c\r\n\r\n"));
  assert!(is_err(b"GET / HTTP/1.1\r\nHost: a\r\nA: b\nc: d\r\n\r\n"));
  assert!(is_err(b"POST / HTTP/1.1\r\nHost: a\r\nContent-Length: -1\r\n\r\n"));
  assert!(is_err(b"POST / HTTP/1.1\r\nHost: a\r\nContent-Length: \r\n\r\n"));
  assert!(is_err(b"POST / HTTP/1.1\r\nHost: a\r\nContent-Length: 99999999999999999999999\r\n\r\n"));
  assert!(is_err(b"POST / HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: gzip\r\n\r\n"));
}

#[test]
fn request_line_needs_crlf() {
  assert!(is_err(b"GET / HTTP/1.11\nHost: a\r\n\r\n"));
  assert!(is_err(b"GET / HTTP/1.1X\nHost: a\r\n\r\n"));
  assert!(is_err(b"GET / HTTP/1.1\0\nHost: a\r\n\r\n"));
  assert!(is_err(b"GET / HTTP/1.1\nHost: a\r\n\r\n"));
}

#[test]
fn one_leading_crlf_is_skipped() {
  let raw: &[u8] = b"\r\nGET /x HTTP/1.1\r\nHost: a\r\n\r\n";
  let (method, path, _, _, _, _, head_len) = complete(raw);
  assert_eq!((method, path.as_str(), head_len), (Method::Get, "/x", raw.len()));
  let mut parser = RequestParser::<64>::default();
  for n in 1..raw.len() {
    assert!(matches!(parser.parse(&raw[..n]), Ok(Status::Partial)), "{n}");
  }
  assert!(is_err(b"\r\n\r\nGET /x HTTP/1.1\r\nHost: a\r\n\r\n"));
}

#[test]
fn transfer_encoding_is_exactly_chunked() {
  let te = |value: &str| {
    let raw = format!("POST / HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: {value}\r\n\r\n");
    match req_whole(raw.as_bytes()) {
      Outcome::Complete(r) => {
        assert_eq!(r.body, BodyKind::Chunked);
        200
      }
      Outcome::Partial => panic!("partial"),
      Outcome::Error(e) => e.status(),
    }
  };
  assert_eq!(te("chunked"), 200);
  assert_eq!(te("CHUNKED"), 200);
  // Not chunked last: the length can not be known (RFC 9112 §6.3).
  assert_eq!(te("gzip"), 400);
  assert_eq!(te("gzip, chunked"), 501);
  assert_eq!(te("chunked, chunked"), 400);
  assert_eq!(te("chunked, gzip"), 400);
  assert_eq!(te(""), 400);
  assert_eq!(te(", chunked"), 400);
  assert_eq!(te("chu nked"), 400);
  assert_eq!(
    err_status(b"POST / HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: chunked\r\nTransfer-Encoding: chunked\r\n\r\n"),
    400
  );
}

#[test]
fn chunked_http10_does_not_keep_alive() {
  let (_, _, _, _, body_kind, keep_alive, _) =
    complete(b"POST / HTTP/1.0\r\nTransfer-Encoding: chunked\r\nConnection: keep-alive\r\n\r\n");
  assert_eq!(body_kind, BodyKind::Chunked);
  assert!(!keep_alive);
}

#[test]
fn host_is_required_once() {
  assert_eq!(err_status(b"GET / HTTP/1.1\r\n\r\n"), 400);
  assert_eq!(err_status(b"GET / HTTP/1.1\r\nX: y\r\n\r\n"), 400);
  assert_eq!(err_status(b"GET / HTTP/1.1\r\nHost: a\r\nHost: b\r\n\r\n"), 400);
  assert_eq!(err_status(b"GET / HTTP/1.1\r\nhost: a\r\nHOST: a\r\n\r\n"), 400);
  assert_eq!(err_status(b"GET / HTTP/1.0\r\nHost: a\r\nHost: b\r\n\r\n"), 400);
  // HTTP/1.0 may leave it out; an empty one is allowed.
  assert_eq!(complete(b"GET /x HTTP/1.0\r\n\r\n").1, "/x");
  assert_eq!(complete(b"GET /x HTTP/1.1\r\nHost:\r\n\r\n").1, "/x");
}

#[test]
fn absolute_form_routes_on_path_and_query() {
  let target = |t: &str| {
    let (_, path, query, ..) = complete(format!("GET {t} HTTP/1.1\r\nHost: a\r\n\r\n").as_bytes());
    (path, query)
  };
  assert_eq!(target("http://evil/x?q=1"), ("/x".into(), "q=1".into()));
  assert_eq!(target("HTTPS://h:8080/a/b"), ("/a/b".into(), "".into()));
  assert_eq!(target("http://h"), ("/".into(), "".into()));
  assert_eq!(target("http://h?x"), ("/".into(), "x".into()));
  assert_eq!(target("/http://h/x"), ("/http://h/x".into(), "".into()));
  assert_eq!(err_status(b"GET http:///x HTTP/1.1\r\nHost: a\r\n\r\n"), 400);
}

// RFC 9112 §3.2.3: for an absolute-form target the server ignores `Host` and uses the target's
// authority, which is what the request's `host` header then reports.
#[test]
fn absolute_form_authority_replaces_host() {
  let host = |raw: &str| {
    let (.., headers, _, _, _) = complete(raw.as_bytes());
    headers.into_iter().filter(|el| el.0.eq_ignore_ascii_case("host")).collect::<Vec<_>>()
  };
  assert_eq!(
    host("GET http://evil/x?q=1 HTTP/1.1\r\nHost: a\r\nAccept: b\r\n\r\n"),
    [("Host".into(), "evil".into())]
  );
  assert_eq!(
    host("GET HTTPS://h:8080?x HTTP/1.1\r\nAccept: b\r\nhost: a\r\n\r\n"),
    [("host".into(), "h:8080".into())]
  );
  assert_eq!(host("GET http://h HTTP/1.0\r\n\r\n"), []);
  // Origin-form: Host is untouched
  assert_eq!(host("GET /x HTTP/1.1\r\nHost: a\r\n\r\n"), [("Host".into(), "a".into())]);
  assert_eq!(host("GET /http://h/x HTTP/1.1\r\nHost: a\r\n\r\n"), [("Host".into(), "a".into())]);
}

// RFC 9110 §4.2.4: an authority with userinfo is refused, and a fragment is not part of a
// request target.
#[test]
fn absolute_form_authority_with_userinfo_or_fragment_is_refused() {
  for target in [
    "http://user:pw@evil/x",
    "http://user@evil",
    "https://@h/x",
    "http://u@h?q=1",
    "http://h#f",
    "http://h#f/x",
    "HTTP://h:80#f?x",
  ] {
    let raw = format!("GET {target} HTTP/1.1\r\nHost: a\r\n\r\n");
    assert_eq!(err_status(raw.as_bytes()), 400, "{target}");
  }
  // `@` and `#` after the authority are the path's or the query's, not the authority's
  let (_, path, query, ..) = complete(b"GET http://h/a@b?x=y@z HTTP/1.1\r\nHost: a\r\n\r\n");
  assert_eq!((path.as_str(), query.as_str()), ("/a@b", "x=y@z"));
  // Changed from rimu-ws: the target is judged as soon as the request line is complete, not
  // once the whole head is (rimu-ws answered Partial here and 400 later).
  assert_eq!(
    req_whole(b"GET http://u@h/x HTTP/1.1\r\nHost: a\r\n").err().map(|e| e.status()),
    Some(400)
  );
  assert_eq!(req_whole(b"GET http://u@h/x HTTP/1.1"), Outcome::Partial);
}

#[test]
fn version_is_reported() {
  assert_eq!(req_whole(b"GET / HTTP/1.0\r\n\r\n").unwrap().version, Version::Http10);
  assert_eq!(req_whole(GET).unwrap().version, Version::Http11);
}

#[test]
fn keep_alive_rules() {
  assert!(complete(b"GET / HTTP/1.1\r\nHost: a\r\n\r\n").5);
  assert!(!complete(b"GET / HTTP/1.1\r\nHost: a\r\nConnection: close\r\n\r\n").5);
  assert!(!complete(b"GET / HTTP/1.0\r\n\r\n").5);
  assert!(complete(b"GET / HTTP/1.0\r\nConnection: keep-alive\r\n\r\n").5);
  assert!(!complete(b"GET / HTTP/1.1\r\nHost: a\r\nConnection: keep-alive, close\r\n\r\n").5);
}

#[test]
fn value_whitespace_and_empty_value() {
  let (_, path, query, headers, _, _, _) =
    complete(b"GET /p? HTTP/1.1\r\nHost: a\r\nA:\t x y \t\r\nB:\r\n\r\n");
  assert_eq!(path, "/p");
  assert_eq!(query, "");
  assert_eq!(
    headers,
    [("Host".into(), "a".into()), ("A".into(), "x y".into()), ("B".into(), "".into())]
  );
}

// ---- Shapes and answers the mature suites agree on ----

// llhttp's request-line checks and h2o t/40bad-request.t: a target with a space, a missing
// method or target, junk in or after the version, a raw NUL, and a second empty line in
// front (RFC 9112 §2.2 tolerates exactly one) are all bad requests.
#[test]
fn request_line_shapes_from_other_suites() {
  assert!(is_err(b"GET /foo bar/ HTTP/1.1\r\nHost: a\r\n\r\n"));
  assert!(is_err(b" / HTTP/1.1\r\nHost: a\r\n\r\n"));
  assert!(is_err(b"GET  HTTP/1.1\r\nHost: a\r\n\r\n"));
  assert!(is_err(b"GET / HTTP/1.1 \r\nHost: a\r\n\r\n"));
  assert!(is_err(b"GET / HTTP/1.01\r\nHost: a\r\n\r\n"));
  assert!(is_err(b"GET / HTTP/A.0\r\nHost: a\r\n\r\n"));
  assert!(is_err(b"GET / aHTTP/1.1\r\nHost: a\r\n\r\n"));
  assert!(is_err(b"GET /\x00 HTTP/1.1\r\nHost: a\r\n\r\n"));
  assert!(is_err(b"\r\n\r\nGET / HTTP/1.1\r\nHost: a\r\n\r\n"));
}

// `OPTIONS *` is the asterisk-form (RFC 9110 §9.3.7): lighttpd answers it, curl sends it.
#[test]
fn asterisk_form_parses() {
  let (method, path, _, _, body_kind, _, _) = complete(b"OPTIONS * HTTP/1.1\r\nHost: a\r\n\r\n");
  assert_eq!(method, Method::Options);
  assert_eq!(path, "*");
  assert_eq!(body_kind, BodyKind::None);
}

// CONNECT's target is an authority, not a path (RFC 9110 §9.3.6); Envoy's CONNECT tests use
// the shape.
#[test]
fn connect_authority_form_parses() {
  let (method, path, _, _, _, keep_alive, _) =
    complete(b"CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n");
  assert_eq!(method, Method::Connect);
  assert_eq!(path, "example.com:443");
  assert!(keep_alive);
}

// llhttp rejects embedded whitespace, commas and signs in `Content-Length`; nginx accepts a
// comma list of equal values, which RFC 9110 §8.6 leaves to recipients.
#[test]
fn content_length_junk_is_rejected() {
  for value in ["4 2", "5, 5", "+5", "4\t2"] {
    let raw = format!("POST / HTTP/1.1\r\nHost: a\r\nContent-Length: {value}\r\n\r\n");
    assert!(is_err(raw.as_bytes()), "{value}");
  }
}

// llhttp and Envoy: no empty header names, no space before the colon (a `Content-Length :`
// must not be re-read as an unknown header), no CR inside a name, and a space before the
// first header name is not a folded value.
#[test]
fn header_name_shapes() {
  assert!(is_err(b"GET / HTTP/1.1\r\nHost: a\r\n: v\r\n\r\n"));
  assert!(is_err(b"POST / HTTP/1.1\r\nHost: a\r\nContent-Length : 4\r\n\r\n"));
  assert!(is_err(b"POST / HTTP/1.1\r\nHost: a\r\nContent\r-Length: 4\r\n\r\n"));
  assert!(is_err(b"GET / HTTP/1.1\r\n Host: a\r\n\r\n"));
}

// A `chunked` with parameters is a coding this server does not speak: llhttp and Envoy also
// refuse `chunked;foo`.
#[test]
fn transfer_encoding_with_parameters_is_refused() {
  assert!(is_err(b"POST / HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: chunked;foo\r\n\r\n"));
}

// ---- What mature servers refuse ----

// httpd's CVE-2011-3368 and Envoy: an authority-shaped target belongs to CONNECT only; a GET
// of `www.somewhere.com` is a bad request.
#[test]
fn authority_form_target_is_rejected() {
  assert!(is_err(b"GET www.somewhere.com HTTP/1.1\r\nHost: a\r\n\r\n"));
}

// A request target carries no fragment (RFC 9110 §7.1); httpd and Envoy answer 400.
#[test]
fn fragment_in_target_is_rejected() {
  assert!(is_err(b"GET /x#f HTTP/1.1\r\nHost: a\r\n\r\n"));
}

// llhttp in strict mode and uWS reject raw non-ASCII bytes in the target; Envoy and lighttpd
// accept them instead. The suites disagree; this parser follows RFC 3986, which has no raw
// non-ASCII in a URI.
#[test]
fn raw_non_ascii_in_target_is_rejected() {
  assert!(is_err("GET /café HTTP/1.1\r\nHost: a\r\n\r\n".as_bytes()));
}

// h2o t/40bad-request.t: userinfo, extra colons, an embedded path and an out-of-range port
// in `Host` are bad requests.
#[test]
fn host_authority_junk_is_rejected() {
  for host in ["a@b:80", "a:b:99", "localhost:80/x", "example.com:99999"] {
    let raw = format!("GET / HTTP/1.1\r\nHost: {host}\r\n\r\n");
    assert!(is_err(raw.as_bytes()), "{host}");
  }
}

// RFC 9112 §2.5: a major version this parser does not speak is a 505, and an unsupported
// minor version is treated as the highest one supported — exactly what httpd does (h2o
// answers 400 to 1.2 instead).
#[test]
fn version_major_and_minor_rules() {
  let request = req_whole(b"GET / HTTP/1.2\r\nHost: a\r\n\r\n").unwrap();
  assert_eq!(request.version, Version::Http11);
  assert!(request.keep_alive);
  assert_eq!(err_status(b"GET / HTTP/9.1\r\nHost: a\r\n\r\n"), 505);
  // HTTP/0.9, a request line without a version, is refused as well.
  assert!(is_err(b"GET /\r\n\r\n"));
}

// nginx and httpd answer 501 to a well-formed but unknown method; Envoy answers 400. Other
// tokens, such as a lowercase method, stay bad requests.
#[test]
fn unknown_method_is_not_implemented() {
  assert_eq!(err_status(b"BAD /ping HTTP/1.1\r\nHost: a\r\n\r\n"), 501);
  assert_eq!(err_status(b"bad /ping HTTP/1.1\r\nHost: a\r\n\r\n"), 400);
  // No method at all is a bad request, not an unknown one (nginx and h2o answer 400).
  assert_eq!(err_status(b" /ping HTTP/1.1\r\nHost: a\r\n\r\n"), 400);
}

// A request line alone over the cap is a long URI: nginx and httpd answer 414, distinct from
// the 431 of oversized headers.
#[test]
fn oversized_request_line_is_uri_too_long() {
  let mut raw = b"GET /".to_vec();
  raw.extend(core::iter::repeat_n(b'a', 20 * 1024));
  raw.extend_from_slice(b" HTTP/1.1\r\nHost: a\r\n\r\n");
  assert_eq!(err_status(&raw), 414);
}

// llhttp rejects bare-LF endings.
#[test]
fn bare_lf_request_is_rejected() {
  assert!(is_err(b"GET / HTTP/1.1\nHost: a\n\n"));
}

// The ported tests above used the default limits; they match rimu-ws's 64 headers.
#[test]
fn default_limits() {
  assert_eq!(Config::DEFAULT.max_headers as usize, MAX_HEADERS);
}
