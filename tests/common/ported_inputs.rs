//! Every byte-string request of the ported rimu-ws parser tests (extracted from
//! `ported_parser.rs`), plus the inputs those tests build with `format!`.

pub const PORTED: &[&[u8]] = &[
  b"GET /baseline11?a=13&b=42 HTTP/1.1\r\nHost: localhost:8080\r\n\r\n",
  b"POST /baseline11?a=13&b=42 HTTP/1.1\r\nHost: localhost:8080\r\nContent-Length: 2\r\n\r\n20",
  b"POST /baseline11?a=13&b=42 HTTP/1.1\r\nHost: localhost:8080\r\nTransfer-Encoding: chunked\r\n\r\n2\r\n20\r\n0\r\n\r\n",
  b"POST /x HTTP/1.1\r\nhost: a\r\ncontent-length: 7\r\n\r\n",
  b"POST /x HTTP/1.1\r\nHost: a\r\nTRANSFER-ENCODING: Chunked\r\nCONNECTION: Close\r\n\r\n",
  b"POST / HTTP/1.1\r\nHost: a\r\nContent-Length: 1\r\nTransfer-Encoding: chunked\r\n\r\n",
  b"POST / HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: chunked\r\nContent-Length: 1\r\n\r\n",
  b"POST / HTTP/1.1\r\nHost: a\r\nContent-Length: 1\r\nContent-Length: 1\r\n\r\n",
  b"POST / HTTP/1.1\r\nHost: a\r\nContent-Length: 1\r\nContent-Length: 2\r\n\r\n",
  b"GET / HTTP/1.1\r\nHost: a\r\n",
  b"\r\n",
  b"GET / HTTP/1.1\r\nHost: a\r\nX: ",
  b"\r\n\r\n",
  b"GET  / HTTP/1.1\r\n\r\n",
  b"GET / HTTP/2.0\r\n\r\n",
  b"GET /\r\n\r\n",
  b"GET  / HTTP/1.1\r\nHost: a\r\n\r\n",
  b"BREW / HTTP/1.1\r\nHost: a\r\n\r\n",
  b"get / HTTP/1.1\r\nHost: a\r\n\r\n",
  b"GET / HTTP/1.1\r\nHost: a\r\nBad Name: v\r\n\r\n",
  b"GET / HTTP/1.1\r\nHost: a\r\nNoColon\r\n\r\n",
  b"GET / HTTP/1.1\r\nHost: a\r\n folded: v\r\n\r\n",
  b"GET / HTTP/1.1\r\nHost: a\r\nA: b\rc\r\n\r\n",
  b"GET / HTTP/1.1\r\nHost: a\r\nA: b\0c\r\n\r\n",
  b"GET / HTTP/1.1\r\nHost: a\r\nA: b\nc: d\r\n\r\n",
  b"POST / HTTP/1.1\r\nHost: a\r\nContent-Length: -1\r\n\r\n",
  b"POST / HTTP/1.1\r\nHost: a\r\nContent-Length: \r\n\r\n",
  b"POST / HTTP/1.1\r\nHost: a\r\nContent-Length: 99999999999999999999999\r\n\r\n",
  b"POST / HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: gzip\r\n\r\n",
  b"GET / HTTP/1.11\nHost: a\r\n\r\n",
  b"GET / HTTP/1.1X\nHost: a\r\n\r\n",
  b"GET / HTTP/1.1\0\nHost: a\r\n\r\n",
  b"GET / HTTP/1.1\nHost: a\r\n\r\n",
  b"\r\nGET /x HTTP/1.1\r\nHost: a\r\n\r\n",
  b"\r\n\r\nGET /x HTTP/1.1\r\nHost: a\r\n\r\n",
  b"POST / HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: chunked\r\nTransfer-Encoding: chunked\r\n\r\n",
  b"POST / HTTP/1.0\r\nTransfer-Encoding: chunked\r\nConnection: keep-alive\r\n\r\n",
  b"GET / HTTP/1.1\r\n\r\n",
  b"GET / HTTP/1.1\r\nX: y\r\n\r\n",
  b"GET / HTTP/1.1\r\nHost: a\r\nHost: b\r\n\r\n",
  b"GET / HTTP/1.1\r\nhost: a\r\nHOST: a\r\n\r\n",
  b"GET / HTTP/1.0\r\nHost: a\r\nHost: b\r\n\r\n",
  b"GET /x HTTP/1.0\r\n\r\n",
  b"GET /x HTTP/1.1\r\nHost:\r\n\r\n",
  b"), (",
  b".into(), ",
  b"GET http:///x HTTP/1.1\r\nHost: a\r\n\r\n",
  b"GET http://h/a@b?x=y@z HTTP/1.1\r\nHost: a\r\n\r\n",
  b", ",
  b"GET http://u@h/x HTTP/1.1\r\nHost: a\r\n",
  b"GET http://u@h/x HTTP/1.1",
  b"GET / HTTP/1.0\r\n\r\n",
  b"GET / HTTP/1.1\r\nHost: a\r\n\r\n",
  b"GET / HTTP/1.1\r\nHost: a\r\nConnection: close\r\n\r\n",
  b"GET / HTTP/1.0\r\nConnection: keep-alive\r\n\r\n",
  b"GET / HTTP/1.1\r\nHost: a\r\nConnection: keep-alive, close\r\n\r\n",
  b"GET /p? HTTP/1.1\r\nHost: a\r\nA:\t x y \t\r\nB:\r\n\r\n",
  b"GET /foo bar/ HTTP/1.1\r\nHost: a\r\n\r\n",
  b" / HTTP/1.1\r\nHost: a\r\n\r\n",
  b"GET  HTTP/1.1\r\nHost: a\r\n\r\n",
  b"GET / HTTP/1.1 \r\nHost: a\r\n\r\n",
  b"GET / HTTP/1.01\r\nHost: a\r\n\r\n",
  b"GET / HTTP/A.0\r\nHost: a\r\n\r\n",
  b"GET / aHTTP/1.1\r\nHost: a\r\n\r\n",
  b"GET /\x00 HTTP/1.1\r\nHost: a\r\n\r\n",
  b"\r\n\r\nGET / HTTP/1.1\r\nHost: a\r\n\r\n",
  b"OPTIONS * HTTP/1.1\r\nHost: a\r\n\r\n",
  b"CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n",
  b"GET / HTTP/1.1\r\nHost: a\r\n: v\r\n\r\n",
  b"POST / HTTP/1.1\r\nHost: a\r\nContent-Length : 4\r\n\r\n",
  b"POST / HTTP/1.1\r\nHost: a\r\nContent\r-Length: 4\r\n\r\n",
  b"GET / HTTP/1.1\r\n Host: a\r\n\r\n",
  b"POST / HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: chunked;foo\r\n\r\n",
  b"GET www.somewhere.com HTTP/1.1\r\nHost: a\r\n\r\n",
  b"GET /x#f HTTP/1.1\r\nHost: a\r\n\r\n",
  b"GET / HTTP/1.2\r\nHost: a\r\n\r\n",
  b"GET / HTTP/9.1\r\nHost: a\r\n\r\n",
  b"BAD /ping HTTP/1.1\r\nHost: a\r\n\r\n",
  b"bad /ping HTTP/1.1\r\nHost: a\r\n\r\n",
  b" /ping HTTP/1.1\r\nHost: a\r\n\r\n",
  b"GET /",
  b" HTTP/1.1\r\nHost: a\r\n\r\n",
  b"GET / HTTP/1.1\nHost: a\n\n",
];

/// The `format!`-built inputs of the ported tests.
pub fn ported_generated() -> Vec<Vec<u8>> {
  let mut v = Vec::new();
  for te in [
    "chunked",
    "CHUNKED",
    "gzip",
    "gzip, chunked",
    "chunked, chunked",
    "chunked, gzip",
    "",
    ", chunked",
    "chu nked",
    "chunked;foo",
  ] {
    v.push(format!("POST / HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: {te}\r\n\r\n").into_bytes());
  }
  for t in [
    "http://evil/x?q=1",
    "HTTPS://h:8080/a/b",
    "http://h",
    "http://h?x",
    "/http://h/x",
    "http://user:pw@evil/x",
    "http://user@evil",
    "https://@h/x",
    "http://u@h?q=1",
    "http://h#f",
    "http://h#f/x",
    "HTTP://h:80#f?x",
  ] {
    v.push(format!("GET {t} HTTP/1.1\r\nHost: a\r\n\r\n").into_bytes());
  }
  for cl in ["4 2", "5, 5", "+5", "4\t2"] {
    v.push(format!("POST / HTTP/1.1\r\nHost: a\r\nContent-Length: {cl}\r\n\r\n").into_bytes());
  }
  for host in ["a@b:80", "a:b:99", "localhost:80/x", "example.com:99999"] {
    v.push(format!("GET / HTTP/1.1\r\nHost: {host}\r\n\r\n").into_bytes());
  }
  v.push("GET /café HTTP/1.1\r\nHost: a\r\n\r\n".as_bytes().to_vec());
  let mut long = b"GET /".to_vec();
  long.extend(core::iter::repeat_n(b'a', 20 * 1024));
  long.extend_from_slice(b" HTTP/1.1\r\nHost: a\r\n\r\n");
  v.push(long);
  let mut big = b"GET / HTTP/1.1\r\nHost: a\r\nX: ".to_vec();
  big.resize(20_000, b'a');
  v.push(big.clone());
  big.extend_from_slice(b"\r\n\r\n");
  v.push(big);
  for n in [64usize, 65] {
    let mut buf = b"GET / HTTP/1.1\r\nHost: a\r\n".to_vec();
    for i in 1..n {
      buf.extend_from_slice(format!("X-H{i}: v\r\n").as_bytes());
    }
    buf.extend_from_slice(b"\r\n");
    v.push(buf);
  }
  v
}
