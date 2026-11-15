//! Realistic messages, and generators of valid and slightly broken ones.

use super::Rng;
use nyseion_http1::Method;

/// Realistic requests, all valid.
pub fn requests() -> Vec<Vec<u8>> {
  let mut v: Vec<Vec<u8>> = [
    "GET / HTTP/1.1\r\nHost: localhost:8080\r\nUser-Agent: curl/8.5.0\r\nAccept: */*\r\n\r\n",
    "GET /plaintext HTTP/1.1\r\nHost: server\r\nAccept: text/plain,text/html;q=0.9\r\nConnection: keep-alive\r\n\r\n",
    "POST /api/orders HTTP/1.1\r\nHost: api.example.com\r\nContent-Type: application/json\r\nContent-Length: 348\r\nAuthorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.abc\r\nUser-Agent: python-requests/2.31.0\r\nAccept: */*\r\n\r\n",
    "GET /api/v1/products/12345?include=reviews&sort=desc HTTP/1.1\r\nHost: shop.example.com\r\nConnection: keep-alive\r\nsec-ch-ua: \"Chromium\";v=\"130\", \"Google Chrome\";v=\"130\", \"Not?A_Brand\";v=\"99\"\r\nsec-ch-ua-mobile: ?0\r\nsec-ch-ua-platform: \"macOS\"\r\nUpgrade-Insecure-Requests: 1\r\nUser-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36\r\nAccept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8\r\nSec-Fetch-Site: same-origin\r\nSec-Fetch-Mode: navigate\r\nSec-Fetch-Dest: document\r\nReferer: https://shop.example.com/products\r\nAccept-Encoding: gzip, deflate, br, zstd\r\nAccept-Language: en-US,en;q=0.9\r\nCookie: session=8f3a9b2c7d1e4f5a6b7c8d9e0f1a2b3c; theme=dark; _ga=GA1.2.123456789.1700000000; cart=abc123\r\n\r\n",
    "PUT /upload/file.bin HTTP/1.1\r\nHost: files.example.com\r\nTransfer-Encoding: chunked\r\nContent-Type: application/octet-stream\r\nExpect: 100-continue\r\n\r\n",
    "GET /chat HTTP/1.1\r\nHost: ws.example.com\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\nOrigin: https://example.com\r\n\r\n",
    "CONNECT proxy.example.com:443 HTTP/1.1\r\nHost: proxy.example.com:443\r\nProxy-Authorization: Basic dXNlcjpwYXNz\r\n\r\n",
    "CONNECT [2001:db8::1]:8443 HTTP/1.1\r\nHost: [2001:db8::1]:8443\r\n\r\n",
    "OPTIONS * HTTP/1.1\r\nHost: example.com\r\n\r\n",
    "GET http://example.com:8080/path/to?x=1&y=%20z HTTP/1.1\r\nHost: ignored.example\r\nProxy-Connection: keep-alive\r\n\r\n",
    "GET /legacy HTTP/1.0\r\nUser-Agent: Wget/1.21\r\nAccept: */*\r\nConnection: Keep-Alive\r\n\r\n",
    "HEAD /index.html HTTP/1.0\r\n\r\n",
    "DELETE /items/42 HTTP/1.1\r\nHost: api\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
    "PATCH /users/7 HTTP/1.1\r\nHost: api\r\nContent-Type: application/merge-patch+json\r\nContent-Length: 17\r\n\r\n{\"name\":\"Zoë\"}",
    "GET /search?q=%E2%9C%93&lang=fr HTTP/1.1\r\nHost: example.fr\r\nAccept-Language: fr-FR, fr;q=0.9\r\nX-Title: café crème — déjà vu\r\nX-Emoji: 🦀 ok\r\n\r\n",
    "GET /tabs HTTP/1.1\r\nHost: a\r\nX-Tab:\tvalue\twith\ttabs\t\r\nX-Empty:\r\nX-Spaces:    lots   \r\n\r\n",
    "\r\nGET /after-crlf HTTP/1.1\r\nHost: a\r\n\r\n",
    "TRACE / HTTP/1.1\r\nHost: a\r\nMax-Forwards: 3\r\n\r\n",
    "GET / HTTP/1.2\r\nHost: a\r\n\r\n",
    "POST /form HTTP/1.1\r\nHost: a\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: 27\r\n\r\nfield1=value1&field2=value2",
  ]
  .iter()
  .map(|s| s.as_bytes().to_vec())
  .collect();
  let mut many = String::from("GET /many HTTP/1.1\r\nHost: example.com\r\n");
  for i in 0..40 {
    many.push_str(&format!(
      "X-Custom-Header-{i}: value-{i}-abcdefghijklmnopqrstuvwxyz0123456789\r\n"
    ));
  }
  many.push_str("\r\n");
  v.push(many.into_bytes());
  let mut long = String::from("GET /");
  long.push_str(&"segment/".repeat(200));
  long.push_str("?q=");
  long.push_str(&"k=v&".repeat(150));
  long.push_str(" HTTP/1.1\r\nHost: a\r\nCookie: ");
  long.push_str(&"c=0123456789abcdef; ".repeat(100));
  long.push_str("\r\n\r\n");
  v.push(long.into_bytes());
  v
}

/// Realistic responses with the method of the request they answer, all valid.
pub fn responses() -> Vec<(Method, Vec<u8>)> {
  [
    (Method::Get, "HTTP/1.1 200 OK\r\nContent-Length: 13\r\nContent-Type: text/plain\r\n\r\nHello, World!"),
    (Method::Get, "HTTP/1.1 200 OK\r\nServer: nginx/1.25.3\r\nDate: Fri, 13 Nov 2026 10:00:00 GMT\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: 4521\r\nConnection: keep-alive\r\nETag: \"6553f2a1-11a9\"\r\n\r\n"),
    (Method::Get, "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nContent-Type: application/json\r\nSet-Cookie: a=1; Path=/; HttpOnly\r\nSet-Cookie: b=2; Secure\r\n\r\n5\r\nhello\r\n0\r\n\r\n"),
    (Method::Get, "HTTP/1.1 200 OK\r\nTransfer-Encoding: gzip, chunked\r\n\r\n"),
    (Method::Get, "HTTP/1.1 200 OK\r\nTransfer-Encoding: gzip\r\n\r\nbody until close"),
    (Method::Delete, "HTTP/1.1 204 No Content\r\nDate: Fri, 13 Nov 2026 10:00:00 GMT\r\n\r\n"),
    (Method::Get, "HTTP/1.1 304 Not Modified\r\nETag: \"x\"\r\nContent-Length: 100\r\n\r\n"),
    (Method::Head, "HTTP/1.1 200 OK\r\nContent-Length: 4521\r\n\r\n"),
    (Method::Get, "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n\r\n"),
    (Method::Connect, "HTTP/1.1 200 Connection Established\r\n\r\n"),
    (Method::Post, "HTTP/1.1 100 Continue\r\n\r\n"),
    (Method::Get, "HTTP/1.0 200 OK\r\nContent-Type: text/html\r\n\r\n<html></html>"),
    (Method::Get, "HTTP/1.0 200 OK\r\nContent-Length: 2\r\nConnection: keep-alive\r\n\r\nok"),
    (Method::Get, "HTTP/1.1 301 Moved Permanently\r\nLocation: https://example.com/\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"),
    (Method::Get, "HTTP/1.1 404 \r\nContent-Length: 0\r\n\r\n"),
    (Method::Get, "HTTP/1.1 200 Très bien ✓\r\nX-Note: café\r\nContent-Length: 0\r\n\r\n"),
    (Method::Get, "HTTP/1.1 503 Service Unavailable\r\nRetry-After: 120\r\nContent-Length: 0\r\n\r\n"),
  ]
  .iter()
  .map(|(m, s)| (*m, s.as_bytes().to_vec()))
  .collect()
}

const TCHARS: &[u8] =
  b"!#$%&'*+-.^_`|~0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
const PATH_CHARS: &[u8] =
  b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._~!$&'()*+,;=:@/%";
const VALUE_CHARS: &[u8] = b" !\"#$%&'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_`abcdefghijklmnopqrstuvwxyz{|}~";
const NAMES: &[&str] = &[
  "Accept",
  "User-Agent",
  "Cookie",
  "X-Request-Id",
  "Cache-Control",
  "Accept-Encoding",
  "Referer",
  "Authorization",
  "If-None-Match",
  "Content-Type",
  "X-Forwarded-For",
  "Origin",
  "Pragma",
];

fn token(rng: &mut Rng, max: usize) -> String {
  let n = 1 + rng.below(max);
  (0..n).map(|_| *rng.pick(TCHARS) as char).collect()
}

fn value(rng: &mut Rng) -> String {
  let mut s = String::new();
  if rng.below(4) == 0 {
    s.push(*rng.pick(&[' ', '\t']));
  }
  let n = rng.below(60);
  for _ in 0..n {
    match rng.below(40) {
      0 => s.push('\t'),
      1 => s.push(*rng.pick(&['é', '€', '🦀', 'ß'])),
      _ => s.push(*rng.pick(VALUE_CHARS) as char),
    }
  }
  if rng.below(4) == 0 {
    s.push(' ');
  }
  s
}

fn path(rng: &mut Rng) -> String {
  let mut s = String::from("/");
  for _ in 0..rng.below(40) {
    s.push(*rng.pick(PATH_CHARS) as char);
  }
  if rng.below(2) == 0 {
    s.push('?');
    for _ in 0..rng.below(30) {
      s.push(*rng.pick(b"a=&?/%20+") as char);
    }
  }
  s
}

/// A valid request: random method, target form, version and fields.
pub fn gen_request(rng: &mut Rng) -> Vec<u8> {
  let http10 = rng.below(6) == 0;
  let (method, target) = match rng.below(14) {
    0 => (
      "CONNECT",
      format!(
        "{}.example:{}",
        token(rng, 8)
          .to_lowercase()
          .replace(['#', '!', '$', '%', '&', '\'', '*', '+', '^', '`', '|', '~'], "x"),
        rng.below(65536)
      ),
    ),
    1 => ("OPTIONS", "*".to_string()),
    2 => (
      "GET",
      format!(
        "http{}://h{}.example{}",
        if rng.below(2) == 0 { "" } else { "s" },
        rng.below(100),
        path(rng)
      ),
    ),
    3 => ("POST", path(rng)),
    4 => ("PUT", path(rng)),
    5 => ("DELETE", path(rng)),
    6 => ("HEAD", path(rng)),
    7 => ("PATCH", path(rng)),
    _ => ("GET", path(rng)),
  };
  let mut s = format!("{method} {target} HTTP/1.{}\r\n", if http10 { 0 } else { 1 });
  let host_at = if http10 && rng.below(2) == 0 { usize::MAX } else { rng.below(4) };
  let nfields = rng.below(12);
  let mut framing = false;
  for k in 0..=nfields {
    if k == host_at {
      s.push_str(&format!(
        "{}: host{}.example:{}\r\n",
        rng.pick(&["Host", "host", "HOST"]),
        rng.below(9),
        1 + rng.below(9000)
      ));
    }
    if k == nfields {
      break;
    }
    let name = if rng.below(3) == 0 { token(rng, 20) } else { (*rng.pick(NAMES)).to_string() };
    if name.eq_ignore_ascii_case("host")
      || name.eq_ignore_ascii_case("content-length")
      || name.eq_ignore_ascii_case("transfer-encoding")
    {
      continue;
    }
    s.push_str(&format!("{name}:{}\r\n", value(rng)));
    if !framing && rng.below(8) == 0 {
      framing = true;
      match rng.below(4) {
        0 => s.push_str("Transfer-Encoding: chunked\r\n"),
        1 => s.push_str("Connection: close\r\n"),
        2 => s.push_str("Connection: keep-alive, Upgrade\r\nUpgrade: websocket\r\n"),
        _ => s.push_str(&format!("Content-Length: {}\r\n", rng.below(100_000))),
      }
    }
  }
  s.push_str("\r\n");
  s.into_bytes()
}

/// A valid response.
pub fn gen_response(rng: &mut Rng) -> (Method, Vec<u8>) {
  let method = *rng.pick(&[Method::Get, Method::Get, Method::Post, Method::Head, Method::Connect]);
  let status = *rng.pick(&[200u16, 201, 204, 301, 304, 400, 404, 500, 101, 100, 302, 418, 599]);
  let mut s = format!("HTTP/1.{} {status} ", rng.below(2));
  for _ in 0..rng.below(20) {
    s.push(*rng.pick(VALUE_CHARS) as char);
  }
  s.push_str("\r\n");
  let mut framing = false;
  for _ in 0..rng.below(14) {
    let name = if rng.below(3) == 0 { token(rng, 20) } else { (*rng.pick(NAMES)).to_string() };
    if name.eq_ignore_ascii_case("content-length") || name.eq_ignore_ascii_case("transfer-encoding")
    {
      continue;
    }
    s.push_str(&format!("{name}: {}\r\n", value(rng)));
    if !framing && rng.below(5) == 0 {
      framing = true;
      match rng.below(4) {
        0 => s.push_str("Transfer-Encoding: chunked\r\n"),
        1 => s.push_str("Connection: close\r\n"),
        2 => s.push_str("Transfer-Encoding: gzip, chunked\r\n"),
        _ => s.push_str(&format!("Content-Length: {}\r\n", rng.below(100_000))),
      }
    }
  }
  s.push_str("\r\n");
  (method, s.into_bytes())
}

/// `input` with a few random edits (byte replaced by an interesting byte, inserted, deleted,
/// or a range duplicated), so that most results are errors of many different kinds.
pub fn mutate(rng: &mut Rng, input: &[u8]) -> Vec<u8> {
  const BYTES: &[u8] = b"\r\n\t :;,=\"\\#?/@[]%\0\x7f\x80\xc3\xa9\xff aZ09-";
  let mut v = input.to_vec();
  for _ in 0..1 + rng.below(3) {
    if v.is_empty() {
      v.push(*rng.pick(BYTES));
      continue;
    }
    let at = rng.below(v.len());
    match rng.below(4) {
      0 => v[at] = *rng.pick(BYTES),
      1 => v.insert(at, *rng.pick(BYTES)),
      2 => {
        v.remove(at);
      }
      _ => {
        let end = (at + 1 + rng.below(16)).min(v.len());
        let piece = v[at..end].to_vec();
        v.splice(at..at, piece);
      }
    }
  }
  v
}
