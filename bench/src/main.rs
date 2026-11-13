//! rimu-http1 vs httparse vs the rimu-ws parser, on whole and split heads.
//!
//! Run pinned to one core: `taskset -c 7 target/release/rimu-http1-bench`.
//! Every contender extracts the same facts (head length, path, query, body framing,
//! keep-alive) and the results are checked to agree before timing.
use rimu_http1::{BodyKind, Config, Method, RequestParser, ResponseParser, Status};
use std::{hint::black_box, time::Instant};

/// Times the contenders interleaved: 41 rounds, each running every contender for ~2 ms.
/// Returns, per contender, the minimum time per call and the median over rounds of
/// `time(contender) / time(last contender)`. Interleaving makes the ratios robust on a shared
/// machine, where load and clock speed change from one moment to the next.
fn measure(fs: &mut [&mut dyn FnMut() -> usize]) -> Vec<(f64, f64)> {
  let iters: Vec<u64> = fs
    .iter_mut()
    .map(|f| {
      let t = Instant::now();
      let mut n = 0u64;
      while t.elapsed().as_millis() < 10 {
        black_box(f());
        n += 1;
      }
      ((2e6 / (t.elapsed().as_nanos() as f64 / n as f64)) as u64).max(1)
    })
    .collect();
  let rounds = 41;
  let mut samples = vec![Vec::with_capacity(rounds); fs.len()];
  for _ in 0..rounds {
    for (k, f) in fs.iter_mut().enumerate() {
      let t = Instant::now();
      for _ in 0..iters[k] {
        black_box(f());
      }
      samples[k].push(t.elapsed().as_nanos() as f64 / iters[k] as f64);
    }
  }
  let last = samples.len() - 1;
  (0..samples.len())
    .map(|k| {
      let min = samples[k].iter().copied().fold(f64::INFINITY, f64::min);
      let mut ratios: Vec<f64> = (0..rounds).map(|r| samples[k][r] / samples[last][r]).collect();
      ratios.sort_by(|a, b| a.partial_cmp(b).unwrap());
      (min, ratios[rounds / 2])
    })
    .collect()
}

/// Facts every contender extracts: (head length, path+query length + body + keep-alive).
type Facts = (usize, usize);

fn httparse_raw(buf: &[u8]) -> Option<usize> {
  let mut headers = [httparse::EMPTY_HEADER; 64];
  let mut req = httparse::Request::new(&mut headers);
  match req.parse(buf).ok()? {
    httparse::Status::Partial => None,
    httparse::Status::Complete(len) => Some(len + req.headers.len()),
  }
}

/// httparse plus the framing work: path/query split, Content-Length, chunked, keep-alive.
fn httparse_framed(buf: &[u8]) -> Option<Facts> {
  let mut headers = [httparse::EMPTY_HEADER; 64];
  let mut req = httparse::Request::new(&mut headers);
  match req.parse(buf).ok()? {
    httparse::Status::Partial => None,
    httparse::Status::Complete(len) => {
      let path = req.path?;
      let (p, q) = path.split_once('?').unwrap_or((path, ""));
      let mut body = 0usize;
      let mut chunked = false;
      let mut keep_alive = req.version == Some(1);
      for h in req.headers.iter() {
        if h.name.eq_ignore_ascii_case("content-length") {
          body = std::str::from_utf8(h.value).ok()?.trim().parse().ok()?;
        } else if h.name.eq_ignore_ascii_case("transfer-encoding") {
          chunked = h.value.eq_ignore_ascii_case(b"chunked");
        } else if h.name.eq_ignore_ascii_case("connection") {
          if h.value.eq_ignore_ascii_case(b"close") {
            keep_alive = false;
          } else if h.value.eq_ignore_ascii_case(b"keep-alive") {
            keep_alive = true;
          }
        }
      }
      Some((len, p.len() + q.len() + body + usize::from(chunked) + usize::from(keep_alive)))
    }
  }
}

fn ows(v: &[u8]) -> &[u8] {
  let s = v.iter().position(|b| *b != b' ' && *b != b'\t').unwrap_or(v.len());
  let e = v.iter().rposition(|b| *b != b' ' && *b != b'\t').map_or(s, |e| e + 1);
  &v[s..e.max(s)]
}

fn host_ok(v: &[u8]) -> bool {
  let (name, port) = match v.iter().position(|b| *b == b':') {
    Some(i) => (&v[..i], Some(&v[i + 1..])),
    None => (v, None),
  };
  name.iter().all(|b| b.is_ascii_alphanumeric() || b"-._~%!$&'()*+,;=".contains(b))
    && port.is_none_or(|p| {
      p.len() <= 5
        && p.iter().all(u8::is_ascii_digit)
        && std::str::from_utf8(p)
          .ok()
          .and_then(|s| s.parse::<u32>().ok())
          .is_some_and(|n| n <= 65535)
    })
}

/// httparse + framing + the checks that make it about as strict as rimu-http1: no bare LF, a
/// target without `#` or raw non-ASCII, UTF-8 values, `Host` required once and valid,
/// `Content-Length` digits only and once, `Transfer-Encoding` exactly `chunked`, not both.
/// (Still laxer: obs-fold/target forms/method set/limits are not re-checked.)
fn httparse_strict(buf: &[u8]) -> Option<Facts> {
  let mut headers = [httparse::EMPTY_HEADER; 64];
  let mut req = httparse::Request::new(&mut headers);
  match req.parse(buf).ok()? {
    httparse::Status::Partial => None,
    httparse::Status::Complete(len) => {
      // Bare LF: httparse accepts `\n` line endings.
      let head = &buf[..len];
      let mut from = 0;
      while let Some(p) = head[from..].iter().position(|b| *b == b'\n') {
        let at = from + p;
        if at == 0 || head[at - 1] != b'\r' {
          return None;
        }
        from = at + 1;
      }
      let path = req.path?;
      if path.bytes().any(|b| b == b'#' || b >= 0x80) {
        return None;
      }
      let (p, q) = path.split_once('?').unwrap_or((path, ""));
      let mut body = 0usize;
      let mut cl = false;
      let mut chunked = false;
      let mut host = false;
      let mut keep_alive = req.version == Some(1);
      for h in req.headers.iter() {
        let value = std::str::from_utf8(h.value).ok()?;
        let n = h.name;
        if n.eq_ignore_ascii_case("host") {
          if host || !host_ok(value.as_bytes()) {
            return None;
          }
          host = true;
        } else if n.eq_ignore_ascii_case("content-length") {
          let v = ows(value.as_bytes());
          if cl || v.is_empty() || !v.iter().all(u8::is_ascii_digit) {
            return None;
          }
          cl = true;
          body = std::str::from_utf8(v).ok()?.parse().ok()?;
        } else if n.eq_ignore_ascii_case("transfer-encoding") {
          if chunked || !ows(value.as_bytes()).eq_ignore_ascii_case(b"chunked") {
            return None;
          }
          chunked = true;
        } else if n.eq_ignore_ascii_case("connection") {
          for t in value.split(',') {
            let t = t.trim();
            if t.eq_ignore_ascii_case("close") {
              keep_alive = false;
            } else if t.eq_ignore_ascii_case("keep-alive") {
              keep_alive = true;
            }
          }
        }
      }
      if (cl && chunked) || (req.version == Some(1) && !host) {
        return None;
      }
      Some((len, p.len() + q.len() + body + usize::from(chunked) + usize::from(keep_alive)))
    }
  }
}

fn body_num(kind: BodyKind) -> usize {
  match kind {
    BodyKind::None | BodyKind::UntilClose => 0,
    BodyKind::ContentLength(n) => n as usize,
    BodyKind::Chunked => 1,
  }
}

fn ours(parser: &mut RequestParser, buf: &[u8]) -> Option<Facts> {
  match parser.parse(buf).ok()? {
    Status::Partial => None,
    Status::Complete(r) => Some((
      r.head_len,
      r.path.len() + r.query.len() + body_num(r.body) + usize::from(r.keep_alive),
    )),
  }
}

fn old(buf: &[u8], scratch: &mut rimu_ws::http1::ParseScratch) -> Option<Facts> {
  use rimu_ws::http1::{BodyKind as K, ParseOutcome, parse_request};
  match parse_request(buf, scratch).ok()? {
    ParseOutcome::Partial => None,
    ParseOutcome::Complete { request, head_len } => {
      let body = match request.body_kind {
        K::None => 0,
        K::ContentLength(n) => n,
        K::Chunked => 1,
      };
      Some((
        head_len,
        request.path.len() + request.query.len() + body + usize::from(request.keep_alive),
      ))
    }
  }
}

fn httparse_response(buf: &[u8]) -> Option<Facts> {
  let mut headers = [httparse::EMPTY_HEADER; 64];
  let mut res = httparse::Response::new(&mut headers);
  match res.parse(buf).ok()? {
    httparse::Status::Partial => None,
    httparse::Status::Complete(len) => {
      let mut body = 0usize;
      let mut chunked = false;
      let mut keep_alive = res.version == Some(1);
      for h in res.headers.iter() {
        if h.name.eq_ignore_ascii_case("content-length") {
          body = std::str::from_utf8(h.value).ok()?.trim().parse().ok()?;
        } else if h.name.eq_ignore_ascii_case("transfer-encoding") {
          chunked = h.value.eq_ignore_ascii_case(b"chunked");
        } else if h.name.eq_ignore_ascii_case("connection")
          && h.value.eq_ignore_ascii_case(b"close")
        {
          keep_alive = false;
        }
      }
      Some((len, usize::from(res.code?) + body + usize::from(chunked) + usize::from(keep_alive)))
    }
  }
}

fn ours_response(parser: &mut ResponseParser, buf: &[u8]) -> Option<Facts> {
  match parser.parse(buf, Method::Get).ok()? {
    Status::Partial => None,
    Status::Complete(r) => {
      Some((r.head_len, usize::from(r.status) + body_num(r.body) + usize::from(r.keep_alive)))
    }
  }
}

/// Calls `f` on growing prefixes: `parts` equal reads (`parts == len`: byte by byte).
fn split(buf: &[u8], parts: usize, f: &mut dyn FnMut(&[u8]) -> bool) -> usize {
  let step = buf.len().div_ceil(parts);
  let mut done = 0;
  let mut end = 0;
  while end < buf.len() {
    end = (end + step).min(buf.len());
    if f(&buf[..end]) {
      done += 1;
    }
  }
  done
}

fn main() {
  let browser = "GET /api/v1/products/12345?include=reviews&sort=desc HTTP/1.1\r\nHost: shop.example.com\r\nConnection: keep-alive\r\nsec-ch-ua: \"Chromium\";v=\"130\", \"Google Chrome\";v=\"130\", \"Not?A_Brand\";v=\"99\"\r\nsec-ch-ua-mobile: ?0\r\nsec-ch-ua-platform: \"macOS\"\r\nUpgrade-Insecure-Requests: 1\r\nUser-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36\r\nAccept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8\r\nSec-Fetch-Site: same-origin\r\nSec-Fetch-Mode: navigate\r\nSec-Fetch-Dest: document\r\nReferer: https://shop.example.com/products\r\nAccept-Encoding: gzip, deflate, br, zstd\r\nAccept-Language: en-US,en;q=0.9\r\nCookie: session=8f3a9b2c7d1e4f5a6b7c8d9e0f1a2b3c; theme=dark; _ga=GA1.2.123456789.1700000000; cart=abc123\r\n\r\n".to_string();
  let mut many = String::from("GET /many HTTP/1.1\r\nHost: example.com\r\n");
  for i in 0..40 {
    many.push_str(&format!(
      "X-Custom-Header-{i}: value-{i}-abcdefghijklmnopqrstuvwxyz0123456789\r\n"
    ));
  }
  many.push_str("\r\n");
  let cases: Vec<(&str, String)> = vec![
    ("curl GET", "GET / HTTP/1.1\r\nHost: localhost:8080\r\nUser-Agent: curl/8.5.0\r\nAccept: */*\r\n\r\n".into()),
    ("plaintext GET", "GET /plaintext HTTP/1.1\r\nHost: server\r\nAccept: text/plain,text/html;q=0.9\r\nConnection: keep-alive\r\n\r\n".into()),
    ("POST JSON", "POST /api/orders HTTP/1.1\r\nHost: api.example.com\r\nContent-Type: application/json\r\nContent-Length: 348\r\nAuthorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.abc\r\nUser-Agent: python-requests/2.31.0\r\nAccept: */*\r\n\r\n".into()),
    ("browser GET (15 headers)", browser),
    ("40 custom headers", many),
  ];
  let responses: Vec<(&str, String)> = vec![
    ("small response", "HTTP/1.1 200 OK\r\nContent-Length: 13\r\nContent-Type: text/plain\r\n\r\n".into()),
    ("nginx response", "HTTP/1.1 200 OK\r\nServer: nginx/1.25.3\r\nDate: Fri, 13 Nov 2026 10:00:00 GMT\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: 4521\r\nConnection: keep-alive\r\nLast-Modified: Thu, 12 Nov 2026 08:00:00 GMT\r\nETag: \"6553f2a1-11a9\"\r\nAccept-Ranges: bytes\r\n\r\n".into()),
    ("CDN response (chunked, cookies)", "HTTP/1.1 200 OK\r\nDate: Fri, 13 Nov 2026 10:00:00 GMT\r\nContent-Type: application/json; charset=utf-8\r\nTransfer-Encoding: chunked\r\nConnection: keep-alive\r\nCache-Control: private, max-age=0, no-cache\r\nVary: Accept-Encoding, Origin\r\nSet-Cookie: __cf_bm=Qm9vbGVhbiBzZXNzaW9uIHRva2VuIGZvciBib3QgbWFuYWdlbWVudA; path=/; expires=Fri, 13-Nov-26 10:30:00 GMT; domain=.example.com; HttpOnly; Secure; SameSite=None\r\nSet-Cookie: session=abc123def456; Path=/; HttpOnly; Secure\r\nStrict-Transport-Security: max-age=31536000; includeSubDomains; preload\r\nX-Content-Type-Options: nosniff\r\nX-Frame-Options: DENY\r\nReferrer-Policy: strict-origin-when-cross-origin\r\nCF-Cache-Status: DYNAMIC\r\nServer: cloudflare\r\nCF-RAY: 8f1a2b3c4d5e6f70-AMS\r\nAlt-Svc: h3=\":443\"; ma=86400\r\n\r\n".into()),
  ];

  println!(
    "ns per head: minimum over 41 interleaved rounds; ratios: median over rounds of other / rimu-http1 (>1: rimu-http1 faster). One core. `4 reads` / `byte by byte`: the head arrives in 4 / len reads and every parser is called after each read (httparse and rimu-ws re-parse from the start; rimu-http1 resumes).\n"
  );
  println!("### Requests, whole\n");
  println!(
    "| request | bytes | httparse tokens | httparse + framing | httparse + framing + strict | rimu-ws | **rimu-http1** | vs httparse+framing | vs httparse strict | vs rimu-ws |"
  );
  println!("|---|---|---|---|---|---|---|---|---|---|");
  let mut parser = RequestParser::<64>::new(Config::DEFAULT);
  let mut scratch = rimu_ws::http1::ParseScratch::new();
  let mut split_rows = Vec::new();
  for (name, req) in &cases {
    let buf = req.as_bytes();
    let a = httparse_framed(buf).expect("httparse");
    assert_eq!(httparse_strict(buf), Some(a), "{name}");
    assert_eq!(old(buf, &mut scratch), Some(a), "{name}");
    assert_eq!(ours(&mut parser, buf), Some(a), "{name}");
    let m = measure(&mut [
      &mut || httparse_raw(black_box(buf)).unwrap(),
      &mut || httparse_framed(black_box(buf)).unwrap().1,
      &mut || httparse_strict(black_box(buf)).unwrap().1,
      &mut || old(black_box(buf), &mut scratch).unwrap().1,
      &mut || ours(&mut parser, black_box(buf)).unwrap().1,
    ]);
    println!(
      "| {name} | {} | {:.0} | {:.0} | {:.0} | {:.0} | **{:.0}** | {:.2}× | {:.2}× | {:.2}× |",
      buf.len(),
      m[0].0,
      m[1].0,
      m[2].0,
      m[3].0,
      m[4].0,
      m[1].1,
      m[2].1,
      m[3].1
    );
    let mut row = Vec::new();
    for parts in [4, buf.len()] {
      let m = measure(&mut [
        &mut || split(buf, parts, &mut |b| httparse_framed(black_box(b)).is_some()),
        &mut || split(buf, parts, &mut |b| old(black_box(b), &mut scratch).is_some()),
        &mut || split(buf, parts, &mut |b| ours(&mut parser, black_box(b)).is_some()),
      ]);
      row.push(m);
    }
    split_rows.push((name, buf.len(), row));
  }
  println!("\n### Requests, split\n");
  println!(
    "| request | bytes | 4 reads: httparse+framing / rimu-ws / **rimu-http1** | byte by byte: httparse+framing / rimu-ws / **rimu-http1** | byte by byte, rimu-http1 ns per byte |"
  );
  println!("|---|---|---|---|---|");
  for (name, len, row) in split_rows {
    let (f4, o4, r4) = (row[0][0], row[0][1], row[0][2]);
    let (fb, ob, rb) = (row[1][0], row[1][1], row[1][2]);
    println!(
      "| {name} | {len} | {:.0} / {:.0} / **{:.0}** ({:.2}× / {:.2}×) | {:.0} / {:.0} / **{:.0}** ({:.1}× / {:.1}×) | {:.1} |",
      f4.0,
      o4.0,
      r4.0,
      f4.1,
      o4.1,
      fb.0,
      ob.0,
      rb.0,
      fb.1,
      ob.1,
      rb.0 / len as f64
    );
  }
  println!("\n### Responses (rimu-ws has no response parser)\n");
  println!(
    "| response | bytes | httparse + framing | **rimu-http1** | ratio | 4 reads: httparse / **rimu-http1** | byte by byte: httparse / **rimu-http1** |"
  );
  println!("|---|---|---|---|---|---|---|");
  let mut rparser = ResponseParser::<64>::new(Config::DEFAULT);
  for (name, res) in &responses {
    let buf = res.as_bytes();
    let a = httparse_response(buf).expect("httparse");
    assert_eq!(ours_response(&mut rparser, buf), Some(a), "{name}");
    let m = measure(&mut [&mut || httparse_response(black_box(buf)).unwrap().1, &mut || {
      ours_response(&mut rparser, black_box(buf)).unwrap().1
    }]);
    let m4 = measure(&mut [
      &mut || split(buf, 4, &mut |b| httparse_response(black_box(b)).is_some()),
      &mut || split(buf, 4, &mut |b| ours_response(&mut rparser, black_box(b)).is_some()),
    ]);
    let mb = measure(&mut [
      &mut || split(buf, buf.len(), &mut |b| httparse_response(black_box(b)).is_some()),
      &mut || split(buf, buf.len(), &mut |b| ours_response(&mut rparser, black_box(b)).is_some()),
    ]);
    println!(
      "| {name} | {} | {:.0} | **{:.0}** | {:.2}× | {:.0} / **{:.0}** ({:.2}×) | {:.0} / **{:.0}** ({:.1}×) |",
      buf.len(),
      m[0].0,
      m[1].0,
      m[0].1,
      m4[0].0,
      m4[1].0,
      m4[0].1,
      mb[0].0,
      mb[1].0,
      mb[0].1
    );
  }
}
