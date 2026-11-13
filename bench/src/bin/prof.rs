//! Loops one parser over one head, for `perf record`. Usage: prof <ours|httparse> <case> <secs>
use rimu_http1::{Config, RequestParser, Status};
use std::{hint::black_box, time::Instant};

fn main() {
  let args: Vec<String> = std::env::args().collect();
  let mut many = String::from("GET /many HTTP/1.1\r\nHost: example.com\r\n");
  for i in 0..40 {
    many.push_str(&format!(
      "X-Custom-Header-{i}: value-{i}-abcdefghijklmnopqrstuvwxyz0123456789\r\n"
    ));
  }
  many.push_str("\r\n");
  let curl =
    "GET / HTTP/1.1\r\nHost: localhost:8080\r\nUser-Agent: curl/8.5.0\r\nAccept: */*\r\n\r\n"
      .to_string();
  let buf = if args.get(2).map(String::as_str) == Some("curl") { curl } else { many };
  let buf = buf.as_bytes();
  let secs: u64 = args.get(3).and_then(|s| s.parse().ok()).unwrap_or(3);
  let mut parser = RequestParser::<64>::new(Config::DEFAULT);
  let t = Instant::now();
  let mut n = 0u64;
  let ours = args.get(1).map(String::as_str) != Some("httparse");
  while t.elapsed().as_secs() < secs {
    for _ in 0..10_000 {
      if ours {
        if let Ok(Status::Complete(r)) = parser.parse(black_box(buf)) {
          black_box(r.head_len);
        }
      } else {
        let mut h = [httparse::EMPTY_HEADER; 64];
        let mut req = httparse::Request::new(&mut h);
        black_box(req.parse(black_box(buf)).ok());
      }
    }
    n += 10_000;
  }
  println!("{:.1} ns", t.elapsed().as_nanos() as f64 / n as f64);
}
