//! Requests: no panics, invariants, and the outcome of the input fed whole equals the outcome of
//! it fed in pieces (the first two bytes choose the split points and the limits).
#![no_main]

use libfuzzer_sys::fuzz_target;
use nyseion_http1::{Config, Error, RequestParser, Status};

#[derive(Debug, PartialEq)]
enum Out {
  Complete { head_len: usize, fields: Vec<(String, String)>, path: String, query: String, body: String },
  Partial,
  Error(Error),
}

fn step(p: &mut RequestParser<16>, buf: &[u8]) -> Out {
  match p.parse(buf) {
    Ok(Status::Complete(r)) => {
      assert!(r.head_len <= buf.len());
      Out::Complete {
        head_len: r.head_len,
        fields: r.headers.iter().map(|h| (h.name.into(), h.value.into())).collect(),
        path: r.path.into(),
        query: r.query.into(),
        body: format!("{:?} {} {} {}", r.body, r.keep_alive, r.expect_continue, r.upgrade),
      }
    }
    Ok(Status::Partial) => Out::Partial,
    Err(e) => Out::Error(e),
  }
}

fuzz_target!(|data: &[u8]| {
  let Some((&[a, b], buf)) = data.split_first_chunk::<2>() else { return };
  let config = if a & 1 == 0 {
    Config::DEFAULT
  } else {
    Config { max_head_len: 128, max_line_len: 40, max_headers: 4, allow_extension_methods: a & 2 != 0 }
  };
  let whole = step(&mut RequestParser::new(config), buf);
  let mut p = RequestParser::new(config);
  let stride = usize::from(b % 17) + 1;
  let mut out = Out::Partial;
  let mut end = 0;
  while end < buf.len() {
    end = (end + stride).min(buf.len());
    let copy = buf[..end].to_vec();
    out = step(&mut p, &copy);
    if out != Out::Partial {
      break;
    }
  }
  if buf.is_empty() {
    out = step(&mut p, buf);
  }
  assert_eq!(out, whole);
});
