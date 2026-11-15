//! Body decoder: no panics, payload is a sub-slice count of the input, whole equals split.
#![no_main]

use libfuzzer_sys::fuzz_target;
use nyseion_http1::{BodyDecoder, BodyKind, BodyStatus, Config, Error};

fn run(kind: BodyKind, config: &Config, buf: &[u8], stride: usize) -> Result<(Vec<u8>, Option<usize>), Error> {
  let mut d = BodyDecoder::with_config(kind, config);
  let mut out = Vec::new();
  let mut start = 0;
  while start <= buf.len() {
    let end = (start + stride).min(buf.len());
    match d.feed(&buf[start..end], |x| out.extend_from_slice(x))? {
      BodyStatus::Complete { consumed } => return Ok((out, Some(start + consumed))),
      BodyStatus::NeedMore => {}
    }
    if end == buf.len() {
      break;
    }
    start = end;
  }
  let _ = d.finish();
  Ok((out, None))
}

fuzz_target!(|data: &[u8]| {
  let Some((&[a, b], buf)) = data.split_first_chunk::<2>() else { return };
  let kind = match a & 3 {
    0 | 1 => BodyKind::Chunked,
    2 => BodyKind::ContentLength(u64::from(b)),
    _ => BodyKind::UntilClose,
  };
  let config = if a & 4 == 0 { Config::DEFAULT } else { Config { max_head_len: 32, max_line_len: 12, max_headers: 2, ..Config::DEFAULT } };
  let whole = run(kind, &config, buf, buf.len().max(1));
  if let Ok((data, consumed)) = &whole {
    assert!(data.len() <= buf.len());
    assert!(consumed.is_none_or(|c| c <= buf.len()));
  }
  assert_eq!(run(kind, &config, buf, usize::from(b % 7) + 1), whole);
});
