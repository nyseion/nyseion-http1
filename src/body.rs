//! Incremental, zero-copy body decoder.

use crate::{BodyKind, Config, Error, scan::is_tchar};

/// Result of one [`BodyDecoder::decode`] step.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Decoded<'a> {
  /// Bytes of the input this step used (framing and payload). Drop them before the next step.
  pub consumed: usize,
  /// Payload: a slice of the input, possibly empty.
  pub data: &'a [u8],
  /// The body is complete; input after `consumed` belongs to the next message.
  pub done: bool,
}

/// Progress of [`BodyDecoder::feed`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BodyStatus {
  /// All input was used and the body needs more.
  NeedMore,
  /// The body is complete.
  Complete {
    /// Bytes of this `feed` input that belong to the body; the rest is the next message.
    consumed: usize,
  },
}

/// Decoder of `Content-Length`, chunked and until-close bodies.
///
/// It resumes at any byte: its state is a few words, and chunk payload is sliced out of the
/// input instead of copied.
///
/// ```
/// use nyseion_http1::{BodyDecoder, BodyKind, BodyStatus};
///
/// let mut decoder = BodyDecoder::new(BodyKind::Chunked);
/// let mut out = Vec::new();
/// let input = b"3\r\nabc\r\n0\r\n\r\nGET /";
/// let status = decoder.feed(input, |data| out.extend_from_slice(data)).unwrap();
/// assert_eq!(status, BodyStatus::Complete { consumed: input.len() - 5 });
/// assert_eq!(out, b"abc");
/// ```
#[derive(Clone, Debug)]
pub struct BodyDecoder {
  state: BState,
  /// Remaining bytes of a `Content-Length` body or of a chunk, or the chunk size being read.
  value: u64,
  /// Bytes of the current chunk-size line, or trailer fields so far.
  count: u32,
  /// Bytes of the trailer section so far.
  trailer_len: u32,
  max_line_len: u32,
  max_trailer_len: u32,
  max_trailers: u16,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum BState {
  Done,
  UntilClose,
  Length,
  /// Hex digits of a chunk size; `any`: at least one.
  Size {
    any: bool,
  },
  /// Whitespace after the size: only `;` may follow.
  SizeBws,
  /// After `;`: whitespace, then an extension name.
  ExtStart,
  ExtName,
  /// Whitespace after a name: `=` or `;`.
  ExtNameBws,
  /// After `=`: whitespace, then a token or a quoted string.
  ExtEq,
  ExtToken,
  ExtQuoted,
  ExtQuotedEscape,
  /// After a closing quote: CR, `;` or whitespace.
  ExtAfterQuote,
  /// Whitespace after a value: only `;` may follow.
  ExtBws,
  /// Saw the CR of the chunk-size line.
  SizeLf,
  Data,
  DataCr,
  DataLf,
  TrailerStart,
  TrailerName,
  TrailerValue,
  TrailerLf,
  FinalLf,
  Failed(Error),
}

impl BodyDecoder {
  /// A decoder for `kind` with the default limits ([`Config::DEFAULT`]).
  #[inline]
  pub const fn new(kind: BodyKind) -> Self {
    Self::with_config(kind, &Config::DEFAULT)
  }

  /// A decoder for `kind`: chunk-size lines are bounded by `max_line_len`, the trailer section
  /// by `max_head_len` bytes and `max_headers` fields.
  #[inline]
  pub const fn with_config(kind: BodyKind, config: &Config) -> Self {
    let (state, value) = match kind {
      BodyKind::None | BodyKind::ContentLength(0) => (BState::Done, 0),
      BodyKind::ContentLength(len) => (BState::Length, len),
      BodyKind::Chunked => (BState::Size { any: false }, 0),
      BodyKind::UntilClose => (BState::UntilClose, 0),
    };
    Self {
      state,
      value,
      count: 0,
      trailer_len: 0,
      max_line_len: config.max_line_len,
      max_trailer_len: config.max_head_len,
      max_trailers: config.max_headers,
    }
  }

  /// If the body is complete.
  #[inline]
  pub const fn is_done(&self) -> bool {
    matches!(self.state, BState::Done)
  }

  /// The connection ended: `Ok` if that ends the body (an until-close body, or a complete one),
  /// else [`Error::UnexpectedEof`].
  #[inline]
  pub const fn finish(&self) -> Result<(), Error> {
    match self.state {
      BState::Done | BState::UntilClose => Ok(()),
      BState::Failed(err) => Err(err),
      _ => Err(Error::UnexpectedEof),
    }
  }

  /// Decodes from the start of `input`: consumes framing bytes and returns at most one run of
  /// payload, as a slice of `input`. Call again with `&input[consumed..]` until all input is
  /// consumed or `done`. An error is repeated by later calls.
  #[inline]
  pub fn decode<'a>(&mut self, input: &'a [u8]) -> Result<Decoded<'a>, Error> {
    let mut i = 0usize;
    loop {
      match self.state {
        BState::Done => return Ok(Decoded { consumed: i, data: &[], done: true }),
        BState::Failed(err) => return Err(err),
        BState::UntilClose => {
          let data = input.get(i..).unwrap_or_default();
          return Ok(Decoded { consumed: input.len(), data, done: false });
        }
        BState::Length | BState::Data => {
          let rest = input.get(i..).unwrap_or_default();
          // Bounded by `rest.len()`, a `usize`.
          let take = self.value.min(rest.len() as u64) as usize;
          let data = rest.get(..take).unwrap_or_default();
          self.value -= take as u64;
          i += take;
          let mut done = false;
          if self.value == 0 {
            if self.state == BState::Length {
              self.state = BState::Done;
              done = true;
            } else {
              self.state = BState::DataCr;
            }
          }
          if !data.is_empty() || done {
            return Ok(Decoded { consumed: i, data, done });
          }
          if i >= input.len() {
            return Ok(Decoded { consumed: i, data, done });
          }
        }
        state => {
          let Some(&byte) = input.get(i) else {
            return Ok(Decoded { consumed: i, data: &[], done: false });
          };
          i += 1;
          match self.step(state, byte) {
            Ok(next) => self.state = next,
            Err(err) => {
              self.state = BState::Failed(err);
              return Err(err);
            }
          }
        }
      }
    }
  }

  /// Decodes all of `input`, passing each run of payload to `sink`. Once the body is complete,
  /// the bytes after `consumed` belong to the next message.
  #[inline]
  pub fn feed<'a>(
    &mut self,
    input: &'a [u8],
    mut sink: impl FnMut(&'a [u8]),
  ) -> Result<BodyStatus, Error> {
    let mut rest = input;
    let mut total = 0usize;
    loop {
      let step = self.decode(rest)?;
      if !step.data.is_empty() {
        sink(step.data);
      }
      total += step.consumed;
      if step.done {
        return Ok(BodyStatus::Complete { consumed: total });
      }
      rest = rest.get(step.consumed..).unwrap_or_default();
      if rest.is_empty() {
        return Ok(BodyStatus::NeedMore);
      }
    }
  }

  /// Counts one more byte of the chunk-size line.
  #[inline]
  fn line_byte(&mut self) -> Result<(), Error> {
    self.count += 1;
    if self.count > self.max_line_len {
      return Err(Error::ChunkLineTooLong);
    }
    Ok(())
  }

  /// One byte of the framing state machine.
  fn step(&mut self, state: BState, byte: u8) -> Result<BState, Error> {
    let ws = byte == b' ' || byte == b'\t';
    let in_size_line = !matches!(
      state,
      BState::SizeLf
        | BState::DataCr
        | BState::DataLf
        | BState::TrailerStart
        | BState::TrailerName
        | BState::TrailerValue
        | BState::TrailerLf
        | BState::FinalLf
    );
    if in_size_line && byte != b'\r' {
      self.line_byte()?;
    }
    Ok(match state {
      BState::Size { any } => {
        if let Some(digit) = hex_digit(byte) {
          self.value = self
            .value
            .checked_mul(16)
            .and_then(|v| v.checked_add(digit))
            .ok_or(Error::InvalidChunkSize)?;
          BState::Size { any: true }
        } else if !any {
          return Err(Error::InvalidChunkSize);
        } else if byte == b'\r' {
          BState::SizeLf
        } else if byte == b';' {
          BState::ExtStart
        } else if ws {
          BState::SizeBws
        } else {
          return Err(Error::InvalidChunkSize);
        }
      }
      // RFC 9112 §7.1.1: chunk-ext = *( BWS ";" BWS chunk-ext-name [ BWS "=" BWS chunk-ext-val ] )
      BState::SizeBws | BState::ExtBws => match byte {
        b';' => BState::ExtStart,
        _ if ws => state,
        _ => return Err(Error::InvalidChunkExtension),
      },
      BState::ExtStart => match byte {
        _ if ws => state,
        _ if is_tchar(byte) => BState::ExtName,
        _ => return Err(Error::InvalidChunkExtension),
      },
      BState::ExtName => match byte {
        _ if is_tchar(byte) => state,
        b'\r' => BState::SizeLf,
        b';' => BState::ExtStart,
        b'=' => BState::ExtEq,
        _ if ws => BState::ExtNameBws,
        _ => return Err(Error::InvalidChunkExtension),
      },
      BState::ExtNameBws => match byte {
        b';' => BState::ExtStart,
        b'=' => BState::ExtEq,
        _ if ws => state,
        _ => return Err(Error::InvalidChunkExtension),
      },
      BState::ExtEq => match byte {
        _ if ws => state,
        b'"' => BState::ExtQuoted,
        _ if is_tchar(byte) => BState::ExtToken,
        _ => return Err(Error::InvalidChunkExtension),
      },
      BState::ExtToken => match byte {
        _ if is_tchar(byte) => state,
        b'\r' => BState::SizeLf,
        b';' => BState::ExtStart,
        _ if ws => BState::ExtBws,
        _ => return Err(Error::InvalidChunkExtension),
      },
      // RFC 9110 §5.6.4: qdtext and quoted-pair.
      BState::ExtQuoted => match byte {
        b'"' => BState::ExtAfterQuote,
        b'\\' => BState::ExtQuotedEscape,
        b'\t' | b' ' | 0x21 | 0x23..=0x5b | 0x5d..=0x7e | 0x80..=0xff => state,
        _ => return Err(Error::InvalidChunkExtension),
      },
      BState::ExtQuotedEscape => match byte {
        b'\t' | b' ' | 0x21..=0x7e | 0x80..=0xff => BState::ExtQuoted,
        _ => return Err(Error::InvalidChunkExtension),
      },
      BState::ExtAfterQuote => match byte {
        b'\r' => BState::SizeLf,
        b';' => BState::ExtStart,
        _ if ws => BState::ExtBws,
        _ => return Err(Error::InvalidChunkExtension),
      },
      BState::SizeLf => {
        if byte != b'\n' {
          return Err(Error::InvalidLineEnding);
        }
        self.count = 0;
        if self.value == 0 { BState::TrailerStart } else { BState::Data }
      }
      BState::DataCr => {
        if byte != b'\r' {
          return Err(Error::InvalidChunkEnd);
        }
        BState::DataLf
      }
      BState::DataLf => {
        if byte != b'\n' {
          return Err(Error::InvalidChunkEnd);
        }
        BState::Size { any: false }
      }
      // Trailer fields are fields (RFC 9112 §7.1.2): token names, values without controls, and
      // no more of them than of a head's fields (as Envoy bounds them).
      BState::TrailerStart | BState::TrailerName | BState::TrailerValue | BState::TrailerLf => {
        self.trailer_len += 1;
        if self.trailer_len > self.max_trailer_len {
          return Err(Error::TrailersTooLarge);
        }
        match state {
          BState::TrailerStart => {
            if byte == b'\r' {
              BState::FinalLf
            } else if !is_tchar(byte) {
              return Err(Error::InvalidTrailer);
            } else if self.count >= u32::from(self.max_trailers) {
              return Err(Error::TrailersTooLarge);
            } else {
              self.count += 1;
              BState::TrailerName
            }
          }
          BState::TrailerName => {
            if byte == b':' {
              BState::TrailerValue
            } else if is_tchar(byte) {
              state
            } else {
              return Err(Error::InvalidTrailer);
            }
          }
          BState::TrailerValue => {
            if byte == b'\r' {
              BState::TrailerLf
            } else if (byte < 0x20 && byte != b'\t') || byte == 0x7f {
              return Err(Error::InvalidTrailer);
            } else {
              state
            }
          }
          _ => {
            if byte != b'\n' {
              return Err(Error::InvalidLineEnding);
            }
            BState::TrailerStart
          }
        }
      }
      BState::FinalLf => {
        if byte != b'\n' {
          return Err(Error::InvalidLineEnding);
        }
        BState::Done
      }
      BState::Done | BState::UntilClose | BState::Length | BState::Data | BState::Failed(_) => {
        state
      }
    })
  }
}

#[inline]
const fn hex_digit(byte: u8) -> Option<u64> {
  match byte {
    b'0'..=b'9' => Some((byte - b'0') as u64),
    b'a'..=b'f' => Some((byte - b'a') as u64 + 10),
    b'A'..=b'F' => Some((byte - b'A') as u64 + 10),
    _ => None,
  }
}
