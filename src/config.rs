//! Limits and options.

/// Limits and the one leniency option, shared by the head parsers and the body decoder.
///
/// Limits are positional: a scan never looks past them, so a message over a limit is rejected
/// the same way whether it arrives whole or in pieces.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Config {
  /// Maximum length of a head, from its first byte to the end of the final empty line. Over it:
  /// [`Error::UriTooLong`](crate::Error::UriTooLong) while still in the request line, else
  /// [`Error::HeadTooLarge`](crate::Error::HeadTooLarge). For the body decoder, the maximum
  /// length of the trailer section. Default 16 KiB.
  pub max_head_len: u32,
  /// Maximum length of one line, without its CRLF: the request line, the status line, a field
  /// line, or a chunk-size line. Over it: as for `max_head_len` (and
  /// [`Error::ChunkLineTooLong`](crate::Error::ChunkLineTooLong) for chunk-size lines).
  /// Default 8 KiB.
  pub max_line_len: u32,
  /// Maximum number of fields of a head (capped by the parser's slot count) or of a trailer
  /// section. Default 64.
  pub max_headers: u16,
  /// Accept any token as a method, reported as [`Method::Other`](crate::Method::Other), instead
  /// of answering unknown methods with [`Error::UnknownMethod`](crate::Error::UnknownMethod)
  /// (501). For servers that implement extension methods such as WebDAV's. Default `false`.
  pub allow_extension_methods: bool,
}

impl Config {
  /// The defaults: 16 KiB heads, 8 KiB lines, 64 fields, known methods only.
  pub const DEFAULT: Self = Self {
    max_head_len: 16 * 1024,
    max_line_len: 8 * 1024,
    max_headers: 64,
    allow_extension_methods: false,
  };

  /// [`Config::DEFAULT`].
  #[inline]
  pub const fn new() -> Self {
    Self::DEFAULT
  }
}

impl Default for Config {
  #[inline]
  fn default() -> Self {
    Self::DEFAULT
  }
}
