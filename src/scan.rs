//! Byte-class scans with validation fused in.
//!
//! Two scans cover the variable-length parts of a head:
//!
//! - [`value_stop`]: the first byte outside `0x20..=0x7e` (field values and reason phrases; the
//!   caller then sees CR, HTAB, a UTF-8 lead byte, or an error);
//! - [`target_stop`]: the first byte outside `0x21..=0x7e` or `#` (request targets; SP ends
//!   the target, anything else is an error), noting the first `?` on the way.
//!
//! On x86-64 the first 32 bytes are scanned inline with SSE2 (the baseline); longer runs go to an
//! out-of-line AVX2 kernel when the CPU has AVX2 (checked once), else stay on SSE2. Elsewhere a
//! portable SWAR kernel reads 8 bytes a step. Every kernel returns the same index as
//! [`value_stop_scalar`] / [`target_stop_scalar`].

/// RFC 9110 `tchar`.
pub(crate) static TCHAR: [bool; 256] = {
  let mut table = [false; 256];
  let mut i = 0usize;
  while i < 256 {
    let b = i as u8;
    table[i] = b.is_ascii_alphanumeric()
      || matches!(
        b,
        b'!'
          | b'#'
          | b'$'
          | b'%'
          | b'&'
          | b'\''
          | b'*'
          | b'+'
          | b'-'
          | b'.'
          | b'^'
          | b'_'
          | b'`'
          | b'|'
          | b'~'
      );
    i += 1;
  }
  table
};

/// If `byte` is an RFC 9110 `tchar`.
#[inline(always)]
pub(crate) fn is_tchar(byte: u8) -> bool {
  TCHAR[usize::from(byte)]
}

/// Sentinel for "no `?` seen yet".
pub(crate) const NO_QUERY: usize = usize::MAX;

/// Index of the first byte of `buf[i..end]` outside `0x20..=0x7e`, or `end`.
///
/// `i <= end <= buf.len()`. Bytes of `buf` after `end` may be read but never decide the result.
#[inline(always)]
pub(crate) fn value_stop(buf: &[u8], i: usize, end: usize) -> usize {
  debug_assert!(i <= end && end <= buf.len());
  #[cfg(target_arch = "x86_64")]
  {
    x86::value_stop(buf, i, end)
  }
  #[cfg(not(target_arch = "x86_64"))]
  {
    swar::value_stop(buf, i, end)
  }
}

/// Index of the first byte of `buf[i..end]` outside `0x21..=0x7e` or equal to `#`, or `end`.
/// If `*query` is [`NO_QUERY`], it is set to the index of the first `?` before that index.
#[inline(always)]
pub(crate) fn target_stop(buf: &[u8], i: usize, end: usize, query: &mut usize) -> usize {
  debug_assert!(i <= end && end <= buf.len());
  #[cfg(target_arch = "x86_64")]
  {
    x86::target_stop(buf, i, end, query)
  }
  #[cfg(not(target_arch = "x86_64"))]
  {
    swar::target_stop(buf, i, end, query)
  }
}

/// Index of the first byte of `buf[i..end]` that is not a `tchar`, or `end`.
#[inline(always)]
pub(crate) fn name_stop(buf: &[u8], i: usize, end: usize) -> usize {
  debug_assert!(i <= end && end <= buf.len());
  #[cfg(target_arch = "x86_64")]
  {
    x86::name_stop(buf, i, end)
  }
  #[cfg(not(target_arch = "x86_64"))]
  {
    name_stop_scalar(buf, i, end)
  }
}

/// Reference version of [`name_stop`].
#[inline]
pub(crate) fn name_stop_scalar(buf: &[u8], i: usize, end: usize) -> usize {
  let tail = buf.get(i..end).unwrap_or_default();
  tail.iter().position(|b| !is_tchar(*b)).map_or(end, |p| i + p)
}

/// Reference version of [`value_stop`].
#[inline]
pub(crate) fn value_stop_scalar(buf: &[u8], i: usize, end: usize) -> usize {
  let tail = buf.get(i..end).unwrap_or_default();
  tail.iter().position(|b| !(0x20..=0x7e).contains(b)).map_or(end, |p| i + p)
}

/// Reference version of [`target_stop`].
#[inline]
pub(crate) fn target_stop_scalar(buf: &[u8], i: usize, end: usize, query: &mut usize) -> usize {
  let tail = buf.get(i..end).unwrap_or_default();
  let stop =
    tail.iter().position(|b| !(0x21..=0x7e).contains(b) || *b == b'#').map_or(end, |p| i + p);
  if *query == NO_QUERY
    && let Some(q) = buf.get(i..stop).unwrap_or_default().iter().position(|b| *b == b'?')
  {
    *query = i + q;
  }
  stop
}

/// Outcome of [`utf8_len`] when the sequence is not complete and valid.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Utf8Error {
  /// The bytes so far are a valid prefix but `end` cuts the sequence.
  Incomplete,
  /// Not UTF-8.
  Invalid,
}

/// Length of the UTF-8 sequence that starts at `buf[i]` (a byte `>= 0x80`), reading no further
/// than `end`. Follows RFC 3629: no overlong forms, no surrogates, nothing above U+10FFFF. Each
/// byte is judged as soon as it is read, so a prefix that is already invalid is `Invalid` even
/// when the sequence is cut.
#[inline]
pub(crate) fn utf8_len(buf: &[u8], i: usize, end: usize) -> Result<usize, Utf8Error> {
  let lead = buf.get(i).copied().ok_or(Utf8Error::Incomplete)?;
  // Allowed range of the second byte, and the sequence length.
  let (lo, hi, len) = match lead {
    0xc2..=0xdf => (0x80, 0xbf, 2),
    0xe0 => (0xa0, 0xbf, 3),
    0xe1..=0xec | 0xee..=0xef => (0x80, 0xbf, 3),
    0xed => (0x80, 0x9f, 3),
    0xf0 => (0x90, 0xbf, 4),
    0xf1..=0xf3 => (0x80, 0xbf, 4),
    0xf4 => (0x80, 0x8f, 4),
    _ => return Err(Utf8Error::Invalid),
  };
  for k in 1..len {
    let idx = i + k;
    if idx >= end {
      return Err(Utf8Error::Incomplete);
    }
    let byte = buf.get(idx).copied().ok_or(Utf8Error::Incomplete)?;
    let (l, h) = if k == 1 { (lo, hi) } else { (0x80, 0xbf) };
    if byte < l || byte > h {
      return Err(Utf8Error::Invalid);
    }
  }
  Ok(len)
}

#[cfg(any(not(target_arch = "x86_64"), test))]
pub(crate) mod swar {
  //! Portable 8-bytes-a-step kernels. The flags of `has_less` can be wrong only above a byte
  //! that is truly flagged (borrows propagate upwards), and words are read little-endian, so the
  //! lowest flag is always a true one, which is all a scan needs.

  use super::NO_QUERY;

  const LO: u64 = 0x0101_0101_0101_0101;
  const HI: u64 = 0x8080_8080_8080_8080;

  /// High bit set in (at least) the lowest byte of `x` that is below `n` (`n <= 0x80`).
  #[inline(always)]
  const fn has_less(x: u64, n: u8) -> u64 {
    x.wrapping_sub(LO.wrapping_mul(n as u64)) & !x & HI
  }

  /// High bit set in (at least) the lowest byte of `x` equal to `b`.
  #[inline(always)]
  const fn has_byte(x: u64, b: u8) -> u64 {
    has_less(x ^ LO.wrapping_mul(b as u64), 1)
  }

  #[inline(always)]
  fn word(buf: &[u8], i: usize) -> Option<u64> {
    let bytes: [u8; 8] = buf.get(i..i + 8)?.try_into().ok()?;
    Some(u64::from_le_bytes(bytes))
  }

  /// [`super::value_stop`].
  #[inline]
  pub(crate) fn value_stop(buf: &[u8], mut i: usize, end: usize) -> usize {
    while i < end {
      let Some(x) = word(buf, i) else {
        return super::value_stop_scalar(buf, i, end);
      };
      let stop = has_less(x, 0x20) | has_byte(x, 0x7f) | (x & HI);
      if stop != 0 {
        return (i + (stop.trailing_zeros() / 8) as usize).min(end);
      }
      i += 8;
    }
    end
  }

  /// [`super::target_stop`].
  #[inline]
  pub(crate) fn target_stop(buf: &[u8], mut i: usize, end: usize, query: &mut usize) -> usize {
    while i < end {
      let Some(x) = word(buf, i) else {
        return super::target_stop_scalar(buf, i, end, query);
      };
      let stop = has_less(x, 0x21) | has_byte(x, 0x7f) | has_byte(x, b'#') | (x & HI);
      let at = if stop != 0 { (stop.trailing_zeros() / 8) as usize } else { 8 };
      let at = at.min(end - i);
      if *query == NO_QUERY {
        let q = has_byte(x, b'?');
        if q != 0 {
          let qi = (q.trailing_zeros() / 8) as usize;
          if qi < at {
            *query = i + qi;
          }
        }
      }
      if at < 8 {
        return i + at;
      }
      i += 8;
    }
    end
  }
}

#[cfg(target_arch = "x86_64")]
pub(crate) mod x86 {
  //! SSE2 inline for the first 32 bytes, then AVX2 (if the CPU has it) out of line.

  use super::NO_QUERY;
  use core::arch::x86_64::*;
  #[cfg(not(target_feature = "avx2"))]
  use core::sync::atomic::{AtomicU8, Ordering};

  /// Bytes scanned inline with SSE2 before switching to the long-run kernel.
  const INLINE: usize = 64;

  /// Mask of the bytes of `v` that are not `tchar`s: controls, SP, DEL, non-ASCII, and the
  /// visible delimiters `"(),/:;<=>?@[\]{}`.
  #[inline(always)]
  fn non_tchar_mask(v: __m128i) -> u32 {
    // SAFETY: SSE2 is part of the x86-64 baseline.
    unsafe {
      let eq = |c: u8| _mm_cmpeq_epi8(v, _mm_set1_epi8(c.cast_signed()));
      // Unsigned `lo <= v <= hi`: `v - lo` wraps above `hi - lo` otherwise.
      let range = |lo: u8, hi: u8| {
        let x = _mm_sub_epi8(v, _mm_set1_epi8(lo.cast_signed()));
        _mm_cmpeq_epi8(_mm_min_epu8(x, _mm_set1_epi8((hi - lo).cast_signed())), x)
      };
      // Signed compare: true exactly for 0x21..=0x7f.
      let visible = _mm_cmpgt_epi8(v, _mm_set1_epi8(0x20));
      let a =
        _mm_or_si128(_mm_or_si128(eq(0x7f), eq(b'"')), _mm_or_si128(range(b'(', b')'), eq(b',')));
      let b = _mm_or_si128(_mm_or_si128(eq(b'/'), range(b':', b'@')), range(b'[', b']'));
      let c = _mm_or_si128(eq(b'{'), eq(b'}'));
      let bad = _mm_or_si128(_mm_or_si128(a, b), c);
      (_mm_movemask_epi8(visible).cast_unsigned() ^ 0xffff) | _mm_movemask_epi8(bad).cast_unsigned()
    }
  }

  /// [`super::name_stop`].
  #[inline(always)]
  pub(crate) fn name_stop(buf: &[u8], mut i: usize, end: usize) -> usize {
    while i < end {
      let Some(v) = load16(buf, i) else {
        return super::name_stop_scalar(buf, i, end);
      };
      let mask = non_tchar_mask(v);
      if mask != 0 {
        return (i + mask.trailing_zeros() as usize).min(end);
      }
      i += 16;
    }
    end
  }

  /// Stop mask of 16 value bytes: bytes outside `0x20..=0x7e`.
  #[inline(always)]
  fn value_mask(v: __m128i) -> u32 {
    // SAFETY: SSE2 is part of the x86-64 baseline.
    unsafe {
      // Signed compare: true exactly for 0x20..=0x7f.
      let printable = _mm_cmpgt_epi8(v, _mm_set1_epi8(0x1f));
      let del = _mm_cmpeq_epi8(v, _mm_set1_epi8(0x7f));
      (_mm_movemask_epi8(printable).cast_unsigned() ^ 0xffff)
        | _mm_movemask_epi8(del).cast_unsigned()
    }
  }

  /// Stop mask and `?` mask of 16 target bytes.
  #[inline(always)]
  fn target_masks(v: __m128i) -> (u32, u32) {
    // SAFETY: SSE2 is part of the x86-64 baseline.
    unsafe {
      // Signed compare: true exactly for 0x21..=0x7f.
      let visible = _mm_cmpgt_epi8(v, _mm_set1_epi8(0x20));
      let bad = _mm_or_si128(
        _mm_cmpeq_epi8(v, _mm_set1_epi8(0x7f)),
        _mm_cmpeq_epi8(v, _mm_set1_epi8(b'#'.cast_signed())),
      );
      let stop = (_mm_movemask_epi8(visible).cast_unsigned() ^ 0xffff)
        | _mm_movemask_epi8(bad).cast_unsigned();
      let q = _mm_movemask_epi8(_mm_cmpeq_epi8(v, _mm_set1_epi8(b'?'.cast_signed())));
      (stop, q.cast_unsigned())
    }
  }

  #[inline(always)]
  fn load16(buf: &[u8], i: usize) -> Option<__m128i> {
    let block: &[u8; 16] = buf.get(i..i + 16)?.try_into().ok()?;
    // SAFETY: `block` is 16 readable bytes; the load is unaligned.
    Some(unsafe { _mm_loadu_si128(block.as_ptr().cast()) })
  }

  /// [`super::value_stop`].
  #[inline(always)]
  pub(crate) fn value_stop(buf: &[u8], mut i: usize, end: usize) -> usize {
    let start = i;
    while i < end {
      let Some(v) = load16(buf, i) else {
        return super::value_stop_scalar(buf, i, end);
      };
      let mask = value_mask(v);
      if mask != 0 {
        return (i + mask.trailing_zeros() as usize).min(end);
      }
      i += 16;
      if i - start >= INLINE && i < end {
        return value_stop_long(buf, i, end);
      }
    }
    end
  }

  /// [`super::target_stop`].
  #[inline(always)]
  pub(crate) fn target_stop(buf: &[u8], mut i: usize, end: usize, query: &mut usize) -> usize {
    let start = i;
    while i < end {
      let Some(v) = load16(buf, i) else {
        return super::target_stop_scalar(buf, i, end, query);
      };
      let (stop, q) = target_masks(v);
      let at = if stop != 0 { stop.trailing_zeros() as usize } else { 16 };
      let at = at.min(end - i);
      if *query == NO_QUERY && q != 0 {
        let qi = q.trailing_zeros() as usize;
        if qi < at {
          *query = i + qi;
        }
      }
      if at < 16 {
        return i + at;
      }
      i += 16;
      if i - start >= INLINE && i < end {
        return target_stop_long(buf, i, end, query);
      }
    }
    end
  }

  /// Long values: AVX2 if available, else SSE2.
  #[inline(never)]
  fn value_stop_long(buf: &[u8], i: usize, end: usize) -> usize {
    if has_avx2() {
      // SAFETY: the CPU has AVX2.
      unsafe { value_stop_avx2(buf, i, end) }
    } else {
      value_stop_sse2(buf, i, end)
    }
  }

  /// Long targets: AVX2 if available, else SSE2.
  #[inline(never)]
  fn target_stop_long(buf: &[u8], i: usize, end: usize, query: &mut usize) -> usize {
    if has_avx2() {
      // SAFETY: the CPU has AVX2.
      unsafe { target_stop_avx2(buf, i, end, query) }
    } else {
      target_stop_sse2(buf, i, end, query)
    }
  }

  /// SSE2 loop without the inline cut-off.
  pub(crate) fn value_stop_sse2(buf: &[u8], mut i: usize, end: usize) -> usize {
    while i < end {
      let Some(v) = load16(buf, i) else {
        return super::value_stop_scalar(buf, i, end);
      };
      let mask = value_mask(v);
      if mask != 0 {
        return (i + mask.trailing_zeros() as usize).min(end);
      }
      i += 16;
    }
    end
  }

  /// SSE2 loop without the inline cut-off.
  pub(crate) fn target_stop_sse2(buf: &[u8], mut i: usize, end: usize, query: &mut usize) -> usize {
    while i < end {
      let Some(v) = load16(buf, i) else {
        return super::target_stop_scalar(buf, i, end, query);
      };
      let (stop, q) = target_masks(v);
      let at = if stop != 0 { stop.trailing_zeros() as usize } else { 16 };
      let at = at.min(end - i);
      if *query == NO_QUERY && q != 0 {
        let qi = q.trailing_zeros() as usize;
        if qi < at {
          *query = i + qi;
        }
      }
      if at < 16 {
        return i + at;
      }
      i += 16;
    }
    end
  }

  #[inline]
  #[target_feature(enable = "avx2")]
  fn load32(buf: &[u8], i: usize) -> Option<__m256i> {
    let block: &[u8; 32] = buf.get(i..i + 32)?.try_into().ok()?;
    // SAFETY: `block` is 32 readable bytes; the load is unaligned.
    Some(unsafe { _mm256_loadu_si256(block.as_ptr().cast()) })
  }

  /// [`super::value_stop`] with AVX2, 32 bytes a step.
  ///
  /// # Safety
  ///
  /// The CPU supports AVX2.
  #[target_feature(enable = "avx2")]
  pub(crate) unsafe fn value_stop_avx2(buf: &[u8], mut i: usize, end: usize) -> usize {
    let low = _mm256_set1_epi8(0x1f);
    let del = _mm256_set1_epi8(0x7f);
    while i < end {
      let Some(v) = load32(buf, i) else {
        return value_stop_sse2(buf, i, end);
      };
      let printable = _mm256_cmpgt_epi8(v, low);
      let mask = !_mm256_movemask_epi8(printable).cast_unsigned()
        | _mm256_movemask_epi8(_mm256_cmpeq_epi8(v, del)).cast_unsigned();
      if mask != 0 {
        return (i + mask.trailing_zeros() as usize).min(end);
      }
      i += 32;
    }
    end
  }

  /// [`super::target_stop`] with AVX2, 32 bytes a step.
  ///
  /// # Safety
  ///
  /// The CPU supports AVX2.
  #[target_feature(enable = "avx2")]
  pub(crate) unsafe fn target_stop_avx2(
    buf: &[u8],
    mut i: usize,
    end: usize,
    query: &mut usize,
  ) -> usize {
    let space = _mm256_set1_epi8(0x20);
    let del = _mm256_set1_epi8(0x7f);
    let hash = _mm256_set1_epi8(b'#'.cast_signed());
    let qm = _mm256_set1_epi8(b'?'.cast_signed());
    while i < end {
      let Some(v) = load32(buf, i) else {
        return target_stop_sse2(buf, i, end, query);
      };
      let visible = _mm256_cmpgt_epi8(v, space);
      let bad = _mm256_or_si256(_mm256_cmpeq_epi8(v, del), _mm256_cmpeq_epi8(v, hash));
      let stop =
        !_mm256_movemask_epi8(visible).cast_unsigned() | _mm256_movemask_epi8(bad).cast_unsigned();
      let at = if stop != 0 { stop.trailing_zeros() as usize } else { 32 };
      let at = at.min(end - i);
      if *query == NO_QUERY {
        let q = _mm256_movemask_epi8(_mm256_cmpeq_epi8(v, qm)).cast_unsigned();
        if q != 0 {
          let qi = q.trailing_zeros() as usize;
          if qi < at {
            *query = i + qi;
          }
        }
      }
      if at < 32 {
        return i + at;
      }
      i += 32;
    }
    end
  }

  /// If the long-run kernels may use AVX2: compiled in.
  #[cfg(target_feature = "avx2")]
  #[inline(always)]
  pub(crate) fn has_avx2() -> bool {
    true
  }

  /// 0: not checked yet, 1: no AVX2, 2: AVX2.
  #[cfg(not(target_feature = "avx2"))]
  static LEVEL: AtomicU8 = AtomicU8::new(0);

  /// If the long-run kernels may use AVX2: the CPU has it and, with `std`, the
  /// `NYSEION_HTTP1_NO_AVX2` environment variable is not set. Checked once.
  #[cfg(not(target_feature = "avx2"))]
  #[inline(always)]
  pub(crate) fn has_avx2() -> bool {
    match LEVEL.load(Ordering::Relaxed) {
      2 => true,
      1 => false,
      _ => detect(),
    }
  }

  #[cfg(not(target_feature = "avx2"))]
  #[cold]
  fn detect() -> bool {
    #[cfg(feature = "std")]
    let allowed = std::env::var_os("NYSEION_HTTP1_NO_AVX2").is_none();
    #[cfg(not(feature = "std"))]
    let allowed = true;
    let avx2 = allowed && cpu_has_avx2();
    LEVEL.store(if avx2 { 2 } else { 1 }, Ordering::Relaxed);
    avx2
  }

  /// AVX2 support from `cpuid`, including the operating system saving the YMM registers.
  #[cfg(not(target_feature = "avx2"))]
  fn cpu_has_avx2() -> bool {
    // Miri cannot run `cpuid`; it checks the SSE2 kernels.
    if cfg!(miri) {
      return false;
    }
    #[allow(unused_unsafe, reason = "`__cpuid` became safe in recent toolchains")]
    // SAFETY: `cpuid` is on every x86-64 CPU; `xgetbv` runs only when OSXSAVE says it can.
    unsafe {
      if __cpuid(0).eax < 7 {
        return false;
      }
      let leaf1 = __cpuid(1);
      let osxsave = leaf1.ecx & (1 << 27) != 0;
      let avx = leaf1.ecx & (1 << 28) != 0;
      if !osxsave || !avx {
        return false;
      }
      // XMM and YMM state enabled by the operating system.
      if xcr0() & 0b110 != 0b110 {
        return false;
      }
      __cpuid_count(7, 0).ebx & (1 << 5) != 0
    }
  }

  /// # Safety
  ///
  /// The CPU supports `xgetbv` (CPUID.1:ECX.OSXSAVE).
  #[cfg(not(target_feature = "avx2"))]
  #[target_feature(enable = "xsave")]
  unsafe fn xcr0() -> u64 {
    // SAFETY: the caller checked OSXSAVE.
    unsafe { _xgetbv(0) }
  }
}

#[cfg(test)]
mod tests {
  use super::*;
  use std::vec;

  fn kernels_value(buf: &[u8], i: usize, end: usize) {
    let expected = value_stop_scalar(buf, i, end);
    assert_eq!(value_stop(buf, i, end), expected, "{buf:?} {i} {end}");
    assert_eq!(swar::value_stop(buf, i, end), expected);
    #[cfg(target_arch = "x86_64")]
    {
      assert_eq!(x86::value_stop_sse2(buf, i, end), expected);
      if x86::has_avx2() {
        // SAFETY: checked above.
        assert_eq!(unsafe { x86::value_stop_avx2(buf, i, end) }, expected);
      }
    }
  }

  fn kernels_name(buf: &[u8], i: usize, end: usize) {
    assert_eq!(name_stop(buf, i, end), name_stop_scalar(buf, i, end), "{buf:?} {i} {end}");
  }

  #[test]
  fn name_kernel_matches_table_for_every_byte() {
    for byte in 0..=255u8 {
      for pos in (0..40).step_by(if cfg!(miri) { 13 } else { 1 }) {
        let mut buf = [b'a'; 40];
        buf[pos] = byte;
        kernels_name(&buf, 0, 40);
        kernels_name(&buf, 0, pos);
        kernels_name(&buf, 1, 33);
      }
    }
  }

  fn kernels_target(buf: &[u8], i: usize, end: usize) {
    let mut q0 = NO_QUERY;
    let expected = target_stop_scalar(buf, i, end, &mut q0);
    let mut q = NO_QUERY;
    assert_eq!(target_stop(buf, i, end, &mut q), expected);
    assert_eq!(q, q0, "{buf:?} {i} {end}");
    let mut q = NO_QUERY;
    assert_eq!(swar::target_stop(buf, i, end, &mut q), expected);
    assert_eq!(q, q0);
    #[cfg(target_arch = "x86_64")]
    {
      let mut q = NO_QUERY;
      assert_eq!(x86::target_stop_sse2(buf, i, end, &mut q), expected);
      assert_eq!(q, q0);
      if x86::has_avx2() {
        let mut q = NO_QUERY;
        // SAFETY: checked above.
        assert_eq!(unsafe { x86::target_stop_avx2(buf, i, end, &mut q) }, expected);
        assert_eq!(q, q0);
      }
    }
  }

  #[test]
  fn kernels_match_scalar() {
    let specials: &[u8] = &[0, 9, 10, 13, 0x1f, b' ', b'#', b'?', 0x7e, 0x7f, 0x80, 0xc3, 0xff];
    // Miri is slow: a smaller grid that still crosses every block boundary of the kernels.
    let lens: &[usize] = if cfg!(miri) {
      &[0, 9, 17, 33, 65, 70]
    } else {
      &[0, 1, 7, 8, 9, 15, 16, 17, 31, 32, 33, 47, 63, 64, 65, 100]
    };
    for &len in lens {
      for &special in specials {
        for pos in 0..len.max(1) {
          let mut buf = vec![b'a'; len];
          if pos < len {
            buf[pos] = special;
          }
          for i in [0, 1, 3] {
            for end in [len, len.saturating_sub(1), len.saturating_sub(9), len / 2] {
              if i <= end {
                kernels_value(&buf, i, end);
                kernels_target(&buf, i, end);
              }
            }
          }
          // A `?` before the stop byte
          if pos > 2 {
            buf[pos / 2] = b'?';
            kernels_target(&buf, 0, len);
          }
        }
      }
    }
  }

  #[test]
  fn utf8_rules() {
    for s in
      ["é", "€", "𝄞", "\u{7ff}", "\u{800}", "\u{ffff}", "\u{10000}", "\u{10ffff}", "\u{d7ff}"]
    {
      let b = s.as_bytes();
      assert_eq!(utf8_len(b, 0, b.len()), Ok(b.len()), "{s}");
      for cut in 1..b.len() {
        assert_eq!(utf8_len(b, 0, cut), Err(Utf8Error::Incomplete), "{s} {cut}");
      }
    }
    for bad in [
      &[0x80u8][..],
      &[0xc0, 0x80],
      &[0xc1, 0xbf],
      &[0xe0, 0x80, 0x80],
      &[0xed, 0xa0, 0x80],
      &[0xf0, 0x80, 0x80, 0x80],
      &[0xf4, 0x90, 0x80, 0x80],
      &[0xf5, 0x80, 0x80, 0x80],
      &[0xff],
      &[0xc3, 0x41],
      &[0xe2, 0x82, 0x41],
    ] {
      assert_eq!(utf8_len(bad, 0, bad.len()), Err(Utf8Error::Invalid), "{bad:?}");
      assert!(core::str::from_utf8(bad).is_err());
    }
    // An invalid prefix is invalid even when cut
    assert_eq!(utf8_len(&[0xe0, 0x80], 0, 2), Err(Utf8Error::Invalid));
  }
}
