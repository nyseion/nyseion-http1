//! Borrowed views of the fields of a parsed head.

use crate::parser::Slot;
use core::{fmt, iter::FusedIterator};

/// One field line: the name as sent and the value without surrounding whitespace.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Header<'b> {
  /// The name, a token (compare it ignoring ASCII case).
  pub name: &'b str,
  /// The value, valid UTF-8 without controls other than HTAB.
  pub value: &'b str,
}

/// The fields of a parsed head, in order, as views into the caller's buffer.
///
/// The parser stores offsets; a view is made when it is asked for, so nothing is copied.
#[derive(Clone, Copy)]
pub struct Headers<'b> {
  head: &'b str,
  slots: &'b [Slot],
}

impl<'b> Headers<'b> {
  #[inline]
  pub(crate) const fn new(head: &'b str, slots: &'b [Slot]) -> Self {
    Self { head, slots }
  }

  /// Number of fields.
  #[inline]
  pub const fn len(&self) -> usize {
    self.slots.len()
  }

  /// If there are no fields.
  #[inline]
  pub const fn is_empty(&self) -> bool {
    self.slots.is_empty()
  }

  /// The field at `index`.
  #[inline]
  pub fn get(&self, index: usize) -> Option<Header<'b>> {
    self.slots.get(index).map(|slot| self.header(slot))
  }

  /// The value of the first field named `name`, ignoring ASCII case.
  #[inline]
  pub fn find(&self, name: &str) -> Option<&'b str> {
    self.iter().find(|h| h.name.eq_ignore_ascii_case(name)).map(|h| h.value)
  }

  /// The fields in order.
  #[inline]
  pub fn iter(&self) -> HeadersIter<'b> {
    HeadersIter { head: self.head, slots: self.slots.iter() }
  }

  #[inline]
  fn header(&self, slot: &Slot) -> Header<'b> {
    view(self.head, slot)
  }
}

#[inline]
fn view<'b>(head: &'b str, slot: &Slot) -> Header<'b> {
  // The offsets are inside the head and on character boundaries (field names are ASCII and
  // values are delimited by ASCII bytes); `get` checks both instead of trusting it.
  Header {
    name: head.get(slot.name_start as usize..slot.name_end as usize).unwrap_or_default(),
    value: head.get(slot.value_start as usize..slot.value_end as usize).unwrap_or_default(),
  }
}

impl fmt::Debug for Headers<'_> {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    f.debug_list().entries(self.iter().map(|h| (h.name, h.value))).finish()
  }
}

impl<'b> IntoIterator for Headers<'b> {
  type Item = Header<'b>;
  type IntoIter = HeadersIter<'b>;

  #[inline]
  fn into_iter(self) -> Self::IntoIter {
    self.iter()
  }
}

impl<'b> IntoIterator for &Headers<'b> {
  type Item = Header<'b>;
  type IntoIter = HeadersIter<'b>;

  #[inline]
  fn into_iter(self) -> Self::IntoIter {
    self.iter()
  }
}

/// Iterator over [`Headers`].
#[derive(Clone, Debug)]
pub struct HeadersIter<'b> {
  head: &'b str,
  slots: core::slice::Iter<'b, Slot>,
}

impl<'b> Iterator for HeadersIter<'b> {
  type Item = Header<'b>;

  #[inline]
  fn next(&mut self) -> Option<Header<'b>> {
    self.slots.next().map(|slot| view(self.head, slot))
  }

  #[inline]
  fn size_hint(&self) -> (usize, Option<usize>) {
    self.slots.size_hint()
  }
}

impl DoubleEndedIterator for HeadersIter<'_> {
  #[inline]
  fn next_back(&mut self) -> Option<Self::Item> {
    self.slots.next_back().map(|slot| view(self.head, slot))
  }
}

impl ExactSizeIterator for HeadersIter<'_> {}

impl FusedIterator for HeadersIter<'_> {}
