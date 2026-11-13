# rimu-http1 design

A strict, single-pass, resumable, zero-copy, sans-IO HTTP/1.1 head parser (requests and
responses) with an incremental body decoder. `no_std`, no allocation.

Starting point: the request parser and body decoder of rimu-ws (`wtx/src/http1/parser.rs`,
`body.rs`). Their tests are the strictness specification and are ported unchanged in meaning.
What changes is the execution model: the rimu-ws parser is a pure function that re-scans the
whole buffer on every call (a SIMD search for `\r\n\r\n`, a UTF-8 pass, then line splitting:
three passes, and quadratic when a head arrives in many pieces). rimu-http1 is the state machine
the rimu-ws spec (§5.2) asked for: it scans every byte once, validating as it goes, and stops
exactly where the input ends.

## 1. Goals and non-goals

Goals, in order:

1. **Strict by default** per RFC 9112 / RFC 9110, rejecting everything the rimu-ws parser rejects
   (smuggling vectors first), with the error mapped to the status a server answers with.
2. **Resumable**: the result never depends on how the input was split, and total work is
   O(total bytes) for any split, byte by byte included.
3. **Fast**: at least httparse's speed on whole requests while doing more validation, and much
   faster than any re-scanning parser on split input.
4. **Zero-copy and allocation free**, in a way that survives the caller's buffer growing or
   moving between calls.

Non-goals: writing messages, HTTP/0.9, obs-fold unfolding, decoding content codings,
percent-decoding, parsing URIs beyond what framing and `Host` need, keeping trailer fields.

## 2. Model: offsets in, views out

```text
          caller's read buffer (may grow, may be reallocated between calls)
          |<-------------- bytes received so far -------------->|
 call 1:  GET /a?b HTTP/1.1\r\nHost: x\r\nAcc
 call 2:  GET /a?b HTTP/1.1\r\nHost: x\r\nAccept: */*\r\n\r\n
                                         ^ pos (where call 1 stopped)
```

The contract of `parse(buf)` for one message: `buf` always starts at the first byte of the
message, and each call passes a buffer whose first `pos` bytes are the ones passed before (the
caller appends; it may also move the bytes to a new allocation). The parser stores only offsets
into the message (`u32`; heads are bounded by `max_head_len`), never pointers, so moving the
buffer is harmless. When the head completes, `parse` returns a `Request<'b>` / `Response<'b>`
that borrows `buf` and the parser's slot array and hands out `&'b str` views computed from the
offsets: zero copies, and nothing to fix up when the buffer moved.

After a `Complete`, the next `parse` call starts a new message (the caller passes the buffer
from the first byte after `head_len` plus the body). `reset()` abandons a message.

## 3. The state machine

One `loop { match state { .. } }` over the buffer. Each arm consumes as much as it can and
either moves to the next state in the same call (whole input never leaves the loop until the
head ends) or stores the state and `pos` and returns `Partial`.

Request states (responses differ only in the start line):

| state | what it is doing | stores |
|---|---|---|
| `Start` | skips one leading CRLF (RFC 9112 §2.2 SHOULD) | — |
| `StartLf` | saw `\r` of the leading CRLF | — |
| `Method` | scans method bytes up to SP | line start, `method_is_token` |
| `Target` | SIMD-scans the target up to SP, validating, noting the first `?` | target start, `?` offset |
| `Version` | needs the 10 bytes `HTTP/d.d\r\n` at once | target end |
| `LineStart` | first byte of a header line or the final CRLF | header count |
| `Name` | scans a header name (`tchar` table) up to `:` | line start |
| `Value` | SIMD-scans the value up to CR, validating | name end, value start |
| `ValueLf` | saw the CR that ends a value | value end |
| `EndLf` | saw the CR of the final empty line | — |
| `Done` | head complete; next call resets | — |

Response start-line states: `Version` (needs `HTTP/d.d SP`), `Status` (needs `ddd SP`),
`Reason` (scanned like a value, up to CR), `ReasonLf`.

**Where work resumes.** `pos` is the first unscanned byte, not the start of the current token:
a header name or value that was cut in the middle is not re-scanned. The only bytes ever looked
at twice are bounded per call:

- fixed-width pieces (`HTTP/1.1\r\n`, `ddd SP`) are matched only when all their bytes are present;
  until then the state waits without consuming (at most 9 bytes re-examined per call);
- a UTF-8 sequence cut by the end of the input is re-examined from its first byte (≤ 3 bytes);
- the trimming of trailing whitespace of a value at its end, and the special-header checks
  (below), look at each value once more after it is complete, which is O(bytes) overall.

So total work is O(total bytes + calls), i.e. linear even byte by byte.

**Determinism of the result.** Every decision is a function of the bytes before the current
position only; nothing depends on where the input happens to end. In particular limits are
positional (§6): a scan never reads past `line_start + max_line_len + 1` or
`head_start + max_head_len`, so a too-long line is reported identically whether it arrives
whole or byte by byte, and an invalid byte beyond the limit is never seen in either case.
Verdicts that the rimu-ws parser takes after the whole request line (unknown method, target
form, version) are deferred to the end of the request line here too, so the status codes agree.

## 4. Scanning and fused validation

Three byte classes cover the head; each is checked in the same loop that finds the delimiter,
so there is no separate UTF-8 or control-character pass.

- **Target** (`Target` state): stop on any byte outside `0x21..=0x7e` or on `#`. A stop on SP
  ends the target; any other stop is an error (control, DEL, raw non-ASCII, fragment). The same
  block also yields the mask of `?`, so the path/query split costs nothing extra.
- **Field value and reason phrase** (`Value`, `Reason`): stop on any byte outside `0x20..=0x7e`.
  CR ends the value; HTAB continues; a byte ≥ 0x80 starts a UTF-8 sequence that is validated in
  place (2–4 bytes, RFC 3629 ranges, no overlongs or surrogates) before the vector scan goes on;
  anything else (LF, NUL, other controls, DEL) is an error. Values are therefore valid UTF-8 and
  are handed out as `&str` without a second check.
- **Method and header name**: a 256-entry `tchar` table, scalar (names are short; a vector
  `tchar` test needs a byte shuffle that SSE2 lacks).

Kernels (`scan.rs`):

- **x86-64**: SSE2 (baseline) 16 bytes a step, inline. Values and targets are mostly short, so
  the first 32 bytes are always scanned inline with SSE2; only if no stop byte was found there
  does the scan call the AVX2 kernel (32 bytes a step), chosen once at run time with `cpuid`
  (cached in an `AtomicU8`, as `rimu-json`'s `escape.rs` does) so the out-of-line call is paid
  only by long values (cookies, user agents, tokens). With `target-feature=+avx2` at compile time
  AVX2 is used inline.

  Value stop test, per 16 bytes `v`: `gt = cmpgt_epi8(v, 0x1f)` (signed, so it is true exactly
  for `0x20..=0x7f`), `stop = !gt | (v == 0x7f)`: two compares and a movemask.
- **Elsewhere**: SWAR on `u64` (8 bytes a step) with the classic `haszero`/`hasless` tricks; the
  lowest flagged byte is always a true stop, which is all the scan needs.

Fast paths that keep whole-request parsing ahead of httparse:

- method `GET ` / `POST` recognised by one 4-byte compare, other methods via the table;
- `HTTP/1.1\r\n` checked as one 8-byte and one 2-byte compare;
- special headers dispatched on the name length first (4 `host`, 6 `expect`, 7 `upgrade`,
  10 `connection`, 14 `content-length`, 17 `transfer-encoding`), then compared as words OR'ed with
  `0x20` (valid for `tchar` bytes); every other header costs one length switch;
- framing, keep-alive, `Host` and `Expect` are computed while the head is parsed, not by a
  second walk over the headers.

## 5. API

```rust
pub struct Config { max_head_len: u32, max_line_len: u32, max_headers: u16,
                    allow_extension_methods: bool }
pub struct RequestParser<const N: usize = 64> { .. }   // owns N header slots (16 B each)
pub struct ResponseParser<const N: usize = 64> { .. }

impl RequestParser<N> {
  pub const fn new(config: Config) -> Self;
  pub fn parse<'b>(&'b mut self, buf: &'b [u8]) -> Result<Status<Request<'b>>, Error>;
  pub fn reset(&mut self);
}
impl ResponseParser<N> {
  pub fn parse<'b>(&'b mut self, buf: &'b [u8], request_method: Method)
    -> Result<Status<Response<'b>>, Error>;
}
pub enum Status<T> { Complete(T), Partial }

pub struct Request<'b> {
  pub method: Method, pub version: Version, pub target: &'b str,
  pub path: &'b str, pub query: &'b str, pub headers: Headers<'b>,
  pub body: BodyKind, pub keep_alive: bool, pub expect_continue: bool,
  pub upgrade: bool, pub head_len: usize, ..
}
pub struct Response<'b> {
  pub version: Version, pub status: u16, pub reason: &'b str, pub headers: Headers<'b>,
  pub body: BodyKind, pub keep_alive: bool, pub upgrade: bool, pub head_len: usize,
}
pub enum BodyKind { None, ContentLength(u64), Chunked, UntilClose }
pub struct Headers<'b>   // len, get(i), iter() -> Header { name: &str, value: &str }, find(name)
```

- **Header slots** live in the parser (`N` from a const generic, default 64; `Config::max_headers`
  can lower the count). This is httparse's caller-provided array, moved into the parser so that
  it persists across calls without self-references and cannot be swapped by mistake between two
  calls for the same message. A slot is four `u32` offsets.
- **Method**: the nine RFC 9110 methods. Any other token is `Error::UnknownMethod` (501) unless
  `allow_extension_methods`, then `Method::Other` and the bytes are in `Request::method_str()`.
- **Framing** (RFC 9112 §6.3), computed at the end of the head:
  - request: `Transfer-Encoding` (ending in `chunked`) → `Chunked`; else `Content-Length` →
    `ContentLength(n)`; else `None`;
  - response: `None` for 1xx, 204, 304 and responses to `HEAD`; `None` with `upgrade` for 101 and
    a 2xx to `CONNECT` (the connection then belongs to the new protocol); else `Chunked` when the
    last transfer coding is chunked, `UntilClose` for any other transfer-coding list,
    `ContentLength(n)`, else `UntilClose`.
- **keep-alive**: HTTP/1.1 unless `Connection: close`; HTTP/1.0 only with `Connection:
  keep-alive`; never after a chunked HTTP/1.0 request (RFC 9112 §6.1) or an `UntilClose` body.
- **Expect**: `expect_continue` for `Expect: 100-continue` on HTTP/1.1 (RFC 9110 §10.1.1 says
  to ignore it on 1.0). Other expectations are left to the caller (they are in `headers`).
- **Upgrade / CONNECT**: a request's `upgrade` is set for HTTP/1.1 with an `Upgrade` header and
  `upgrade` in `Connection` (RFC 9110 §7.8). A CONNECT target is authority-form, validated as
  `host:port`. In both cases the bytes after `head_len` belong to the next protocol once the
  server agrees, which the parser cannot know; it reports the framing the headers declare.
- **Absolute-form** (`GET http://h/p?q`): `path`/`query` come from the target, `Host` is checked
  and its view is replaced by the target's authority (RFC 9112 §3.2.3), as rimu-ws does.

## 6. Limits

| limit | default | error | status |
|---|---|---|---|
| `max_head_len` (head incl. final CRLF) | 16 KiB | `UriTooLong` while in the request line, else `HeadTooLarge` | 414 / 431 |
| `max_line_len` (one line, without CRLF) | 8 KiB | same as above | 414 / 431 |
| `max_headers` | 64 (≤ `N`) | `TooManyHeaders` | 431 |

Body decoder: chunk-size line ≤ `max_line_len`, trailer section ≤ `max_head_len`, trailer fields
≤ `max_headers`.

## 7. Errors

`Error` is a `Copy` enum with one variant per rule so tests can tell rules apart;
`Error::status()` gives the status code a server answers with.

| status | variants |
|---|---|
| 400 | `InvalidMethod`, `InvalidTarget`, `InvalidVersion`, `InvalidLineEnding`, `InvalidHeaderName`, `InvalidHeaderValue`, `WhitespaceBeforeName` (obs-fold or SP before the first field), `MissingHost`, `DuplicateHost`, `InvalidHost`, `InvalidContentLength`, `DuplicateContentLength`, `ContentLengthWithTransferEncoding`, `InvalidTransferEncoding`, `InvalidStatus`, body: `InvalidChunkSize`, `InvalidChunkExtension`, `InvalidChunkEnd`, `InvalidTrailer`, `UnexpectedEof` |
| 414 | `UriTooLong` |
| 431 | `HeadTooLarge`, `TooManyHeaders`, body: `TrailersTooLarge` |
| 501 | `UnknownMethod`, `UnsupportedTransferCoding` |
| 505 | `VersionNotSupported` |

For a client parsing a response the codes are only descriptive (a client would treat any of them
as a bad gateway).

## 8. Strictness policy

Strict by default; every rejection cites a rule. Carried over from rimu-ws:

- CRLF only: a bare LF or a CR not followed by LF anywhere in the head is an error
  (RFC 9112 §2.2 allows a recipient to accept a bare LF; we do not, as llhttp's strict mode).
- Controls (other than HTAB in values), DEL and invalid UTF-8 are errors; values must be UTF-8
  (obs-text that is not UTF-8 is rejected: RFC 9110 §5.5 makes obs-text obsolete).
- Request line: exactly `method SP target SP HTTP/d.d CRLF`; no raw non-ASCII, controls, HTAB or
  `#` in the target (RFC 9112 §3, RFC 9110 §7.1, RFC 3986); method a token; major version 1 only
  (505), minor > 1 treated as 1.1 (RFC 9112 §2.5).
- Target forms (RFC 9112 §3.2): origin-form; absolute-form with `http`/`https` and a non-empty
  authority without userinfo; asterisk-form; authority-form. New: authority-form only for
  CONNECT and must be `host:port`, CONNECT only takes authority-form, asterisk-form only for
  OPTIONS (RFC 9112 §3.2.3–3.2.4).
- Fields: name a non-empty token, no whitespace before `:` (RFC 9112 §5.1), no obs-fold
  (§5.2) and no whitespace before the first field (§2.2).
- `Host`: required once on HTTP/1.1, at most once on 1.0, value `host [":" port]` with port
  ≤ 65535 (RFC 9112 §3.2, RFC 3986 §3.2.2).
- `Content-Length`: digits only, no overflow, at most one header (no `5, 5` lists).
- `Transfer-Encoding` (requests): a list of tokens ending in `chunked`, `chunked` once; other
  codings before it → 501; not ending in `chunked` → 400 (RFC 9112 §6.1, §6.3); with
  `Content-Length` → 400 (§6.3 item 3; smuggling).
- Responses: status code 100–599 (RFC 9110 §15), reason phrase as a field value.
- Chunked bodies: hex size without prefix or sign, no overflow, chunk extensions validated
  against the RFC 9112 §7.1.1 grammar (`BWS ; BWS token [BWS = BWS (token / quoted-string)]`),
  CRLF after every chunk, trailer fields validated like header fields and bounded.

Leniency: one leading CRLF is skipped (that is RFC 9112 §2.2's SHOULD, not an option). The only
named option is `allow_extension_methods` (WebDAV and other registered methods). No option for
bare LF, obs-fold, spaces in targets or Latin-1 values: clients that matter do not send them.

## 9. Body decoder

```rust
pub struct BodyDecoder { .. }
impl BodyDecoder {
  pub fn new(kind: BodyKind) -> Self;                      // default limits
  pub fn with_config(kind: BodyKind, config: &Config) -> Self;
  pub fn decode<'a>(&mut self, input: &'a [u8]) -> Result<Decoded<'a>, Error>;
  pub fn feed<'a>(&mut self, input: &'a [u8], sink: impl FnMut(&'a [u8])) -> Result<BodyStatus, Error>;
  pub fn finish(&self) -> Result<(), Error>;               // at EOF
  pub fn is_done(&self) -> bool;
}
pub struct Decoded<'a> { pub consumed: usize, pub data: &'a [u8], pub done: bool }
pub enum BodyStatus { NeedMore, Complete { consumed: usize } }
```

`decode` consumes framing bytes and returns at most one run of payload as a slice of `input`
(zero-copy); the caller drops `consumed` bytes and calls again. `feed` loops over `decode` and
passes each run to `sink` (the rimu-ws `feed(input, &mut Vec)` becomes
`feed(input, |d| out.extend_from_slice(d))`). The chunked framing is a byte-wise state machine
(size, extension grammar, CRLFs, trailers) whose state is a few words, so it resumes at any byte;
payload is never scanned, only sliced. `UntilClose` returns all input as payload and only
`finish` ends it; `finish` on an incomplete `Content-Length` or chunked body is `UnexpectedEof`.

## 10. Verification and benchmarks

- **Ported tests**: all 37 parser tests and 22 body tests of rimu-ws, adapted to the API.
- **Resumability**: for every test input and a corpus of realistic requests and responses, the
  outcome (all fields, or the exact error) of feeding the bytes split at every offset, at random
  multi-splits and byte by byte equals the outcome of feeding them whole. The same for the body
  decoder (concatenated payload, consumed count, error).
- **Differential vs httparse**: generated and corpus messages; when both accept, method, target,
  version, status, reason, and every header name/value (after OWS trimming) agree; every class of
  input rimu-http1 rejects and httparse accepts is tied to an RFC rule (README strictness table).
- **Differential vs the rimu-ws parser** (in the bench crate, which depends on rimu-ws): accept /
  reject, status code and fields agree on its test corpus and generated inputs, except for the
  documented intentional differences (CONNECT / asterisk forms; error precedence where rimu-ws
  checks the whole head first).
- **Fuzzing**: cargo-fuzz targets (request, response, body, split equivalence) plus a long seeded
  randomized test in the test suite: no panics, and work bounded by the input length.
- **Benchmarks** (`bench/`): rimu-http1 vs httparse (tokens only; + framing; + validation matching
  rimu-http1's strictness as closely as practical) vs the rimu-ws parser, on curl GET, plaintext
  GET, POST JSON, browser GET (15 headers), 40 headers and three responses; whole, 4 reads, byte
  by byte; default target (no `target-cpu=native`), pinned to one core. Targets: ≥ httparse on
  whole requests; split cost roughly linear in bytes.
