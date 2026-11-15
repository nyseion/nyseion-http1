# nyseion-http1

A strict, single-pass, resumable, zero-copy, sans-IO HTTP/1.1 parser for Rust: request and
response heads, plus an incremental body decoder. `no_std`, no allocation.

Part of the nyseion family of performance crates, alongside nyseion-ws.

```rust
use nyseion_http1::{BodyDecoder, BodyKind, BodyStatus, Config, RequestParser, Status};

let mut parser = RequestParser::<64>::new(Config::DEFAULT);
let mut buf: Vec<u8> = Vec::new();
// ... read into `buf` (append; the Vec may reallocate, that is fine) ...
loop {
  match parser.parse(&buf) {
    Ok(Status::Complete(req)) => {
      println!("{} {} {:?}", req.method_str, req.path, req.headers.find("host"));
      let mut body = BodyDecoder::new(req.body);
      let rest = &buf[req.head_len..];
      body.feed(rest, |payload| { /* slices of `rest`, no copies */ })?;
      break;
    }
    Ok(Status::Partial) => { /* read more into `buf`, call again */ }
    Err(err) => { /* answer err.status() (400/414/431/501/505) and close */ }
  }
}
```

## What it is

- **Resumable by construction.** The parsers are state machines that remember the state and the
  offset where the input ended and continue from there, so every byte is scanned once however the
  head is split: feeding a head byte by byte costs a constant factor (about 25×) more than feeding
  it whole, not a factor proportional to its length. The result never depends on the split (tested
  at every offset, see below).
- **Zero-copy across calls.** The parser stores offsets, never pointers, so the caller's buffer may
  grow or be reallocated between calls. A completed `Request` / `Response` hands out `&str` views
  into the buffer: target, path, query, field names and values.
- **Validation fused into the scan.** Targets, field values and reason phrases are scanned 16
  bytes at a time (SSE2, inline) or 32 (AVX2 for long runs, chosen at run time; SWAR on other
  architectures), and the same compares that find the delimiter reject controls, DEL and bare LF;
  non-ASCII bytes are validated as UTF-8 in place. Field names are classified as tokens 16 bytes
  at a time. Framing (`Content-Length`, `Transfer-Encoding`), `Host`, `Connection`, `Expect` and
  `Upgrade` are checked as each field completes. There is no second pass.
- **Strict.** RFC 9112 / RFC 9110 by default, including the request-smuggling rules; every
  rejection is an `Error` variant naming the rule, with the status code a server answers it with.

See [`docs/design.md`](docs/design.md) for the state machine, the scanning kernels and the
policies.

## API

| item | purpose |
|---|---|
| `RequestParser<N>` / `ResponseParser<N>` | resumable head parsers with `N` field slots (default 64); `parse(buf)` / `parse(buf, request_method)` → `Status::{Complete, Partial}` or `Error`; `reset()` |
| `Request` | `method`, `method_str`, `version`, `target`, `path`, `query`, `headers`, `body`, `keep_alive`, `expect_continue`, `upgrade`, `head_len` |
| `Response` | `version`, `status`, `reason`, `headers`, `body`, `keep_alive`, `upgrade` (101, or 2xx to CONNECT), `head_len` |
| `Headers` | `len`, `get(i)`, `find(name)` (case-insensitive), `iter()` → `Header { name, value }` |
| `BodyKind` | `None`, `ContentLength(u64)`, `Chunked`, `UntilClose` (responses), per RFC 9112 §6.3 |
| `BodyDecoder` | `decode(input)` → one payload slice + bytes consumed; `feed(input, sink)`; `finish()` at EOF |
| `Config` | `max_head_len` (16 KiB), `max_line_len` (8 KiB), `max_headers` (64), `allow_extension_methods` (false) |
| `Error` | one variant per rule; `status()` → 400, 414, 431, 501 or 505 |

After a `Complete`, the next `parse` call starts a new message (pass the bytes after `head_len`
plus the body, or the next pipelined request). An error is repeated until `reset()`.

## Strictness compared with httparse

httparse is a tokenizer: it splits a head into method, path, version and fields and leaves the
semantics to the caller. Each row is an input class that nyseion-http1 rejects and httparse
accepts; the differential test (`tests/differential_httparse.rs`) checks that every
disagreement on about 45 000 corpus, generated and mutated messages falls into one of these
rows, and that all fields agree exactly when both accept.

| rejected by nyseion-http1, accepted by httparse | error (status) | rule |
|---|---|---|
| bare LF line endings (`GET / HTTP/1.1\nHost: a\n\n`) | `InvalidLineEnding` (400) | RFC 9112 §2.2 lets a recipient accept a bare LF; nyseion-http1 does not (as llhttp strict) |
| more than one empty line before the request line | `InvalidMethod` (400) | RFC 9112 §2.2 asks to skip at least one; exactly one is skipped |
| fragment in the target (`GET /a#b`) | `InvalidTarget` (400) | RFC 9110 §7.1, RFC 9112 §3.2: a request target has no fragment |
| raw non-ASCII bytes in the target | `InvalidTarget` (400) | RFC 9112 §3.2 and RFC 3986 §2: URIs are ASCII |
| authority-form for a method other than CONNECT, CONNECT with anything but `host:port`, asterisk-form other than `OPTIONS *`, absolute-form with userinfo or an empty authority, a non-`http(s)` scheme | `InvalidTarget` (400) | RFC 9112 §3.2.2–3.2.4, RFC 9110 §4.2.4 |
| a method outside the RFC 9110 set (and PATCH) | `UnknownMethod` (501) / `InvalidMethod` (400, not uppercase) | RFC 9110 §9.1, §15.6.2; `allow_extension_methods` accepts any token |
| field value or reason phrase that is not UTF-8 | `InvalidHeaderValue` (400) | obs-text is obsolete (RFC 9110 §5.5); values are handed out as `&str` |
| HTTP/1.1 request without `Host`, more than one `Host`, `Host` not `host[:port]` with port ≤ 65535 | `MissingHost`, `DuplicateHost`, `InvalidHost` (400) | RFC 9112 §3.2, RFC 3986 §3.2.2 |
| `Content-Length` not digits (`+5`, `4 2`, `5, 5`), or more than one | `InvalidContentLength`, `DuplicateContentLength` (400) | RFC 9110 §8.6, RFC 9112 §6.3 |
| both `Content-Length` and `Transfer-Encoding` | `ContentLengthWithTransferEncoding` (400) | RFC 9112 §6.3 item 3 (request smuggling) |
| request `Transfer-Encoding` not ending in `chunked`, `chunked` twice, with parameters; other codings before `chunked` | `InvalidTransferEncoding` (400) / `UnsupportedTransferCoding` (501) | RFC 9112 §6.1, §6.3 |
| response status code outside 100–599, or no space after it (`HTTP/1.1 200\r\n`) | `InvalidStatus` | RFC 9110 §15, RFC 9112 §4 |
| empty line before a status line | `InvalidVersion` | RFC 9112 §2.2 skips empty lines before request lines only |
| a line, head or field count over the configured limits | `UriTooLong` (414), `HeadTooLarge`, `TooManyHeaders` (431) | configurable; httparse has no limits besides its slot count |

The other direction: httparse rejects `HTTP/1.2`–`HTTP/1.9`, which nyseion-http1 accepts as HTTP/1.1
as RFC 9112 §2.5 asks. httparse also reports a reason phrase with non-ASCII bytes as empty, which
nyseion-http1 returns.

The body decoder (httparse only offers `parse_chunk_size`) also validates chunk extensions
against the RFC 9112 §7.1.1 grammar, requires CRLF after every chunk, validates and bounds
trailer fields, and bounds the chunk-size line.

Compared with the nyseion-ws parser it replaces, nyseion-http1 keeps every rule (all its tests are
ported) and adds: CONNECT only with authority-form `host:port` and asterisk-form only for
OPTIONS; an 8 KiB line limit; responses; and errors reported as soon as their bytes arrive
(nyseion-ws waited for the whole head).

## Performance

`bench/` (run pinned to one core with `taskset -c 7`, default target, no `target-cpu=native`).
Every contender extracts the same facts (head length, path, query, framing, keep-alive) and
results are checked to agree before timing. "httparse + framing" adds the path/query split and
the `Content-Length` / `Transfer-Encoding` / `Connection` lookups; "httparse + strict" adds checks
that bring it close to nyseion-http1's strictness (bare LF, target bytes, UTF-8 values, `Host`
presence/uniqueness/syntax, `Content-Length` syntax and uniqueness, `Transfer-Encoding: chunked`
only, not both). The machine was shared and loaded, so contenders are interleaved and the ratios
are medians of per-round ratios (stable across runs to a few percent); absolute ns are minimums.

Run on an AMD Ryzen 9 5900X (AVX2), 2026-11-13, load average 12 on 24 threads. ns are minimums over 41 interleaved rounds; ratios are medians of per-round ratios (other / nyseion-http1, above 1 means nyseion-http1 is faster). In the split tables httparse and nyseion-ws re-parse from the start on each read; nyseion-http1 resumes.

#### Requests, whole

| request | bytes | httparse tokens | httparse + framing | httparse + framing + strict | nyseion-ws | **nyseion-http1** | vs httparse+framing | vs httparse strict | vs nyseion-ws |
|---|---|---|---|---|---|---|---|---|---|
| curl GET | 77 | 118 | 144 | 284 | 277 | **80** | 1.13× | 2.23× | 2.20× |
| plaintext GET | 101 | 134 | 159 | 298 | 270 | **144** | 1.13× | 2.13× | 1.93× |
| POST JSON | 246 | 124 | 154 | 286 | 245 | **116** | 1.22× | 2.56× | 2.25× |
| browser GET (15 headers) | 805 | 244 | 279 | 738 | 591 | **246** | 1.10× | 3.12× | 2.50× |
| 40 custom headers | 2701 | 698 | 743 | 2036 | 1417 | **620** | 1.17× | 3.46× | 2.64× |

#### Requests, split

| request | bytes | 4 reads: httparse+framing / nyseion-ws / **nyseion-http1** | byte by byte: httparse+framing / nyseion-ws / **nyseion-http1** | byte by byte, nyseion-http1 ns per byte |
|---|---|---|---|---|
| curl GET | 77 | 266 / 193 / **109** (2.06× / 1.77×) | 7983 / 3032 / **1175** (6.4× / 2.4×) | 15.3 |
| plaintext GET | 101 | 322 / 229 / **119** (2.26× / 1.81×) | 10460 / 3722 / **1460** (7.3× / 2.6×) | 14.5 |
| POST JSON | 246 | 706 / 644 / **319** (2.20× / 2.00×) | 20677 / 8573 / **1931** (10.8× / 4.0×) | 7.8 |
| browser GET (15 headers) | 805 | 751 / 806 / **301** (2.28× / 2.61×) | 124195 / 79625 / **7187** (20.8× / 9.8×) | 8.9 |
| 40 custom headers | 2701 | 3124 / 3817 / **1253** (2.45× / 2.99×) | 1012753 / 651682 / **17331** (49.8× / 26.1×) | 6.4 |

#### Responses (nyseion-ws has no response parser)

| response | bytes | httparse + framing | **nyseion-http1** | ratio | 4 reads: httparse / **nyseion-http1** | byte by byte: httparse / **nyseion-http1** |
|---|---|---|---|---|---|---|
| small response | 65 | 142 | **86** | 1.62× | 217 / **82** (2.32×) | 5516 / **985** (5.6×) |
| nginx response | 255 | 148 | **123** | 1.20× | 730 / **343** (2.11×) | 20056 / **1942** (10.9×) |
| CDN response (chunked, cookies) | 751 | 477 | **418** | 1.14× | 1017 / **467** (2.21×) | 114881 / **5190** (19.2×) |

## Testing

- **Ported tests**: all 37 request-parser tests and 22 body-decoder tests of nyseion-ws
  (`tests/ported_parser.rs`, `tests/ported_body.rs`), plus `tests/semantics.rs` for responses,
  the new rules, limits, the API and the body decoder.
- **Resumability** (`tests/resumable.rs`): for every ported input, a corpus of realistic
  requests and responses, generated messages and thousands of mutated (mostly invalid) ones, with
  default and tight limits, the outcome — every field, or the exact error — of the input split at
  every offset, at random multi-splits and byte by byte, each piece in a newly allocated buffer,
  equals the outcome of the input fed whole. Same for bodies.
- **Differential vs httparse** (`tests/differential_httparse.rs`): see the strictness table.
- **Differential vs nyseion-ws** (`bench/tests/diff_old.rs`): on about 35 000 inputs, 15 700 accepted
  by both agree on every field; rejections agree on the status code except where nyseion-ws checks
  the whole head before the request line (UTF-8, size, bare LF) and nyseion-http1 reports the first
  problem in byte order; the only accept/reject differences are the CONNECT rule above.
- **Fuzzing**: `fuzz/` has cargo-fuzz targets for requests, responses and bodies that also check
  whole-vs-split equality; `tests/random_bytes.rs` is a seeded randomized test over biased random
  bytes (`NYSEION_HTTP1_RANDOM_ITERS`; run with 40 million inputs per target) and checks that the work
  of byte-by-byte feeding is linear.

## Limitations

- Field values must be UTF-8 (no Latin-1 obs-text), so that they can be `&str`.
- Trailer fields are validated and skipped, not returned.
- No HTTP/0.9, no obs-fold unfolding, no lenient mode for bare LF or spaces in targets.
- Header names are matched to `Host`, `Content-Length`, `Transfer-Encoding`, `Connection`,
  `Expect` and `Upgrade` only; everything else is left to the caller via `headers`.
- The SIMD kernels are x86-64 (SSE2/AVX2); other architectures use the portable SWAR and scalar
  kernels (no NEON yet).

## License

Apache-2.0
