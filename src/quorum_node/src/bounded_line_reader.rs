//! Audit finding A13 (Low-Medium, independent audit): `quorum_node`'s
//! node-to-node wire reader used `tokio::io::AsyncBufReadExt::lines()`,
//! which has no maximum line length. An authenticated peer -- holding a
//! valid pinned mTLS certificate, so this is specifically the "compromised
//! or buggy participant" threat model this project cares about, not an
//! anonymous internet attacker -- that sent an arbitrarily long line with
//! no terminating `\n` could grow this node's memory without bound for as
//! long as it kept the connection open and kept streaming bytes.
//!
//! [`BoundedLineReader`] replaces it: it reads in fixed-size chunks and
//! checks the accumulated, still-unterminated line length against
//! [`MAX_WIRE_LINE_BYTES`] on every chunk, returning an error (which
//! `handle_inbound`'s caller already logs and treats as a reason to drop
//! the connection -- see its `Err(e) => eprintln!(...)` handling) as soon
//! as that cap is crossed, rather than continuing to buffer.

use tokio::io::{AsyncRead, AsyncReadExt};

/// Maximum length, in bytes, of a single JSON-encoded wire message
/// (before its terminating `\n`) this node will buffer before giving up
/// on it and closing the connection.
///
/// Individual DKG messages (`DkgCommitment`, `DkgShare`) and derive
/// request/response messages are a few KB at most -- the group's public
/// key set, one Feldman commitment (degree `t+1` G1 points), and one BLS
/// share or signature, all base64-encoded. The one message type that
/// legitimately grows with usage is an audit-log bulk transfer, so this
/// cap is set generously above any realistic legitimate message rather
/// than tuned tightly against today's typical size: the goal is bounding
/// a compromised peer's ability to grow this node's memory without
/// limit, not rate-limiting or validating normal traffic (that's
/// `serde_json::from_str`'s job, applied after a line is fully read).
pub const MAX_WIRE_LINE_BYTES: usize = 8 * 1024 * 1024;

/// Size of each read performed against the underlying socket while
/// accumulating a line. Independent of [`MAX_WIRE_LINE_BYTES`]; this is
/// just an I/O granularity choice.
const READ_CHUNK_BYTES: usize = 8 * 1024;

/// A length-bounded, newline-delimited line reader over an async byte
/// stream. See the module doc for why this exists instead of
/// `tokio::io::AsyncBufReadExt::lines()`.
pub struct BoundedLineReader<R> {
    inner: R,
    buf: Vec<u8>,
    /// How many bytes of `buf`, from the start, have already been scanned
    /// for `\n` and found not to contain one. Without this, searching for
    /// the delimiter from byte 0 on every newly-arrived chunk turns a
    /// single large adversarial line into an O(n^2) scan (re-checking the
    /// same already-clean prefix every time) rather than the O(n) it
    /// should be -- exactly the kind of thing that would let a
    /// compromised peer trade a small amount of bandwidth for a large
    /// amount of this node's CPU, which is the same family of problem
    /// this reader exists to close off for memory.
    scanned: usize,
    chunk: Box<[u8; READ_CHUNK_BYTES]>,
}

impl<R: AsyncRead + Unpin> BoundedLineReader<R> {
    pub fn new(inner: R) -> Self {
        Self {
            inner,
            buf: Vec::new(),
            scanned: 0,
            chunk: Box::new([0u8; READ_CHUNK_BYTES]),
        }
    }

    /// Returns the next `\n`-terminated line (with the `\n`, and any
    /// preceding `\r`, stripped), `Ok(None)` on a clean EOF with no
    /// partial line pending, or `Err` if either the underlying stream
    /// errored, the line was not valid UTF-8, or the still-unterminated
    /// line exceeded [`MAX_WIRE_LINE_BYTES`] -- the caller is expected to
    /// treat any `Err` as "close this connection", which is already how
    /// `handle_inbound`'s `?`-propagation and its caller's `Err(e) =>
    /// eprintln!(...)` logging behave.
    pub async fn next_line(&mut self) -> std::io::Result<Option<String>> {
        loop {
            // Only scan the suffix not already known to be '\n'-free.
            if let Some(pos) = self.buf[self.scanned..].iter().position(|&b| b == b'\n') {
                let pos = self.scanned + pos;
                let mut line_bytes: Vec<u8> = self.buf.drain(..=pos).collect();
                self.scanned = 0; // buf now starts fresh after the drained line
                line_bytes.pop(); // the '\n' itself
                if line_bytes.last() == Some(&b'\r') {
                    line_bytes.pop();
                }
                let line = String::from_utf8(line_bytes).map_err(|e| {
                    std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        format!("non-UTF-8 wire line: {e}"),
                    )
                })?;
                return Ok(Some(line));
            }
            self.scanned = self.buf.len();

            if self.buf.len() > MAX_WIRE_LINE_BYTES {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!(
                        "wire line exceeded {MAX_WIRE_LINE_BYTES} bytes without a \\n terminator -- \
                         closing connection (audit finding A13)"
                    ),
                ));
            }

            let n = self.inner.read(&mut self.chunk[..]).await?;
            if n == 0 {
                return if self.buf.is_empty() {
                    Ok(None)
                } else {
                    Err(std::io::Error::new(
                        std::io::ErrorKind::UnexpectedEof,
                        "connection closed mid-line",
                    ))
                };
            }
            self.buf.extend_from_slice(&self.chunk[..n]);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[tokio::test]
    async fn reads_normal_lines() {
        let data = b"first\nsecond\r\nthird".to_vec();
        let mut r = BoundedLineReader::new(Cursor::new(data));
        assert_eq!(r.next_line().await.unwrap().as_deref(), Some("first"));
        assert_eq!(r.next_line().await.unwrap().as_deref(), Some("second"));
        // Final line has no trailing '\n' (EOF instead) -- treated as a
        // connection-closed-mid-line error, matching real socket behavior
        // where a peer that vanishes mid-message shouldn't have its
        // partial data silently accepted as a complete one.
        let result = r.next_line().await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn clean_eof_with_no_partial_line_is_none() {
        let mut r = BoundedLineReader::new(Cursor::new(b"complete\n".to_vec()));
        assert_eq!(r.next_line().await.unwrap().as_deref(), Some("complete"));
        assert_eq!(r.next_line().await.unwrap(), None);
    }

    /// The adversarial case this whole module exists for: a peer sends an
    /// unterminated line far past the cap. Must return an error -- and,
    /// just as importantly, must not have grown the buffer far beyond the
    /// cap in the process (bounded, not merely "eventually detected").
    #[tokio::test]
    async fn oversized_unterminated_line_is_rejected_with_bounded_memory() {
        let oversized = vec![b'a'; MAX_WIRE_LINE_BYTES + (4 * READ_CHUNK_BYTES)];
        let mut r = BoundedLineReader::new(Cursor::new(oversized));
        let result = r.next_line().await;
        assert!(
            result.is_err(),
            "an unterminated line past the cap must be rejected"
        );
        assert!(
            r.buf.len() <= MAX_WIRE_LINE_BYTES + READ_CHUNK_BYTES,
            "buffer grew to {} bytes, far past the {MAX_WIRE_LINE_BYTES}-byte cap plus one chunk's \
             slack -- the bound isn't actually bounding anything",
            r.buf.len()
        );
    }

    /// A line sitting exactly at the cap, terminated, must still be
    /// accepted -- this is a bound on unterminated growth, not a message
    /// size limit that rejects legitimate maximum-sized messages.
    #[tokio::test]
    async fn line_exactly_at_the_cap_is_still_accepted() {
        let mut data = vec![b'a'; MAX_WIRE_LINE_BYTES];
        data.push(b'\n');
        let mut r = BoundedLineReader::new(Cursor::new(data));
        let line = r.next_line().await.unwrap();
        assert_eq!(line.map(|l| l.len()), Some(MAX_WIRE_LINE_BYTES));
    }

    #[tokio::test]
    async fn multiple_lines_split_across_small_reads_still_parse_correctly() {
        // Cursor delivers whatever's asked for in one shot, so to actually
        // exercise the multi-chunk accumulation path we feed lines longer
        // than READ_CHUNK_BYTES.
        let long_a = "a".repeat(READ_CHUNK_BYTES * 3);
        let long_b = "b".repeat(READ_CHUNK_BYTES * 2);
        let data = format!("{long_a}\n{long_b}\n").into_bytes();
        let mut r = BoundedLineReader::new(Cursor::new(data));
        assert_eq!(
            r.next_line().await.unwrap().as_deref(),
            Some(long_a.as_str())
        );
        assert_eq!(
            r.next_line().await.unwrap().as_deref(),
            Some(long_b.as_str())
        );
        assert_eq!(r.next_line().await.unwrap(), None);
    }

    #[tokio::test]
    async fn non_utf8_line_is_rejected_not_panicked() {
        let mut data = vec![0xff, 0xfe, 0xfd];
        data.push(b'\n');
        let mut r = BoundedLineReader::new(Cursor::new(data));
        assert!(r.next_line().await.is_err());
    }
}
