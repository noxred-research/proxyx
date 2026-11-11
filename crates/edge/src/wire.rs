//! HTTP/1.1 wire handling for the forward proxy: strict head parsing, body
//! framing, and passing bodies through (fixed length, chunked, until close)
//! with bandwidth pacing.
//!
//! Parsing is strict on purpose: a request with both `Content-Length` and
//! `Transfer-Encoding`, with differing `Content-Length` values, or with a
//! framing the proxy cannot follow is refused, never repaired: a proxy that
//! guesses where a message ends is a request-smuggling hole.

use std::io;
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncReadExt as _, AsyncWrite, AsyncWriteExt as _};
use tokio::net::TcpStream;
use tokio::time::timeout;

use crate::headers::Header;
use crate::limits::Shaper;

const MAX_HEADERS: usize = 100;
const READ_CHUNK: usize = 16 * 1024;
/// Longest chunk-size line (size and extensions).
const MAX_CHUNK_LINE: usize = 1024;

/// A socket with the bytes read ahead of the parser.
pub struct Pipe<S = TcpStream> {
    pub stream: S,
    pub buf: Vec<u8>,
}

impl<S: AsyncRead + Unpin> Pipe<S> {
    pub fn new(stream: S) -> Self {
        Self {
            stream,
            buf: Vec::new(),
        }
    }

    /// Read more bytes into the buffer; `Ok(0)` is end of stream.
    pub async fn fill(&mut self, limit: Duration) -> io::Result<usize> {
        self.fill_at_most(limit, READ_CHUNK).await
    }

    /// Head readers may consume only their remaining size budget.
    async fn fill_at_most(&mut self, limit: Duration, max: usize) -> io::Result<usize> {
        let start = self.buf.len();
        self.buf.resize(start + READ_CHUNK.min(max), 0);
        let r = timeout(limit, self.stream.read(&mut self.buf[start..])).await;
        match r {
            Ok(Ok(n)) => {
                self.buf.truncate(start + n);
                Ok(n)
            }
            Ok(Err(e)) => {
                self.buf.truncate(start);
                Err(e)
            }
            Err(_) => {
                self.buf.truncate(start);
                Err(io::Error::from(io::ErrorKind::TimedOut))
            }
        }
    }

    pub fn into_parts(self) -> (S, Vec<u8>) {
        (self.stream, self.buf)
    }
}

#[derive(Debug)]
pub enum HeadError {
    /// The peer closed before a full head (or between requests).
    Closed,
    TooLarge,
    Malformed(&'static str),
    Timeout,
    Io(io::Error),
}

impl From<io::Error> for HeadError {
    fn from(e: io::Error) -> Self {
        if e.kind() == io::ErrorKind::TimedOut {
            HeadError::Timeout
        } else {
            HeadError::Io(e)
        }
    }
}

#[derive(Debug, Clone)]
pub struct RequestHead {
    pub method: String,
    pub target: String,
    /// 0 for HTTP/1.0, 1 for HTTP/1.1.
    pub minor: u8,
    pub headers: Vec<Header>,
}

#[derive(Debug, Clone)]
pub struct ResponseHead {
    pub status: u16,
    pub reason: String,
    pub minor: u8,
    pub headers: Vec<Header>,
}

fn collect(h: &[httparse::Header<'_>]) -> Vec<Header> {
    h.iter()
        .map(|h| (h.name.to_owned(), h.value.to_vec()))
        .collect()
}

/// Read one request head. `limit` bounds each wait for bytes; `max` the head size.
pub async fn read_request_head<S: AsyncRead + Unpin>(
    pipe: &mut Pipe<S>,
    max: usize,
    limit: Duration,
) -> Result<RequestHead, HeadError> {
    loop {
        if !pipe.buf.is_empty() {
            let mut headers = [httparse::EMPTY_HEADER; MAX_HEADERS];
            let mut req = httparse::Request::new(&mut headers);
            match req.parse(&pipe.buf[..pipe.buf.len().min(max)]) {
                Ok(httparse::Status::Complete(n)) => {
                    let head = RequestHead {
                        method: req.method.unwrap_or_default().to_owned(),
                        target: req.path.unwrap_or_default().to_owned(),
                        minor: req.version.unwrap_or(1),
                        headers: collect(req.headers),
                    };
                    pipe.buf.drain(..n);
                    return Ok(head);
                }
                Ok(httparse::Status::Partial) => {}
                Err(httparse::Error::TooManyHeaders) => return Err(HeadError::TooLarge),
                Err(_) => return Err(HeadError::Malformed("not a valid HTTP request")),
            }
        }
        if pipe.buf.len() >= max {
            return Err(HeadError::TooLarge);
        }
        match pipe.fill_at_most(limit, max - pipe.buf.len()).await? {
            0 if pipe.buf.is_empty() => return Err(HeadError::Closed),
            0 => {
                return Err(HeadError::Malformed(
                    "connection closed inside the request head",
                ));
            }
            _ => {}
        }
    }
}

pub async fn read_response_head<S: AsyncRead + Unpin>(
    pipe: &mut Pipe<S>,
    max: usize,
    limit: Duration,
) -> Result<ResponseHead, HeadError> {
    loop {
        if !pipe.buf.is_empty() {
            let mut headers = [httparse::EMPTY_HEADER; MAX_HEADERS];
            let mut resp = httparse::Response::new(&mut headers);
            match resp.parse(&pipe.buf[..pipe.buf.len().min(max)]) {
                Ok(httparse::Status::Complete(n)) => {
                    let head = ResponseHead {
                        status: resp.code.unwrap_or(0),
                        reason: resp.reason.unwrap_or_default().to_owned(),
                        minor: resp.version.unwrap_or(1),
                        headers: collect(resp.headers),
                    };
                    pipe.buf.drain(..n);
                    return Ok(head);
                }
                Ok(httparse::Status::Partial) => {}
                Err(httparse::Error::TooManyHeaders) => return Err(HeadError::TooLarge),
                Err(_) => return Err(HeadError::Malformed("not a valid HTTP response")),
            }
        }
        if pipe.buf.len() >= max {
            return Err(HeadError::TooLarge);
        }
        match pipe.fill_at_most(limit, max - pipe.buf.len()).await? {
            0 if pipe.buf.is_empty() => return Err(HeadError::Closed),
            0 => {
                return Err(HeadError::Malformed(
                    "connection closed inside the response head",
                ));
            }
            _ => {}
        }
    }
}

/// First value of a header, case-insensitive.
pub fn header<'a>(h: &'a [Header], name: &str) -> Option<&'a [u8]> {
    h.iter()
        .find(|(n, _)| n.eq_ignore_ascii_case(name))
        .map(|(_, v)| v.as_slice())
}

pub fn header_str<'a>(h: &'a [Header], name: &str) -> Option<&'a str> {
    header(h, name).and_then(|v| std::str::from_utf8(v).ok())
}

/// True when a comma-separated header holds `token` (case-insensitive).
pub fn has_token(h: &[Header], name: &str, token: &str) -> bool {
    h.iter()
        .filter(|(n, _)| n.eq_ignore_ascii_case(name))
        .any(|(_, v)| {
            String::from_utf8_lossy(v)
                .split(',')
                .any(|t| t.trim().eq_ignore_ascii_case(token))
        })
}

/// How a message body is delimited.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Framing {
    None,
    Length(u64),
    Chunked,
    /// A response body that ends when the server closes.
    UntilClose,
}

fn transfer_encoding(h: &[Header]) -> Result<Option<bool>, &'static str> {
    let values: Vec<String> = h
        .iter()
        .filter(|(n, _)| n.eq_ignore_ascii_case("transfer-encoding"))
        .map(|(_, v)| String::from_utf8_lossy(v).to_ascii_lowercase())
        .collect();
    if values.is_empty() {
        return Ok(None);
    }
    let codings: Vec<String> = values
        .iter()
        .flat_map(|v| {
            v.split(',')
                .map(|c| c.trim().to_owned())
                .collect::<Vec<_>>()
        })
        .filter(|c| !c.is_empty())
        .collect();
    // Only a lone `chunked` is followed; any other coding stack is refused.
    if codings == ["chunked"] {
        Ok(Some(true))
    } else {
        Err("unsupported Transfer-Encoding")
    }
}

fn content_length(h: &[Header]) -> Result<Option<u64>, &'static str> {
    let mut found: Option<u64> = None;
    for (n, v) in h {
        if !n.eq_ignore_ascii_case("content-length") {
            continue;
        }
        for part in String::from_utf8_lossy(v).split(',') {
            let part = part.trim();
            if part.is_empty() || !part.bytes().all(|b| b.is_ascii_digit()) {
                return Err("bad Content-Length");
            }
            let n: u64 = part.parse().map_err(|_| "bad Content-Length")?;
            match found {
                Some(prev) if prev != n => return Err("conflicting Content-Length"),
                _ => found = Some(n),
            }
        }
    }
    Ok(found)
}

pub fn request_framing(h: &[Header]) -> Result<Framing, &'static str> {
    let te = transfer_encoding(h)?;
    let cl = content_length(h)?;
    match (te, cl) {
        (Some(_), Some(_)) => Err("both Transfer-Encoding and Content-Length"),
        (Some(_), None) => Ok(Framing::Chunked),
        (None, Some(0)) | (None, None) => Ok(Framing::None),
        (None, Some(n)) => Ok(Framing::Length(n)),
    }
}

pub fn response_framing(
    status: u16,
    head_request: bool,
    h: &[Header],
) -> Result<Framing, &'static str> {
    if head_request || (100..200).contains(&status) || status == 204 || status == 304 {
        return Ok(Framing::None);
    }
    let te = transfer_encoding(h)?;
    let cl = content_length(h)?;
    match (te, cl) {
        (Some(_), Some(_)) => Err("both Transfer-Encoding and Content-Length"),
        (Some(_), None) => Ok(Framing::Chunked),
        (None, Some(n)) => Ok(Framing::Length(n)),
        (None, None) => Ok(Framing::UntilClose),
    }
}

/// Serialize a head: `line`, the headers, a blank line.
pub fn render_head(line: &str, headers: &[Header]) -> Vec<u8> {
    let mut out = Vec::with_capacity(256);
    out.extend_from_slice(line.as_bytes());
    out.extend_from_slice(b"\r\n");
    for (n, v) in headers {
        out.extend_from_slice(n.as_bytes());
        out.extend_from_slice(b": ");
        out.extend_from_slice(v);
        out.extend_from_slice(b"\r\n");
    }
    out.extend_from_slice(b"\r\n");
    out
}

async fn write_paced<W: AsyncWrite + Unpin>(
    dst: &mut W,
    data: &[u8],
    shaper: &Shaper,
) -> io::Result<()> {
    if shaper.is_limited() {
        let step = shaper.chunk(READ_CHUNK);
        for piece in data.chunks(step) {
            shaper.pace(piece.len()).await;
            dst.write_all(piece).await?;
        }
        Ok(())
    } else {
        dst.write_all(data).await
    }
}

fn eof() -> io::Error {
    io::Error::from(io::ErrorKind::UnexpectedEof)
}

async fn copy_exact<R: AsyncRead + Unpin, W: AsyncWrite + Unpin>(
    src: &mut Pipe<R>,
    dst: &mut W,
    mut n: u64,
    shaper: &Shaper,
    idle: Duration,
    moved: &mut u64,
) -> io::Result<()> {
    while n > 0 {
        if src.buf.is_empty() && src.fill(idle).await? == 0 {
            return Err(eof());
        }
        let take = usize::try_from(n).map_or(src.buf.len(), |n| n.min(src.buf.len()));
        write_paced(dst, &src.buf[..take], shaper).await?;
        src.buf.drain(..take);
        n -= take as u64;
        *moved += take as u64;
    }
    Ok(())
}

/// Read one line up to and including CRLF out of the buffer (filling it as needed).
async fn take_line<R: AsyncRead + Unpin>(
    src: &mut Pipe<R>,
    max: usize,
    idle: Duration,
) -> io::Result<Vec<u8>> {
    loop {
        if let Some(i) = src.buf.windows(2).position(|w| w == b"\r\n") {
            let line: Vec<u8> = src.buf.drain(..i + 2).collect();
            return Ok(line);
        }
        if src.buf.len() > max {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "line too long"));
        }
        if src.fill(idle).await? == 0 {
            return Err(eof());
        }
    }
}

fn chunk_size(line: &[u8]) -> io::Result<u64> {
    let bad = || io::Error::new(io::ErrorKind::InvalidData, "bad chunk size");
    let line = &line[..line.len() - 2];
    let digits = line.split(|&b| b == b';').next().unwrap_or_default();
    let digits = std::str::from_utf8(digits).map_err(|_| bad())?.trim();
    if digits.is_empty() || digits.len() > 16 || !digits.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(bad());
    }
    u64::from_str_radix(digits, 16).map_err(|_| bad())
}

async fn copy_chunked<R: AsyncRead + Unpin, W: AsyncWrite + Unpin>(
    src: &mut Pipe<R>,
    dst: &mut W,
    shaper: &Shaper,
    idle: Duration,
    max_trailer: usize,
    moved: &mut u64,
) -> io::Result<()> {
    loop {
        let line = take_line(src, MAX_CHUNK_LINE, idle).await?;
        let size = chunk_size(&line)?;
        dst.write_all(&line).await?;
        if size == 0 {
            // trailer section: lines until the blank one
            let mut total = 0usize;
            loop {
                let l = take_line(src, max_trailer, idle).await?;
                total += l.len();
                if total > max_trailer {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "trailers too large",
                    ));
                }
                dst.write_all(&l).await?;
                if l.len() == 2 {
                    return Ok(());
                }
            }
        }
        copy_exact(src, dst, size, shaper, idle, moved).await?;
        while src.buf.len() < 2 {
            if src.fill(idle).await? == 0 {
                return Err(eof());
            }
        }
        if &src.buf[..2] != b"\r\n" {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "chunk not followed by CRLF",
            ));
        }
        dst.write_all(b"\r\n").await?;
        src.buf.drain(..2);
    }
}

async fn copy_until_close<R: AsyncRead + Unpin, W: AsyncWrite + Unpin>(
    src: &mut Pipe<R>,
    dst: &mut W,
    shaper: &Shaper,
    idle: Duration,
    moved: &mut u64,
) -> io::Result<()> {
    loop {
        if src.buf.is_empty() && src.fill(idle).await? == 0 {
            return Ok(());
        }
        let n = src.buf.len();
        write_paced(dst, &src.buf, shaper).await?;
        src.buf.clear();
        *moved += n as u64;
    }
}

/// Pass one message body from `src` to `dst`. Returns the bytes moved.
pub async fn copy_body<R: AsyncRead + Unpin, W: AsyncWrite + Unpin>(
    src: &mut Pipe<R>,
    dst: &mut W,
    framing: Framing,
    shaper: &Shaper,
    idle: Duration,
    max_trailer: usize,
) -> io::Result<u64> {
    let mut moved = 0u64;
    match framing {
        Framing::None => {}
        Framing::Length(n) => copy_exact(src, dst, n, shaper, idle, &mut moved).await?,
        Framing::Chunked => copy_chunked(src, dst, shaper, idle, max_trailer, &mut moved).await?,
        Framing::UntilClose => copy_until_close(src, dst, shaper, idle, &mut moved).await?,
    }
    Ok(moved)
}

#[cfg(test)]
mod tests {
    use tokio::net::TcpListener;

    use super::*;

    fn h(list: &[(&str, &str)]) -> Vec<Header> {
        list.iter()
            .map(|(k, v)| ((*k).to_owned(), v.as_bytes().to_vec()))
            .collect()
    }

    #[test]
    fn request_framing_rules() {
        assert_eq!(request_framing(&h(&[])), Ok(Framing::None));
        assert_eq!(
            request_framing(&h(&[("Content-Length", "0")])),
            Ok(Framing::None)
        );
        assert_eq!(
            request_framing(&h(&[("content-length", "12")])),
            Ok(Framing::Length(12))
        );
        assert_eq!(
            request_framing(&h(&[("Transfer-Encoding", "Chunked")])),
            Ok(Framing::Chunked)
        );
        // smuggling shapes are refused
        for bad in [
            h(&[("Content-Length", "5"), ("Transfer-Encoding", "chunked")]),
            h(&[("Content-Length", "5"), ("Content-Length", "6")]),
            h(&[("Content-Length", "5, 6")]),
            h(&[("Content-Length", "-1")]),
            h(&[("Content-Length", "+5")]),
            h(&[("Content-Length", "")]),
            h(&[("Transfer-Encoding", "gzip, chunked")]),
            h(&[("Transfer-Encoding", "identity")]),
        ] {
            assert!(request_framing(&bad).is_err(), "{bad:?}");
        }
        // equal duplicates are one value
        assert_eq!(
            request_framing(&h(&[("Content-Length", "5"), ("Content-Length", "5")])),
            Ok(Framing::Length(5))
        );
    }

    #[test]
    fn response_framing_rules() {
        let none = h(&[]);
        assert_eq!(response_framing(200, false, &none), Ok(Framing::UntilClose));
        assert_eq!(
            response_framing(200, true, &h(&[("Content-Length", "9")])),
            Ok(Framing::None)
        );
        assert_eq!(response_framing(204, false, &none), Ok(Framing::None));
        assert_eq!(
            response_framing(304, false, &h(&[("Content-Length", "9")])),
            Ok(Framing::None)
        );
        assert_eq!(response_framing(100, false, &none), Ok(Framing::None));
        assert_eq!(
            response_framing(200, false, &h(&[("Content-Length", "9")])),
            Ok(Framing::Length(9))
        );
        assert_eq!(
            response_framing(200, false, &h(&[("Transfer-Encoding", "chunked")])),
            Ok(Framing::Chunked)
        );
    }

    #[test]
    fn chunk_sizes() {
        assert_eq!(chunk_size(b"1a\r\n").ok(), Some(26));
        assert_eq!(chunk_size(b"0;ext=1\r\n").ok(), Some(0));
        for bad in [
            &b"\r\n"[..],
            b"zz\r\n",
            b"+5\r\n",
            b"-1\r\n",
            b"11111111111111111\r\n",
        ] {
            assert!(chunk_size(bad).is_err());
        }
    }

    #[test]
    fn tokens_and_headers() {
        let l = h(&[("Connection", "keep-alive, Upgrade"), ("X", "1")]);
        assert!(has_token(&l, "connection", "upgrade"));
        assert!(!has_token(&l, "connection", "close"));
        assert_eq!(header_str(&l, "x"), Some("1"));
        assert_eq!(
            render_head("GET / HTTP/1.1", &h(&[("Host", "a")])),
            b"GET / HTTP/1.1\r\nHost: a\r\n\r\n"
        );
    }

    async fn pair() -> (TcpStream, TcpStream) {
        let l = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = l.local_addr().expect("addr");
        let (a, b) = tokio::join!(TcpStream::connect(addr), l.accept());
        (a.expect("connect"), b.expect("accept").0)
    }

    const IDLE: Duration = Duration::from_secs(5);

    #[tokio::test]
    async fn complete_heads_cannot_bypass_the_limit_and_bodies_do_not_count() {
        let request = b"GET / HTTP/1.1\r\nX: value\r\n\r\n";
        let response = b"HTTP/1.1 200 OK\r\nX: value\r\n\r\n";
        for (head, request_side) in [(request.as_slice(), true), (response.as_slice(), false)] {
            for maximum in [0, head.len() - 1, head.len()] {
                let mut pipe = Pipe::new(tokio::io::empty());
                pipe.buf.extend_from_slice(head);
                // Read-ahead body/pipeline bytes are not part of the head budget.
                pipe.buf.extend_from_slice(&[b'x'; 8192]);
                let result = if request_side {
                    read_request_head(&mut pipe, maximum, IDLE)
                        .await
                        .map(|_| ())
                } else {
                    read_response_head(&mut pipe, maximum, IDLE)
                        .await
                        .map(|_| ())
                };
                if maximum == head.len() {
                    assert!(result.is_ok());
                    assert_eq!(pipe.buf, vec![b'x'; 8192]);
                } else {
                    assert!(matches!(result, Err(HeadError::TooLarge)));
                }
            }
        }
    }

    #[tokio::test]
    async fn head_reads_never_consume_past_the_remaining_budget() {
        let oversized = b"GET / HTTP/1.1\r\nX: long value\r\n\r\npayload";
        let mut pipe = Pipe::new(&oversized[..]);
        let max = oversized.len() - b"\r\n\r\npayload".len();
        assert!(matches!(
            read_request_head(&mut pipe, max, IDLE).await,
            Err(HeadError::TooLarge)
        ));
        assert_eq!(pipe.buf.len(), max);
        assert_eq!(pipe.stream, &oversized[max..]);

        let oversized = b"HTTP/1.1 200 OK\r\nX: long value\r\n\r\npayload";
        let mut pipe = Pipe::new(&oversized[..]);
        let max = oversized.len() - b"\r\n\r\npayload".len();
        assert!(matches!(
            read_response_head(&mut pipe, max, IDLE).await,
            Err(HeadError::TooLarge)
        ));
        assert_eq!(pipe.buf.len(), max);
        assert_eq!(pipe.stream, &oversized[max..]);
    }

    #[tokio::test]
    async fn request_heads_parse_across_reads_and_keep_pipelined_bytes() {
        let (mut peer, srv) = pair().await;
        let mut pipe = Pipe::new(srv);
        peer.write_all(b"GET http://a.test/x HTTP/1.1\r\nHo")
            .await
            .expect("write");
        let t = tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(50)).await;
            peer.write_all(b"st: a.test\r\n\r\nGET /second HTTP/1.1\r\n\r\n")
                .await
                .expect("write");
            peer
        });
        let head = read_request_head(&mut pipe, 8192, IDLE)
            .await
            .expect("head");
        assert_eq!(
            (head.method.as_str(), head.target.as_str(), head.minor),
            ("GET", "http://a.test/x", 1)
        );
        assert_eq!(header_str(&head.headers, "host"), Some("a.test"));
        let second = read_request_head(&mut pipe, 8192, IDLE)
            .await
            .expect("second");
        assert_eq!(second.target, "/second");
        let _peer = t.await.expect("join");
    }

    #[tokio::test]
    async fn bad_and_oversized_heads_are_refused() {
        let (mut peer, srv) = pair().await;
        let mut pipe = Pipe::new(srv);
        peer.write_all(b"NOT HTTP AT ALL\r\n\r\n")
            .await
            .expect("write");
        assert!(matches!(
            read_request_head(&mut pipe, 8192, IDLE).await,
            Err(HeadError::Malformed(_))
        ));
        let (mut peer, srv) = pair().await;
        let mut pipe = Pipe::new(srv);
        peer.write_all(&[b'a'; 9000]).await.expect("write");
        assert!(matches!(
            read_request_head(&mut pipe, 4096, IDLE).await,
            Err(HeadError::TooLarge | HeadError::Malformed(_))
        ));
        let (peer, srv) = pair().await;
        drop(peer);
        let mut pipe = Pipe::new(srv);
        assert!(matches!(
            read_request_head(&mut pipe, 8192, IDLE).await,
            Err(HeadError::Closed)
        ));
        let (_peer, srv) = pair().await;
        let mut pipe = Pipe::new(srv);
        assert!(matches!(
            read_request_head(&mut pipe, 8192, Duration::from_millis(80)).await,
            Err(HeadError::Timeout)
        ));
    }

    async fn pass(
        framing: Framing,
        input: &[u8],
        rest: &[u8],
    ) -> (io::Result<u64>, Vec<u8>, Vec<u8>) {
        let (mut src_peer, src) = pair().await;
        let (dst, mut dst_peer) = pair().await;
        let mut pipe = Pipe::new(src);
        let mut dst = dst;
        src_peer.write_all(input).await.expect("write");
        src_peer.write_all(rest).await.expect("write");
        src_peer.shutdown().await.expect("shutdown");
        let r = copy_body(&mut pipe, &mut dst, framing, &Shaper::none(), IDLE, 4096).await;
        drop(dst);
        let mut out = Vec::new();
        dst_peer.read_to_end(&mut out).await.expect("read");
        // what was left unread in the source (the next message)
        let mut left = std::mem::take(&mut pipe.buf);
        let mut more = Vec::new();
        let _ = timeout(
            Duration::from_millis(200),
            pipe.stream.read_to_end(&mut more),
        )
        .await;
        left.extend(more);
        (r, out, left)
    }

    #[tokio::test]
    async fn fixed_length_bodies_stop_at_the_length() {
        let (r, out, left) = pass(Framing::Length(5), b"hello", b"NEXT").await;
        assert_eq!(r.expect("copy"), 5);
        assert_eq!(out, b"hello");
        assert_eq!(left, b"NEXT");
        let (r, ..) = pass(Framing::Length(9), b"short", b"").await;
        assert_eq!(r.expect_err("eof").kind(), io::ErrorKind::UnexpectedEof);
    }

    #[tokio::test]
    async fn chunked_bodies_pass_through_with_trailers_and_stop_at_the_end() {
        let body = b"5\r\nhello\r\n6;x=y\r\n world\r\n0\r\nTrailer-A: 1\r\n\r\n";
        let (r, out, left) = pass(Framing::Chunked, body, b"NEXT").await;
        assert!(r.is_ok(), "{r:?}");
        assert_eq!(out, body);
        assert_eq!(left, b"NEXT");
        // bad framing
        for bad in [
            &b"5\r\nhelloXX0\r\n\r\n"[..],
            b"zz\r\nhello\r\n",
            b"5\r\nhel",
        ] {
            let (r, ..) = pass(Framing::Chunked, bad, b"").await;
            assert!(r.is_err(), "{}", String::from_utf8_lossy(bad));
        }
    }

    #[tokio::test]
    async fn until_close_copies_everything() {
        let (r, out, _) = pass(Framing::UntilClose, b"abc", b"def").await;
        assert_eq!(r.expect("copy"), 6);
        assert_eq!(out, b"abcdef");
    }
}
