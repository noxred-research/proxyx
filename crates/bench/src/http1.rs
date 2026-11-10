//! A small HTTP/1.1 client and the response-head parser the scenarios share.
//!
//! Only what the load needs: `Content-Length` bodies, keep-alive and
//! `Connection: close`. A chunked or length-less response is a protocol error.

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::load::LoadError;

/// Largest response or request head accepted.
pub const MAX_HEAD_BYTES: usize = 16 * 1024;

/// A parsed response head.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResponseHead {
    pub status: u16,
    pub reason: String,
    pub content_length: Option<usize>,
    pub chunked: bool,
    pub close: bool,
}

/// Parse a response head (through the blank line).
pub fn parse_response_head(head: &[u8]) -> Result<ResponseHead, LoadError> {
    let mut headers = [httparse::EMPTY_HEADER; 64];
    let mut response = httparse::Response::new(&mut headers);
    match response.parse(head) {
        Ok(httparse::Status::Complete(_)) => {}
        Ok(httparse::Status::Partial) => return Err(LoadError::protocol("partial response head")),
        Err(e) => return Err(LoadError::protocol(format!("bad response head: {e}"))),
    }
    let header = |name: &str| {
        response
            .headers
            .iter()
            .find(|h| h.name.eq_ignore_ascii_case(name))
            .and_then(|h| std::str::from_utf8(h.value).ok())
    };
    Ok(ResponseHead {
        status: response.code.unwrap_or(0),
        reason: response.reason.unwrap_or("").to_owned(),
        content_length: header("content-length").and_then(|v| v.trim().parse().ok()),
        chunked: header("transfer-encoding")
            .is_some_and(|v| v.to_ascii_lowercase().contains("chunked")),
        close: header("connection").is_some_and(|v| v.eq_ignore_ascii_case("close")),
    })
}

/// A short lowercase token of a reason phrase, for an error class name.
pub fn reason_token(reason: &str) -> String {
    let token: String = reason
        .trim()
        .chars()
        .take(32)
        .map(|c| {
            if c.is_ascii_alphanumeric() {
                c.to_ascii_lowercase()
            } else {
                '_'
            }
        })
        .collect();
    if token.is_empty() {
        "none".to_owned()
    } else {
        token
    }
}

/// A stream with a read buffer, so bytes read past one message stay for the
/// next.
pub struct Conn<S> {
    stream: S,
    buf: Vec<u8>,
}

impl<S: AsyncRead + AsyncWrite + Unpin> Conn<S> {
    pub fn new(stream: S) -> Self {
        Self {
            stream,
            buf: Vec::with_capacity(4096),
        }
    }

    /// The stream and the bytes read from it that no message consumed yet.
    pub fn into_parts(self) -> (S, Vec<u8>) {
        (self.stream, self.buf)
    }

    pub async fn write_all(&mut self, bytes: &[u8]) -> Result<(), LoadError> {
        self.stream
            .write_all(bytes)
            .await
            .map_err(|e| LoadError::io("write", &e))
    }

    /// Read until a blank line and return the head with it. Bytes after the
    /// blank line stay buffered.
    pub async fn read_head(&mut self) -> Result<Vec<u8>, LoadError> {
        loop {
            if let Some(end) = find_head_end(&self.buf) {
                return Ok(self.buf.drain(..end).collect());
            }
            if self.buf.len() > MAX_HEAD_BYTES {
                return Err(LoadError::protocol("response head too large"));
            }
            self.fill().await?;
        }
    }

    /// Read and drop `n` bytes of body.
    pub async fn skip(&mut self, mut n: usize) -> Result<(), LoadError> {
        while n > 0 {
            if self.buf.is_empty() {
                self.fill().await?;
            }
            let take = n.min(self.buf.len());
            self.buf.drain(..take);
            n -= take;
        }
        Ok(())
    }

    /// Read exactly `out.len()` bytes into `out`.
    pub async fn read_exact_into(&mut self, out: &mut [u8]) -> Result<(), LoadError> {
        let from_buf = out.len().min(self.buf.len());
        out[..from_buf].copy_from_slice(&self.buf[..from_buf]);
        self.buf.drain(..from_buf);
        if from_buf < out.len() {
            self.stream
                .read_exact(&mut out[from_buf..])
                .await
                .map_err(|e| LoadError::io("read", &e))?;
        }
        Ok(())
    }

    async fn fill(&mut self) -> Result<(), LoadError> {
        let mut chunk = [0u8; 16 * 1024];
        let n = self
            .stream
            .read(&mut chunk)
            .await
            .map_err(|e| LoadError::io("read", &e))?;
        if n == 0 {
            return Err(LoadError::new("read_eof", "connection closed by the peer"));
        }
        self.buf.extend_from_slice(&chunk[..n]);
        Ok(())
    }

    /// One `POST` with a `body_len`-byte body and its response. Returns the
    /// application bytes moved: request body plus response body.
    pub async fn post(&mut self, host: &str, body: &[u8], close: bool) -> Result<u64, LoadError> {
        let mut request = format!(
            "POST /bench HTTP/1.1\r\nHost: {host}\r\nContent-Type: application/octet-stream\r\nContent-Length: {}\r\n{}\r\n",
            body.len(),
            if close { "Connection: close\r\n" } else { "" }
        )
        .into_bytes();
        request.extend_from_slice(body);
        self.write_all(&request).await?;
        let head = parse_response_head(&self.read_head().await?)?;
        if head.status != 200 {
            return Err(LoadError::new(
                format!("http_status_{}", head.status),
                format!("{} {}", head.status, head.reason),
            ));
        }
        if head.chunked {
            return Err(LoadError::protocol("chunked response"));
        }
        let len = head
            .content_length
            .ok_or_else(|| LoadError::protocol("response without Content-Length"))?;
        self.skip(len).await?;
        Ok((body.len() + len) as u64)
    }
}

/// Open a TCP connection to `proxy` and run `CONNECT authority` with the
/// given `Proxy-Authorization` value. Returns the stream when the proxy
/// answers `2xx`; any other answer is an error class `connect_<status>_<reason>`
/// (for the pool gateway the reason is the cause code, `503 cache_empty`).
pub async fn connect_tunnel(
    proxy: std::net::SocketAddr,
    authority: &str,
    proxy_authorization: &str,
) -> Result<tokio::net::TcpStream, LoadError> {
    let stream = tokio::net::TcpStream::connect(proxy)
        .await
        .map_err(|e| LoadError::io("connect", &e))?;
    stream
        .set_nodelay(true)
        .map_err(|e| LoadError::io("connect", &e))?;
    let mut conn = Conn::new(stream);
    conn.write_all(
        format!(
            "CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\nProxy-Authorization: {proxy_authorization}\r\n\r\n"
        )
        .as_bytes(),
    )
    .await?;
    let head = parse_response_head(&conn.read_head().await?)?;
    if !(200..300).contains(&head.status) {
        return Err(LoadError::new(
            format!("connect_{}_{}", head.status, reason_token(&head.reason)),
            format!(
                "CONNECT {authority} answered {} {}",
                head.status, head.reason
            ),
        ));
    }
    let (stream, leftover) = conn.into_parts();
    if !leftover.is_empty() {
        return Err(LoadError::protocol("bytes after the CONNECT answer"));
    }
    Ok(stream)
}

fn find_head_end(buf: &[u8]) -> Option<usize> {
    buf.windows(4).position(|w| w == b"\r\n\r\n").map(|i| i + 4)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_head_is_parsed_with_its_framing_headers() {
        let h = parse_response_head(
            b"HTTP/1.1 200 OK\r\nContent-Length: 12\r\nConnection: close\r\n\r\n",
        )
        .expect("parse");
        assert_eq!(h.status, 200);
        assert_eq!(h.reason, "OK");
        assert_eq!(h.content_length, Some(12));
        assert!(h.close && !h.chunked);
    }

    #[test]
    fn a_chunked_head_is_recognised_and_header_names_are_case_blind() {
        let h = parse_response_head(b"HTTP/1.1 200 OK\r\ntransfer-ENCODING: Chunked\r\n\r\n")
            .expect("parse");
        assert!(h.chunked);
        assert_eq!(h.content_length, None);
    }

    #[test]
    fn a_proxy_refusal_keeps_the_cause_in_the_reason() {
        let h = parse_response_head(b"HTTP/1.1 503 cache_empty\r\nContent-Length: 0\r\n\r\n")
            .expect("parse");
        assert_eq!((h.status, h.reason.as_str()), (503, "cache_empty"));
        assert_eq!(reason_token(&h.reason), "cache_empty");
    }

    #[test]
    fn partial_and_garbled_heads_are_protocol_errors() {
        assert_eq!(
            parse_response_head(b"HTTP/1.1 200 OK\r\nCont")
                .expect_err("partial")
                .class,
            "protocol"
        );
        assert_eq!(
            parse_response_head(b"nonsense\r\n\r\n")
                .expect_err("garbled")
                .class,
            "protocol"
        );
    }

    #[test]
    fn reason_tokens_are_short_lowercase_and_never_empty() {
        assert_eq!(
            reason_token("Proxy Authentication Required"),
            "proxy_authentication_required"
        );
        assert_eq!(reason_token(""), "none");
        assert_eq!(reason_token(&"x".repeat(100)).len(), 32);
    }

    #[tokio::test]
    async fn post_reads_the_body_and_keeps_the_next_message_buffered() {
        let (client, mut server) = tokio::io::duplex(64 * 1024);
        let serve = tokio::spawn(async move {
            let mut got = vec![0u8; 8192];
            let _ = server.read(&mut got).await.expect("read");
            // two responses back to back in one write
            server
                .write_all(
                    b"HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\nabcHTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nxy",
                )
                .await
                .expect("write");
        });
        let mut conn = Conn::new(client);
        assert_eq!(conn.post("h", b"12345", false).await.expect("first"), 8);
        // the second response is already buffered: no further read is needed
        let head = parse_response_head(&conn.read_head().await.expect("head")).expect("parse");
        assert_eq!(head.content_length, Some(2));
        conn.skip(2).await.expect("skip");
        serve.await.expect("server");
    }

    #[tokio::test]
    async fn a_non_200_response_is_a_status_error_class() {
        let (client, mut server) = tokio::io::duplex(4096);
        tokio::spawn(async move {
            let mut got = [0u8; 1024];
            let _ = server.read(&mut got).await;
            let _ = server
                .write_all(b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n")
                .await;
        });
        let mut conn = Conn::new(client);
        let e = conn.post("h", b"x", false).await.expect_err("status");
        assert_eq!(e.class, "http_status_502");
    }

    #[tokio::test]
    async fn a_closed_stream_is_an_eof_error() {
        let (client, server) = tokio::io::duplex(1024);
        drop(server);
        let mut conn = Conn::new(client);
        let e = conn.read_head().await.expect_err("eof");
        assert_eq!(e.class, "read_eof");
    }
}
