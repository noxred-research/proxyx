//! HTTP CONNECT client. Accepts only `200`; `407` is a credential failure.

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use common::types::UpstreamEndpoint;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use crate::DialError;

/// Same cap as the session proxy: a reply head above this is not a proxy answering.
const MAX_HEAD_BYTES: usize = 8192;

pub(crate) async fn connect(
    stream: &mut TcpStream,
    up: &UpstreamEndpoint,
    host: &str,
    port: u16,
) -> Result<(), DialError> {
    let authority = authority(host, port);
    let mut request = format!("CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\n");
    if !up.username.is_empty() {
        let credentials = format!("{}:{}", up.username.expose(), up.password.expose());
        request.push_str(&format!(
            "Proxy-Authorization: Basic {}\r\n",
            STANDARD.encode(credentials)
        ));
    }
    request.push_str("\r\n");
    stream
        .write_all(request.as_bytes())
        .await
        .map_err(DialError::Io)?;

    let head = read_head(stream).await?;
    match status(&head)? {
        200 => Ok(()),
        407 => Err(DialError::Auth),
        other => Err(DialError::Status(other)),
    }
}

/// Read up to and including the blank line, one byte at a time. A buffered
/// reader could swallow tunnel bytes the target sends right after the
/// `200` (SMTP, SSH and FTP servers speak first), and the stream goes on to
/// the relay. The head is a few hundred bytes, so the syscalls are cheap.
async fn read_head(stream: &mut TcpStream) -> Result<Vec<u8>, DialError> {
    let mut head = Vec::with_capacity(256);
    loop {
        head.push(stream.read_u8().await.map_err(DialError::Io)?);
        if head.ends_with(b"\r\n\r\n") {
            return Ok(head);
        }
        if head.len() >= MAX_HEAD_BYTES {
            return Err(DialError::Protocol("response head too large"));
        }
    }
}

/// `host:port`, with brackets around an IPv6 literal.
fn authority(host: &str, port: u16) -> String {
    if host.contains(':') {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    }
}

/// Status code of `HTTP/1.x SP code SP reason`.
fn status(head: &[u8]) -> Result<u16, DialError> {
    let line_end = head.iter().position(|&b| b == b'\r').unwrap_or(head.len());
    let line = &head[..line_end];
    let mut parts = line.split(|&b| b == b' ');
    match parts.next() {
        Some(v) if v.starts_with(b"HTTP/1.") => {}
        _ => return Err(DialError::Protocol("not an HTTP/1 status line")),
    }
    parts
        .next()
        .filter(|code| code.len() == 3 && code.iter().all(u8::is_ascii_digit))
        .and_then(|code| std::str::from_utf8(code).ok()?.parse().ok())
        .ok_or(DialError::Protocol("malformed status code"))
}

#[cfg(test)]
mod tests {
    use super::status;

    #[test]
    fn status_line_parsing() {
        assert_eq!(status(b"HTTP/1.1 200 OK\r\n\r\n").ok(), Some(200));
        assert_eq!(status(b"HTTP/1.0 407\r\n\r\n").ok(), Some(407));
        assert_eq!(
            status(b"HTTP/1.1 502 Bad Gateway\r\nX: y\r\n\r\n").ok(),
            Some(502)
        );
        for bad in [
            &b"HTTP/2 200 OK\r\n\r\n"[..],
            b"200 OK\r\n\r\n",
            b"HTTP/1.1\r\n\r\n",
            b"HTTP/1.1 20 OK\r\n\r\n",
            b"HTTP/1.1 2000 OK\r\n\r\n",
            b"HTTP/1.1 +20 OK\r\n\r\n",
            b"\r\n\r\n",
        ] {
            assert!(status(bad).is_err(), "{}", String::from_utf8_lossy(bad));
        }
    }
}
