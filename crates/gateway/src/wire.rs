//! Inbound wire formats: the HTTP CONNECT request head and the SOCKS5
//! handshake (RFC 1928, RFC 1929), and the replies for both.
//!
//! Parsing is strict and bounded: the head has a size cap, and a request that
//! does not parse is refused, never repaired. The caller wraps each read in
//! its own timeout.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use common::Cause;
use common::Secret;
use common::types::Target;
use tokio::io::{AsyncRead, AsyncReadExt};

/// Largest CONNECT request head ProxyX reads, like the session proxy's own cap on
/// proxy replies (`egress.rs`).
const MAX_HEAD_BYTES: usize = 8 * 1024;

const MAX_HEADERS: usize = 32;
const MAX_HOST_BYTES: usize = 253;

/// A CONNECT request after parsing.
#[derive(Debug)]
pub(crate) struct ConnectHead {
    pub target: Target,
    /// `None` when the request has no usable `Proxy-Authorization: Basic`.
    pub login: Option<Login>,
    /// Bytes the client sent after the blank line (tunnel data that was
    /// pipelined before the `200`). Forwarded upstream first.
    pub leftover: Vec<u8>,
}

/// Proxy username (the options) and password (the org key).
#[derive(Debug)]
pub(crate) struct Login {
    pub username: String,
    pub key: Secret,
}

/// Why the request head could not be used.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum HeadError {
    /// The client closed before a full head arrived.
    Closed,
    /// More than [`MAX_HEAD_BYTES`] without a blank line.
    TooLarge,
    /// Not valid HTTP/1.x, or a request target that is not `host:port`.
    Malformed,
    /// A method other than CONNECT.
    NotConnect,
    Io,
}

impl HeadError {
    /// The refusal to send, `None` when the peer is gone.
    pub(crate) fn reply(&self) -> Option<Vec<u8>> {
        let (status, reason) = match self {
            HeadError::Closed | HeadError::Io => return None,
            HeadError::TooLarge => (431, "Request Header Fields Too Large"),
            HeadError::Malformed => (400, "Bad Request"),
            HeadError::NotConnect => (405, "Method Not Allowed"),
        };
        Some(status_line(status, reason, ""))
    }
}

fn find_blank_line(buf: &[u8], from: usize) -> Option<usize> {
    let start = from.saturating_sub(3);
    buf[start..]
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .map(|i| start + i + 4)
}

/// Read and parse one CONNECT request head.
pub(crate) async fn read_connect<R: AsyncRead + Unpin>(
    r: &mut R,
) -> Result<ConnectHead, HeadError> {
    let mut buf: Vec<u8> = Vec::with_capacity(512);
    let mut chunk = [0u8; 1024];
    let end = loop {
        let n = r.read(&mut chunk).await.map_err(|_| HeadError::Io)?;
        if n == 0 {
            return Err(HeadError::Closed);
        }
        let before = buf.len();
        buf.extend_from_slice(&chunk[..n]);
        if let Some(end) = find_blank_line(&buf, before) {
            break end;
        }
        if buf.len() >= MAX_HEAD_BYTES {
            return Err(HeadError::TooLarge);
        }
    };
    if end > MAX_HEAD_BYTES {
        return Err(HeadError::TooLarge);
    }

    let mut headers = [httparse::EMPTY_HEADER; MAX_HEADERS];
    let mut req = httparse::Request::new(&mut headers);
    match req.parse(&buf[..end]) {
        Ok(httparse::Status::Complete(_)) => {}
        _ => return Err(HeadError::Malformed),
    }
    if req.method != Some("CONNECT") {
        return Err(HeadError::NotConnect);
    }
    let target = req
        .path
        .and_then(parse_authority)
        .ok_or(HeadError::Malformed)?;
    let login = req
        .headers
        .iter()
        .find(|h| h.name.eq_ignore_ascii_case("proxy-authorization"))
        .and_then(|h| parse_basic(h.value));
    Ok(ConnectHead {
        target,
        login,
        leftover: buf[end..].to_vec(),
    })
}

/// `host:port`, `[v6]:port`. The host keeps no brackets and is lowercase.
fn parse_authority(s: &str) -> Option<Target> {
    let (host, port) = if let Some(rest) = s.strip_prefix('[') {
        let (host, rest) = rest.split_once(']')?;
        let port = rest.strip_prefix(':')?;
        host.parse::<Ipv6Addr>().ok()?;
        (host, port)
    } else {
        let (host, port) = s.rsplit_once(':')?;
        if host.contains(':') {
            return None;
        }
        (host, port)
    };
    // `u16::from_str` accepts a leading `+`: `example.test:+80` is no authority
    if !port.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    target(host, port.parse().ok()?)
}

/// A target with a non-zero port and a host of plausible bytes; the host is lowercased.
fn target(host: &str, port: u16) -> Option<Target> {
    if port == 0
        || host.is_empty()
        || host.len() > MAX_HOST_BYTES
        || !host
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'_' | b':'))
    {
        return None;
    }
    Some(Target {
        host: host.to_ascii_lowercase(),
        port,
    })
}

/// `Basic base64(user:password)`; the password is everything after the first `:`.
fn parse_basic(value: &[u8]) -> Option<Login> {
    let value = std::str::from_utf8(value).ok()?.trim();
    let (scheme, encoded) = value.split_once(' ')?;
    if !scheme.eq_ignore_ascii_case("basic") {
        return None;
    }
    let decoded = STANDARD.decode(encoded.trim()).ok()?;
    let decoded = String::from_utf8(decoded).ok()?;
    let (username, key) = decoded.split_once(':')?;
    Some(Login {
        username: username.to_owned(),
        key: Secret::new(key),
    })
}

fn status_line(status: u16, reason: &str, extra: &str) -> Vec<u8> {
    format!("HTTP/1.1 {status} {reason}\r\n{extra}Content-Length: 0\r\nConnection: close\r\n\r\n")
        .into_bytes()
}

/// `HTTP/1.1 <status> <cause code>`, which the session proxy prints in its dial error.
pub(crate) fn refusal(cause: Cause) -> Vec<u8> {
    let challenge = if cause == Cause::AuthRequired {
        "Proxy-Authenticate: Basic realm=\"proxyx\"\r\n"
    } else {
        ""
    };
    status_line(cause.status(), cause.code(), challenge)
}

/// The `200` that opens the tunnel, with the correlation headers.
pub(crate) fn established(session: &str, exit_ip: IpAddr) -> Vec<u8> {
    format!(
        "HTTP/1.1 200 Connection established\r\nX-ProxyX-Pool-Session: {session}\r\nX-ProxyX-Exit-IP: {exit_ip}\r\n\r\n"
    )
    .into_bytes()
}

// --- SOCKS5 ---

const SOCKS_VERSION: u8 = 5;
const AUTH_VERSION: u8 = 1;
const METHOD_USER_PASS: u8 = 0x02;
const METHOD_NONE_ACCEPTABLE: u8 = 0xff;
const CMD_CONNECT: u8 = 0x01;

/// SOCKS5 reply code for an unsupported command or address type.
pub(crate) const SOCKS_COMMAND_NOT_SUPPORTED: u8 = 0x07;
pub(crate) const SOCKS_ADDRESS_NOT_SUPPORTED: u8 = 0x08;
pub(crate) const SOCKS_SUCCESS: u8 = 0x00;

/// Why a SOCKS5 step failed. The variants that carry a reply code say what to
/// send before closing.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum SocksError {
    Io,
    /// Not SOCKS5, or a malformed message: close without a reply.
    Protocol,
    /// The client offers no username/password method.
    NoMethod,
    /// A request the gateway does not serve, with the reply code.
    Refused(u8),
}

async fn byte<R: AsyncRead + Unpin>(r: &mut R) -> Result<u8, SocksError> {
    r.read_u8().await.map_err(|_| SocksError::Io)
}

async fn bytes<R: AsyncRead + Unpin>(r: &mut R, n: usize) -> Result<Vec<u8>, SocksError> {
    let mut v = vec![0u8; n];
    r.read_exact(&mut v).await.map_err(|_| SocksError::Io)?;
    Ok(v)
}

async fn array<const N: usize, R: AsyncRead + Unpin>(r: &mut R) -> Result<[u8; N], SocksError> {
    let mut a = [0u8; N];
    r.read_exact(&mut a).await.map_err(|_| SocksError::Io)?;
    Ok(a)
}

/// Method selection: the client must offer username/password (`0x02`).
pub(crate) async fn socks_greeting<R: AsyncRead + Unpin>(r: &mut R) -> Result<(), SocksError> {
    if byte(r).await? != SOCKS_VERSION {
        return Err(SocksError::Protocol);
    }
    let n = usize::from(byte(r).await?);
    let methods = bytes(r, n).await?;
    if methods.contains(&METHOD_USER_PASS) {
        Ok(())
    } else {
        Err(SocksError::NoMethod)
    }
}

pub(crate) const SOCKS_SELECT_USER_PASS: [u8; 2] = [SOCKS_VERSION, METHOD_USER_PASS];
pub(crate) const SOCKS_SELECT_NONE: [u8; 2] = [SOCKS_VERSION, METHOD_NONE_ACCEPTABLE];
pub(crate) const SOCKS_AUTH_OK: [u8; 2] = [AUTH_VERSION, 0x00];
pub(crate) const SOCKS_AUTH_FAILED: [u8; 2] = [AUTH_VERSION, 0x01];

/// RFC 1929 username/password message.
pub(crate) async fn socks_login<R: AsyncRead + Unpin>(r: &mut R) -> Result<Login, SocksError> {
    if byte(r).await? != AUTH_VERSION {
        return Err(SocksError::Protocol);
    }
    let n = usize::from(byte(r).await?);
    let username = bytes(r, n).await?;
    let n = usize::from(byte(r).await?);
    let key = bytes(r, n).await?;
    Ok(Login {
        username: String::from_utf8(username).map_err(|_| SocksError::Protocol)?,
        key: Secret::new(String::from_utf8(key).map_err(|_| SocksError::Protocol)?),
    })
}

/// The CONNECT request. Only the `CONNECT` command is served.
pub(crate) async fn socks_request<R: AsyncRead + Unpin>(r: &mut R) -> Result<Target, SocksError> {
    let head: [u8; 4] = array(r).await?;
    if head[0] != SOCKS_VERSION {
        return Err(SocksError::Protocol);
    }
    if head[1] != CMD_CONNECT {
        return Err(SocksError::Refused(SOCKS_COMMAND_NOT_SUPPORTED));
    }
    let host = match head[3] {
        0x01 => Ipv4Addr::from(array::<4, _>(r).await?).to_string(),
        0x03 => {
            let n = usize::from(byte(r).await?);
            let name = bytes(r, n).await?;
            String::from_utf8(name).map_err(|_| SocksError::Refused(SOCKS_ADDRESS_NOT_SUPPORTED))?
        }
        0x04 => Ipv6Addr::from(array::<16, _>(r).await?).to_string(),
        _ => return Err(SocksError::Refused(SOCKS_ADDRESS_NOT_SUPPORTED)),
    };
    let port = u16::from_be_bytes(array(r).await?);
    target(&host, port).ok_or(SocksError::Refused(SOCKS_ADDRESS_NOT_SUPPORTED))
}

/// A reply with a zero bound address (the client does not use it for CONNECT).
pub(crate) fn socks_reply(code: u8) -> [u8; 10] {
    [SOCKS_VERSION, code, 0, 0x01, 0, 0, 0, 0, 0, 0]
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn head(input: &[u8]) -> Result<ConnectHead, HeadError> {
        let mut r = input;
        read_connect(&mut r).await
    }

    fn basic(user: &str, key: &str) -> String {
        format!(
            "Proxy-Authorization: Basic {}\r\n",
            STANDARD.encode(format!("{user}:{key}"))
        )
    }

    #[tokio::test]
    async fn connect_head_yields_target_login_and_pipelined_bytes() {
        let req = format!(
            "CONNECT Example.COM:443 HTTP/1.1\r\nHost: x\r\n{}\r\nHELLO",
            basic("px-kind-static", "k:ey")
        );
        let h = head(req.as_bytes()).await.expect("valid head");
        assert_eq!(h.target.to_string(), "example.com:443");
        let login = h.login.expect("login");
        assert_eq!(login.username, "px-kind-static");
        // the key is everything after the first colon
        assert_eq!(login.key.expose(), "k:ey");
        assert_eq!(h.leftover, b"HELLO");
    }

    #[tokio::test]
    async fn head_without_usable_credentials_has_no_login() {
        let none = head(b"CONNECT a.test:443 HTTP/1.1\r\n\r\n")
            .await
            .expect("head");
        assert!(none.login.is_none());
        for value in ["Bearer abc", "Basic !!!", "Basic Zm9v"] {
            let req =
                format!("CONNECT a.test:443 HTTP/1.1\r\nProxy-Authorization: {value}\r\n\r\n");
            let h = head(req.as_bytes()).await.expect("head");
            assert!(h.login.is_none(), "{value}");
        }
    }

    #[tokio::test]
    async fn head_errors_are_classified() {
        assert_eq!(
            head(b"GET / HTTP/1.1\r\n\r\n").await.err(),
            Some(HeadError::NotConnect)
        );
        assert_eq!(
            head(b"CONNECT nonsense HTTP/1.1\r\n\r\n").await.err(),
            Some(HeadError::Malformed)
        );
        assert_eq!(
            head(b"CONNECT a.test:0 HTTP/1.1\r\n\r\n").await.err(),
            Some(HeadError::Malformed)
        );
        assert_eq!(
            head(b"CONNECT a.test:443 HTT").await.err(),
            Some(HeadError::Closed)
        );
        let mut big = b"CONNECT a.test:443 HTTP/1.1\r\n".to_vec();
        big.extend(std::iter::repeat_n(b'a', MAX_HEAD_BYTES));
        assert_eq!(head(&big).await.err(), Some(HeadError::TooLarge));
    }

    #[test]
    fn authority_parsing_covers_names_and_ip_literals() {
        let t = |s| parse_authority(s).map(|t| (t.host, t.port));
        assert_eq!(t("a.b:80"), Some(("a.b".into(), 80)));
        assert_eq!(t("[::1]:443"), Some(("::1".into(), 443)));
        assert_eq!(t("10.0.0.1:8080"), Some(("10.0.0.1".into(), 8080)));
        for bad in [
            "a.b",
            "a.b:",
            ":80",
            "a b:80",
            "[::1]443",
            "[nope]:80",
            "::1:80",
            "a.b:65536",
            "a.b:+80",
            "[::1]:+443",
        ] {
            assert_eq!(t(bad), None, "{bad}");
        }
    }

    #[test]
    fn refusal_names_the_cause_and_asks_for_credentials_on_407() {
        let text = |c| String::from_utf8(refusal(c)).expect("ascii");
        assert!(text(Cause::NoHealthyIp).starts_with("HTTP/1.1 503 no_healthy_ip\r\n"));
        assert!(text(Cause::AuthRequired).contains("Proxy-Authenticate: Basic"));
        assert!(!text(Cause::OptionDenied).contains("Proxy-Authenticate"));
    }

    #[test]
    fn established_carries_both_correlation_headers() {
        let text = String::from_utf8(established("abc", "203.0.113.9".parse().expect("ip")))
            .expect("ascii");
        assert!(text.starts_with("HTTP/1.1 200 "));
        assert!(text.contains("X-ProxyX-Pool-Session: abc\r\n"));
        assert!(text.contains("X-ProxyX-Exit-IP: 203.0.113.9\r\n"));
        assert!(text.ends_with("\r\n\r\n"));
    }

    #[tokio::test]
    async fn socks_handshake_messages_parse() {
        let mut r: &[u8] = &[5, 2, 0, 2];
        assert_eq!(socks_greeting(&mut r).await, Ok(()));
        let mut r: &[u8] = &[5, 1, 0];
        assert_eq!(socks_greeting(&mut r).await, Err(SocksError::NoMethod));
        let mut r: &[u8] = &[4, 1, 2];
        assert_eq!(socks_greeting(&mut r).await, Err(SocksError::Protocol));

        let mut r: &[u8] = &[1, 3, b'a', b'r', b'g', 2, b'k', b'1'];
        let login = socks_login(&mut r).await.expect("login");
        assert_eq!((login.username.as_str(), login.key.expose()), ("arg", "k1"));

        let mut domain = vec![5, 1, 0, 3, 6];
        domain.extend_from_slice(b"A.test");
        domain.extend_from_slice(&[0x01, 0xbb]);
        let mut r = domain.as_slice();
        let t = socks_request(&mut r).await.expect("target");
        assert_eq!((t.host.as_str(), t.port), ("a.test", 443));

        let mut v6 = vec![5, 1, 0, 4];
        v6.extend_from_slice(&Ipv6Addr::LOCALHOST.octets());
        v6.extend_from_slice(&[0, 80]);
        let mut r = v6.as_slice();
        let t = socks_request(&mut r).await.expect("target");
        assert_eq!((t.host.as_str(), t.port), ("::1", 80));
    }

    #[tokio::test]
    async fn socks_request_refuses_other_commands_and_address_types() {
        let mut r: &[u8] = &[5, 2, 0, 1, 1, 1, 1, 1, 0, 80];
        assert_eq!(
            socks_request(&mut r).await.err(),
            Some(SocksError::Refused(SOCKS_COMMAND_NOT_SUPPORTED))
        );
        let mut r: &[u8] = &[5, 1, 0, 9, 1, 1];
        assert_eq!(
            socks_request(&mut r).await.err(),
            Some(SocksError::Refused(SOCKS_ADDRESS_NOT_SUPPORTED))
        );
        let mut r: &[u8] = &[5, 1, 0, 1, 1, 1, 1, 1, 0, 0];
        assert_eq!(
            socks_request(&mut r).await.err(),
            Some(SocksError::Refused(SOCKS_ADDRESS_NOT_SUPPORTED))
        );
    }
}
