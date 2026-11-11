//! Inbound HTTP CONNECT and probe-only absolute-form requests, the SOCKS5
//! handshake (RFC 1928, RFC 1929), and the replies for all three.
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
use tokio::io::{self, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader};

/// Largest inbound HTTP request head ProxyX reads, like the session proxy's own cap on
/// proxy replies (`egress.rs`).
const MAX_HEAD_BYTES: usize = 8 * 1024;

const MAX_HEADERS: usize = 32;
const MAX_HOST_BYTES: usize = 253;

/// A CONNECT or probe HTTP request after parsing.
#[derive(Debug)]
pub(crate) struct ConnectHead {
    pub target: Target,
    /// `None` when the request has no usable `Proxy-Authorization: Basic`.
    pub login: Option<Login>,
    /// Bytes after the blank line: unrestricted tunnel data for CONNECT,
    /// but passed only through the framed body parser for probe HTTP.
    pub leftover: Vec<u8>,
    /// Present only for a probe listener's absolute-form HTTP exchange.
    pub http: Option<HttpRequest>,
}

/// Proxy username (the options) and password (the org key).
#[derive(Debug)]
pub(crate) struct Login {
    pub username: String,
    pub key: Secret,
}

/// One HTTP exchange, never an unrestricted client-to-origin tunnel.
#[derive(Debug)]
pub(crate) struct HttpRequest {
    pub head: Vec<u8>,
    pub body: HttpBody,
    pub head_only: bool,
}

#[derive(Debug, Clone, Copy)]
pub(crate) enum HttpBody {
    Length(u64),
    Chunked,
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
    allow_http: bool,
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
    let (target, http) = if req.method == Some("CONNECT") {
        let target = req
            .path
            .and_then(parse_authority)
            .ok_or(HeadError::Malformed)?;
        (target, None)
    } else if allow_http {
        let (target, http) = parse_http(&req)?;
        (target, Some(http))
    } else {
        return Err(HeadError::NotConnect);
    };
    let login = req
        .headers
        .iter()
        .find(|h| h.name.eq_ignore_ascii_case("proxy-authorization"))
        .and_then(|h| parse_basic(h.value));
    Ok(ConnectHead {
        target,
        login,
        leftover: buf[end..].to_vec(),
        http,
    })
}

/// HTTP URLs are parsed without normalization that could hide userinfo or bad
/// authority bytes from policy. HTTPS continues to use CONNECT.
fn absolute_target(url: &str) -> Result<(Target, &str), HeadError> {
    let rest = url
        .get(..7)
        .filter(|scheme| scheme.eq_ignore_ascii_case("http://"))
        .and_then(|_| url.get(7..))
        .ok_or(HeadError::Malformed)?;
    if rest
        .bytes()
        .any(|b| b <= b' ' || b >= 127 || matches!(b, b'\\' | b'#'))
    {
        return Err(HeadError::Malformed);
    }
    let end = rest.find(['/', '?']).unwrap_or(rest.len());
    let authority = &rest[..end];
    let target = http_authority(authority).ok_or(HeadError::Malformed)?;
    Ok((target, &rest[end..]))
}

fn http_authority(authority: &str) -> Option<Target> {
    if authority.starts_with('[') {
        if authority.ends_with(']') {
            let host = &authority[1..authority.len() - 1];
            host.parse::<Ipv6Addr>().ok()?;
            target(host, 80)
        } else {
            parse_authority(authority)
        }
    } else if authority.contains(':') {
        parse_authority(authority)
    } else {
        target(authority, 80)
    }
}

fn hop_header(name: &str, headers: &[httparse::Header<'_>]) -> bool {
    [
        "connection",
        "proxy-connection",
        "proxy-authorization",
        "proxy-authenticate",
        "keep-alive",
        "te",
        "trailer",
        "transfer-encoding",
        "upgrade",
    ]
    .iter()
    .any(|hop| name.eq_ignore_ascii_case(hop))
        || connection_header(name, headers)
}

fn connection_header(name: &str, headers: &[httparse::Header<'_>]) -> bool {
    headers
        .iter()
        .filter(|h| h.name.eq_ignore_ascii_case("connection"))
        .any(|h| {
            h.value.split(|b| *b == b',').any(|token| {
                std::str::from_utf8(token)
                    .is_ok_and(|token| token.trim().eq_ignore_ascii_case(name))
            })
        })
}

fn unique_header<'a>(
    headers: &[httparse::Header<'a>],
    name: &str,
) -> Result<Option<&'a [u8]>, HeadError> {
    let mut values = headers.iter().filter(|h| h.name.eq_ignore_ascii_case(name));
    let value = values.next().map(|h| h.value);
    if values.next().is_some() {
        return Err(HeadError::Malformed);
    }
    Ok(value)
}

/// Framing shared by both directions. Absence means no request body or a
/// close-delimited response, depending on the message's role.
fn http_framing(headers: &[httparse::Header<'_>]) -> Result<Option<HttpBody>, HeadError> {
    if ["content-length", "transfer-encoding"]
        .iter()
        .any(|name| connection_header(name, headers))
    {
        return Err(HeadError::Malformed);
    }
    match (
        unique_header(headers, "content-length")?,
        unique_header(headers, "transfer-encoding")?,
    ) {
        (Some(_), Some(_)) => Err(HeadError::Malformed),
        (Some(value), None) => {
            if value.is_empty() || !value.iter().all(u8::is_ascii_digit) {
                return Err(HeadError::Malformed);
            }
            let n = std::str::from_utf8(value)
                .ok()
                .and_then(|s| s.parse().ok())
                .ok_or(HeadError::Malformed)?;
            Ok(Some(HttpBody::Length(n)))
        }
        (None, Some(value)) if value.eq_ignore_ascii_case(b"chunked") => {
            Ok(Some(HttpBody::Chunked))
        }
        (None, Some(_)) => Err(HeadError::Malformed),
        (None, None) => Ok(None),
    }
}

fn parse_http(req: &httparse::Request<'_, '_>) -> Result<(Target, HttpRequest), HeadError> {
    let (target, path) = absolute_target(req.path.ok_or(HeadError::Malformed)?)?;
    let host = unique_header(req.headers, "host")?
        .and_then(|v| std::str::from_utf8(v).ok())
        .and_then(http_authority)
        .ok_or(HeadError::Malformed)?;
    if host.host != target.host || host.port != target.port {
        return Err(HeadError::Malformed);
    }
    unique_header(req.headers, "proxy-authorization")?;
    let body = http_framing(req.headers)?.unwrap_or(HttpBody::Length(0));
    // Connection-nominated framing or authority would change what the origin
    // parses. Refuse rather than silently removing those fields.
    if [
        "host",
        "content-length",
        "transfer-encoding",
        "proxy-authorization",
    ]
    .iter()
    .any(|name| connection_header(name, req.headers))
    {
        return Err(HeadError::Malformed);
    }
    let mut head = Vec::with_capacity(512);
    head.extend_from_slice(req.method.ok_or(HeadError::Malformed)?.as_bytes());
    head.push(b' ');
    if !path.starts_with('/') {
        head.push(b'/');
    }
    head.extend_from_slice(path.as_bytes());
    head.extend_from_slice(b" HTTP/1.1\r\n");
    for header in req.headers.iter() {
        if !hop_header(header.name, req.headers) {
            head.extend_from_slice(header.name.as_bytes());
            head.extend_from_slice(b": ");
            head.extend_from_slice(header.value);
            head.extend_from_slice(b"\r\n");
        }
    }
    if matches!(body, HttpBody::Chunked) {
        head.extend_from_slice(b"Transfer-Encoding: chunked\r\n");
    }
    head.extend_from_slice(b"Connection: close\r\n\r\n");
    Ok((
        target,
        HttpRequest {
            head,
            body,
            head_only: req.method == Some("HEAD"),
        },
    ))
}

fn invalid_http() -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::InvalidData, "invalid HTTP exchange")
}

async fn copy_exact<R, W>(r: &mut R, w: &mut W, n: u64) -> io::Result<()>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    if io::copy(&mut r.take(n), w).await? != n {
        return Err(std::io::ErrorKind::UnexpectedEof.into());
    }
    Ok(())
}

async fn copy_http_body<R, W>(r: &mut R, w: &mut W, body: HttpBody) -> io::Result<()>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    if let HttpBody::Length(n) = body {
        return copy_exact(r, w, n).await;
    }
    let mut line = Vec::with_capacity(64);
    loop {
        line.clear();
        while !line.ends_with(b"\r\n") {
            if line.len() >= 1024 {
                return Err(invalid_http());
            }
            line.push(r.read_u8().await?);
        }
        let size = line[..line.len() - 2]
            .split(|b| *b == b';')
            .next()
            .ok_or_else(invalid_http)?;
        if size.is_empty()
            || !size.iter().all(u8::is_ascii_hexdigit)
            || line[..line.len() - 2]
                .iter()
                .any(|b| *b < b' ' || *b >= 127)
        {
            return Err(invalid_http());
        }
        let n = u64::from_str_radix(std::str::from_utf8(size).map_err(|_| invalid_http())?, 16)
            .map_err(|_| invalid_http())?;
        if n == 0 {
            // Do not forward trailers: they can contain credentials or
            // framing fields. Nothing after the terminal chunk goes upstream.
            line.clear();
            loop {
                let start = line.len();
                while !line.ends_with(b"\r\n") || line.len() == start {
                    if line.len() >= MAX_HEAD_BYTES {
                        return Err(invalid_http());
                    }
                    line.push(r.read_u8().await?);
                }
                if line.len() - start == 2 {
                    break;
                }
            }
            let mut trailers = [httparse::EMPTY_HEADER; MAX_HEADERS];
            if !matches!(
                httparse::parse_headers(&line, &mut trailers),
                Ok(httparse::Status::Complete(_))
            ) {
                return Err(invalid_http());
            }
            return w.write_all(b"0\r\n\r\n").await;
        }
        // Strip extensions, and write only the validated size.
        w.write_all(size).await?;
        w.write_all(b"\r\n").await?;
        copy_exact(r, w, n).await?;
        let mut crlf = [0; 2];
        r.read_exact(&mut crlf).await?;
        if crlf != *b"\r\n" {
            return Err(invalid_http());
        }
        w.write_all(&crlf).await?;
    }
}

async fn copy_http_response<R, W>(
    r: &mut R,
    w: &mut W,
    session: &str,
    exit_ip: IpAddr,
    head_only: bool,
) -> io::Result<()>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut r = BufReader::new(r);
    let mut head = Vec::with_capacity(512);
    loop {
        head.clear();
        while !head.ends_with(b"\r\n\r\n") {
            if head.len() >= MAX_HEAD_BYTES {
                return Err(invalid_http());
            }
            head.push(r.read_u8().await?);
        }
        let mut headers = [httparse::EMPTY_HEADER; MAX_HEADERS];
        let mut response = httparse::Response::new(&mut headers);
        if !matches!(response.parse(&head), Ok(httparse::Status::Complete(_))) {
            return Err(invalid_http());
        }
        let status = response.code.ok_or_else(invalid_http)?;
        let framing = http_framing(response.headers).map_err(|_| invalid_http())?;
        if !(100..600).contains(&status)
            || status == 101
            || ((status < 200 || status == 204) && framing.is_some())
        {
            return Err(invalid_http());
        }
        let first = head
            .windows(2)
            .position(|s| s == b"\r\n")
            .ok_or_else(invalid_http)?;
        w.write_all(&head[..first + 2]).await?;
        for header in response.headers.iter() {
            // Gateway owns correlation. Never accept an origin's spoofed IDs.
            if !header.name.eq_ignore_ascii_case("x-proxyx-pool-session")
                && !header.name.eq_ignore_ascii_case("x-proxyx-exit-ip")
                && !hop_header(header.name, response.headers)
            {
                w.write_all(header.name.as_bytes()).await?;
                w.write_all(b": ").await?;
                w.write_all(header.value).await?;
                w.write_all(b"\r\n").await?;
            }
        }
        if matches!(framing, Some(HttpBody::Chunked)) {
            w.write_all(b"Transfer-Encoding: chunked\r\n").await?;
        }
        if status >= 200 {
            let correlation = format!(
                "X-ProxyX-Pool-Session: {session}\r\nX-ProxyX-Exit-IP: {exit_ip}\r\nConnection: close\r\n\r\n"
            );
            w.write_all(correlation.as_bytes()).await?;
            if !head_only && !matches!(status, 204 | 304) {
                if let Some(body) = framing {
                    copy_http_body(&mut r, w, body).await?;
                } else {
                    io::copy(&mut r, w).await?;
                }
            }
            return w.shutdown().await;
        }
        w.write_all(b"\r\n").await?;
        w.flush().await?;
    }
}

/// Adapt one framed request to the ordinary metered relay. The request half
/// stays open until the response ends, without reading any subsequent request.
pub(crate) async fn http_exchange<S, U>(
    client: S,
    channel: U,
    leftover: Vec<u8>,
    body: HttpBody,
    head_only: bool,
    session: &str,
    exit_ip: IpAddr,
) -> io::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
    U: AsyncRead + AsyncWrite + Unpin,
{
    let (client_r, mut client_w) = io::split(client);
    let (mut channel_r, mut channel_w) = io::split(channel);
    let mut request = BufReader::new(std::io::Cursor::new(leftover).chain(client_r));
    let send = async {
        copy_http_body(&mut request, &mut channel_w, body).await?;
        channel_w.flush().await?;
        std::future::pending::<io::Result<()>>().await
    };
    tokio::select! {
        result = send => result,
        result = copy_http_response(&mut channel_r, &mut client_w, session, exit_ip, head_only) => result,
    }
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

    async fn probe_head(input: &[u8]) -> Result<ConnectHead, HeadError> {
        read_connect(&mut &input[..], true).await
    }

    #[tokio::test]
    async fn probe_http_rewrites_absolute_form_and_strips_proxy_and_hop_headers() {
        let request = format!(
            "GET http://Page.Stub?x=1 HTTP/1.1\r\nHost: page.stub:80\r\n{}\
             Connection: keep-alive, X-Remove\r\nX-Remove: secret\r\n\
             Proxy-Connection: keep-alive\r\nTE: trailers\r\nUpgrade: websocket\r\n\
             Accept: text/html\r\n\r\n",
            basic("px", "signed-token"),
        );
        let parsed = probe_head(request.as_bytes()).await.expect("HTTP head");
        assert_eq!(parsed.target.to_string(), "page.stub:80");
        assert_eq!(parsed.login.expect("login").key.expose(), "signed-token");
        let rewritten = String::from_utf8(parsed.http.expect("HTTP").head).expect("ASCII");
        assert_eq!(
            rewritten,
            "GET /?x=1 HTTP/1.1\r\nHost: page.stub:80\r\nAccept: text/html\r\nConnection: close\r\n\r\n",
        );
        assert!(!rewritten.contains("signed-token"));
    }

    #[tokio::test]
    async fn probe_http_refuses_bad_urls_authorities_and_ambiguous_framing() {
        for url in [
            "/",
            "https://page.stub/",
            "http://user:pass@page.stub/",
            "http://page.stub/#fragment",
            "http://page.stub:0/",
            "http://page.stub:+80/",
            "http://page.stub\\other/",
            "http:///missing",
            "http://[bad]/",
        ] {
            let request = format!("GET {url} HTTP/1.1\r\nHost: page.stub\r\n\r\n");
            assert_eq!(
                probe_head(request.as_bytes()).await.err(),
                Some(HeadError::Malformed),
                "{url}"
            );
        }
        for headers in [
            "Host: other.stub\r\n",
            "Host: page.stub:81\r\n",
            "Host: page.stub\r\nHost: page.stub\r\n",
            "Host: page.stub\r\nContent-Length: 0\r\nContent-Length: 0\r\n",
            "Host: page.stub\r\nContent-Length: 0, 0\r\n",
            "Host: page.stub\r\nContent-Length: +1\r\n",
            "Host: page.stub\r\nContent-Length: 18446744073709551616\r\n",
            "Host: page.stub\r\nContent-Length: 1\r\nTransfer-Encoding: chunked\r\n",
            "Host: page.stub\r\nTransfer-Encoding: gzip, chunked\r\n",
            "Host: page.stub\r\nTransfer-Encoding: chunked\r\nTransfer-Encoding: chunked\r\n",
            "Host: page.stub\r\nConnection: content-length\r\nContent-Length: 1\r\n",
            "Host: page.stub\r\nProxy-Authorization: Basic eDph\r\nProxy-Authorization: Basic eDpi\r\n",
            "",
        ] {
            let request = format!("POST http://page.stub/ HTTP/1.1\r\n{headers}\r\n");
            assert_eq!(
                probe_head(request.as_bytes()).await.err(),
                Some(HeadError::Malformed),
                "{headers}"
            );
        }
    }

    #[tokio::test]
    async fn probe_http_keeps_existing_head_and_header_limits() {
        let mut request = b"GET http://page.stub/ HTTP/1.1\r\nHost: page.stub\r\nX: ".to_vec();
        request.extend(std::iter::repeat_n(b'x', MAX_HEAD_BYTES));
        request.extend_from_slice(b"\r\n\r\n");
        assert_eq!(probe_head(&request).await.err(), Some(HeadError::TooLarge));
        let request = format!(
            "GET http://page.stub/ HTTP/1.1\r\nHost: page.stub\r\n{}\r\n",
            "X: y\r\n".repeat(MAX_HEADERS),
        );
        assert_eq!(
            probe_head(request.as_bytes()).await.err(),
            Some(HeadError::Malformed)
        );
    }

    #[tokio::test]
    async fn framed_bodies_never_forward_a_later_request_or_chunk_trailers() {
        let pipeline = b"GET http://other.stub/ HTTP/1.1\r\nProxy-Authorization: secret\r\n\r\n";
        let mut fixed = b"body".to_vec();
        fixed.extend_from_slice(pipeline);
        let mut input = fixed.as_slice();
        let mut output = Vec::new();
        copy_http_body(&mut input, &mut output, HttpBody::Length(4))
            .await
            .expect("body");
        assert_eq!(output, b"body");
        assert_eq!(input, pipeline);

        let mut chunked =
            b"4;discard=extension\r\nbody\r\n0\r\nProxy-Authorization: secret\r\n\r\n".to_vec();
        chunked.extend_from_slice(pipeline);
        let mut input = chunked.as_slice();
        output.clear();
        copy_http_body(&mut input, &mut output, HttpBody::Chunked)
            .await
            .expect("chunks");
        assert_eq!(output, b"4\r\nbody\r\n0\r\n\r\n");
        assert_eq!(input, pipeline);
        for malformed in [
            &b"z\r\n"[..],
            &b"4\r\nabc"[..],
            &b"1\r\naXX"[..],
            &b"0\r\nNot a trailer\r\n\r\n"[..],
            &b"0\r\n"[..],
        ] {
            let mut input = malformed;
            assert!(
                copy_http_body(&mut input, &mut Vec::new(), HttpBody::Chunked)
                    .await
                    .is_err()
            );
        }
        let mut input = &b"short"[..];
        assert!(
            copy_http_body(&mut input, &mut Vec::new(), HttpBody::Length(6))
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn http_response_keeps_informational_replies_and_owns_correlation() {
        let mut response = &b"HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 200 OK\r\n\
            Content-Length: 4\r\nX-ProxyX-Pool-Session: fake\r\n\
            X-ProxyX-Exit-IP: 1.2.3.4\r\nConnection: keep-alive\r\n\r\npage"[..];
        let mut output = Vec::new();
        copy_http_response(
            &mut response,
            &mut output,
            "real",
            "203.0.113.8".parse().expect("IP"),
            false,
        )
        .await
        .expect("response");
        let output = String::from_utf8(output).expect("ASCII");
        assert!(output.starts_with("HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 200 OK\r\n"));
        assert!(output.contains("X-ProxyX-Pool-Session: real\r\n"));
        assert!(output.contains("X-ProxyX-Exit-IP: 203.0.113.8\r\n"));
        assert!(!output.contains("fake"));
        assert!(!output.contains("1.2.3.4"));
        assert!(output.ends_with("Connection: close\r\n\r\npage"));
    }

    #[tokio::test]
    async fn http_responses_stop_at_one_framed_body_without_waiting_for_eof() {
        let (mut upstream, mut reader) = io::duplex(1024);
        upstream.write_all(
            b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\npageHTTP/1.1 200 leaked\r\n\r\nsecret",
        ).await.expect("upstream response");
        let mut output = Vec::new();
        tokio::time::timeout(
            std::time::Duration::from_secs(1),
            copy_http_response(
                &mut reader,
                &mut output,
                "real",
                "203.0.113.8".parse().expect("IP"),
                false,
            ),
        )
        .await
        .expect("must not wait for upstream close")
        .expect("response");
        let output = String::from_utf8(output).expect("ASCII");
        assert_eq!(output.split_once("\r\n\r\n").expect("head").1, "page");
        assert!(!output.contains("secret"));
    }

    #[tokio::test]
    async fn head_204_and_304_responses_never_forward_a_body() {
        for (method, status, framing) in [
            ("HEAD", "200 OK", "Content-Length: 999\r\n"),
            ("HEAD", "200 OK", "Transfer-Encoding: chunked\r\n"),
            ("GET", "204 No Content", ""),
            ("GET", "304 Not Modified", "Content-Length: 999\r\n"),
        ] {
            let request = format!("{method} http://page.stub/ HTTP/1.1\r\nHost: page.stub\r\n\r\n");
            let parsed = probe_head(request.as_bytes()).await.expect("request");
            let head_only = parsed.http.expect("HTTP request").head_only;
            assert_eq!(head_only, method == "HEAD");
            let response = format!("HTTP/1.1 {status}\r\n{framing}\r\nnever-forward");
            let mut input = response.as_bytes();
            let mut output = Vec::new();
            copy_http_response(
                &mut input,
                &mut output,
                "real",
                "203.0.113.8".parse().expect("IP"),
                head_only,
            )
            .await
            .expect("bodyless response");
            assert!(output.ends_with(b"\r\n\r\n"), "{status}");
            assert!(
                !String::from_utf8(output)
                    .expect("ASCII")
                    .contains("never-forward")
            );
        }
    }

    #[tokio::test]
    async fn response_chunk_trailers_and_connection_nominated_fields_cannot_leak() {
        let mut input = &b"HTTP/1.1 200 OK\r\nTransfer-Encoding: Chunked\r\n\
            Connection: keep-alive, X-Remove\r\nX-Remove: hop-secret\r\n\
            Proxy-Authorization: proxy-secret\r\nTrailer: X-ProxyX-Pool-Session\r\n\r\n\
            4;extension=discard\r\npage\r\n0\r\nX-ProxyX-Pool-Session: fake-session\r\n\
            X-ProxyX-Exit-IP: fake-ip\r\nProxy-Authorization: trailer-secret\r\n\r\n\
            HTTP/1.1 200 leaked\r\n\r\nlater-secret"[..];
        let mut output = Vec::new();
        copy_http_response(
            &mut input,
            &mut output,
            "real",
            "203.0.113.8".parse().expect("IP"),
            false,
        )
        .await
        .expect("chunked response");
        let output = String::from_utf8(output).expect("ASCII");
        assert!(output.contains("Transfer-Encoding: chunked\r\n"));
        assert_eq!(output.matches("X-ProxyX-Pool-Session: ").count(), 1);
        assert_eq!(output.matches("X-ProxyX-Exit-IP: ").count(), 1);
        assert_eq!(
            output.split_once("\r\n\r\n").expect("head").1,
            "4\r\npage\r\n0\r\n\r\n"
        );
        for forbidden in [
            "X-Remove",
            "Proxy-Authorization",
            "Trailer:",
            "secret",
            "fake",
            "extension",
        ] {
            assert!(!output.contains(forbidden), "{forbidden}");
        }
    }

    #[tokio::test]
    async fn response_framing_errors_are_rejected_before_any_header_is_emitted() {
        for (status, headers) in [
            ("200 OK", "Content-Length: 0\r\nContent-Length: 0\r\n"),
            ("200 OK", "Content-Length: 0, 0\r\n"),
            ("200 OK", "Content-Length: +1\r\n"),
            (
                "200 OK",
                "Content-Length: 0\r\nTransfer-Encoding: chunked\r\n",
            ),
            (
                "200 OK",
                "Transfer-Encoding: chunked\r\nTransfer-Encoding: chunked\r\n",
            ),
            ("200 OK", "Transfer-Encoding: gzip, chunked\r\n"),
            (
                "200 OK",
                "Content-Length: 0\r\nConnection: content-length\r\n",
            ),
            (
                "200 OK",
                "Transfer-Encoding: chunked\r\nConnection: transfer-encoding\r\n",
            ),
            ("204 No Content", "Content-Length: 0\r\n"),
            ("100 Continue", "Content-Length: 0\r\n"),
            ("101 Switching Protocols", ""),
        ] {
            let response = format!("HTTP/1.1 {status}\r\n{headers}\r\n");
            let mut input = response.as_bytes();
            let mut output = Vec::new();
            assert!(
                copy_http_response(
                    &mut input,
                    &mut output,
                    "real",
                    "203.0.113.8".parse().expect("IP"),
                    false,
                )
                .await
                .is_err(),
                "{status} {headers}"
            );
            assert!(
                output.is_empty(),
                "unvalidated headers were emitted: {headers}"
            );
        }
    }

    async fn head(input: &[u8]) -> Result<ConnectHead, HeadError> {
        let mut r = input;
        read_connect(&mut r, false).await
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
