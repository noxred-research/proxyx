use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::AtomicBool;
use std::time::Duration;

use anyhow::{Context, Result};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::time::timeout;
use tokio_util::sync::CancellationToken;
use tracing::{debug, info, warn};
use uuid::Uuid;

use super::common::{
    ConnOutcome, MAX_HEADER_BYTES, PROXY_ERROR_HEADER, UpGuard, find_double_crlf, refuse_over_limit,
};
use crate::breaker::BreakerOpen;
use crate::context::{ProxyContext, Refusal};
use crate::egress::{DialTimedOut, DnsLookupFailed};
use crate::mitm::{MitmParams, PrefixedStream};
use crate::ratelimit::OrgRateLimit;
use crate::state::{AuthError, AuthResult, SessionLookup};

pub async fn serve(
    addr: SocketAddr,
    ctx: Arc<ProxyContext>,
    up: Arc<AtomicBool>,
    shutdown: CancellationToken,
) -> Result<()> {
    let listener = TcpListener::bind(addr)
        .await
        .with_context(|| format!("bind {}", addr))?;

    info!(%addr, "SOCKS5 proxy listening");

    let _up = UpGuard::new(&up);
    loop {
        let (stream, peer) = tokio::select! {
            result = listener.accept() => {
                match result {
                    Ok(pair) => pair,
                    Err(e) => {
                        warn!(error = %e, "accept error on SOCKS5 listener; backing off");
                        tokio::time::sleep(Duration::from_millis(50)).await;
                        continue;
                    }
                }
            }
            _ = shutdown.cancelled() => {
                info!("SOCKS5 listener shutting down");
                return Ok(());
            }
        };

        let ctx = ctx.clone();
        let slot = match ctx.admit(&stream) {
            Ok(slot) => slot,
            Err(Refusal::LimitReached) => {
                refuse_over_limit(stream, "socks5", false);
                continue;
            }
            Err(Refusal::Closed) => break, // semaphore closed — shutting down
        };

        tokio::spawn(async move {
            let outcome = match handle_socks5(stream, peer, ctx).await {
                Ok(outcome) => outcome.label(),
                Err(e) => {
                    debug!(%peer, error=?e, "SOCKS5 connection ended with error");
                    "error"
                }
            };
            common::metrics::PROXY_CONNECTIONS_TOTAL
                .with_label_values(&[outcome, "socks5"])
                .inc();
            drop(slot);
        });
    }
    Ok(())
}

const SOCKS5_VERSION: u8 = 0x05;
const AUTH_VERSION: u8 = 0x01;
const AUTH_USERNAME_PASSWORD: u8 = 0x02;
const CMD_CONNECT: u8 = 0x01;
const ATYP_IPV4: u8 = 0x01;
const ATYP_DOMAIN: u8 = 0x03;
const ATYP_IPV6: u8 = 0x04;

/// SOCKS5 reply codes.
const REP_SUCCEEDED: u8 = 0x00;
const REP_COMMAND_NOT_SUPPORTED: u8 = 0x07;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum TunnelProtocol {
    Http,
    Tls,
    Opaque,
}

const HTTP_METHODS: &[&[u8]] = &[
    b"GET ",
    b"POST ",
    b"PUT ",
    b"PATCH ",
    b"DELETE ",
    b"HEAD ",
    b"OPTIONS ",
    b"TRACE ",
    b"CONNECT ",
    b"PRI ",
];

fn classify_tunnel_prefix(prefix: &[u8]) -> Option<TunnelProtocol> {
    if prefix.first() == Some(&0x16) {
        return Some(TunnelProtocol::Tls);
    }
    if HTTP_METHODS.iter().any(|method| prefix.starts_with(method)) {
        return Some(TunnelProtocol::Http);
    }
    if HTTP_METHODS.iter().any(|method| method.starts_with(prefix)) {
        return None;
    }
    Some(TunnelProtocol::Opaque)
}

async fn sniff_tunnel_protocol(
    stream: &mut TcpStream,
    handshake_timeout: Duration,
) -> Result<(TunnelProtocol, Vec<u8>)> {
    let mut prefix = Vec::with_capacity(16);
    let protocol = timeout(handshake_timeout, async {
        loop {
            if let Some(protocol) = classify_tunnel_prefix(&prefix) {
                return Ok::<TunnelProtocol, std::io::Error>(protocol);
            }
            let mut byte = [0u8; 1];
            if stream.read(&mut byte).await? == 0 {
                return Ok(TunnelProtocol::Opaque);
            }
            prefix.push(byte[0]);
            if prefix.len() == prefix.capacity() {
                return Ok(TunnelProtocol::Opaque);
            }
        }
    })
    .await
    .unwrap_or(Ok(TunnelProtocol::Opaque))?;
    Ok((protocol, prefix))
}

/// Send a SOCKS5 reply with the given status, bound to 0.0.0.0:0.
async fn write_reply(stream: &mut TcpStream, rep: u8) -> Result<()> {
    //   VER  REP  RSV  ATYP  BND.ADDR(4)   BND.PORT(2)
    let reply = [0x05, rep, 0x00, ATYP_IPV4, 0, 0, 0, 0, 0, 0];
    stream.write_all(&reply).await?;
    Ok(())
}

/// Why a tunnel could not be set up. The socks5 listener has already replied
/// `0x00`, so it reports these in band as an HTTP response (`report_failure`).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum TunnelFailure {
    SessionNotFound,
    SessionBackendUnavailable,
    UpstreamRefused,
    UpstreamDns,
    UpstreamError,
    UpstreamTimeout,
    /// The upstream's circuit breaker is open: the dial failed fast.
    UpstreamUnavailable,
}

impl TunnelFailure {
    /// `via_egress_proxy`: the dial went through the session's egress proxy,
    /// so a refusal or lookup failure may be the proxy's, not the target's.
    fn from_dial_error(e: &anyhow::Error, via_egress_proxy: bool) -> Self {
        if e.downcast_ref::<BreakerOpen>().is_some() {
            return Self::UpstreamUnavailable;
        }
        if e.downcast_ref::<DialTimedOut>().is_some() {
            return Self::UpstreamTimeout;
        }
        if via_egress_proxy {
            return Self::UpstreamError;
        }
        if e.downcast_ref::<DnsLookupFailed>().is_some() {
            return Self::UpstreamDns;
        }
        let refused = e.chain().any(|cause| {
            cause
                .downcast_ref::<std::io::Error>()
                .is_some_and(|io| io.kind() == std::io::ErrorKind::ConnectionRefused)
        });
        if refused {
            Self::UpstreamRefused
        } else {
            Self::UpstreamError
        }
    }

    /// Value of the `X-ProxyX-Error` response header.
    fn cause(self) -> &'static str {
        match self {
            Self::SessionNotFound => "session_not_found",
            Self::SessionBackendUnavailable => "session_backend_unavailable",
            Self::UpstreamRefused => "upstream_refused",
            Self::UpstreamDns => "upstream_dns",
            Self::UpstreamError => "upstream_error",
            Self::UpstreamTimeout => "upstream_timeout",
            Self::UpstreamUnavailable => "upstream_unavailable",
        }
    }

    fn status_line(self) -> &'static str {
        match self {
            Self::SessionNotFound | Self::SessionBackendUnavailable | Self::UpstreamUnavailable => {
                "503 Service Unavailable"
            }
            Self::UpstreamRefused | Self::UpstreamDns | Self::UpstreamError => "502 Bad Gateway",
            Self::UpstreamTimeout => "504 Gateway Timeout",
        }
    }

    fn outcome(self) -> ConnOutcome {
        match self {
            Self::SessionNotFound => ConnOutcome::Rejected,
            Self::SessionBackendUnavailable => ConnOutcome::BackendUnavailable,
            Self::UpstreamRefused | Self::UpstreamDns | Self::UpstreamError => {
                ConnOutcome::UpstreamError
            }
            Self::UpstreamTimeout => ConnOutcome::UpstreamTimeout,
            Self::UpstreamUnavailable => ConnOutcome::UpstreamUnavailable,
        }
    }

    fn response(self, host: &str, port: u16) -> Vec<u8> {
        let cause = self.cause();
        let body = format!("ProxyX proxy error: {cause} {host}:{port}\n");
        format!(
            "HTTP/1.1 {}\r\n\
Server: proxyx\r\n\
{PROXY_ERROR_HEADER}: {cause}\r\n\
Cache-Control: no-store\r\n\
Content-Type: text/plain\r\n\
Connection: close\r\n\
Content-Length: {}\r\n\
\r\n\
{body}",
            self.status_line(),
            body.len()
        )
        .into_bytes()
    }
}

/// The tunnel a failure report names on its log line.
struct Tunnel<'a> {
    session_id: Uuid,
    peer: SocketAddr,
    host: &'a str,
    port: u16,
}

/// Per-context client headers of the request answered in band, logged under
/// the names the capture pipeline uses.
#[derive(Debug, Default, PartialEq)]
struct RequestIds {
    correlation_id: Option<String>,
    parent_correlation_id: Option<String>,
    tool_call_id: Option<String>,
}

fn request_ids(head: &[u8]) -> RequestIds {
    let mut ids = RequestIds::default();
    for line in String::from_utf8_lossy(head).lines().skip(1) {
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        let name = name.trim();
        let slot = if name.eq_ignore_ascii_case("X-ProxyX-Agent") {
            &mut ids.correlation_id
        } else if name.eq_ignore_ascii_case("X-ProxyX-Parent-Agent") {
            &mut ids.parent_correlation_id
        } else if name.eq_ignore_ascii_case("X-ProxyX-Tool") {
            &mut ids.tool_call_id
        } else {
            continue;
        };
        let value = value.trim();
        if !value.is_empty() {
            *slot = Some(value.to_string());
        }
    }
    ids
}

/// Read one request head (bounded by `MAX_HEADER_BYTES`), answer it with
/// `response`, and close the stream.
async fn answer_request<S: AsyncRead + AsyncWrite + Unpin>(
    stream: &mut S,
    response: &[u8],
) -> Result<RequestIds> {
    let mut head = Vec::with_capacity(1024);
    let mut buf = [0u8; 4096];
    let end = loop {
        if let Some(end) = find_double_crlf(&head) {
            break end;
        }
        if head.len() >= MAX_HEADER_BYTES {
            anyhow::bail!("request head exceeds {MAX_HEADER_BYTES} bytes");
        }
        let n = stream.read(&mut buf).await?;
        if n == 0 {
            anyhow::bail!("client closed before a complete request head");
        }
        head.extend_from_slice(&buf[..n]);
    };
    stream.write_all(response).await?;
    stream.shutdown().await?;
    Ok(request_ids(&head[..end]))
}

/// Report a tunnel that could not be set up. The client already has SOCKS
/// `0x00`, so its first bytes are a request meant for the target: plaintext
/// HTTP is answered directly, TLS is terminated with ProxyX's fixed error
/// certificate and then answered, anything else is closed. The response
/// names the cause in `X-ProxyX-Error`.
async fn report_failure(
    mut stream: TcpStream,
    ctx: &ProxyContext,
    tunnel: &Tunnel<'_>,
    failure: TunnelFailure,
    error: Option<String>,
) -> Result<ConnOutcome> {
    warn!(
        session_id = %tunnel.session_id,
        peer = %tunnel.peer,
        host = %tunnel.host,
        port = tunnel.port,
        cause = failure.cause(),
        error = error.as_deref(),
        "SOCKS5 tunnel failed"
    );
    let response = failure.response(tunnel.host, tunnel.port);
    let answer = async move {
        let (protocol, prefix) =
            sniff_tunnel_protocol(&mut stream, ctx.network.socks_handshake_timeout()).await?;
        let mut client = PrefixedStream::new(prefix, stream);
        match protocol {
            TunnelProtocol::Http => answer_request(&mut client, &response).await.map(Some),
            TunnelProtocol::Tls => {
                let mut tls = ctx.mitm.error_acceptor().accept(client).await?;
                answer_request(&mut tls, &response).await.map(Some)
            }
            TunnelProtocol::Opaque => Ok(None),
        }
    };
    let (ids, answer_error) = match timeout(ctx.network.client_header_timeout(), answer).await {
        Ok(Ok(ids)) => (ids, None),
        Ok(Err(e)) => (None, Some(format!("{e:#}"))),
        Err(_) => (None, Some("timed out".to_string())),
    };
    let answered = ids.is_some();
    let ids = ids.unwrap_or_default();
    debug!(
        session_id = %tunnel.session_id,
        answered,
        answer_error = answer_error.as_deref(),
        correlation_id = ids.correlation_id.as_deref(),
        parent_correlation_id = ids.parent_correlation_id.as_deref(),
        tool_call_id = ids.tool_call_id.as_deref(),
        "SOCKS5 tunnel failure answered"
    );
    Ok(failure.outcome())
}

pub(super) async fn handle_socks5(
    mut stream: TcpStream,
    peer: SocketAddr,
    ctx: Arc<ProxyContext>,
) -> Result<ConnOutcome> {
    stream.set_nodelay(true).ok();

    // ---- Handshake with overall timeout ----
    // Wrap the entire greeting/auth/request phase so a stalled client is
    // dropped within `network.socks_handshake_timeout_ms`.

    let handshake = async {
        // 1. SOCKS5 greeting — RFC 1928 §3
        let mut greeting = [0u8; 2];
        stream.read_exact(&mut greeting).await?;
        if greeting[0] != SOCKS5_VERSION {
            anyhow::bail!("not SOCKS5: version byte 0x{:02x}", greeting[0]);
        }
        let nmethods = greeting[1] as usize;
        let mut methods = vec![0u8; nmethods];
        stream.read_exact(&mut methods).await?;

        // We require username/password auth (0x02) — the username carries the
        // session_id, the password is ignored.
        if !methods.contains(&AUTH_USERNAME_PASSWORD) {
            stream.write_all(&[SOCKS5_VERSION, 0xFF]).await?;
            anyhow::bail!("client does not offer username/password auth");
        }
        stream
            .write_all(&[SOCKS5_VERSION, AUTH_USERNAME_PASSWORD])
            .await?;

        // 2. Username/password sub-negotiation — RFC 1929
        let mut auth_ver = [0u8; 1];
        stream.read_exact(&mut auth_ver).await?;
        if auth_ver[0] != AUTH_VERSION {
            anyhow::bail!("unsupported auth sub-version: 0x{:02x}", auth_ver[0]);
        }

        let mut ulen = [0u8; 1];
        stream.read_exact(&mut ulen).await?;
        let mut username = vec![0u8; ulen[0] as usize];
        stream.read_exact(&mut username).await?;

        let mut plen = [0u8; 1];
        stream.read_exact(&mut plen).await?;
        let mut password = vec![0u8; plen[0] as usize];
        stream.read_exact(&mut password).await?;
        drop(password); // not used — session_id is in the username

        let username_str = String::from_utf8_lossy(&username);
        let session_id: Uuid = username_str.parse().map_err(|_| {
            anyhow::anyhow!("invalid session_id in SOCKS5 username: {}", username_str)
        })?;

        // Accept auth at protocol level whatever the lookup says: a missing
        // session or an unavailable backend is reported in band after the
        // CONNECT request, where the client can see the cause.
        let lookup = ctx.state.get_session(&session_id).await;
        stream.write_all(&[AUTH_VERSION, 0x00]).await?;

        // 3. SOCKS5 CONNECT request — RFC 1928 §4
        let mut req_header = [0u8; 4];
        stream.read_exact(&mut req_header).await?;
        if req_header[0] != SOCKS5_VERSION {
            anyhow::bail!("unexpected version in request: 0x{:02x}", req_header[0]);
        }
        if req_header[1] != CMD_CONNECT {
            write_reply(&mut stream, REP_COMMAND_NOT_SUPPORTED).await?;
            anyhow::bail!("unsupported SOCKS5 command: 0x{:02x}", req_header[1]);
        }

        let (host, port) = read_target_address(&mut stream, req_header[3]).await?;
        Ok((session_id, lookup, host, port))
    };

    let (session_id, lookup, host, port) =
        match timeout(ctx.network.socks_handshake_timeout(), handshake).await {
            Ok(Ok(result)) => result,
            Ok(Err(e)) => return Err(e),
            Err(_) => {
                anyhow::bail!("SOCKS5 handshake timed out");
            }
        };

    // Reply success before the outcome is known. Every failure from here on
    // is reported in band by `report_failure`; until then the client's first
    // bytes wait in the socket buffer.
    write_reply(&mut stream, REP_SUCCEEDED).await?;
    debug!(%peer, %host, %port, %session_id, "SOCKS5 CONNECT");
    let tunnel = Tunnel {
        session_id,
        peer,
        host: &host,
        port,
    };

    match lookup {
        SessionLookup::Found(_) => {}
        SessionLookup::NotFound => {
            return report_failure(stream, &ctx, &tunnel, TunnelFailure::SessionNotFound, None)
                .await;
        }
        SessionLookup::BackendUnavailable => {
            return report_failure(
                stream,
                &ctx,
                &tunnel,
                TunnelFailure::SessionBackendUnavailable,
                None,
            )
            .await;
        }
    }

    // --- From here, join the existing proxy flow (mirrors handle_client in connect.rs) ---

    // Routing decision (session is cached from the check above)
    let AuthResult { decision, .. } = match ctx
        .state
        .authenticate_socks_and_route(session_id, &host, port)
        .await
    {
        Ok(r) => r,
        Err(e) => {
            let failure = match &e {
                AuthError::SessionNotFound(_) => TunnelFailure::SessionNotFound,
                AuthError::BackendUnavailable => TunnelFailure::SessionBackendUnavailable,
                // Auth/session rejection: reported like a missing session.
                AuthError::Other(_) => TunnelFailure::SessionNotFound,
            };
            return report_failure(stream, &ctx, &tunnel, failure, Some(e.to_string())).await;
        }
    };

    // Serialization lock — passed into the MITM keepalive loop so it is
    // held per-exchange, not for the entire connection lifetime.
    let serial_lock = if decision.serialize {
        ctx.state.get_serial_lock(&session_id)
    } else {
        None
    };

    // Per-exchange rate limiter for MITM tunnels
    let exchange_ratelimit: Option<Arc<dyn crate::ratelimit::ExchangeRateLimit>> = if decision.mitm
    {
        Some(Arc::new(OrgRateLimit::new(
            ctx.ratelimit.clone(),
            decision.org_id.to_string(),
            decision.rate_limit.clone(),
        )))
    } else {
        None
    };

    // Connect to this session's private target when the exact logical authority is mapped.
    let mapped = decision.upstream_override.as_deref();
    let target = mapped.map_or((host.as_str(), port), |route| {
        (route.upstream_host.as_str(), route.upstream_port)
    });
    let egress_proxy = if mapped.is_some() {
        None
    } else {
        decision.egress_proxy.as_deref()
    };
    let upstream = match ctx
        .egress
        .connect_tunnel(target, egress_proxy, mapped.is_some())
        .await
    {
        Ok(s) => s,
        Err(e) => {
            let error = format!("upstream {}:{}: {e:#}", target.0, target.1);
            let failure = TunnelFailure::from_dial_error(&e, egress_proxy.is_some());
            return report_failure(stream, &ctx, &tunnel, failure, Some(error)).await;
        }
    };

    // Tunnel established. SOCKS carries only host/port, not the target
    // scheme, so sniff the first client bytes instead of guessing from the
    // port. This keeps plaintext HTTP on nonstandard ports and TLS on
    // nonstandard ports both correct. Blind tunnels never wait for client
    // bytes, so server-speaks-first protocols keep working.
    if decision.mitm {
        let (protocol, prefix) =
            sniff_tunnel_protocol(&mut stream, ctx.network.socks_handshake_timeout()).await?;
        let mut client = PrefixedStream::new(prefix, stream);
        match protocol {
            TunnelProtocol::Http => {
                info!(%host, scheme = "http", "SOCKS5: performing MITM interception");
                super::connect::run_mitm_intercept(
                    &ctx,
                    &session_id,
                    "http",
                    &host,
                    port,
                    exchange_ratelimit.clone(),
                    |captures| {
                        ctx.mitm.intercept_plaintext(
                            client,
                            upstream,
                            &host,
                            &decision.inject_headers,
                            captures.exchange_tx,
                            exchange_ratelimit.clone(),
                            Some(captures.ws_sink),
                            serial_lock.clone(),
                            false,
                        )
                    },
                )
                .await;
            }
            TunnelProtocol::Tls => {
                info!(%host, scheme = "https", "SOCKS5: performing MITM interception");
                super::connect::run_mitm_intercept(
                    &ctx,
                    &session_id,
                    "https",
                    &host,
                    port,
                    exchange_ratelimit.clone(),
                    |captures| {
                        ctx.mitm.intercept(
                            client,
                            upstream,
                            MitmParams {
                                host: &host,
                                port,
                                inject_headers: &decision.inject_headers,
                                tls_profile: decision.tls_profile,
                                exchange_tx: captures.exchange_tx,
                                exchange_ratelimit: exchange_ratelimit.clone(),
                                ws_sink: Some(captures.ws_sink),
                                serial_lock: serial_lock.clone(),
                                egress_proxy,
                                upstream_tls: mapped.is_none(),
                            },
                        )
                    },
                )
                .await;
            }
            TunnelProtocol::Opaque => {
                debug!(%host, %port, "SOCKS5: tunneling unrecognized protocol without interception");
                let mut upstream = upstream;
                let _ = tokio::io::copy_bidirectional(&mut client, &mut upstream).await;
            }
        }
    } else {
        let mut upstream = upstream;
        let _ = tokio::io::copy_bidirectional(&mut stream, &mut upstream).await;
    }

    Ok(ConnOutcome::Ok)
}

/// Read the target address from a SOCKS5 request based on the address type byte.
async fn read_target_address(stream: &mut TcpStream, atyp: u8) -> Result<(String, u16)> {
    match atyp {
        ATYP_IPV4 => {
            let mut addr = [0u8; 4];
            stream.read_exact(&mut addr).await?;
            let mut port_buf = [0u8; 2];
            stream.read_exact(&mut port_buf).await?;
            let ip = std::net::Ipv4Addr::from(addr);
            Ok((ip.to_string(), u16::from_be_bytes(port_buf)))
        }
        ATYP_DOMAIN => {
            let mut len = [0u8; 1];
            stream.read_exact(&mut len).await?;
            let mut domain = vec![0u8; len[0] as usize];
            stream.read_exact(&mut domain).await?;
            let mut port_buf = [0u8; 2];
            stream.read_exact(&mut port_buf).await?;
            Ok((
                String::from_utf8_lossy(&domain).to_ascii_lowercase(),
                u16::from_be_bytes(port_buf),
            ))
        }
        ATYP_IPV6 => {
            let mut addr = [0u8; 16];
            stream.read_exact(&mut addr).await?;
            let mut port_buf = [0u8; 2];
            stream.read_exact(&mut port_buf).await?;
            let ip = std::net::Ipv6Addr::from(addr);
            Ok((ip.to_string(), u16::from_be_bytes(port_buf)))
        }
        _ => anyhow::bail!("unsupported SOCKS5 address type: 0x{:02x}", atyp),
    }
}

#[cfg(test)]
mod tests {
    use super::{TunnelProtocol, classify_tunnel_prefix};

    #[test]
    fn classifies_plaintext_http_without_using_port() {
        assert_eq!(
            classify_tunnel_prefix(b"GET /health HTTP/1.1\r\n"),
            Some(TunnelProtocol::Http)
        );
    }

    #[test]
    fn classifies_tls_client_hello_without_using_port() {
        assert_eq!(
            classify_tunnel_prefix(&[0x16, 0x03, 0x01]),
            Some(TunnelProtocol::Tls)
        );
    }

    #[test]
    fn leaves_unknown_protocol_unintercepted() {
        assert_eq!(
            classify_tunnel_prefix(b"\x01\x02\x03"),
            Some(TunnelProtocol::Opaque)
        );
    }
}
