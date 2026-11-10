mod ca;
mod h2_stream_io;
mod tls;
pub mod websocket;

use crate::listener::common::{MAX_HEADER_COUNT, PROXY_ERROR_HEADER};
use crate::ratelimit::ExchangeRateLimit;
use anyhow::{Context, Result};
use bytes::Bytes;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context as TaskContext, Poll};
use std::time::Duration;
use tokio::io::{
    AsyncBufReadExt, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader, ReadBuf,
};
use tokio::net::TcpStream;
use tokio::sync::mpsc;

pub use ca::CertificateAuthority;
pub use tls::{TlsProfile, build_connector, make_server_config};

/// Parameters for MITM interception, grouped to keep function arity bounded.
///
/// The two stream arguments (`client`, `upstream`) are kept separate because
/// they are consumed by the handshake and cannot be cloned or shared.
pub struct MitmParams<'a> {
    /// Target hostname -- used for SNI, cert generation, and error messages.
    pub host: &'a str,
    /// Target port -- used to dial fallback connections (e.g. WS-over-H2 →
    /// H1.1 fallback when the H2 upstream does not advertise RFC 8441
    /// `SETTINGS_ENABLE_CONNECT_PROTOCOL=1`).
    pub port: u16,
    /// Headers to inject into every forwarded request.
    pub inject_headers: &'a [(String, String)],
    /// TLS browser profile for the outbound (proxy -> server) handshake.
    pub tls_profile: TlsProfile,
    /// Channel for captured request/response exchanges.
    pub exchange_tx: mpsc::Sender<CapturedExchange>,
    /// Per-session exchange rate limiter (None = unlimited).
    pub exchange_ratelimit: Option<Arc<dyn ExchangeRateLimit>>,
    /// WebSocket capture configuration. When set, an HTTP/1.1 upgrade
    /// handshake (101 + Upgrade: websocket) will hand off to the WS proxy
    /// instead of falling out of the keepalive loop.
    pub ws_sink: Option<WsCaptureSink>,
    /// Per-session serialization lock. When present, held during each
    /// request/response exchange but released during keep-alive idle waits
    /// so other connections can proceed.
    pub serial_lock: Option<Arc<tokio::sync::Mutex<()>>>,
    /// The session's egress proxy, if any. Routes the WS-over-H2 → H1.1
    /// fallback dial through the same upstream proxy as the primary
    /// connection so the proxy's own egress IP is never leaked.
    pub egress_proxy: Option<&'a common::types::EgressProxy>,
    /// Whether the proxy-to-upstream leg performs TLS. Session overrides use plain HTTP.
    pub upstream_tls: bool,
}

/// Trait alias for an upstream stream that can be returned from the
/// H1-fallback dialer (boxed dyn).
pub trait UpstreamIo: AsyncRead + AsyncWrite + Send + Unpin {}
impl<T: AsyncRead + AsyncWrite + Send + Unpin + ?Sized> UpstreamIo for T {}

/// Boxed upstream stream used by the WS-over-H2 → H1.1 fallback path.
pub type BoxedUpstream = Box<dyn UpstreamIo + 'static>;

/// Dialer used to open a fresh TLS connection to the original upstream when
/// the H2 server does not support RFC 8441 Extended CONNECT. The dialer
/// MUST force ALPN to `http/1.1` so the upstream selects HTTP/1.1.
///
/// Wrapped in `Arc<dyn Fn ...>` so it can be cloned cheaply into the
/// `proxy_h1_to_h2` task that needs it.
pub type H1FallbackDial = Arc<
    dyn Fn(
            String,
            u16,
        )
            -> Pin<Box<dyn std::future::Future<Output = anyhow::Result<BoxedUpstream>> + Send>>
        + Send
        + Sync,
>;

/// All the per-session metadata + channel needed to build a `WsContext`
/// at WS handoff time. Cloned into both directional loops via `Arc`.
pub struct WsCaptureSink {
    /// Sink for captured WS messages.
    pub tx: mpsc::Sender<crate::pipeline::WsPipelineEvent>,
    /// Per-message captured-payload byte cap.
    pub max_payload_capture: usize,
    /// Capture PING/PONG too. CLOSE is always captured.
    pub capture_control_frames: bool,
    pub session_id: common::types::SessionId,
    pub org_id: String,
    pub source: String,
    pub source_id: String,
    pub proxy_id: String,
    /// Per-message rate limit applied to c2s messages only. Same shared
    /// instance as the parent HTTP exchange ratelimit so the org's quota
    /// covers both HTTP and WS traffic.
    pub exchange_ratelimit: Option<Arc<dyn ExchangeRateLimit>>,
}
/// Default maximum body size to capture (16 MB).
/// Override via `TuningConfig::max_body_capture`.
#[cfg(test)]
const DEFAULT_MAX_BODY_CAPTURE: usize = 16 * 1024 * 1024;

/// Timeouts and limits of the HTTP loops, taken from `[network]`.
#[derive(Clone, Copy, Debug)]
pub(crate) struct HttpLimits {
    /// Idle time between requests on a client connection.
    pub keepalive_idle: Duration,
    /// Requests served on one client connection before it is closed.
    pub max_requests: Option<u32>,
    /// Wait for upstream response headers. Prevents indefinite blocking when
    /// the upstream accepts a connection but never sends a response.
    pub upstream_response: Duration,
    /// Longest wait for the next bytes of a message body. An idle limit, not
    /// a total one: a slow but steady body is not cut.
    pub body_idle: Duration,
    /// One TLS handshake, client or upstream.
    pub tls_handshake: Duration,
    /// Wait for the upstream's reply to the SETTINGS ping before a
    /// WebSocket upgrade over HTTP/2.
    pub h2_settings: Duration,
}

impl From<&crate::config::NetworkConfig> for HttpLimits {
    fn from(network: &crate::config::NetworkConfig) -> Self {
        Self {
            keepalive_idle: Duration::from_millis(network.http_keepalive_idle_timeout_ms),
            max_requests: (network.http_keepalive_max_requests > 0)
                .then_some(network.http_keepalive_max_requests),
            upstream_response: Duration::from_millis(network.upstream_response_header_timeout_ms),
            body_idle: Duration::from_millis(network.body_idle_timeout_ms),
            tls_handshake: Duration::from_millis(network.tls_handshake_timeout_ms),
            h2_settings: Duration::from_millis(network.h2_settings_timeout_ms),
        }
    }
}

impl Default for HttpLimits {
    fn default() -> Self {
        Self::from(&crate::config::NetworkConfig::default())
    }
}

/// Handles MITM TLS interception.
pub struct MitmHandler {
    /// One pre-built SslConnector per TlsProfile variant, indexed by discriminant.
    /// SslConnector is Arc-backed internally; per-connection config is derived via
    /// connector.configure() which is cheap.
    connectors: Box<[boring::ssl::SslConnector]>,
    /// Shared TLS server config for all inbound MITM connections.
    /// Created once at startup; the embedded CertResolver generates
    /// hostname-specific certs on demand from the CA cache.
    server_config: Arc<rustls::ServerConfig>,
    /// Single-certificate config (see `make_error_server_config`) for the
    /// in-band error response the socks5 listener serves when a tunnel
    /// cannot be set up.
    error_server_config: Arc<rustls::ServerConfig>,
    /// Maximum body size to capture per request/response.
    max_body_capture: usize,
    /// Maximum individual header value size (bytes) to capture.
    /// Values exceeding this are truncated at the largest UTF-8 char boundary
    /// that fits. Header names and forwarded traffic are unaffected.
    max_header_capture: usize,
    /// Shared egress handle (DNS cache + egress-proxy dialing). Used by the
    /// WS-over-H2 → H1.1 fallback so the fallback connection follows the same
    /// routing as the primary tunnel instead of dialing the target directly.
    egress: crate::egress::Egress,
    /// Timeouts and limits of the HTTP loops.
    limits: HttpLimits,
}

impl MitmHandler {
    /// Compile-time guard: `TlsProfile::ALL[i] as usize == i` for every variant.
    ///
    /// `connectors` is indexed by `tls_profile as usize`. Both the enum
    /// discriminants (`#[repr(usize)]`) and the `ALL` ordering must agree.
    /// This assertion fires at compile time if someone reorders the enum or
    /// `ALL` without updating the other.
    const _PROFILE_INDEX_INVARIANT: () = {
        let all = TlsProfile::ALL;
        let mut i = 0usize;
        while i < all.len() {
            assert!(
                all[i] as usize == i,
                "TlsProfile::ALL order must match discriminant values"
            );
            i += 1;
        }
    };

    pub fn new(
        ca: Arc<CertificateAuthority>,
        max_body_capture: usize,
        max_header_capture: usize,
        egress: crate::egress::Egress,
        network: &crate::config::NetworkConfig,
    ) -> anyhow::Result<Self> {
        let connectors: Vec<boring::ssl::SslConnector> = TlsProfile::ALL
            .iter()
            .map(|&p| build_connector(p))
            .collect::<anyhow::Result<_>>()?;
        let error_server_config = tls::make_error_server_config(&ca)?;
        let server_config = make_server_config(ca)?;
        Ok(Self {
            connectors: connectors.into_boxed_slice(),
            server_config: Arc::new(server_config),
            error_server_config: Arc::new(error_server_config),
            max_body_capture,
            max_header_capture,
            egress,
            limits: HttpLimits::from(network),
        })
    }

    /// TLS acceptor for in-band proxy error responses: one fixed certificate,
    /// ALPN `http/1.1` only.
    pub fn error_acceptor(&self) -> tokio_rustls::TlsAcceptor {
        tokio_rustls::TlsAcceptor::from(self.error_server_config.clone())
    }

    /// Intercept a CONNECT tunnel with TLS MITM.
    ///
    /// - `client`: TCP stream from client (after 200 Connection Established sent)
    /// - `upstream`: TCP stream to upstream server
    /// - `host`: Target hostname (for cert generation and SNI)
    /// - `inject_headers`: Headers to add to all requests
    ///
    /// Returns captured request/response pairs for logging.
    pub async fn intercept<C>(
        &self,
        client: C,
        upstream: TcpStream,
        params: MitmParams<'_>,
    ) -> Result<()>
    where
        C: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
    {
        let MitmParams {
            host,
            port,
            inject_headers,
            tls_profile,
            exchange_tx,
            exchange_ratelimit,
            ws_sink,
            serial_lock,
            egress_proxy,
            upstream_tls,
        } = params;

        // 1. Accept TLS from client (rustls — inbound does not affect the
        //    fingerprint the destination server observes).
        //    The ServerConfig is shared across all connections; the embedded
        //    CertResolver generates hostname certs on demand via SNI.
        let acceptor = tokio_rustls::TlsAcceptor::from(self.server_config.clone());
        let handshake_start = std::time::Instant::now();
        let client_tls = tokio::time::timeout(self.limits.tls_handshake, acceptor.accept(client))
            .await
            .with_context(|| format!("client TLS handshake for {host} timed out"))??;
        observe_tls_handshake("client", handshake_start);
        if !upstream_tls {
            let exit = proxy_http_keepalive(
                client_tls,
                upstream,
                host,
                inject_headers,
                exchange_tx,
                exchange_ratelimit,
                self.max_body_capture,
                self.max_header_capture,
                ws_sink.as_ref(),
                serial_lock,
                false,
                "https",
                self.limits,
            )
            .await?;
            return handoff_or_close(exit, ws_sink.as_ref()).await;
        }

        // 2. Connect TLS to upstream with the assigned browser profile.
        //    The connector for this profile was pre-built at startup; configure()
        //    derives a per-connection ConnectConfiguration from the shared context.
        let connector = &self.connectors[tls_profile as usize];
        // verify_hostname is a no-op when set_verify(NONE) is set on the
        // connector, but configure() returns a ConnectConfiguration for any
        // additional per-connection overrides.
        let config = connector.configure()?;
        let handshake_start = std::time::Instant::now();
        let upstream_tls = tokio::time::timeout(
            self.limits.tls_handshake,
            tokio_boring::connect(config, host, upstream),
        )
        .await
        .with_context(|| format!("TLS handshake to {host} timed out"))?
        .map_err(|e| anyhow::anyhow!("TLS handshake to {}: {}", host, e))?;
        observe_tls_handshake("upstream", handshake_start);

        // 3. Check negotiated ALPN to select upstream HTTP protocol.
        //    The inbound client→proxy leg always speaks HTTP/1.1.
        let is_h2 = upstream_tls
            .ssl()
            .selected_alpn_protocol()
            .is_some_and(|p| p == b"h2");

        let max_body_capture = self.max_body_capture;
        let max_header_capture = self.max_header_capture;
        if is_h2 {
            // HTTP/2 upstream: translate H1 from client into H2 toward upstream.
            // proxy_h1_to_h2 takes ownership of the BufReader and handles its own
            // client shutdown (including the WS-handoff path).
            //
            // Build the H1.1 fallback dialer for WS-over-H2 → H1.1 graceful
            // degradation when the upstream does not advertise RFC 8441
            // SETTINGS_ENABLE_CONNECT_PROTOCOL=1.
            let fallback_connector = self.connectors[tls_profile as usize].clone();
            let fallback_egress = self.egress.clone();
            let fallback_egress_proxy = egress_proxy.cloned();
            let fallback_tls_timeout = self.limits.tls_handshake;
            let h1_fallback: H1FallbackDial = Arc::new(move |dial_host: String, dial_port: u16| {
                let connector = fallback_connector.clone();
                let egress = fallback_egress.clone();
                let egress_proxy = fallback_egress_proxy.clone();
                Box::pin(async move {
                    // Route the fallback dial through the same egress path as
                    // every other connection (egress proxy chain + DNS cache)
                    // so we never leak the proxy's own egress IP. The egress
                    // applies the upstream connect timeout and the breaker.
                    let tcp = egress
                        .connect_tunnel(
                            (dial_host.as_str(), dial_port),
                            egress_proxy.as_ref(),
                            false,
                        )
                        .await
                        .with_context(|| {
                            format!("h1 fallback connect to {dial_host}:{dial_port}")
                        })?;
                    let mut config = connector
                        .configure()
                        .context("h1 fallback connector configure failed")?;
                    // Force ALPN to http/1.1 only (length-prefixed wire format).
                    config
                        .set_alpn_protos(b"\x08http/1.1")
                        .context("h1 fallback set_alpn_protos failed")?;
                    let handshake_start = std::time::Instant::now();
                    let stream = tokio::time::timeout(
                        fallback_tls_timeout,
                        tokio_boring::connect(config, dial_host.as_str(), tcp),
                    )
                    .await
                    .with_context(|| format!("h1 fallback TLS handshake to {dial_host} timed out"))?
                    .map_err(|e| {
                        anyhow::anyhow!("h1 fallback TLS handshake to {dial_host}: {e}")
                    })?;
                    observe_tls_handshake("upstream", handshake_start);
                    let boxed: BoxedUpstream = Box::new(stream);
                    Ok(boxed)
                })
            });

            let client_buf = BufReader::new(client_tls);
            proxy_h1_to_h2(
                client_buf,
                upstream_tls,
                host,
                port,
                inject_headers,
                exchange_tx,
                exchange_ratelimit,
                max_body_capture,
                max_header_capture,
                ws_sink.as_ref(),
                Some(h1_fallback),
                serial_lock,
                self.limits,
            )
            .await
        } else {
            // HTTP/1.1 upstream: WS-handoff capable keepalive loop.
            let exit = proxy_http_keepalive(
                client_tls,
                upstream_tls,
                host,
                inject_headers,
                exchange_tx,
                exchange_ratelimit.clone(),
                max_body_capture,
                max_header_capture,
                ws_sink.as_ref(),
                serial_lock,
                false,
                "https",
                self.limits,
            )
            .await?;
            handoff_or_close(exit, ws_sink.as_ref()).await
        }
    }

    /// Intercept plain HTTP traffic (no TLS).
    ///
    /// Same as `intercept()` but for unencrypted HTTP connections.
    /// The client stream may be a `PrefixedStream` if the caller already
    /// read the first request's bytes for routing.
    #[allow(clippy::too_many_arguments)]
    pub async fn intercept_plaintext<C: AsyncRead + AsyncWrite + Send + Unpin + 'static>(
        &self,
        client: C,
        upstream: TcpStream,
        host: &str,
        inject_headers: &[(String, String)],
        exchange_tx: mpsc::Sender<CapturedExchange>,
        exchange_ratelimit: Option<Arc<dyn ExchangeRateLimit>>,
        ws_sink: Option<WsCaptureSink>,
        serial_lock: Option<Arc<tokio::sync::Mutex<()>>>,
        close_after_exchange: bool,
    ) -> Result<()> {
        let exit = proxy_http_keepalive(
            client,
            upstream,
            host,
            inject_headers,
            exchange_tx,
            exchange_ratelimit,
            self.max_body_capture,
            self.max_header_capture,
            ws_sink.as_ref(),
            serial_lock,
            close_after_exchange,
            "http",
            self.limits,
        )
        .await?;
        handoff_or_close(exit, ws_sink.as_ref()).await
    }

    /// Relay one uncaptured plaintext exchange, then close both sides.
    pub async fn relay_plaintext_once<C: AsyncRead + AsyncWrite + Send + Unpin + 'static>(
        &self,
        client: C,
        upstream: TcpStream,
        host: &str,
    ) -> Result<()> {
        let (exchange_tx, exchange_rx) = mpsc::channel(1);
        drop(exchange_rx);
        let exit = proxy_http_keepalive(
            client,
            upstream,
            host,
            &[],
            exchange_tx,
            None,
            0,
            0,
            None,
            None,
            true,
            "http",
            self.limits,
        )
        .await?;
        handoff_or_close(exit, None).await
    }
}

/// Shared post-keepalive cleanup. On clean close, shut down both streams.
/// On WS handoff, build a `WsContext` from the sink + handoff data and run
/// `proxy_websocket`.
async fn handoff_or_close<C, U>(
    exit: KeepaliveExit<C, U>,
    ws_sink: Option<&WsCaptureSink>,
) -> Result<()>
where
    C: AsyncRead + AsyncWrite + Send + Unpin + 'static,
    U: AsyncRead + AsyncWrite + Send + Unpin + 'static,
{
    match exit {
        KeepaliveExit::Closed {
            mut client,
            mut upstream,
        } => {
            let _ = client.shutdown().await;
            let _ = upstream.shutdown().await;
            Ok(())
        }
        KeepaliveExit::WsHandoff {
            client,
            upstream,
            parent_event_id,
            s2c_prefix,
            deflate,
            host: ws_host,
        } => {
            let sink = match ws_sink {
                Some(s) => s,
                None => {
                    // Keepalive only emits WsHandoff when a sink was supplied;
                    // this branch is structurally unreachable.
                    tracing::error!(
                        host = %ws_host,
                        %parent_event_id,
                        "ws handoff returned without a sink available; closing"
                    );
                    return Ok(());
                }
            };
            let ws_ctx = websocket::WsContext {
                parent_event_id,
                session_id: sink.session_id,
                proxy_id: sink.proxy_id.clone(),
                org_id: sink.org_id.clone(),
                source: sink.source.clone(),
                source_id: sink.source_id.clone(),
                host: ws_host.clone(),
                capture_tx: sink.tx.clone(),
                max_payload_capture: sink.max_payload_capture,
                deflate,
                capture_control_frames: sink.capture_control_frames,
                exchange_ratelimit: sink.exchange_ratelimit.clone(),
            };
            if let Err(e) = websocket::proxy_websocket(client, upstream, s2c_prefix, ws_ctx).await {
                tracing::warn!(
                    error = ?e,
                    host = %ws_host,
                    %parent_event_id,
                    "proxy_websocket exited with error"
                );
            }
            Ok(())
        }
    }
}

/// A read/write stream that first drains a prefix buffer, then delegates to
/// the inner stream. Writes always go directly to the inner stream.
///
/// Used when the caller already consumed bytes from the TCP socket (e.g. to
/// parse the first HTTP request for routing) and needs to "replay" them
/// into the keepalive loop.
pub struct PrefixedStream<S> {
    prefix: Vec<u8>,
    prefix_pos: usize,
    stream: S,
}

impl<S> PrefixedStream<S> {
    pub fn new(prefix: Vec<u8>, stream: S) -> Self {
        Self {
            prefix,
            prefix_pos: 0,
            stream,
        }
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for PrefixedStream<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        // Drain prefix first
        if self.prefix_pos < self.prefix.len() {
            let remaining = &self.prefix[self.prefix_pos..];
            let to_copy = remaining.len().min(buf.remaining());
            buf.put_slice(&remaining[..to_copy]);
            self.prefix_pos += to_copy;
            return Poll::Ready(Ok(()));
        }
        Pin::new(&mut self.stream).poll_read(cx, buf)
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for PrefixedStream<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.stream).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.stream).poll_flush(cx)
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.stream).poll_shutdown(cx)
    }
}

/// A captured HTTP request/response exchange.
#[derive(Debug, Clone)]
pub struct CapturedExchange {
    /// UUIDv7 minted at exchange finalization. Propagated end-to-end so the
    /// API's ClickHouse insert is idempotent and so a WS upgrade can
    /// reference the 101 row's id as `parent_event_id`.
    pub event_id: uuid::Uuid,
    pub method: String,
    pub path: String,
    pub host: String,
    pub request_headers: Vec<(String, String)>,
    pub request_body: Bytes,
    pub request_body_truncated: bool,
    pub status: u16,
    pub response_headers: Vec<(String, String)>,
    pub response_body: Bytes,
    pub response_body_truncated: bool,
    /// Wall-clock time at which the exchange began (request line read).
    /// Captured at the proxy so the ClickHouse `timestamp` reflects request
    /// order, not when the publisher happened to dequeue it under backpressure.
    pub timestamp: time::OffsetDateTime,
    /// Duration of this individual request/response exchange in milliseconds.
    pub duration_ms: u64,
}

/// Outcome of `proxy_http_keepalive`. The streams are returned to the caller
/// either way: clean close lets the caller shut them down; WS handoff hands
/// them to `proxy_websocket`.
pub enum KeepaliveExit<C, U> {
    /// Connection ended cleanly (peer EOF, idle timeout, Connection: close).
    Closed { client: C, upstream: U },
    /// HTTP/1.1 -> WebSocket upgrade (101). Caller should hand off to
    /// `proxy_websocket` with the supplied parent_event_id and s2c_prefix.
    WsHandoff {
        client: C,
        upstream: U,
        /// `event_id` of the 101 row -- used as `parent_event_id` for every
        /// captured WS message on this connection.
        parent_event_id: uuid::Uuid,
        /// Bytes already read from upstream past the 101 `\\r\\n\\r\\n` boundary.
        /// Forwarded to the client + fed to the s2c parser by `proxy_websocket`.
        s2c_prefix: Vec<u8>,
        /// Negotiated `permessage-deflate` parameters from the 101 response.
        deflate: Option<websocket::DeflateNegotiation>,
        /// Authoritative host for the WS conversation (mirrors the 101 row's host).
        host: String,
    },
}

/// Returns true when this request/response is a successful WebSocket upgrade.
/// Per RFC 6455 section 4.2.2, the response must be 101 with `Upgrade: websocket`,
/// and the request must have offered the upgrade.
pub(crate) fn is_ws_upgrade(
    req_headers: &[(String, String)],
    resp_status: u16,
    resp_headers: &[(String, String)],
) -> bool {
    if resp_status != 101 {
        return false;
    }
    let req_offered = offers_ws_upgrade(req_headers);
    let resp_accepted = resp_headers
        .iter()
        .any(|(k, v)| k.eq_ignore_ascii_case("upgrade") && v.eq_ignore_ascii_case("websocket"));
    req_offered && resp_accepted
}

/// Returns true when the request asks for a WebSocket upgrade.
fn offers_ws_upgrade(req_headers: &[(String, String)]) -> bool {
    req_headers
        .iter()
        .any(|(k, v)| k.eq_ignore_ascii_case("upgrade") && v.eq_ignore_ascii_case("websocket"))
}

/// One request forwarded upstream, for `PROXY_REQUESTS_TOTAL` and
/// `PROXY_UPSTREAM_DURATION_SECONDS`. Dropping it before [`Self::response`]
/// counts the request as `error`, which covers every `?` and early exit
/// between forwarding the request and reading the response headers.
struct UpstreamRequest {
    protocol: &'static str,
    sent: std::time::Instant,
    answered: bool,
}

impl UpstreamRequest {
    fn start(protocol: &'static str) -> Self {
        Self {
            protocol,
            sent: std::time::Instant::now(),
            answered: false,
        }
    }

    /// Upstream response headers arrived with `status`. Returns the arrival
    /// time, which starts the `response` overhead phase.
    fn response(mut self, status: u16) -> std::time::Instant {
        let now = std::time::Instant::now();
        common::metrics::PROXY_UPSTREAM_DURATION_SECONDS
            .with_label_values(&[self.protocol])
            .observe((now - self.sent).as_secs_f64());
        common::metrics::PROXY_REQUESTS_TOTAL
            .with_label_values(&[self.protocol, common::metrics::status_class(status)])
            .inc();
        self.answered = true;
        now
    }
}

impl Drop for UpstreamRequest {
    fn drop(&mut self) {
        if !self.answered {
            common::metrics::PROXY_REQUESTS_TOTAL
                .with_label_values(&[self.protocol, "error"])
                .inc();
        }
    }
}

/// Record a successful MITM TLS handshake on `side` (client | upstream).
fn observe_tls_handshake(side: &'static str, start: std::time::Instant) {
    common::metrics::PROXY_TLS_HANDSHAKE_SECONDS
        .with_label_values(&[side])
        .observe(start.elapsed().as_secs_f64());
}

/// Record one phase of time the proxy itself adds to an exchange.
fn observe_overhead(protocol: &'static str, phase: &'static str, elapsed: Duration) {
    common::metrics::PROXY_OVERHEAD_SECONDS
        .with_label_values(&[protocol, phase])
        .observe(elapsed.as_secs_f64());
}

/// Acquire the per-session serial lock. Returns the guard and how long the
/// acquisition waited; both are `None` when the session has no lock.
async fn acquire_serial_lock(
    lock: Option<&tokio::sync::Mutex<()>>,
) -> (Option<tokio::sync::MutexGuard<'_, ()>>, Option<Duration>) {
    let Some(lock) = lock else {
        return (None, None);
    };
    let start = std::time::Instant::now();
    let guard = lock.lock().await;
    (Some(guard), Some(start.elapsed()))
}

/// Proxy HTTP/1.1 traffic with keep-alive support.
///
/// Returns `KeepaliveExit` so the caller can either shut down both streams
/// (clean close) or hand them off to `proxy_websocket` (101 upgrade).
#[allow(clippy::too_many_arguments)]
async fn proxy_http_keepalive<C, U>(
    client: C,
    upstream: U,
    target_host: &str,
    inject_headers: &[(String, String)],
    exchange_tx: mpsc::Sender<CapturedExchange>,
    exchange_ratelimit: Option<Arc<dyn ExchangeRateLimit>>,
    max_body_capture: usize,
    max_header_capture: usize,
    ws_sink: Option<&WsCaptureSink>,
    serial_lock: Option<Arc<tokio::sync::Mutex<()>>>,
    close_after_exchange: bool,
    // Client-facing scheme for request metrics: "http" or "https".
    scheme: &'static str,
    limits: HttpLimits,
) -> Result<KeepaliveExit<C, U>>
where
    C: AsyncRead + AsyncWriteExt + Unpin,
    U: AsyncRead + AsyncWriteExt + Unpin,
{
    let mut client = BufReader::new(client);
    let mut upstream = BufReader::new(upstream);
    let mut has_exchanges = false;
    let mut client_carryover: Vec<u8> = Vec::new();
    let mut upstream_carryover: Vec<u8> = Vec::new();
    let mut served: u32 = 0;

    loop {
        // Read request headers with timeout for idle connections
        let req_result = tokio::time::timeout(
            limits.keepalive_idle,
            read_http_headers(&mut client, &client_carryover),
        )
        .await;
        client_carryover.clear(); // consumed into buf

        let (req_header_buf, req_header_len) = match req_result {
            Ok(Ok((buf, len))) if len > 0 => (buf, len),
            Ok(Ok(_)) => break, // Clean EOF
            Ok(Err(e)) => {
                // Only error if we had no exchanges - first request errors are real
                if !has_exchanges {
                    return Err(e);
                }
                break;
            }
            Err(_) => break, // Timeout - client idle, close connection
        };

        // Acquire serial lock for the duration of this exchange.
        // Dropped at end of each loop iteration before the next idle wait.
        let (_serial_guard, lock_wait) = acquire_serial_lock(serial_lock.as_deref()).await;

        // Start timing this exchange
        let exchange_start = std::time::Instant::now();
        let exchange_ts = time::OffsetDateTime::now_utc();

        // Parse request
        let parsed_req = parse_request(&req_header_buf[..req_header_len])?;
        let req_wants_close = wants_close(&parsed_req.headers);
        let protocol = if offers_ws_upgrade(&parsed_req.headers) {
            "websocket"
        } else {
            scheme
        };
        if let Some(wait) = lock_wait {
            observe_overhead(protocol, "lock_wait", wait);
        }

        // Rate limit: acquire a token per exchange before forwarding.
        // Send a proper 429 response instead of bare-resetting the connection.
        // The wait is policy, not overhead: it is recorded as its own
        // `ratelimit_wait` phase and excluded from the `request` phase.
        let mut ratelimit_wait = Duration::ZERO;
        if let Some(rl) = &exchange_ratelimit {
            let rl_start = std::time::Instant::now();
            let acquired = rl.acquire().await;
            ratelimit_wait = rl_start.elapsed();
            observe_overhead(protocol, "ratelimit_wait", ratelimit_wait);
            if let Err(e) = acquired {
                tracing::warn!(error = %e, host = %target_host, "rate limit exceeded, sending 429");
                let _ = write_status_response(
                    client.get_mut(),
                    &parsed_req.method,
                    429,
                    "Too Many Requests",
                    "rate limit exceeded",
                )
                .await;
                break;
            }
        }

        // Build modified request with injected headers
        let modified_headers =
            build_request_with_injected_headers(&req_header_buf[..req_header_len], inject_headers);

        // Forward modified request headers to upstream
        observe_overhead(
            protocol,
            "request",
            exchange_start.elapsed().saturating_sub(ratelimit_wait),
        );
        let upstream_req = UpstreamRequest::start(protocol);
        upstream.get_mut().write_all(&modified_headers).await?;

        // Stream request body to upstream
        let req_framing = request_body_framing(&parsed_req.headers);
        let sb = stream_body(
            &mut client,
            upstream.get_mut(),
            req_framing,
            &req_header_buf[req_header_len..],
            max_body_capture,
            limits.body_idle,
        )
        .await?;
        upstream.get_mut().flush().await?;

        let request_body = sb.captured;
        let request_body_truncated = sb.truncated;
        // Leftover from request body = start of next pipelined request
        client_carryover = sb.leftover;

        // Read response headers with upstream timeout (F2.1).
        // Prevents indefinite blocking when upstream accepts but never replies.
        let resp_result = tokio::time::timeout(
            limits.upstream_response,
            read_http_headers(&mut upstream, &upstream_carryover),
        )
        .await;
        upstream_carryover.clear(); // consumed into buf
        let (resp_header_buf, resp_header_len) = match resp_result {
            Ok(Ok((buf, len))) if len > 0 => (buf, len),
            Ok(Ok(_)) => {
                anyhow::bail!("upstream closed without response");
            }
            Ok(Err(e)) => {
                return Err(e);
            }
            Err(_) => {
                tracing::warn!(
                    host = %target_host,
                    method = %parsed_req.method,
                    path = %parsed_req.path,
                    "upstream response header read timed out, sending 504"
                );
                let _ = write_status_response(
                    client.get_mut(),
                    &parsed_req.method,
                    504,
                    "Gateway Timeout",
                    "upstream did not send response headers in time",
                )
                .await;
                break;
            }
        };

        // Parse response
        let parsed_resp = parse_response(&resp_header_buf[..resp_header_len])?;
        let answered = upstream_req.response(parsed_resp.status);
        let resp_wants_close = wants_close(&parsed_resp.headers);

        // WS upgrade detection happens BEFORE reading the response body. A 101
        // has no HTTP body; the bytes past \r\n\r\n are the start of the WS
        // stream and must be handed to `proxy_websocket` instead of forwarded
        // as an HTTP body.
        let ws_upgraded = is_ws_upgrade(
            &parsed_req.headers,
            parsed_resp.status,
            &parsed_resp.headers,
        );

        // F2.3: if this is a WS upgrade but ws_sink is not configured,
        // send a 502 to the client instead of forwarding the 101 (which
        // would leave the client with a half-open upgrade).
        if ws_upgraded && ws_sink.is_none() {
            tracing::warn!(
                host = %target_host,
                "ws upgrade succeeded upstream but ws_sink not configured; sending 502 to client"
            );
            let _ = write_status_response(
                client.get_mut(),
                &parsed_req.method,
                502,
                "Bad Gateway",
                "websocket upgrade could not be captured by the proxy",
            )
            .await;
            break;
        }

        // The connection has served its quota: advertise the close so the
        // client redials instead of sending a request into a closing socket.
        served += 1;
        let quota_reached = limits.max_requests.is_some_and(|max| served >= max);

        // Authority-bound forward sessions advertise the close so pooling
        // clients redial before sending a request for another host.
        client
            .get_mut()
            .write_all(&client_response_head(
                &resp_header_buf[..resp_header_len],
                &parsed_resp.headers,
                close_after_exchange || quota_reached,
            ))
            .await?;
        observe_overhead(protocol, "response", answered.elapsed());

        // Stream response body (skipped for WS upgrades)
        let (response_body, response_body_truncated) = if ws_upgraded {
            (Bytes::new(), false)
        } else {
            let resp_framing =
                response_body_framing(&parsed_req.method, parsed_resp.status, &parsed_resp.headers);
            let sb = stream_body(
                &mut upstream,
                client.get_mut(),
                resp_framing,
                &resp_header_buf[resp_header_len..],
                max_body_capture,
                limits.body_idle,
            )
            .await?;
            upstream_carryover = sb.leftover;
            (sb.captured, sb.truncated)
        };
        client.get_mut().flush().await?;

        // Mint the event_id at exchange finalization. For WS upgrades this is
        // the parent_event_id used by every WS message that follows.
        let event_id = uuid::Uuid::now_v7();

        // Send exchange to publisher (bounded channel provides backpressure)
        let exchange = CapturedExchange {
            event_id,
            method: parsed_req.method.clone(),
            path: parsed_req.path.clone(),
            host: parsed_req
                .host
                .clone()
                .unwrap_or_else(|| target_host.to_string()),
            request_headers: captured_request_headers(&parsed_req.headers, max_header_capture),
            request_body,
            request_body_truncated,
            status: parsed_resp.status,
            response_headers: truncate_header_values(
                parsed_resp.headers.clone(),
                max_header_capture,
            ),
            response_body,
            response_body_truncated,
            timestamp: exchange_ts,
            duration_ms: exchange_start.elapsed().as_millis() as u64,
        };
        let send_start = tokio::time::Instant::now();
        let _ = exchange_tx.send(exchange).await;
        let send_elapsed = send_start.elapsed();
        observe_overhead(protocol, "capture_wait", send_elapsed);
        if send_elapsed > Duration::from_secs(5) {
            tracing::warn!(
                elapsed_ms = send_elapsed.as_millis() as u64,
                host = %target_host,
                "exchange channel backpressure: send blocked >5s (H1 path)"
            );
        }
        has_exchanges = true;

        // WS handoff: only after the 101 row's CapturedExchange has been
        // queued (so the parent row lands first in the broker order).
        if ws_upgraded {
            // ws_sink=None was already intercepted above (502 sent).
            // Here ws_sink is guaranteed to be Some.
            let s2c_prefix = resp_header_buf[resp_header_len..].to_vec();
            let deflate = websocket::parse_extensions(&parsed_resp.headers);
            let host = parsed_req
                .host
                .clone()
                .unwrap_or_else(|| target_host.to_string());
            tracing::info!(
                %host,
                %event_id,
                deflate = deflate.is_some(),
                "ws upgrade detected, handing off to proxy_websocket"
            );
            return Ok(KeepaliveExit::WsHandoff {
                client: client.into_inner(),
                upstream: upstream.into_inner(),
                parent_event_id: event_id,
                s2c_prefix,
                deflate,
                host,
            });
        }

        // Forward-proxy connections with session overrides are authority-bound to
        // their first request. Close before any pipelined next authority is relayed.
        if close_after_exchange || req_wants_close || resp_wants_close || quota_reached {
            break;
        }

        // _serial_guard dropped here — lock released before next idle wait
    }

    Ok(KeepaliveExit::Closed {
        client: client.into_inner(),
        upstream: upstream.into_inner(),
    })
}

/// Hop-by-hop headers that authenticate the client to *this* proxy and must
/// never be forwarded to the origin (nor recorded in the capture): the
/// session credential rides `Proxy-Authorization`.
const STRIP_REQUEST_HEADERS: [&str; 2] = ["proxy-authorization", "proxy-connection"];

fn header_line_is_stripped(line: &[u8]) -> bool {
    let Some(colon) = line.iter().position(|&b| b == b':') else {
        return false;
    };
    let name = &line[..colon];
    STRIP_REQUEST_HEADERS
        .iter()
        .any(|h| name.eq_ignore_ascii_case(h.as_bytes()))
}

/// Rebuild a request header block, dropping hop-by-hop proxy headers and
/// appending `inject_headers`. The request line (first line) is always
/// preserved verbatim; subsequent `Proxy-Authorization` / `Proxy-Connection`
/// lines are removed so the session credential never reaches upstream or the
/// capture log.
pub(crate) fn build_request_with_injected_headers(
    original_headers: &[u8],
    inject_headers: &[(String, String)],
) -> Vec<u8> {
    let header_end = original_headers
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .map(|idx| idx + 2) // Position after last header's \r\n, before final \r\n
        .unwrap_or(original_headers.len());
    let block = &original_headers[..header_end];

    let mut result = Vec::with_capacity(original_headers.len() + inject_headers.len() * 64);
    let mut line_start = 0;
    let mut is_request_line = true;
    while line_start < block.len() {
        let (line, next) = match block[line_start..].windows(2).position(|w| w == b"\r\n") {
            Some(p) => (&block[line_start..line_start + p], line_start + p + 2),
            None => (&block[line_start..], block.len()),
        };
        if line.is_empty() {
            line_start = next;
            continue;
        }
        if is_request_line {
            result.extend_from_slice(&origin_form_request_line(line));
            result.extend_from_slice(b"\r\n");
        } else if !header_line_is_stripped(line) {
            result.extend_from_slice(line);
            result.extend_from_slice(b"\r\n");
        }
        is_request_line = false;
        line_start = next;
    }

    for (name, value) in inject_headers {
        result.extend_from_slice(name.as_bytes());
        result.extend_from_slice(b": ");
        result.extend_from_slice(value.as_bytes());
        result.extend_from_slice(b"\r\n");
    }

    result.extend_from_slice(b"\r\n");

    result
}

/// The request line with an absolute-form target (`GET http://host/p?q
/// HTTP/1.1`, what a client sends to a proxy) rewritten to origin-form
/// (`GET /p?q HTTP/1.1`), what an origin server expects (RFC 9112 3.2).
/// Origin-form, authority-form and asterisk-form lines are returned unchanged.
pub(crate) fn origin_form_request_line(line: &[u8]) -> std::borrow::Cow<'_, [u8]> {
    let mut parts = line.splitn(3, |b| *b == b' ');
    let (Some(method), Some(target), Some(version)) = (parts.next(), parts.next(), parts.next())
    else {
        return std::borrow::Cow::Borrowed(line);
    };
    let rest = [b"http://".as_slice(), b"https://".as_slice()]
        .iter()
        .find(|scheme| {
            target.len() >= scheme.len() && target[..scheme.len()].eq_ignore_ascii_case(scheme)
        })
        .map(|scheme| &target[scheme.len()..]);
    let Some(rest) = rest else {
        return std::borrow::Cow::Borrowed(line);
    };
    let path_start = rest.iter().position(|b| *b == b'/' || *b == b'?');
    let mut out = Vec::with_capacity(line.len());
    out.extend_from_slice(method);
    out.push(b' ');
    match path_start {
        Some(i) if rest[i] == b'/' => out.extend_from_slice(&rest[i..]),
        Some(i) => {
            out.push(b'/');
            out.extend_from_slice(&rest[i..]);
        }
        None => out.push(b'/'),
    }
    out.push(b' ');
    out.extend_from_slice(version);
    std::borrow::Cow::Owned(out)
}

/// Strip hop-by-hop proxy headers from a raw request header block without
/// injecting anything. Used by the non-MITM forward path, which relays the
/// original bytes but must still remove the session credential.
pub(crate) fn strip_hop_by_hop_request_headers(original_headers: &[u8]) -> Vec<u8> {
    build_request_with_injected_headers(original_headers, &[])
}

/// The upstream response head as the client receives it: without
/// `PROXY_ERROR_HEADER`, which only the socks5 listener's own error responses
/// may carry, and with `Connection: close` in place of any `Connection`
/// header when `close` is set. Borrows `head` when nothing changes, the
/// common case. `headers` is `head` as `parse_response` read it.
fn client_response_head<'a>(
    head: &'a [u8],
    headers: &[(String, String)],
    close: bool,
) -> std::borrow::Cow<'a, [u8]> {
    let spoofed = headers
        .iter()
        .any(|(name, _)| name.eq_ignore_ascii_case(PROXY_ERROR_HEADER));
    if !close && !spoofed {
        return std::borrow::Cow::Borrowed(head);
    }
    let header_end = head
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .map(|idx| idx + 2)
        .unwrap_or(head.len());
    let block = &head[..header_end];
    let mut result = Vec::with_capacity(head.len() + 19);
    let mut line_start = 0;
    let mut is_status_line = true;
    while line_start < block.len() {
        let (line, next) = match block[line_start..].windows(2).position(|w| w == b"\r\n") {
            Some(pos) => (&block[line_start..line_start + pos], line_start + pos + 2),
            None => (&block[line_start..], block.len()),
        };
        let dropped = !is_status_line
            && line
                .split(|byte| *byte == b':')
                .next()
                .map(<[u8]>::trim_ascii)
                .is_some_and(|name| {
                    name.eq_ignore_ascii_case(PROXY_ERROR_HEADER.as_bytes())
                        || (close && name.eq_ignore_ascii_case(b"connection"))
                });
        if !line.is_empty() && !dropped {
            result.extend_from_slice(line);
            result.extend_from_slice(b"\r\n");
        }
        is_status_line = false;
        line_start = next;
    }
    if close {
        result.extend_from_slice(b"Connection: close\r\n");
    }
    result.extend_from_slice(b"\r\n");
    std::borrow::Cow::Owned(result)
}

/// Truncate a single header value to at most `max_bytes`, cutting at the
/// largest UTF-8 char boundary that fits. Returns the original string
/// unmodified when it already fits.
fn truncate_header_value(mut val: String, max_bytes: usize) -> String {
    if val.len() <= max_bytes {
        return val;
    }
    // Find the largest char boundary <= max_bytes.
    let mut end = max_bytes;
    while end > 0 && !val.is_char_boundary(end) {
        end -= 1;
    }
    val.truncate(end);
    val
}

/// Truncate every header value in-place, leaving names intact.
fn truncate_header_values(
    headers: Vec<(String, String)>,
    max_bytes: usize,
) -> Vec<(String, String)> {
    headers
        .into_iter()
        .map(|(name, val)| (name, truncate_header_value(val, max_bytes)))
        .collect()
}

/// Filter a parsed header list for the capture log, dropping the same
/// hop-by-hop proxy headers as the forward path so the session credential is
/// never persisted to ClickHouse. Header values are truncated to
/// `max_header_capture` bytes.
fn captured_request_headers(
    headers: &[(String, String)],
    max_header_capture: usize,
) -> Vec<(String, String)> {
    headers
        .iter()
        .filter(|(name, _)| {
            !STRIP_REQUEST_HEADERS
                .iter()
                .any(|h| name.eq_ignore_ascii_case(h))
        })
        .map(|(name, val)| {
            (
                name.clone(),
                truncate_header_value(val.clone(), max_header_capture),
            )
        })
        .collect()
}

/// Write an HTML-bodied HTTP/1.1 error response to `writer` and flush.
/// Used for error paths (429, 502, 503, 504) where the proxy needs to send a
/// clean response before tearing down the connection. `request_method` is the
/// client's method; a HEAD reply gets the headers only.
async fn write_status_response<W: AsyncWrite + Unpin>(
    writer: &mut W,
    request_method: &str,
    status: u16,
    reason: &str,
    detail: &str,
) -> std::io::Result<()> {
    let mut response = crate::listener::common::proxy_error_response(status, reason, detail, &[]);
    // A response to HEAD must not carry a body (RFC 9110 section 9.3.2).
    if request_method.eq_ignore_ascii_case("HEAD")
        && let Some(header_end) = crate::listener::common::find_double_crlf(&response)
    {
        response.truncate(header_end);
    }
    writer.write_all(&response).await?;
    writer.flush().await
}

fn wants_close(headers: &[(String, String)]) -> bool {
    headers
        .iter()
        .any(|(k, v)| k.eq_ignore_ascii_case("connection") && v.eq_ignore_ascii_case("close"))
}

fn is_chunked(headers: &[(String, String)]) -> bool {
    headers.iter().any(|(k, v)| {
        k.eq_ignore_ascii_case("transfer-encoding") && v.to_lowercase().contains("chunked")
    })
}

fn get_content_length(headers: &[(String, String)]) -> Option<usize> {
    headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case("content-length"))
        .and_then(|(_, v)| v.parse().ok())
}

/// Read HTTP headers until \r\n\r\n, returning buffer and header length.
/// May read extra bytes (start of body) into the buffer.
///
/// `prefix` contains bytes already consumed from the socket (e.g. leftover
/// from a previous body read). If it already holds a complete header block
/// we return immediately without touching the socket.
async fn read_http_headers<R: AsyncRead + Unpin>(
    reader: &mut BufReader<R>,
    prefix: &[u8],
) -> Result<(Vec<u8>, usize)> {
    let mut buf = prefix.to_vec();

    // The prefix may already contain a full header block (pipelined request).
    if let Some(pos) = find_header_end(&buf) {
        return Ok((buf, pos));
    }
    // If prefix is non-empty but not a full header, the search_start
    // optimisation needs to account for a partial \r\n\r\n straddling old/new.

    loop {
        let available = reader.fill_buf().await?;
        if available.is_empty() {
            return Ok((buf, 0)); // Connection closed
        }

        let prev_len = buf.len();
        buf.extend_from_slice(available);
        let consumed = available.len();
        reader.consume(consumed);

        // Look for end of headers (search from where new data starts, minus overlap)
        let search_start = prev_len.saturating_sub(3);
        if let Some(pos) = find_header_end(&buf[search_start..]) {
            return Ok((buf, search_start + pos));
        }

        if buf.len() > 64 * 1024 {
            anyhow::bail!("headers too large");
        }
    }
}

fn find_header_end(buf: &[u8]) -> Option<usize> {
    buf.windows(4)
        .position(|w| w == b"\r\n\r\n")
        .map(|idx| idx + 4)
}

// ---------------------------------------------------------------------------
// Body framing model
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BodyFraming {
    None,
    ContentLength(usize),
    Chunked,
    CloseDelimited,
}

/// Working buffer size for streaming a body reader→writer. Bounds memory.
const STREAM_CHUNK: usize = 64 * 1024;

fn request_body_framing(headers: &[(String, String)]) -> BodyFraming {
    if is_chunked(headers) {
        BodyFraming::Chunked
    } else if let Some(n) = get_content_length(headers) {
        BodyFraming::ContentLength(n)
    } else {
        BodyFraming::None
    }
}

fn response_body_framing(
    req_method: &str,
    status: u16,
    headers: &[(String, String)],
) -> BodyFraming {
    let no_body = req_method.eq_ignore_ascii_case("HEAD")
        || status == 204
        || status == 304
        || (100..200).contains(&status);
    if no_body {
        return BodyFraming::None;
    }
    if is_chunked(headers) {
        BodyFraming::Chunked
    } else if let Some(n) = get_content_length(headers) {
        BodyFraming::ContentLength(n)
    } else {
        BodyFraming::CloseDelimited
    }
}

// ---------------------------------------------------------------------------
// Capture accumulator — bounded body capture without whole-body allocation
// ---------------------------------------------------------------------------

struct BodyCapture {
    buf: Vec<u8>,
    truncated: bool,
    cap: usize,
}

impl BodyCapture {
    fn new(cap: usize) -> Self {
        Self {
            buf: Vec::new(),
            truncated: false,
            cap,
        }
    }

    fn push(&mut self, data: &[u8]) {
        if self.buf.len() < self.cap {
            let take = (self.cap - self.buf.len()).min(data.len());
            self.buf.extend_from_slice(&data[..take]);
            if take < data.len() {
                self.truncated = true;
            }
        } else if !data.is_empty() {
            self.truncated = true;
        }
    }
}

// ---------------------------------------------------------------------------
// Streaming body pump — replaces read_body for the H1→H1 path
// ---------------------------------------------------------------------------

struct StreamedBody {
    captured: Bytes,
    truncated: bool,
    leftover: Vec<u8>,
}

/// Run one body read, failing if no bytes arrive within `idle`
/// (`network.body_idle_timeout_ms`).
async fn body_read<T>(idle: Duration, read: impl Future<Output = std::io::Result<T>>) -> Result<T> {
    let result = tokio::time::timeout(idle, read)
        .await
        .context("body read idle timeout")?;
    result.context("read body")
}

/// Stream a body from `reader` to `writer` in bounded pieces, capturing up to
/// `max_body_capture` decoded bytes.
///
/// `extra` is bytes already consumed past the header boundary. They belong to
/// this body (or to nothing, for `BodyFraming::None`).
///
/// Returns the captured prefix, truncation flag, and any leftover bytes that
/// belong to the NEXT message on the connection.
async fn stream_body<R, W>(
    reader: &mut BufReader<R>,
    writer: &mut W,
    framing: BodyFraming,
    extra: &[u8],
    max_body_capture: usize,
    body_idle: Duration,
) -> Result<StreamedBody>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut capture = BodyCapture::new(max_body_capture);

    match framing {
        BodyFraming::None => {
            // No body. `extra` is the start of the NEXT message — carry it over.
            Ok(StreamedBody {
                captured: Bytes::new(),
                truncated: false,
                leftover: extra.to_vec(),
            })
        }

        BodyFraming::ContentLength(n) => {
            let from_extra = extra.len().min(n);
            if from_extra > 0 {
                writer.write_all(&extra[..from_extra]).await?;
                capture.push(&extra[..from_extra]);
            }
            let leftover = extra[from_extra..].to_vec();
            let mut remaining = n - from_extra;

            let mut buf = vec![0u8; STREAM_CHUNK];
            while remaining > 0 {
                let want = remaining.min(STREAM_CHUNK);
                let got = body_read(body_idle, reader.read(&mut buf[..want])).await?;
                if got == 0 {
                    anyhow::bail!("unexpected EOF in content-length body");
                }
                writer.write_all(&buf[..got]).await?;
                capture.push(&buf[..got]);
                remaining -= got;
            }

            Ok(StreamedBody {
                captured: Bytes::from(capture.buf),
                truncated: capture.truncated,
                leftover,
            })
        }

        BodyFraming::CloseDelimited => {
            if !extra.is_empty() {
                writer.write_all(extra).await?;
                capture.push(extra);
            }
            let mut buf = vec![0u8; STREAM_CHUNK];
            loop {
                let got = body_read(body_idle, reader.read(&mut buf)).await?;
                if got == 0 {
                    break;
                }
                writer.write_all(&buf[..got]).await?;
                capture.push(&buf[..got]);
            }
            Ok(StreamedBody {
                captured: Bytes::from(capture.buf),
                truncated: capture.truncated,
                leftover: Vec::new(),
            })
        }

        BodyFraming::Chunked => {
            stream_chunked_body(reader, writer, extra, &mut capture, body_idle).await
        }
    }
}

/// Stream chunked transfer-encoding, forwarding raw chunked bytes verbatim
/// and capturing decoded data into `capture`.
async fn stream_chunked_body<R, W>(
    reader: &mut BufReader<R>,
    writer: &mut W,
    extra: &[u8],
    capture: &mut BodyCapture,
    body_idle: Duration,
) -> Result<StreamedBody>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut buf = Vec::from(extra);

    loop {
        // Ensure we have a complete chunk size line (\r\n terminated).
        while find_crlf(&buf).is_none() {
            let available = body_read(body_idle, reader.fill_buf()).await?;
            if available.is_empty() {
                anyhow::bail!("unexpected EOF in chunked body");
            }
            buf.extend_from_slice(available);
            let len = available.len();
            reader.consume(len);
        }

        // Parse chunk size line.
        let line_end = find_crlf(&buf).expect("loop ensures CRLF present");
        let size_line = &buf[..line_end];
        let size_str = std::str::from_utf8(size_line).context("invalid chunk size line")?;
        let size_str = size_str.trim();
        // Handle chunk extensions (;ext=value).
        let size_hex = size_str.split(';').next().unwrap_or("").trim();
        let chunk_size = usize::from_str_radix(size_hex, 16).context("invalid chunk size hex")?;

        // Forward the raw size line + CRLF.
        writer.write_all(&buf[..line_end + 2]).await?;
        buf.drain(..line_end + 2);

        if chunk_size == 0 {
            // Terminal chunk. Read + forward trailing CRLF (and any trailers
            // up to the final CRLF pair).
            // Minimal approach: read until we get a \r\n after the 0-chunk line.
            // Trailers end with a blank \r\n line, but the simple case (no
            // trailers) is just \r\n immediately.
            loop {
                if let Some(crlf_pos) = find_crlf(&buf) {
                    let line = &buf[..crlf_pos];
                    // Forward this line + CRLF.
                    writer.write_all(&buf[..crlf_pos + 2]).await?;
                    let is_empty_line = line.is_empty();
                    buf.drain(..crlf_pos + 2);
                    if is_empty_line {
                        // Final blank line — end of chunked message.
                        break;
                    }
                    // Otherwise it was a trailer line; keep going.
                } else {
                    let available = body_read(body_idle, reader.fill_buf()).await?;
                    if available.is_empty() {
                        // EOF before final CRLF — tolerate.
                        break;
                    }
                    buf.extend_from_slice(available);
                    let len = available.len();
                    reader.consume(len);
                }
            }
            break;
        }

        // Read + forward exactly chunk_size data bytes + trailing CRLF.
        let need = chunk_size + 2; // data + \r\n
        // Stream data from buf first, then from reader, in <=STREAM_CHUNK pieces.
        let mut forwarded = 0usize;
        while forwarded < need {
            if buf.is_empty() {
                // Refill from reader.
                let available = body_read(body_idle, reader.fill_buf()).await?;
                if available.is_empty() {
                    anyhow::bail!("unexpected EOF reading chunk data");
                }
                buf.extend_from_slice(available);
                let len = available.len();
                reader.consume(len);
            }
            let can_take = buf.len().min(need - forwarded).min(STREAM_CHUNK);
            writer.write_all(&buf[..can_take]).await?;
            // Capture decoded bytes (not the trailing \r\n).
            let data_remaining = chunk_size.saturating_sub(forwarded);
            if data_remaining > 0 {
                let capture_end = can_take.min(data_remaining);
                capture.push(&buf[..capture_end]);
            }
            buf.drain(..can_take);
            forwarded += can_take;
        }
    }

    Ok(StreamedBody {
        captured: Bytes::from(std::mem::take(&mut capture.buf)),
        truncated: capture.truncated,
        leftover: buf,
    })
}

// ---------------------------------------------------------------------------
// Full-body read for H2 request path (bounded incremental allocation)
// ---------------------------------------------------------------------------

/// Read a full decoded body into memory, growing incrementally (never
/// pre-sized from Content-Length). Used by the H1→H2 path which needs the
/// complete body bytes to send via `h2::SendStream::send_data`.
///
/// Returns `(full_decoded_body, captured_prefix, truncated)`.
/// Largest request body the HTTP/1.1 to HTTP/2 path buffers before it
/// forwards. That path needs the whole body up front (the HTTP/1.1 keepalive
/// path streams instead); a client that declares or sends more gets `413`.
pub(crate) const MAX_BUFFERED_BODY: usize = 64 * 1024 * 1024;

/// A body larger than [`MAX_BUFFERED_BODY`]; answered with `413`.
#[derive(Debug, thiserror::Error)]
#[error("request body exceeds {MAX_BUFFERED_BODY} bytes")]
pub(crate) struct BodyTooLarge;

async fn read_full_body<R: AsyncRead + Unpin>(
    reader: &mut BufReader<R>,
    framing: BodyFraming,
    extra: &[u8],
    max_body_capture: usize,
) -> Result<(Bytes, Bytes, bool)> {
    read_full_body_bounded(reader, framing, extra, max_body_capture, MAX_BUFFERED_BODY).await
}

async fn read_full_body_bounded<R: AsyncRead + Unpin>(
    reader: &mut BufReader<R>,
    framing: BodyFraming,
    extra: &[u8],
    max_body_capture: usize,
    max_body: usize,
) -> Result<(Bytes, Bytes, bool)> {
    match framing {
        BodyFraming::None => {
            // No body.
            Ok((Bytes::new(), Bytes::new(), false))
        }

        BodyFraming::ContentLength(n) => {
            if n > max_body {
                return Err(BodyTooLarge.into());
            }
            let mut body = Vec::new();
            let from_extra = extra.len().min(n);
            body.extend_from_slice(&extra[..from_extra]);
            let mut remaining = n - from_extra;
            let mut tmp = vec![0u8; STREAM_CHUNK];
            while remaining > 0 {
                let want = remaining.min(STREAM_CHUNK);
                let got = reader.read(&mut tmp[..want]).await.context("read body")?;
                if got == 0 {
                    anyhow::bail!("unexpected EOF in content-length body");
                }
                body.extend_from_slice(&tmp[..got]);
                remaining -= got;
            }
            let full = Bytes::from(body);
            let truncated = full.len() > max_body_capture;
            let captured = if truncated {
                full.slice(..max_body_capture)
            } else {
                full.clone()
            };
            Ok((full, captured, truncated))
        }

        BodyFraming::Chunked => {
            read_full_chunked_body(reader, extra, max_body_capture, max_body).await
        }

        BodyFraming::CloseDelimited => {
            // Close-delimited: read until EOF.
            let mut body = Vec::from(extra);
            let mut tmp = vec![0u8; STREAM_CHUNK];
            loop {
                let got = reader.read(&mut tmp).await?;
                if got == 0 {
                    break;
                }
                if got > max_body.saturating_sub(body.len()) {
                    return Err(BodyTooLarge.into());
                }
                body.extend_from_slice(&tmp[..got]);
            }
            let full = Bytes::from(body);
            let truncated = full.len() > max_body_capture;
            let captured = if truncated {
                full.slice(..max_body_capture)
            } else {
                full.clone()
            };
            Ok((full, captured, truncated))
        }
    }
}

/// Decode a chunked body fully into memory (incrementally grown).
async fn read_full_chunked_body<R: AsyncRead + Unpin>(
    reader: &mut BufReader<R>,
    extra: &[u8],
    max_body_capture: usize,
    max_body: usize,
) -> Result<(Bytes, Bytes, bool)> {
    let mut decoded = Vec::new();
    let mut buf = Vec::from(extra);

    loop {
        // Ensure we have a complete chunk size line.
        while find_crlf(&buf).is_none() {
            let available = reader.fill_buf().await?;
            if available.is_empty() {
                anyhow::bail!("unexpected EOF in chunked body");
            }
            buf.extend_from_slice(available);
            let len = available.len();
            reader.consume(len);
        }

        let line_end = find_crlf(&buf).expect("loop ensures CRLF present");
        let size_str = std::str::from_utf8(&buf[..line_end]).context("invalid chunk size line")?;
        let size_str = size_str.trim();
        let size_hex = size_str.split(';').next().unwrap_or("").trim();
        let chunk_size = usize::from_str_radix(size_hex, 16).context("invalid chunk size hex")?;
        buf.drain(..line_end + 2);

        if chunk_size == 0 {
            break;
        }
        if chunk_size > max_body.saturating_sub(decoded.len()) {
            return Err(BodyTooLarge.into());
        }

        let need = chunk_size + 2;
        while buf.len() < need {
            let available = reader.fill_buf().await?;
            if available.is_empty() {
                anyhow::bail!("unexpected EOF reading chunk data");
            }
            buf.extend_from_slice(available);
            let len = available.len();
            reader.consume(len);
        }

        decoded.extend_from_slice(&buf[..chunk_size]);
        buf.drain(..need);
    }

    let full = Bytes::from(decoded);
    let truncated = full.len() > max_body_capture;
    let captured = if truncated {
        full.slice(..max_body_capture)
    } else {
        full.clone()
    };
    Ok((full, captured, truncated))
}

fn find_crlf(buf: &[u8]) -> Option<usize> {
    buf.windows(2).position(|w| w == b"\r\n")
}

struct ParsedRequest {
    method: String,
    path: String,
    host: Option<String>,
    headers: Vec<(String, String)>,
}

struct ParsedResponse {
    status: u16,
    headers: Vec<(String, String)>,
}

fn parse_request(buf: &[u8]) -> Result<ParsedRequest> {
    let mut headers = [httparse::EMPTY_HEADER; MAX_HEADER_COUNT];
    let mut req = httparse::Request::new(&mut headers);

    req.parse(buf)?;

    let method = req.method.unwrap_or("").to_string();
    let raw_path = req.path.unwrap_or("");

    // HTTP forward proxy requests use absolute-form URIs
    // (e.g. "http://host/path"). Strip scheme+authority to keep only the path.
    let path = if let Some(rest) = raw_path
        .strip_prefix("http://")
        .or_else(|| raw_path.strip_prefix("https://"))
    {
        rest.find('/')
            .map_or("/".to_string(), |i| rest[i..].to_string())
    } else {
        raw_path.to_string()
    };

    let mut host = None;
    let mut parsed_headers = Vec::new();

    for h in req.headers.iter() {
        let name = h.name.to_string();
        let value = String::from_utf8_lossy(h.value).to_string();
        if h.name.eq_ignore_ascii_case("host") {
            host = Some(value.clone());
        }
        parsed_headers.push((name, value));
    }

    Ok(ParsedRequest {
        method,
        path,
        host,
        headers: parsed_headers,
    })
}

fn parse_response(buf: &[u8]) -> Result<ParsedResponse> {
    let mut headers = [httparse::EMPTY_HEADER; MAX_HEADER_COUNT];
    let mut resp = httparse::Response::new(&mut headers);

    resp.parse(buf)?;

    let status = resp.code.unwrap_or(0);

    let mut parsed_headers = Vec::new();
    for h in resp.headers.iter() {
        let name = h.name.to_string();
        let value = String::from_utf8_lossy(h.value).to_string();
        parsed_headers.push((name, value));
    }

    Ok(ParsedResponse {
        status,
        headers: parsed_headers,
    })
}

/// Proxy HTTP/1.1 requests from client to an HTTP/2 upstream.
///
/// Used when ALPN negotiation selects h2 for the upstream connection.
/// The inbound client→proxy leg remains HTTP/1.1; this function translates
/// each H1 request into an H2 stream and converts the H2 response back to H1.
/// Body handling is fully buffered (same 16 MB capture limit as the H1 path).
#[allow(clippy::too_many_arguments)]
async fn proxy_h1_to_h2<C, U>(
    mut client: BufReader<C>,
    upstream_tls: U,
    target_host: &str,
    target_port: u16,
    inject_headers: &[(String, String)],
    exchange_tx: mpsc::Sender<CapturedExchange>,
    exchange_ratelimit: Option<Arc<dyn ExchangeRateLimit>>,
    max_body_capture: usize,
    max_header_capture: usize,
    ws_sink: Option<&WsCaptureSink>,
    h1_fallback: Option<H1FallbackDial>,
    serial_lock: Option<Arc<tokio::sync::Mutex<()>>>,
    limits: HttpLimits,
) -> Result<()>
where
    // Send + 'static required because (a) the h2 Connection is spawned as a task,
    // and (b) the inner stream is handed to proxy_websocket on WS upgrade.
    C: AsyncRead + AsyncWriteExt + Unpin + Send + 'static,
    U: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    // Perform h2 handshake — sends the client connection preface and SETTINGS frame.
    let (mut send_request, mut connection) = h2::client::handshake(upstream_tls)
        .await
        .context("h2 handshake failed")?;

    // Extract a ping_pong handle BEFORE moving the connection into the driver
    // task.  We use it lazily at WS-upgrade time to synchronize on a server
    // round-trip, ensuring the server's SETTINGS frame has been processed
    // before we check `is_extended_connect_protocol_enabled`.
    let mut ping_pong = connection.ping_pong();

    // h2 requires the Connection to be polled continuously to drive the state
    // machine (ACKs, WINDOW_UPDATE, PING, GOAWAY). Spawn it independently so
    // it runs concurrently with request/response processing.
    let conn_handle = tokio::spawn(async move {
        if let Err(e) = connection.await {
            tracing::debug!(error = ?e, "h2 upstream connection closed");
        }
    });

    let mut has_exchanges = false;
    let mut served: u32 = 0;

    loop {
        // Read H1 request headers with idle timeout (same policy as H1 path)
        let req_result =
            tokio::time::timeout(limits.keepalive_idle, read_http_headers(&mut client, &[])).await;

        let (req_header_buf, req_header_len) = match req_result {
            Ok(Ok((buf, len))) if len > 0 => (buf, len),
            Ok(Ok(_)) => break, // Clean EOF
            Ok(Err(e)) => {
                if !has_exchanges {
                    return Err(e);
                }
                break;
            }
            Err(_) => break, // Idle timeout
        };

        // Acquire serial lock for the duration of this exchange.
        // Dropped at end of each loop iteration before the next idle wait.
        let (_serial_guard, lock_wait) = acquire_serial_lock(serial_lock.as_deref()).await;

        let exchange_start = std::time::Instant::now();
        let exchange_ts = time::OffsetDateTime::now_utc();

        let parsed_req = parse_request(&req_header_buf[..req_header_len])?;
        // RFC 8441: translate Upgrade: websocket into an Extended CONNECT request.
        // The upgrade block is self-contained: all error paths return from the function
        // directly (avoiding use-after-move of send_request when ready() consumes it);
        // the success path calls proxy_websocket inline and returns.
        let req_wants_ws_upgrade = offers_ws_upgrade(&parsed_req.headers);
        let protocol = if req_wants_ws_upgrade {
            "websocket"
        } else {
            "https"
        };
        if let Some(wait) = lock_wait {
            observe_overhead(protocol, "lock_wait", wait);
        }
        if req_wants_ws_upgrade {
            tracing::info!(
                host = %target_host,
                path = %parsed_req.path,
                "ws upgrade over h2 (RFC 8441): attempting Extended CONNECT"
            );

            // Extract Sec-WebSocket-Key for the 101 we will send to the client.
            let client_ws_key = match parsed_req
                .headers
                .iter()
                .find(|(k, _)| k.eq_ignore_ascii_case("sec-websocket-key"))
                .map(|(_, v)| v.clone())
            {
                Some(k) => k,
                None => {
                    tracing::warn!(host = %target_host, "ws upgrade missing Sec-WebSocket-Key");
                    let _ = client
                        .get_mut()
                        .write_all(&crate::listener::common::proxy_error_response(
                            400,
                            "Bad Request",
                            "missing Sec-WebSocket-Key",
                            &[],
                        ))
                        .await;
                    let _ = client.get_mut().flush().await;
                    return Ok(());
                }
            };

            // RFC 8441 §3 mandates: a client MUST NOT send Extended CONNECT
            // until it has received `SETTINGS_ENABLE_CONNECT_PROTOCOL=1` from
            // the peer.  Many H2 origins (e.g., AWS ALB → Express backends)
            // never advertise this and reject the request with 400 Bad Request.
            //
            // If the upstream has not advertised support, fall back to a fresh
            // HTTP/1.1 connection (when a fallback dialer is configured).  Any
            // race in which we observe `false` before the server's SETTINGS
            // arrives is functionally fine — it just routes through H1.1.
            // Synchronize on a server round-trip so we have observed at least
            // the initial server SETTINGS frame before checking ENABLE_CONNECT_PROTOCOL.
            // This adds 1 RTT but only on WS-upgrade requests (rare).  PingPong is
            // taken once per connection; on subsequent WS upgrades on the same
            // connection it is None (and unnecessary — SETTINGS is long-since received).
            // The ping is an upstream round trip, so it is excluded from the
            // `request` overhead phase.
            let mut ping_wait = Duration::ZERO;
            if let Some(pp) = ping_pong.as_mut() {
                let ping_start = std::time::Instant::now();
                let _ = tokio::time::timeout(limits.h2_settings, pp.ping(h2::Ping::opaque())).await;
                ping_wait = ping_start.elapsed();
                drop(ping_pong.take());
            }
            let connect_protocol_enabled = send_request.is_extended_connect_protocol_enabled();
            if !connect_protocol_enabled {
                if let Some(dial) = h1_fallback.clone() {
                    tracing::info!(
                        host = %target_host,
                        port = target_port,
                        "upstream did not advertise SETTINGS_ENABLE_CONNECT_PROTOCOL; falling back to HTTP/1.1"
                    );
                    drop(send_request);
                    let _ = conn_handle.await;
                    return run_h1_fallback_ws_upgrade(
                        client,
                        dial,
                        target_host,
                        target_port,
                        &parsed_req,
                        &req_header_buf[..req_header_len],
                        inject_headers,
                        &exchange_tx,
                        exchange_start,
                        exchange_ts,
                        max_header_capture,
                        ws_sink,
                        &client_ws_key,
                    )
                    .await;
                } else {
                    tracing::warn!(
                        host = %target_host,
                        "upstream lacks SETTINGS_ENABLE_CONNECT_PROTOCOL and no h1 fallback dialer configured; returning 502"
                    );
                    let _ = client
                        .get_mut()
                        .write_all(&crate::listener::common::proxy_error_response(
                            502,
                            "Bad Gateway",
                            "upstream does not support RFC 8441 Extended CONNECT",
                            &[],
                        ))
                        .await;
                    let _ = client.get_mut().flush().await;
                    return Ok(());
                }
            }

            // Build the Extended CONNECT request.
            let h2_req = match build_h2_extended_connect(&parsed_req, target_host, inject_headers) {
                Ok(r) => r,
                Err(e) => {
                    tracing::warn!(error = ?e, host = %target_host, "failed to build Extended CONNECT");
                    let _ = client
                        .get_mut()
                        .write_all(&crate::listener::common::proxy_error_response(
                            500,
                            "Internal Server Error",
                            "failed to build Extended CONNECT",
                            &[],
                        ))
                        .await;
                    let _ = client.get_mut().flush().await;
                    return Ok(());
                }
            };

            observe_overhead(
                protocol,
                "request",
                exchange_start.elapsed().saturating_sub(ping_wait),
            );
            let upstream_req = UpstreamRequest::start(protocol);
            // Acquire an h2 stream slot (ready() consumes send_request by value;
            // error arm returns from the function so send_request is not double-used).
            send_request = match send_request.ready().await {
                Ok(sr) => sr,
                Err(e) => {
                    tracing::warn!(error = ?e, host = %target_host, "h2 not ready for ws upgrade");
                    let _ = client
                        .get_mut()
                        .write_all(&crate::listener::common::proxy_error_response(
                            502,
                            "Bad Gateway",
                            "h2 connection failed",
                            &[],
                        ))
                        .await;
                    let _ = client.get_mut().flush().await;
                    return Ok(());
                }
            };

            let (resp_fut, send_stream) = match send_request.send_request(h2_req, false) {
                Ok(t) => t,
                Err(e) => {
                    tracing::warn!(error = ?e, host = %target_host, "h2 send_request failed for ws upgrade");
                    let _ = client
                        .get_mut()
                        .write_all(&crate::listener::common::proxy_error_response(
                            502,
                            "Bad Gateway",
                            "h2 send_request failed for ws upgrade",
                            &[],
                        ))
                        .await;
                    let _ = client.get_mut().flush().await;
                    return Ok(());
                }
            };

            // Await upstream CONNECT response.
            let h2_resp = match resp_fut.await {
                Ok(r) => r,
                Err(e) => {
                    tracing::warn!(error = ?e, host = %target_host, "upstream Extended CONNECT response failed");
                    let _ = client
                        .get_mut()
                        .write_all(&crate::listener::common::proxy_error_response(
                            502,
                            "Bad Gateway",
                            "upstream Extended CONNECT response failed",
                            &[],
                        ))
                        .await;
                    let _ = client.get_mut().flush().await;
                    return Ok(());
                }
            };
            // Extended CONNECT answers 200 where H1 answers 101; record what
            // the client sees on success.
            let answered = upstream_req.response(match h2_resp.status() {
                http::StatusCode::OK => 101,
                s => s.as_u16(),
            });

            if h2_resp.status() != http::StatusCode::OK {
                let detail = format!("upstream rejected ws upgrade: {}", h2_resp.status());
                tracing::warn!(
                    host = %target_host,
                    status = %h2_resp.status(),
                    "upstream rejected Extended CONNECT (ws upgrade)"
                );
                let _ = client
                    .get_mut()
                    .write_all(&crate::listener::common::proxy_error_response(
                        502,
                        "Bad Gateway",
                        &detail,
                        &[],
                    ))
                    .await;
                let _ = client.get_mut().flush().await;
                return Ok(());
            }

            // Collect upstream response headers (Sec-WebSocket-Protocol, etc.).
            let h2_resp_headers: Vec<(String, String)> = h2_resp
                .headers()
                .iter()
                .filter_map(|(k, v)| v.to_str().ok().map(|vs| (k.to_string(), vs.to_string())))
                .collect();

            // F2.3: if ws_sink is not configured, do NOT forward the 101
            // upgrade — send a 502 to the client so it never sees a half-open
            // upgrade, and tear down cleanly.
            if ws_sink.is_none() {
                tracing::warn!(
                    host = %target_host,
                    "ws upgrade over h2 succeeded upstream but ws_sink not configured; sending 502 to client"
                );
                let _ = write_status_response(
                    client.get_mut(),
                    &parsed_req.method,
                    502,
                    "Bad Gateway",
                    "websocket upgrade could not be captured by the proxy",
                )
                .await;
                drop(send_request);
                let _ = conn_handle.await;
                return Ok(());
            }

            // Send HTTP/1.1 101 Switching Protocols to client.
            let h1_101 = build_h1_101_response(&client_ws_key, &h2_resp_headers);
            if let Err(e) = client.get_mut().write_all(h1_101.as_bytes()).await {
                tracing::warn!(error = ?e, host = %target_host, "failed to send 101 to client");
                return Ok(());
            }
            if let Err(e) = client.get_mut().flush().await {
                tracing::warn!(error = ?e, host = %target_host, "failed to flush 101 to client");
                return Ok(());
            }
            observe_overhead(protocol, "response", answered.elapsed());

            // Capture the 101 exchange row (parent_event_id for all WS messages).
            let event_id = uuid::Uuid::now_v7();
            let host = parsed_req
                .host
                .clone()
                .unwrap_or_else(|| target_host.to_string());

            // Build captured response headers — reflect what we sent to the client,
            // not what the h2 upstream sent (which has no Sec-WebSocket-Accept).
            let ws_accept = compute_ws_accept(&client_ws_key);
            let mut captured_resp_headers = vec![
                ("upgrade".to_string(), "websocket".to_string()),
                ("connection".to_string(), "Upgrade".to_string()),
                ("sec-websocket-accept".to_string(), ws_accept),
            ];
            for (k, v) in &h2_resp_headers {
                if k.eq_ignore_ascii_case("sec-websocket-protocol")
                    || k.eq_ignore_ascii_case("sec-websocket-extensions")
                {
                    captured_resp_headers.push((k.clone(), v.clone()));
                }
            }

            let exchange = CapturedExchange {
                event_id,
                method: parsed_req.method.clone(),
                path: parsed_req.path.clone(),
                host: host.clone(),
                request_headers: captured_request_headers(&parsed_req.headers, max_header_capture),
                request_body: Bytes::new(),
                request_body_truncated: false,
                status: 101,
                response_headers: truncate_header_values(captured_resp_headers, max_header_capture),
                response_body: Bytes::new(),
                response_body_truncated: false,
                timestamp: exchange_ts,
                duration_ms: exchange_start.elapsed().as_millis() as u64,
            };
            let send_start = std::time::Instant::now();
            let _ = exchange_tx.send(exchange).await;
            observe_overhead(protocol, "capture_wait", send_start.elapsed());

            tracing::info!(%host, %event_id, "ws upgrade over h2 (RFC 8441) succeeded");

            // Hand off to proxy_websocket inline. ws_sink=None was already
            // intercepted above (502 sent); ws_sink is guaranteed Some here.
            let sink = ws_sink.expect("ws_sink checked above");
            let deflate = websocket::parse_extensions(&h2_resp_headers);
            let recv_stream = h2_resp.into_body();
            let upstream_io = h2_stream_io::H2StreamIo::new(send_stream, recv_stream);
            let ws_ctx = websocket::WsContext {
                parent_event_id: event_id,
                session_id: sink.session_id,
                proxy_id: sink.proxy_id.clone(),
                org_id: sink.org_id.clone(),
                source: sink.source.clone(),
                source_id: sink.source_id.clone(),
                host: host.clone(),
                capture_tx: sink.tx.clone(),
                max_payload_capture: sink.max_payload_capture,
                deflate,
                capture_control_frames: sink.capture_control_frames,
                exchange_ratelimit: sink.exchange_ratelimit.clone(),
            };
            drop(send_request);
            let client_inner = client.into_inner();
            if let Err(e) =
                websocket::proxy_websocket(client_inner, upstream_io, Vec::new(), ws_ctx).await
            {
                tracing::warn!(
                    error = ?e,
                    %host,
                    %event_id,
                    "proxy_websocket (h2) exited with error"
                );
            }
            let _ = conn_handle.await;
            return Ok(());
        }

        let req_wants_close = wants_close(&parsed_req.headers);

        // Read request body (bounded incremental, no CL-sized pre-alloc).
        // Body time is excluded from the `request` overhead phase.
        let req_framing = request_body_framing(&parsed_req.headers);
        let body_start = std::time::Instant::now();
        let (req_body_raw, request_body, request_body_truncated) = match read_full_body(
            &mut client,
            req_framing,
            &req_header_buf[req_header_len..],
            max_body_capture,
        )
        .await
        {
            Ok(read) => read,
            Err(err) if err.is::<BodyTooLarge>() => {
                tracing::warn!(host = %target_host, "request body over the buffered limit, sending 413");
                let _ = write_status_response(
                    client.get_mut(),
                    &parsed_req.method,
                    413,
                    "Content Too Large",
                    "request body too large",
                )
                .await;
                break;
            }
            Err(err) => return Err(err),
        };
        let body_read = body_start.elapsed();

        // Rate limit: acquire a token per exchange before forwarding.
        // Send a proper 429 response instead of bare-resetting. The wait is
        // policy, not overhead, so it is excluded from the `request` phase.
        let mut ratelimit_wait = Duration::ZERO;
        if let Some(rl) = &exchange_ratelimit {
            let rl_start = std::time::Instant::now();
            let acquired = rl.acquire().await;
            ratelimit_wait = rl_start.elapsed();
            observe_overhead(protocol, "ratelimit_wait", ratelimit_wait);
            if let Err(e) = acquired {
                tracing::warn!(error = %e, host = %target_host, "rate limit exceeded, sending 429");
                let _ = write_status_response(
                    client.get_mut(),
                    &parsed_req.method,
                    429,
                    "Too Many Requests",
                    "rate limit exceeded",
                )
                .await;
                break;
            }
        }

        // --- H1 → H2 request translation ---

        // Build an absolute URI so h2 can populate :scheme, :authority, :path.
        let uri = build_h2_uri(target_host, &parsed_req.path);
        let mut req_builder = http::Request::builder()
            .method(parsed_req.method.as_str())
            .uri(uri.as_str());

        // Translate headers: strip hop-by-hop headers that don't apply to H2.
        // H2 uses the :authority pseudo-header (derived from URI) instead of Host.
        for (name, value) in &parsed_req.headers {
            if matches!(
                name.to_ascii_lowercase().as_str(),
                "transfer-encoding"
                    | "connection"
                    | "keep-alive"
                    | "proxy-connection"
                    | "upgrade"
                    | "host"
            ) {
                continue;
            }
            req_builder = req_builder.header(name.as_str(), value.as_str());
        }

        // Inject custom headers after original headers
        for (name, value) in inject_headers {
            req_builder = req_builder.header(name.as_str(), value.as_str());
        }

        let has_body = !req_body_raw.is_empty();
        let h2_request = req_builder.body(()).context("failed to build h2 request")?;

        // Wait until the h2 connection can accept a new stream (respects MAX_CONCURRENT_STREAMS).
        observe_overhead(
            protocol,
            "request",
            exchange_start
                .elapsed()
                .saturating_sub(body_read + ratelimit_wait),
        );
        let upstream_req = UpstreamRequest::start(protocol);
        send_request = send_request
            .ready()
            .await
            .context("h2 connection not ready")?;

        // Send request headers; end_of_stream=true when there is no body.
        let (response_future, mut send_stream) = send_request
            .send_request(h2_request, !has_body)
            .context("h2 send_request failed")?;

        // Send request body if present.
        if has_body {
            send_stream
                .send_data(req_body_raw, true)
                .context("h2 send_data failed")?;
        }

        // Await response headers with upstream timeout (F2.1).
        let h2_response =
            match tokio::time::timeout(limits.upstream_response, response_future).await {
                Ok(Ok(r)) => r,
                Ok(Err(e)) => {
                    return Err(anyhow::anyhow!(e).context("h2 response failed"));
                }
                Err(_) => {
                    tracing::warn!(
                        host = %target_host,
                        method = %parsed_req.method,
                        path = %parsed_req.path,
                        "upstream h2 response header read timed out, sending 504"
                    );
                    let _ = write_status_response(
                        client.get_mut(),
                        &parsed_req.method,
                        504,
                        "Gateway Timeout",
                        "upstream did not send response headers in time",
                    )
                    .await;
                    break;
                }
            };
        let (response_parts, mut recv_body) = h2_response.into_parts();

        let status = response_parts.status.as_u16();
        let answered = upstream_req.response(status);
        let h2_headers = response_parts.headers;

        // --- Frame decision (made BEFORE any body bytes leave the proxy) ---
        //
        // HTTP/2 (RFC 7540 §8.1.2.6) makes Content-Length optional and forbids
        // Transfer-Encoding (§8.1.2.2).  HTTP/1.1 requires one of:
        // Content-Length, Transfer-Encoding: chunked, or Connection: close to
        // frame the body.  Choose:
        //   - upstream sent CL → forward verbatim, stream body 1:1
        //   - otherwise        → emit `Transfer-Encoding: chunked` and wrap
        //
        // RFC 9112 §6.1 / RFC 9110 §9.3.2: 1xx, 204, 304, and any response to
        // a HEAD request MUST NOT include a body.  Skip body forwarding for
        // these regardless of CL.  We still forward CL when present (HEAD
        // expects CL identical to the equivalent GET).
        let upstream_has_cl = h2_headers
            .iter()
            .any(|(n, _)| n.as_str().eq_ignore_ascii_case("content-length"));
        let body_forbidden = matches!(status, 100..=199 | 204 | 304)
            || parsed_req.method.eq_ignore_ascii_case("HEAD");
        let use_chunked = !upstream_has_cl && !body_forbidden;

        // --- Build H1 status line + header block ---
        //
        // We write raw bytes so non-ASCII header values are preserved.  The
        // previous implementation used `HeaderValue::to_str()` which silently
        // dropped any header value that wasn't visible-ASCII.
        let mut h1_resp_bytes: Vec<u8> = Vec::with_capacity(256 + h2_headers.len() * 64);
        h1_resp_bytes.extend_from_slice(
            format!(
                "HTTP/1.1 {} {}\r\n",
                status,
                response_parts
                    .status
                    .canonical_reason()
                    .unwrap_or("Unknown")
            )
            .as_bytes(),
        );
        for (name, value) in h2_headers.iter() {
            // H2 forbids Transfer-Encoding; strip it defensively to avoid
            // double-framing if a non-conforming upstream emitted it. Only
            // ProxyX may send PROXY_ERROR_HEADER (see `client_response_head`).
            if name.as_str().eq_ignore_ascii_case("transfer-encoding")
                || name.as_str().eq_ignore_ascii_case(PROXY_ERROR_HEADER)
            {
                continue;
            }
            h1_resp_bytes.extend_from_slice(name.as_str().as_bytes());
            h1_resp_bytes.extend_from_slice(b": ");
            h1_resp_bytes.extend_from_slice(value.as_bytes());
            h1_resp_bytes.extend_from_slice(b"\r\n");
        }
        if use_chunked {
            h1_resp_bytes.extend_from_slice(b"Transfer-Encoding: chunked\r\n");
        }
        // The connection has served its quota: tell the client to redial.
        served += 1;
        let quota_reached = limits.max_requests.is_some_and(|max| served >= max);
        if quota_reached {
            h1_resp_bytes.extend_from_slice(b"Connection: close\r\n");
        }
        h1_resp_bytes.extend_from_slice(b"\r\n");

        client.get_mut().write_all(&h1_resp_bytes).await?;
        observe_overhead(protocol, "response", answered.elapsed());

        // --- Stream the body ---
        //
        // Forward every byte to the client; capture only the first
        // `max_body_capture` bytes for the publisher.  This matches the
        // H1->H1 path: wire bytes are never truncated even when the
        // captured copy is.
        let mut captured: Vec<u8> = Vec::new();
        let mut response_body_truncated = false;

        while let Some(chunk) = tokio::time::timeout(limits.body_idle, recv_body.data())
            .await
            .context("h2 body read idle timeout")?
        {
            let chunk = chunk.context("h2 recv_data failed")?;
            // Release flow control unconditionally so the h2 connection
            // doesn't stall — even for bodyless responses where a
            // non-conforming upstream still sent DATA frames.
            recv_body
                .flow_control()
                .release_capacity(chunk.len())
                .context("h2 release_capacity failed")?;

            if body_forbidden || chunk.is_empty() {
                // Drain-and-discard for body_forbidden statuses; skip empty
                // chunks so we never emit a chunked terminator mid-stream.
                continue;
            }

            if use_chunked {
                let len_line = format!("{:x}\r\n", chunk.len());
                client.get_mut().write_all(len_line.as_bytes()).await?;
                client.get_mut().write_all(&chunk).await?;
                client.get_mut().write_all(b"\r\n").await?;
            } else {
                client.get_mut().write_all(&chunk).await?;
            }

            // Capture up to the cap.  Bytes past the cap are forwarded
            // but not stored.
            if captured.len() < max_body_capture {
                let take = chunk.len().min(max_body_capture - captured.len());
                captured.extend_from_slice(&chunk[..take]);
                if take < chunk.len() {
                    response_body_truncated = true;
                }
            } else {
                response_body_truncated = true;
            }
        }

        if use_chunked {
            // Final chunked terminator.  No trailers.
            client.get_mut().write_all(b"0\r\n\r\n").await?;
        }
        client.get_mut().flush().await?;

        let response_body = Bytes::from(captured);

        // Captured-exchange headers reflect what upstream actually sent.
        // Use lossy UTF-8 conversion so non-ASCII values become replacement
        // chars rather than disappearing entirely.
        let response_headers: Vec<(String, String)> = h2_headers
            .iter()
            .map(|(k, v)| {
                let val = String::from_utf8_lossy(v.as_bytes()).into_owned();
                (
                    k.as_str().to_string(),
                    truncate_header_value(val, max_header_capture),
                )
            })
            .collect();
        let exchange = CapturedExchange {
            event_id: uuid::Uuid::now_v7(),
            method: parsed_req.method,
            path: parsed_req.path,
            host: parsed_req.host.unwrap_or_else(|| target_host.to_string()),
            request_headers: truncate_header_values(parsed_req.headers, max_header_capture),
            request_body,
            request_body_truncated,
            status,
            response_headers,
            response_body,
            response_body_truncated,
            timestamp: exchange_ts,
            duration_ms: exchange_start.elapsed().as_millis() as u64,
        };
        let send_start = tokio::time::Instant::now();
        let _ = exchange_tx.send(exchange).await;
        let send_elapsed = send_start.elapsed();
        observe_overhead(protocol, "capture_wait", send_elapsed);
        if send_elapsed > Duration::from_secs(5) {
            tracing::warn!(
                elapsed_ms = send_elapsed.as_millis() as u64,
                host = %target_host,
                "exchange channel backpressure: send blocked >5s (H2 path)"
            );
        }
        has_exchanges = true;

        if req_wants_close || quota_reached {
            break;
        }

        // _serial_guard dropped here — lock released before next idle wait
    }

    // WS upgrades are handled inline above (return Ok(()) without reaching here).
    // This is the normal (non-WS) path cleanup.
    drop(send_request);
    let _ = client.into_inner().shutdown().await;
    let _ = conn_handle.await;
    Ok(())
}

/// Build an absolute URI for H2 requests from a target host and H1 request path.
///
/// H2 requires absolute URIs so the `http` crate can populate the :scheme,
/// :authority, and :path pseudo-headers correctly. This function produces
/// `https://<host><path>` for relative paths (the normal MITM CONNECT case).
fn build_h2_uri(host: &str, path: &str) -> String {
    if path.starts_with('/') {
        format!("https://{}{}", host, path)
    } else {
        // Absolute-form path (e.g. `*` for OPTIONS, or unusual proxy requests)
        format!("https://{}/{}", host, path)
    }
}

/// Compute the `Sec-WebSocket-Accept` value per RFC 6455 §4.2.2.
///
/// SHA-1(key + WS-GUID) encoded as Base64. We generate this ourselves rather
/// than relying on the upstream, which (per RFC 8441) does not send it.
fn compute_ws_accept(client_key: &str) -> String {
    use base64::Engine;
    use sha1::{Digest, Sha1};
    const WS_GUID: &str = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
    let mut hasher = Sha1::new();
    hasher.update(client_key.as_bytes());
    hasher.update(WS_GUID.as_bytes());
    base64::engine::general_purpose::STANDARD.encode(hasher.finalize())
}

/// Build an HTTP/2 Extended CONNECT request (RFC 8441) from an H1 WS upgrade.
///
/// Sets `Method::CONNECT` and inserts the `h2::ext::Protocol("websocket")`
/// extension. Hop-by-hop and WS-handshake headers are stripped; all other
/// application headers and injected headers are forwarded.
fn build_h2_extended_connect(
    parsed_req: &ParsedRequest,
    target_host: &str,
    inject_headers: &[(String, String)],
) -> Result<http::Request<()>> {
    let uri = build_h2_uri(target_host, &parsed_req.path);
    let mut req_builder = http::Request::builder()
        .method(http::Method::CONNECT)
        .uri(uri.as_str());

    for (name, value) in &parsed_req.headers {
        if matches!(
            name.to_ascii_lowercase().as_str(),
            "upgrade"
                | "connection"
                | "host"
                | "sec-websocket-key"
                | "transfer-encoding"
                | "keep-alive"
                | "proxy-connection"
                | "proxy-authorization"
        ) {
            continue;
        }
        req_builder = req_builder.header(name.as_str(), value.as_str());
    }
    for (name, value) in inject_headers {
        req_builder = req_builder.header(name.as_str(), value.as_str());
    }

    let mut request = req_builder
        .body(())
        .context("failed to build h2 extended connect request")?;
    // RFC 8441 §4: `:protocol` pseudo-header identifies the tunnelled protocol.
    request
        .extensions_mut()
        .insert(h2::ext::Protocol::from_static("websocket"));
    Ok(request)
}

/// Construct the HTTP/1.1 101 response the proxy sends to the client.
///
/// `Sec-WebSocket-Accept` is derived from the client's key (RFC 6455 §4.2.2).
/// `Sec-WebSocket-Protocol` and `Sec-WebSocket-Extensions` from the upstream
/// h2 response are passed through unchanged.
fn build_h1_101_response(client_ws_key: &str, upstream_h2_headers: &[(String, String)]) -> String {
    let accept = compute_ws_accept(client_ws_key);
    let mut resp = format!(
        "HTTP/1.1 101 Switching Protocols\r\n\
         Upgrade: websocket\r\n\
         Connection: Upgrade\r\n\
         Sec-WebSocket-Accept: {accept}\r\n"
    );
    for (k, v) in upstream_h2_headers {
        if k.eq_ignore_ascii_case("sec-websocket-protocol")
            || k.eq_ignore_ascii_case("sec-websocket-extensions")
        {
            resp.push_str(k);
            resp.push_str(": ");
            resp.push_str(v);
            resp.push_str("\r\n");
        }
    }
    resp.push_str("\r\n");
    resp
}

/// Run the WS upgrade handshake against a fresh HTTP/1.1 upstream connection.
///
/// Triggered when the original H2 upstream does not advertise RFC 8441
/// `SETTINGS_ENABLE_CONNECT_PROTOCOL=1` and a fallback dialer is configured.
///
/// The flow:
///   1. Dial fresh upstream via `dial(host, port)` (forces ALPN http/1.1).
///   2. Replay the original WS upgrade request bytes (with injected headers).
///   3. Parse the upstream response.  Forward it to the client.
///   4. If it's a 101 WS upgrade: capture exchange, hand off to `proxy_websocket`.
///   5. Otherwise: forward the (non-101) response and close.
///
/// `client_ws_key` is unused here (the upstream computes Sec-WebSocket-Accept
/// itself) but kept in the signature for symmetry with the H2 path.
#[allow(clippy::too_many_arguments)]
async fn run_h1_fallback_ws_upgrade<C>(
    mut client: BufReader<C>,
    dial: H1FallbackDial,
    target_host: &str,
    target_port: u16,
    parsed_req: &ParsedRequest,
    req_header_bytes: &[u8],
    inject_headers: &[(String, String)],
    exchange_tx: &mpsc::Sender<CapturedExchange>,
    exchange_start: std::time::Instant,
    exchange_ts: time::OffsetDateTime,
    max_header_capture: usize,
    ws_sink: Option<&WsCaptureSink>,
    _client_ws_key: &str,
) -> Result<()>
where
    C: AsyncRead + AsyncWriteExt + Unpin + Send + 'static,
{
    // 1. Dial fresh H1.1 upstream.
    let mut upstream_req = UpstreamRequest::start("websocket");
    let h1_upstream = match dial(target_host.to_string(), target_port).await {
        Ok(s) => s,
        Err(e) => {
            tracing::warn!(error = ?e, host = %target_host, port = target_port, "h1 fallback dial failed");
            let _ = client
                .get_mut()
                .write_all(&crate::listener::common::proxy_error_response(
                    502,
                    "Bad Gateway",
                    "h1.1 fallback dial failed",
                    &[],
                ))
                .await;
            let _ = client.get_mut().flush().await;
            return Ok(());
        }
    };
    let mut h1_upstream = BufReader::new(h1_upstream);

    // 2. Replay request headers (with injection) to upstream.
    // Upstream latency excludes the dial; a dial failure still counts as error.
    upstream_req.sent = std::time::Instant::now();
    let h1_request_bytes = build_request_with_injected_headers(req_header_bytes, inject_headers);
    if let Err(e) = h1_upstream.get_mut().write_all(&h1_request_bytes).await {
        tracing::warn!(error = ?e, host = %target_host, "h1 fallback: failed to write request");
        return Ok(());
    }
    if let Err(e) = h1_upstream.get_mut().flush().await {
        tracing::warn!(error = ?e, host = %target_host, "h1 fallback: failed to flush request");
        return Ok(());
    }

    // 3. Read upstream response headers.
    let (resp_header_buf, resp_header_len) = match read_http_headers(&mut h1_upstream, &[]).await {
        Ok((buf, len)) if len > 0 => (buf, len),
        Ok(_) => {
            tracing::warn!(host = %target_host, "h1 fallback: upstream closed without response");
            let _ = client
                .get_mut()
                .write_all(&crate::listener::common::proxy_error_response(
                    502,
                    "Bad Gateway",
                    "upstream closed without response",
                    &[],
                ))
                .await;
            let _ = client.get_mut().flush().await;
            return Ok(());
        }
        Err(e) => {
            tracing::warn!(error = ?e, host = %target_host, "h1 fallback: upstream read failed");
            let _ = client
                .get_mut()
                .write_all(&crate::listener::common::proxy_error_response(
                    502,
                    "Bad Gateway",
                    "upstream read failed",
                    &[],
                ))
                .await;
            let _ = client.get_mut().flush().await;
            return Ok(());
        }
    };
    let (parsed_resp, answered) = match parse_response(&resp_header_buf[..resp_header_len]) {
        Ok(r) => {
            let answered = upstream_req.response(r.status);
            (r, answered)
        }
        Err(e) => {
            tracing::warn!(error = ?e, host = %target_host, "h1 fallback: malformed upstream response");
            return Ok(());
        }
    };

    // F2.3: if ws_sink is not configured and this is a 101, do NOT forward
    // the upgrade — send a 502 instead so the client never sees a half-open
    // upgrade.
    let will_upgrade = is_ws_upgrade(
        &parsed_req.headers,
        parsed_resp.status,
        &parsed_resp.headers,
    );
    if will_upgrade && ws_sink.is_none() {
        tracing::warn!(
            host = %target_host,
            "h1 fallback: ws upgrade succeeded upstream but ws_sink not configured; sending 502 to client"
        );
        let _ = write_status_response(
            client.get_mut(),
            &parsed_req.method,
            502,
            "Bad Gateway",
            "upstream connection failed",
        )
        .await;
        let _ = client.into_inner().shutdown().await;
        return Ok(());
    }

    // Forward upstream response headers to client (so non-101 errors are surfaced).
    if let Err(e) = client
        .get_mut()
        .write_all(&client_response_head(
            &resp_header_buf[..resp_header_len],
            &parsed_resp.headers,
            false,
        ))
        .await
    {
        tracing::warn!(error = ?e, host = %target_host, "h1 fallback: failed to forward response headers to client");
        return Ok(());
    }
    observe_overhead("websocket", "response", answered.elapsed());

    // 4. If it's not a 101 WS upgrade, forward the non-101 body if present and close.
    if !will_upgrade {
        tracing::warn!(
            host = %target_host,
            status = parsed_resp.status,
            "h1 fallback: upstream did not perform WS upgrade"
        );
        // Forward over-read bytes from the response, then any remaining body.
        let extra = &resp_header_buf[resp_header_len..];
        if !extra.is_empty() {
            let _ = client.get_mut().write_all(extra).await;
        }
        // Best-effort drain of any remaining body to the client.
        let mut buf = [0u8; 8192];
        loop {
            match h1_upstream.read(&mut buf).await {
                Ok(0) => break,
                Ok(n) => {
                    if client.get_mut().write_all(&buf[..n]).await.is_err() {
                        break;
                    }
                }
                Err(_) => break,
            }
        }
        let _ = client.get_mut().flush().await;
        let _ = client.into_inner().shutdown().await;
        return Ok(());
    }

    // 5. Capture the 101 exchange row.
    let _ = client.get_mut().flush().await;
    let event_id = uuid::Uuid::now_v7();
    let host = parsed_req
        .host
        .clone()
        .unwrap_or_else(|| target_host.to_string());
    let exchange = CapturedExchange {
        event_id,
        method: parsed_req.method.clone(),
        path: parsed_req.path.clone(),
        host: host.clone(),
        request_headers: captured_request_headers(&parsed_req.headers, max_header_capture),
        request_body: Bytes::new(),
        request_body_truncated: false,
        status: parsed_resp.status,
        response_headers: truncate_header_values(parsed_resp.headers.clone(), max_header_capture),
        response_body: Bytes::new(),
        response_body_truncated: false,
        timestamp: exchange_ts,
        duration_ms: exchange_start.elapsed().as_millis() as u64,
    };
    let send_start = std::time::Instant::now();
    let _ = exchange_tx.send(exchange).await;
    observe_overhead("websocket", "capture_wait", send_start.elapsed());

    tracing::info!(%host, %event_id, "ws upgrade over h1.1 fallback succeeded");

    // 6. Hand off to proxy_websocket. ws_sink=None with a 101 was already
    //    intercepted above (502 sent); ws_sink is guaranteed Some here.
    let s2c_prefix = resp_header_buf[resp_header_len..].to_vec();
    let sink = ws_sink.expect("ws_sink checked above");
    let deflate = websocket::parse_extensions(&parsed_resp.headers);
    let ws_ctx = websocket::WsContext {
        parent_event_id: event_id,
        session_id: sink.session_id,
        proxy_id: sink.proxy_id.clone(),
        org_id: sink.org_id.clone(),
        source: sink.source.clone(),
        source_id: sink.source_id.clone(),
        host: host.clone(),
        capture_tx: sink.tx.clone(),
        max_payload_capture: sink.max_payload_capture,
        deflate,
        capture_control_frames: sink.capture_control_frames,
        exchange_ratelimit: sink.exchange_ratelimit.clone(),
    };
    let upstream_inner = h1_upstream.into_inner();
    let client_inner = client.into_inner();
    if let Err(e) =
        websocket::proxy_websocket(client_inner, upstream_inner, s2c_prefix, ws_ctx).await
    {
        tracing::warn!(
            error = ?e,
            %host,
            %event_id,
            "proxy_websocket (h1 fallback) exited with error"
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt, split};
    use tokio::net::{TcpListener, TcpStream};

    #[test]
    fn strips_proxy_authorization_and_connection() {
        let raw = b"GET http://example.com/path HTTP/1.1\r\n\
Host: example.com\r\n\
Proxy-Authorization: Basic c2Vzc2lvbg==\r\n\
Proxy-Connection: keep-alive\r\n\
User-Agent: curl/8\r\n\r\n";
        let out = strip_hop_by_hop_request_headers(raw);
        let text = String::from_utf8(out).unwrap();
        assert!(text.starts_with("GET /path HTTP/1.1\r\n"), "{text}");
        assert!(!text.to_ascii_lowercase().contains("proxy-authorization"));
        assert!(!text.to_ascii_lowercase().contains("proxy-connection"));
        assert!(text.contains("Host: example.com\r\n"));
        assert!(text.contains("User-Agent: curl/8\r\n"));
        assert!(text.ends_with("\r\n\r\n"));
    }

    #[test]
    fn absolute_form_targets_are_forwarded_in_origin_form() {
        let line = |raw: &str| {
            String::from_utf8(origin_form_request_line(raw.as_bytes()).into_owned()).unwrap()
        };
        assert_eq!(
            line("GET http://h:8080/a/b?x=1 HTTP/1.1"),
            "GET /a/b?x=1 HTTP/1.1"
        );
        assert_eq!(line("GET HTTP://h HTTP/1.1"), "GET / HTTP/1.1");
        assert_eq!(line("GET http://h?q=1 HTTP/1.1"), "GET /?q=1 HTTP/1.1");
        assert_eq!(line("POST https://h/p HTTP/1.1"), "POST /p HTTP/1.1");
        // Already origin-form, authority-form and asterisk-form stay as they are.
        assert_eq!(line("GET /p HTTP/1.1"), "GET /p HTTP/1.1");
        assert_eq!(line("CONNECT h:443 HTTP/1.1"), "CONNECT h:443 HTTP/1.1");
        assert_eq!(line("OPTIONS * HTTP/1.1"), "OPTIONS * HTTP/1.1");
    }

    fn client_head(raw: &[u8], close: bool) -> String {
        let parsed = parse_response(raw).unwrap();
        String::from_utf8(client_response_head(raw, &parsed.headers, close).into_owned()).unwrap()
    }

    /// A target must not be able to fake ProxyX's in-band proxy error.
    #[test]
    fn upstream_proxy_error_header_never_reaches_the_client() {
        let raw = b"HTTP/1.1 502 Bad Gateway\r\n\
x-proxyx-error: upstream_timeout\r\n\
Content-Length: 0\r\n\
Connection: keep-alive\r\n\r\n";

        let kept_open = client_head(raw, false);
        assert_eq!(
            kept_open,
            "HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\nConnection: keep-alive\r\n\r\n"
        );

        let closed = client_head(raw, true);
        assert_eq!(
            closed,
            "HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
        );
    }

    #[test]
    fn clean_upstream_head_passes_through_unchanged() {
        let raw = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: keep-alive\r\n\r\n";
        let parsed = parse_response(raw).unwrap();
        assert!(matches!(
            client_response_head(raw, &parsed.headers, false),
            std::borrow::Cow::Borrowed(head) if head == raw
        ));
        assert_eq!(
            client_head(raw, true),
            "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\n"
        );
    }

    #[test]
    fn injected_headers_appended_and_creds_stripped() {
        let raw = b"GET / HTTP/1.1\r\nHost: h\r\nProxy-Authorization: x\r\n\r\n";
        let out = build_request_with_injected_headers(
            raw,
            &[("X-Injected".to_string(), "yes".to_string())],
        );
        let text = String::from_utf8(out).unwrap();
        assert!(!text.to_ascii_lowercase().contains("proxy-authorization"));
        assert!(text.contains("X-Injected: yes\r\n"));
        assert!(text.contains("Host: h\r\n"));
    }

    /// Spin up a bare TCP h2 server, feed it an H1 request through proxy_h1_to_h2,
    /// and verify that (a) the H1 response is correctly reconstructed and (b) the
    /// exchange is captured with the right fields.
    ///
    /// This tests the protocol-translation layer in isolation.
    /// TLS is deliberately absent: the production code establishes TLS before calling
    /// proxy_h1_to_h2, so the underlying stream type is irrelevant here.
    #[tokio::test]
    async fn test_proxy_h1_to_h2_basic_get() {
        // 1. Bind a local h2 server over plain TCP.
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let server_addr = listener.local_addr().unwrap();

        // 2. Spawn the h2 server task.
        let server = tokio::spawn(async move {
            let (socket, _) = listener.accept().await.unwrap();
            let mut conn = h2::server::handshake(socket).await.unwrap();

            // Drive the connection with while-let so the server stays alive until
            // the proxy sends GOAWAY (after its exchange loop finishes). If we
            // exit immediately after send_data the Connection drop can tear down
            // the TCP socket before the proxy's driver has consumed all frames,
            // producing a "broken pipe" on the proxy side.
            while let Some(result) = conn.accept().await {
                let (req, mut respond) = result.unwrap();
                assert_eq!(req.method(), &http::Method::GET);
                assert_eq!(req.uri().path(), "/hello");
                // :authority pseudo-header must be set from the URI we build.
                assert_eq!(req.uri().authority().map(|a| a.as_str()), Some("test.host"));
                // Injected headers must reach the h2 upstream.
                assert_eq!(
                    req.headers()
                        .get("x-injected")
                        .and_then(|v| v.to_str().ok()),
                    Some("yes"),
                    "X-Injected header must be forwarded to h2 upstream"
                );
                // Host header must NOT be forwarded (replaced by :authority).
                assert!(
                    req.headers().get("host").is_none(),
                    "Host header must be stripped before forwarding to h2 upstream"
                );

                let response = http::Response::builder()
                    .status(200)
                    .header("content-length", "8")
                    .body(())
                    .unwrap();
                let mut send_body = respond.send_response(response, false).unwrap();
                send_body
                    .send_data(bytes::Bytes::from_static(b"hello h2"), true)
                    .unwrap();
            }
            // conn.accept() returned None: proxy sent GOAWAY, connection closing cleanly.
        });

        // 3. Connect the proxy's "upstream" TCP stream to the h2 server.
        let upstream = TcpStream::connect(server_addr).await.unwrap();

        // 4. Create an in-memory duplex channel to simulate the client-side H1 connection.
        //    Writing to test_writer is read by the proxy as incoming H1 bytes;
        //    the proxy's H1 response is readable from test_reader.
        let (client_stream, test_end) = tokio::io::duplex(65536);
        let (mut test_reader, mut test_writer) = split(test_end);

        let (exchange_tx, mut exchange_rx) = tokio::sync::mpsc::channel(8);

        // 5. Run proxy_h1_to_h2 in a background task.
        let proxy = tokio::spawn(async move {
            let client_buf = BufReader::new(client_stream);
            proxy_h1_to_h2(
                client_buf,
                upstream,
                "test.host",
                443,
                &[("X-Injected".to_string(), "yes".to_string())],
                exchange_tx,
                None,
                DEFAULT_MAX_BODY_CAPTURE,
                DEFAULT_MAX_BODY_CAPTURE, // max_header_capture
                None,                     // ws_sink
                None,                     // h1_fallback
                None,                     // serial_lock
                HttpLimits::default(),
            )
            .await
        });

        // 6. Write an H1 GET request.
        test_writer
            .write_all(b"GET /hello HTTP/1.1\r\nHost: test.host\r\nAccept: */*\r\n\r\n")
            .await
            .unwrap();

        // 7. Shutdown the write half so the proxy sees EOF after this one request
        //    and exits cleanly rather than waiting on the 30-second keepalive timeout.
        test_writer.shutdown().await.unwrap();

        // 8. Wait for the proxy to finish (it exits after seeing EOF on the client).
        proxy.await.unwrap().unwrap();

        // 9. Read the H1 response. The proxy has already written it; the duplex
        //    buffer holds it. Proxy task completion (step 8) dropped client_stream,
        //    so read_to_end will terminate.
        let mut response_bytes = Vec::new();
        test_reader.read_to_end(&mut response_bytes).await.unwrap();
        let response = String::from_utf8_lossy(&response_bytes);

        // 10. Wait for the h2 server task.
        server.await.unwrap();

        // 11. Verify the reconstructed H1 response.
        assert!(
            response.starts_with("HTTP/1.1 200"),
            "expected HTTP/1.1 200, got: {response:?}"
        );
        assert!(
            response.to_lowercase().contains("content-length: 8"),
            "expected Content-Length: 8 (case-insensitive — h2 lowercases header names), got: {response:?}"
        );
        assert!(
            response.ends_with("hello h2"),
            "expected body 'hello h2', got: {response:?}"
        );

        // 12. Verify the captured exchange.
        let exchange = exchange_rx.try_recv().expect("exchange must be captured");
        assert_eq!(exchange.method, "GET");
        assert_eq!(exchange.path, "/hello");
        assert_eq!(exchange.host, "test.host");
        assert_eq!(exchange.status, 200);
        assert_eq!(&exchange.response_body[..], b"hello h2");
        // Captured request_headers are the original H1 headers as sent by the client
        // (same semantics as the H1 path). Host IS present — stripping only applies
        // to what gets forwarded to the h2 upstream (:authority takes its place there).
        assert!(
            exchange
                .request_headers
                .iter()
                .any(|(k, _)| k.eq_ignore_ascii_case("host")),
            "Host header must be preserved in captured headers (reflects what client sent)"
        );
        // The h2 server verified :authority=test.host via the URI assertion above,
        // confirming the Host→:authority translation happened correctly upstream.

        // Injected headers are added to the forwarded h2 request but are NOT added to
        // the captured exchange (which records what the client sent, not what the proxy
        // added). The h2 server task above already asserted X-Injected reached upstream.
        assert!(
            !exchange
                .request_headers
                .iter()
                .any(|(k, _)| k == "X-Injected"),
            "injected headers must NOT appear in the captured exchange (proxy-added, not client-sent)"
        );
    }

    /// Regression: when an H2 upstream sends a body larger than `max_body_capture`,
    /// the H1 leg must still forward the full body so Content-Length framing stays
    /// intact. Only the captured-exchange copy is bounded.
    #[tokio::test]
    async fn test_proxy_h1_to_h2_large_body_not_truncated_on_wire() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let server_addr = listener.local_addr().unwrap();

        const CAP: usize = 4 * 1024;
        const BODY_LEN: usize = 32 * 1024;
        let body = vec![0xABu8; BODY_LEN];
        let body_for_server = body.clone();

        let server = tokio::spawn(async move {
            let (socket, _) = listener.accept().await.unwrap();
            let mut conn = h2::server::handshake(socket).await.unwrap();
            while let Some(result) = conn.accept().await {
                let (_req, mut respond) = result.unwrap();
                let response = http::Response::builder()
                    .status(200)
                    .header("content-length", body_for_server.len().to_string())
                    .body(())
                    .unwrap();
                let mut send_body = respond.send_response(response, false).unwrap();
                send_body
                    .send_data(bytes::Bytes::from(body_for_server.clone()), true)
                    .unwrap();
            }
        });

        let upstream = TcpStream::connect(server_addr).await.unwrap();
        let (client_stream, test_end) = tokio::io::duplex(BODY_LEN * 4);
        let (mut test_reader, mut test_writer) = split(test_end);
        let (exchange_tx, mut exchange_rx) = tokio::sync::mpsc::channel(8);

        let proxy = tokio::spawn(async move {
            let client_buf = BufReader::new(client_stream);
            proxy_h1_to_h2(
                client_buf,
                upstream,
                "test.host",
                443,
                &[],
                exchange_tx,
                None,
                CAP,
                CAP, // max_header_capture
                None,
                None,
                None, // serial_lock
                HttpLimits::default(),
            )
            .await
        });

        test_writer
            .write_all(b"GET /big HTTP/1.1\r\nHost: test.host\r\n\r\n")
            .await
            .unwrap();
        test_writer.shutdown().await.unwrap();
        proxy.await.unwrap().unwrap();

        let mut response_bytes = Vec::new();
        test_reader.read_to_end(&mut response_bytes).await.unwrap();
        server.await.unwrap();

        // Headers must advertise the real body length, body bytes must match.
        let header_end = response_bytes
            .windows(4)
            .position(|w| w == b"\r\n\r\n")
            .expect("response must have header terminator");
        let header_str = String::from_utf8_lossy(&response_bytes[..header_end]);
        assert!(
            header_str
                .lines()
                .any(|l| l.eq_ignore_ascii_case(&format!("Content-Length: {BODY_LEN}"))),
            "Content-Length must advertise full upstream body length, got headers: {header_str}"
        );
        let forwarded_body = &response_bytes[header_end + 4..];
        assert_eq!(
            forwarded_body.len(),
            BODY_LEN,
            "H1 client must receive full body bytes despite max_body_capture cap"
        );
        assert_eq!(forwarded_body, &body[..], "body bytes must match upstream");

        // Captured exchange must be truncated to the cap.
        let exchange = exchange_rx.try_recv().expect("exchange must be captured");
        assert!(
            exchange.response_body_truncated,
            "captured response body must be flagged truncated"
        );
        assert_eq!(
            exchange.response_body.len(),
            CAP,
            "captured response body must be bounded by max_body_capture"
        );
    }

    // -----------------------------------------------------------------------
    // Memory diagnostics tests
    //
    // These tests quantify the memory amplification in the MITM body path.
    // Run with: cargo test -p proxy memory_diag -- --nocapture --ignored
    // -----------------------------------------------------------------------

    /// Read RSS (Resident Set Size) from /proc/self/statm.
    /// Returns bytes. Falls back to 0 on non-Linux.
    fn rss_bytes() -> usize {
        std::fs::read_to_string("/proc/self/statm")
            .ok()
            .and_then(|s| s.split_whitespace().nth(1)?.parse::<usize>().ok())
            .map(|pages| pages * 4096)
            .unwrap_or(0)
    }

    /// Force the allocator to return memory to the OS so RSS reflects
    /// actual live allocations rather than cached free pages.
    fn stabilize_rss() {
        // Multiple small alloc/dealloc cycles + explicit trim hint.
        // malloc_trim is glibc-specific; on other allocators this is a no-op.
        for _ in 0..3 {
            let _: Vec<Vec<u8>> = (0..100).map(|_| vec![0u8; 4096]).collect();
        }
        std::thread::sleep(std::time::Duration::from_millis(50));
    }

    /// Build an HTTP/1.1 request with a body of `body_size` bytes.
    fn make_h1_request(host: &str, path: &str, body: &[u8]) -> Vec<u8> {
        let req = format!(
            "POST {} HTTP/1.1\r\nHost: {}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            path,
            host,
            body.len()
        );
        let mut out = req.into_bytes();
        out.extend_from_slice(body);
        out
    }

    /// Build an HTTP/1.1 response with a body of `body_size` bytes.
    fn make_h1_response(body: &[u8]) -> Vec<u8> {
        let hdr = format!(
            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            body.len()
        );
        let mut out = hdr.into_bytes();
        out.extend_from_slice(body);
        out
    }

    /// Helper: run a single-exchange fake HTTP server.
    /// Reads one full HTTP request (headers + content-length body), responds, then closes.
    async fn run_fake_http_server(listener: TcpListener, resp_data: Vec<u8>) {
        let (mut socket, _) = listener.accept().await.unwrap();
        let mut buf = vec![0u8; 64 * 1024];
        let mut header_buf = Vec::new();

        // Read until headers are complete
        loop {
            let n = socket.read(&mut buf).await.unwrap();
            if n == 0 {
                return;
            }
            header_buf.extend_from_slice(&buf[..n]);
            if header_buf.windows(4).any(|w| w == b"\r\n\r\n") {
                break;
            }
        }

        // Parse content-length and drain remaining body bytes
        let header_str = String::from_utf8_lossy(&header_buf);
        let cl: usize = header_str
            .lines()
            .find(|l| l.to_lowercase().starts_with("content-length:"))
            .and_then(|l| l.split(':').nth(1)?.trim().parse().ok())
            .unwrap_or(0);

        let header_end = header_buf
            .windows(4)
            .position(|w| w == b"\r\n\r\n")
            .map(|p| p + 4)
            .unwrap_or(header_buf.len());
        let body_read = header_buf.len() - header_end;
        let mut remaining = cl.saturating_sub(body_read);
        while remaining > 0 {
            let chunk = remaining.min(buf.len());
            let n = socket.read(&mut buf[..chunk]).await.unwrap();
            if n == 0 {
                return;
            }
            remaining -= n;
        }

        socket.write_all(&resp_data).await.unwrap();
        socket.shutdown().await.ok();
    }

    /// Diagnose: body memory amplification (historical).
    ///
    /// Sends a single exchange with a 5 MB request body and 5 MB response
    /// body through the H1 keep-alive proxy loop. Measures the RSS delta
    /// to reveal how much memory the proxy allocates beyond the raw data.
    ///
    /// With streaming, memory should be bounded by O(STREAM_CHUNK + max_body_capture).
    #[tokio::test]
    #[ignore = "memory diagnostic — run with --nocapture --ignored"]
    async fn memory_diag_body_clone_amplification() {
        const BODY_SIZE: usize = 5 * 1024 * 1024; // 5 MB
        let req_body = vec![0x41u8; BODY_SIZE]; // 'A' repeated
        let resp_body = vec![0x42u8; BODY_SIZE]; // 'B' repeated

        // Spin up a fake upstream that reads the request and sends a canned response
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let server_addr = listener.local_addr().unwrap();
        let resp_data = make_h1_response(&resp_body);

        let server = tokio::spawn(run_fake_http_server(listener, resp_data));

        // Build client-side request bytes
        let request_bytes = make_h1_request("test.local", "/upload", &req_body);

        // Drop the large source buffers before measuring so they don't
        // pollute the baseline.
        drop(req_body);
        drop(resp_body);
        stabilize_rss();
        let rss_before = rss_bytes();

        // Create in-memory duplex for the client side
        let (client_stream, test_end) = tokio::io::duplex(256 * 1024);
        let (mut test_reader, mut test_writer) = split(test_end);
        let (exchange_tx, mut exchange_rx) = tokio::sync::mpsc::channel(8);

        // Connect to fake upstream
        let upstream = TcpStream::connect(server_addr).await.unwrap();

        let proxy = tokio::spawn(async move {
            let client_buf = BufReader::new(client_stream);
            let upstream_buf = BufReader::new(upstream);
            proxy_http_keepalive(
                client_buf.into_inner(),
                upstream_buf.into_inner(),
                "test.local",
                &[],
                exchange_tx,
                None,
                DEFAULT_MAX_BODY_CAPTURE,
                DEFAULT_MAX_BODY_CAPTURE, // max_header_capture
                None,
                None, // serial_lock
                false,
                "http",
                HttpLimits::default(),
            )
            .await
            .map(|_| ())
        });

        // Write request and close
        test_writer.write_all(&request_bytes).await.unwrap();
        test_writer.shutdown().await.unwrap();

        // Read response (we don't need to inspect it)
        let mut response = Vec::new();
        test_reader.read_to_end(&mut response).await.unwrap();

        proxy.await.unwrap().unwrap();
        server.await.unwrap();

        // Measure RSS while the exchange is still alive in the channel
        stabilize_rss();
        let rss_after = rss_bytes();
        let rss_delta = rss_after.saturating_sub(rss_before);

        // Collect exchange
        let exchange = exchange_rx.try_recv().expect("exchange must be captured");

        let input_data_size = BODY_SIZE * 2; // req + resp bodies
        let captured_size = exchange.request_body.len() + exchange.response_body.len();
        let amplification = if input_data_size > 0 {
            rss_delta as f64 / input_data_size as f64
        } else {
            0.0
        };

        println!("\n=== memory_diag_body_clone_amplification ===");
        println!(
            "  Input body size:      {} MB (req) + {} MB (resp)",
            BODY_SIZE / 1024 / 1024,
            BODY_SIZE / 1024 / 1024
        );
        println!(
            "  Captured req body:    {} MB",
            exchange.request_body.len() / 1024 / 1024
        );
        println!(
            "  Captured resp body:   {} MB",
            exchange.response_body.len() / 1024 / 1024
        );
        println!("  RSS before:           {} MB", rss_before / 1024 / 1024);
        println!("  RSS after:            {} MB", rss_after / 1024 / 1024);
        println!("  RSS delta:            {} MB", rss_delta / 1024 / 1024);
        println!(
            "  Amplification factor: {:.1}x (RSS delta / input data)",
            amplification
        );
        println!("  Captured data total:  {} MB", captured_size / 1024 / 1024);
        println!();

        // The exchange should have captured the full bodies
        assert_eq!(
            exchange.request_body.len(),
            BODY_SIZE,
            "request body truncated"
        );
        assert_eq!(
            exchange.response_body.len(),
            BODY_SIZE,
            "response body truncated"
        );

        // DIAGNOSTIC ASSERTION: If amplification > 1.5x, the clone bug is present.
        // After fixing, this should be close to 1.0x.
        if amplification > 1.5 {
            println!(
                "  ** DIAGNOSIS: Memory amplification {:.1}x exceeds 1.5x target.",
                amplification
            );
            println!("     Root cause: full body buffering before streaming was added.");
            println!(
                "     Expected: ~{} MB RSS delta for {} MB input.",
                input_data_size / 1024 / 1024,
                input_data_size / 1024 / 1024
            );
        }
    }

    /// Diagnose: unbounded exchange channel accumulation.
    ///
    /// Simulates a fast-producing MITM tunnel sending many exchanges into
    /// an unbounded channel with a slow consumer. Measures how much memory
    /// the queued exchanges consume.
    #[tokio::test]
    #[ignore = "memory diagnostic — run with --nocapture --ignored"]
    async fn memory_diag_unbounded_channel_accumulation() {
        const NUM_EXCHANGES: usize = 200;
        const BODY_SIZE: usize = 256 * 1024; // 256 KB per body

        stabilize_rss();
        let rss_before = rss_bytes();

        // Create an unbounded channel (same as production code)
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<CapturedExchange>();

        // Rapidly produce exchanges — simulates a fast tunnel
        for i in 0..NUM_EXCHANGES {
            let exchange = CapturedExchange {
                event_id: uuid::Uuid::now_v7(),
                method: "GET".to_string(),
                path: format!("/page/{}", i),
                host: "target.com".to_string(),
                request_headers: vec![
                    ("Host".to_string(), "target.com".to_string()),
                    ("User-Agent".to_string(), "test".to_string()),
                ],
                request_body: Bytes::from(vec![0x41u8; BODY_SIZE]),
                request_body_truncated: false,
                status: 200,
                response_headers: vec![
                    (
                        "Content-Type".to_string(),
                        "application/octet-stream".to_string(),
                    ),
                    ("Content-Length".to_string(), BODY_SIZE.to_string()),
                ],
                response_body: Bytes::from(vec![0x42u8; BODY_SIZE]),
                response_body_truncated: false,
                timestamp: time::OffsetDateTime::now_utc(),
                duration_ms: 50,
            };
            tx.send(exchange).unwrap();
        }

        stabilize_rss();
        let rss_with_queue = rss_bytes();
        let rss_queued_delta = rss_with_queue.saturating_sub(rss_before);

        let expected_min = NUM_EXCHANGES * BODY_SIZE * 2; // req + resp bodies
        let queued_mb = rss_queued_delta as f64 / (1024.0 * 1024.0);
        let expected_mb = expected_min as f64 / (1024.0 * 1024.0);

        println!("\n=== memory_diag_unbounded_channel_accumulation ===");
        println!("  Exchanges queued:     {}", NUM_EXCHANGES);
        println!(
            "  Body size:            {} KB each (req + resp)",
            BODY_SIZE / 1024 * 2
        );
        println!("  RSS before:           {} MB", rss_before / 1024 / 1024);
        println!(
            "  RSS with queue:       {} MB",
            rss_with_queue / 1024 / 1024
        );
        println!("  RSS delta (queued):   {:.1} MB", queued_mb);
        println!(
            "  Minimum expected:     {:.1} MB (just body data)",
            expected_mb
        );

        // Now drain the channel and measure release
        let mut count = 0;
        while rx.try_recv().is_ok() {
            count += 1;
        }
        drop(rx);
        drop(tx);
        assert_eq!(count, NUM_EXCHANGES);

        stabilize_rss();
        let rss_after_drain = rss_bytes();
        let rss_released = rss_with_queue.saturating_sub(rss_after_drain);

        println!(
            "  RSS after drain:      {} MB",
            rss_after_drain / 1024 / 1024
        );
        println!(
            "  RSS released:         {:.1} MB",
            rss_released as f64 / (1024.0 * 1024.0)
        );
        println!();

        if rss_queued_delta > expected_min {
            println!(
                "  ** DIAGNOSIS: Unbounded channel held {:.1} MB for {} exchanges.",
                queued_mb, NUM_EXCHANGES
            );
            println!(
                "     With a bounded channel(16), max would be {:.1} MB.",
                16.0 * BODY_SIZE as f64 * 2.0 / (1024.0 * 1024.0)
            );
        }
    }

    /// Diagnose: pipeline event clones bodies from CapturedExchange.
    ///
    /// Simulates the publisher path in `run_mitm_intercept` (connect.rs)
    /// that clones body data from CapturedExchange into PipelineEvent.
    /// Measures the memory cost of this clone step.
    #[tokio::test]
    #[ignore = "memory diagnostic — run with --nocapture --ignored"]
    async fn memory_diag_pipeline_event_clone() {
        use crate::pipeline::{PipelineEvent, SessionMetadata, TimingInfo};

        const BODY_SIZE: usize = 5 * 1024 * 1024; // 5 MB

        // Simulate what run_mitm_intercept does: create a CapturedExchange,
        // then clone its bodies into a PipelineEvent.
        let exchange = CapturedExchange {
            event_id: uuid::Uuid::now_v7(),
            method: "POST".to_string(),
            path: "/api/data".to_string(),
            host: "api.example.com".to_string(),
            request_headers: vec![("Content-Type".to_string(), "application/json".to_string())],
            request_body: Bytes::from(vec![0x41u8; BODY_SIZE]),
            request_body_truncated: false,
            status: 200,
            response_headers: vec![("Content-Type".to_string(), "application/json".to_string())],
            response_body: Bytes::from(vec![0x42u8; BODY_SIZE]),
            response_body_truncated: false,
            timestamp: time::OffsetDateTime::now_utc(),
            duration_ms: 100,
        };

        stabilize_rss();
        let rss_before = rss_bytes();

        // This mirrors connect.rs lines 397-430: clone bodies into PipelineEvent
        let event = PipelineEvent {
            event_id: uuid::Uuid::now_v7(),
            session_id: uuid::Uuid::nil(),
            proxy_id: "proxy-1".to_string(),
            timestamp: time::OffsetDateTime::now_utc(),
            method: exchange.method.clone(),
            scheme: "https".to_string(),
            host: exchange.host.clone(),
            port: 443,
            path: exchange.path.clone(),
            request_headers: exchange.request_headers.clone(),
            request_body: exchange.request_body.clone(),
            request_body_size: exchange.request_body.len() as u64,
            request_body_truncated: exchange.request_body_truncated,
            response_status: exchange.status as u32,
            response_status_text: String::new(),
            response_headers: exchange.response_headers.clone(),
            response_body: exchange.response_body.clone(),
            response_body_size: exchange.response_body.len() as u64,
            response_body_truncated: exchange.response_body_truncated,
            timing: TimingInfo {
                total_ms: exchange.duration_ms,
                ..Default::default()
            },
            metadata: SessionMetadata {
                org_id: "org-1".to_string(),
                source: "test".to_string(),
                source_id: "scan-1".to_string(),
            },
        };

        stabilize_rss();
        let rss_with_both = rss_bytes();

        // Both exchange and event are alive — bodies exist twice
        let exchange_body_total = exchange.request_body.len() + exchange.response_body.len();
        let event_body_total = event.request_body.len() + event.response_body.len();
        let rss_delta = rss_with_both.saturating_sub(rss_before);

        println!("\n=== memory_diag_pipeline_event_clone ===");
        println!(
            "  Body size:            {} MB (req) + {} MB (resp)",
            BODY_SIZE / 1024 / 1024,
            BODY_SIZE / 1024 / 1024
        );
        println!(
            "  Exchange bodies:      {} MB",
            exchange_body_total / 1024 / 1024
        );
        println!(
            "  Event bodies (clone): {} MB",
            event_body_total / 1024 / 1024
        );
        println!(
            "  Both alive:           {} MB total body data",
            (exchange_body_total + event_body_total) / 1024 / 1024
        );
        println!("  RSS delta:            {} MB", rss_delta / 1024 / 1024);

        // Now simulate what happens in production: exchange is dropped
        // after the pipeline event is created, but the event lives on
        // in the pipeline channel.
        drop(exchange);
        stabilize_rss();
        let rss_event_only = rss_bytes();
        let released = rss_with_both.saturating_sub(rss_event_only);

        println!(
            "  RSS after drop exch:  {} MB",
            rss_event_only / 1024 / 1024
        );
        println!("  Released by drop:     {} MB", released / 1024 / 1024);
        println!();

        println!("  ** DIAGNOSIS: Cloning bodies from CapturedExchange into PipelineEvent");
        println!(
            "     duplicates {} MB of body data. Using Arc<Vec<u8>> or Bytes",
            (BODY_SIZE * 2) / 1024 / 1024
        );
        println!("     would make this clone O(1) instead of O(n).");

        // Verify the clone actually happened (not optimized away)
        assert_eq!(event.request_body.len(), BODY_SIZE);
        assert_eq!(event.response_body.len(), BODY_SIZE);
    }

    /// Helper: keep-alive HTTP response (no Connection: close).
    fn make_h1_keepalive_response(body: &[u8]) -> Vec<u8> {
        let hdr = format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n", body.len());
        let mut out = hdr.into_bytes();
        out.extend_from_slice(body);
        out
    }

    /// Helper: keep-alive HTTP request (no Connection: close).
    fn make_h1_keepalive_request(host: &str, path: &str, body: &[u8]) -> Vec<u8> {
        let req = format!(
            "POST {} HTTP/1.1\r\nHost: {}\r\nContent-Length: {}\r\n\r\n",
            path,
            host,
            body.len()
        );
        let mut out = req.into_bytes();
        out.extend_from_slice(body);
        out
    }

    /// Send `request` to an H1 keep-alive proxy whose upstream accepts the
    /// connection but never answers, and return everything the client reads.
    async fn read_reply_from_silent_upstream(request: &[u8]) -> Vec<u8> {
        let (mut client, proxy_client) = tokio::io::duplex(64 * 1024);
        // Held open and never written: the upstream stays silent.
        let (_upstream, proxy_upstream) = tokio::io::duplex(64 * 1024);
        let (exchange_tx, _exchange_rx) = tokio::sync::mpsc::channel(8);

        let proxy = tokio::spawn(async move {
            proxy_http_keepalive(
                proxy_client,
                proxy_upstream,
                "test.local",
                &[],
                exchange_tx,
                None,
                DEFAULT_MAX_BODY_CAPTURE,
                DEFAULT_MAX_BODY_CAPTURE, // max_header_capture
                None,
                None, // serial_lock
                false,
                "http",
                HttpLimits::default(),
            )
            .await
            .map(|_| ())
        });

        client.write_all(request).await.unwrap();
        let mut resp = Vec::new();
        client.read_to_end(&mut resp).await.unwrap();
        proxy.await.unwrap().unwrap();
        resp
    }

    /// An upstream that accepts the request but never answers must get the
    /// client a 504 from the proxy, not a bare connection close.
    #[tokio::test(start_paused = true)]
    async fn test_h1_upstream_header_timeout_sends_504() {
        let resp =
            read_reply_from_silent_upstream(&make_h1_keepalive_request("test.local", "/slow", b""))
                .await;

        assert!(
            resp.starts_with(b"HTTP/1.1 504 Gateway Timeout\r\n"),
            "expected 504, got: {}",
            String::from_utf8_lossy(&resp)
        );
    }

    /// The 504 for a HEAD request must stop after the headers.
    #[tokio::test(start_paused = true)]
    async fn test_h1_upstream_header_timeout_head_504_has_no_body() {
        let resp =
            read_reply_from_silent_upstream(b"HEAD /slow HTTP/1.1\r\nHost: test.local\r\n\r\n")
                .await;

        assert!(
            resp.starts_with(b"HTTP/1.1 504 Gateway Timeout\r\n"),
            "expected 504, got: {}",
            String::from_utf8_lossy(&resp)
        );
        assert_eq!(
            crate::listener::common::find_double_crlf(&resp),
            Some(resp.len()),
            "HEAD reply must end after the headers, got: {}",
            String::from_utf8_lossy(&resp)
        );
    }

    /// An upstream that sends headers and part of the body, then goes silent,
    /// must release the connection after BODY_IDLE_TIMEOUT with an error.
    #[tokio::test(start_paused = true)]
    async fn test_h1_response_body_stall_times_out() {
        let (mut client, proxy_client) = tokio::io::duplex(64 * 1024);
        let (mut upstream, proxy_upstream) = tokio::io::duplex(64 * 1024);
        let (exchange_tx, _exchange_rx) = tokio::sync::mpsc::channel(8);

        let proxy = tokio::spawn(async move {
            proxy_http_keepalive(
                proxy_client,
                proxy_upstream,
                "test.local",
                &[],
                exchange_tx,
                None,
                DEFAULT_MAX_BODY_CAPTURE,
                DEFAULT_MAX_BODY_CAPTURE, // max_header_capture
                None,
                None, // serial_lock
                false,
                "http",
                HttpLimits::default(),
            )
            .await
            .map(|_| ())
        });

        client
            .write_all(&make_h1_keepalive_request("test.local", "/stall", b""))
            .await
            .unwrap();
        // Read the forwarded request, then send 10 of the 100 promised bytes.
        let mut buf = vec![0u8; 4096];
        let _ = upstream.read(&mut buf).await.unwrap();
        upstream
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\n0123456789")
            .await
            .unwrap();

        let err = proxy.await.unwrap().unwrap_err();
        assert!(
            format!("{err:#}").contains("body read idle timeout"),
            "unexpected error: {err:#}"
        );
    }

    /// A client that connects but never sends a ClientHello must be released
    /// after TLS_HANDSHAKE_TIMEOUT.
    #[tokio::test(start_paused = true)]
    async fn test_client_tls_handshake_times_out() {
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
        let ca_dir =
            std::env::temp_dir().join(format!("proxyx-mitm-test-{}", uuid::Uuid::new_v4()));
        let ca = crate::ca::load(&crate::config::CaConfig::Generate {
            data_dir: ca_dir.clone(),
        })
        .unwrap();
        let handler = MitmHandler::new(
            Arc::new(ca),
            DEFAULT_MAX_BODY_CAPTURE,
            DEFAULT_MAX_BODY_CAPTURE,
            crate::egress::Egress::new(
                &crate::config::NetworkConfig::default(),
                &crate::breaker::BreakerConfig::default(),
            ),
            &crate::config::NetworkConfig::default(),
        )
        .unwrap();

        let (_client, proxy_client) = tokio::io::duplex(1024);
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let upstream = TcpStream::connect(listener.local_addr().unwrap())
            .await
            .unwrap();
        let (exchange_tx, _exchange_rx) = tokio::sync::mpsc::channel(8);

        let err = handler
            .intercept(
                proxy_client,
                upstream,
                MitmParams {
                    host: "test.local",
                    port: 443,
                    inject_headers: &[],
                    tls_profile: TlsProfile::Chrome133,
                    exchange_tx,
                    exchange_ratelimit: None,
                    ws_sink: None,
                    serial_lock: None,
                    egress_proxy: None,
                    upstream_tls: true,
                },
            )
            .await
            .unwrap_err();
        assert!(
            format!("{err:#}").contains("client TLS handshake for test.local timed out"),
            "unexpected error: {err:#}"
        );
        let _ = std::fs::remove_dir_all(ca_dir);
    }

    /// Helper: run a multi-exchange fake HTTP server over keep-alive.
    /// Reads `count` full HTTP requests, responds to each, then waits for close.
    async fn run_fake_keepalive_server(listener: TcpListener, resp_data: Vec<u8>, count: usize) {
        let (mut socket, _) = listener.accept().await.unwrap();
        let mut buf = vec![0u8; 64 * 1024];

        for _ in 0..count {
            let mut header_buf = Vec::new();
            loop {
                let n = socket.read(&mut buf).await.unwrap();
                if n == 0 {
                    return;
                }
                header_buf.extend_from_slice(&buf[..n]);
                if header_buf.windows(4).any(|w| w == b"\r\n\r\n") {
                    break;
                }
            }

            let header_str = String::from_utf8_lossy(&header_buf);
            let cl: usize = header_str
                .lines()
                .find(|l| l.to_lowercase().starts_with("content-length:"))
                .and_then(|l| l.split(':').nth(1)?.trim().parse().ok())
                .unwrap_or(0);

            let header_end = header_buf
                .windows(4)
                .position(|w| w == b"\r\n\r\n")
                .map(|p| p + 4)
                .unwrap_or(header_buf.len());
            let body_read = header_buf.len() - header_end;
            let mut remaining = cl.saturating_sub(body_read);
            while remaining > 0 {
                let chunk = remaining.min(buf.len());
                let n = socket.read(&mut buf[..chunk]).await.unwrap();
                if n == 0 {
                    return;
                }
                remaining -= n;
            }

            if socket.write_all(&resp_data).await.is_err() {
                return;
            }
        }
        // Wait for client to close
        let _ = socket.read(&mut buf).await;
    }

    /// Diagnose: full pipeline memory — end-to-end from proxy_http_keepalive
    /// through CapturedExchange channel to PipelineEvent construction.
    ///
    /// Sends multiple large exchanges through the MITM loop and measures
    /// peak RSS to show the combined effect of all amplification sources.
    #[tokio::test]
    #[ignore = "memory diagnostic — run with --nocapture --ignored"]
    async fn memory_diag_full_pipeline_peak() {
        const NUM_EXCHANGES: usize = 20;
        const BODY_SIZE: usize = 2 * 1024 * 1024; // 2 MB each

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let server_addr = listener.local_addr().unwrap();
        let resp_body = vec![0x42u8; BODY_SIZE];
        let resp_data = make_h1_keepalive_response(&resp_body);

        let server = tokio::spawn(run_fake_keepalive_server(
            listener,
            resp_data,
            NUM_EXCHANGES,
        ));

        // Build all request bytes (keep-alive framing — no Connection: close)
        let req_body = vec![0x41u8; BODY_SIZE];
        let single_req = make_h1_keepalive_request("test.local", "/data", &req_body);
        let mut all_requests = Vec::new();
        for _ in 0..NUM_EXCHANGES {
            all_requests.extend_from_slice(&single_req);
        }
        drop(req_body);
        drop(resp_body);

        stabilize_rss();
        let rss_before = rss_bytes();

        let (client_stream, test_end) = tokio::io::duplex(512 * 1024);
        let (mut test_reader, mut test_writer) = split(test_end);
        let (exchange_tx, mut exchange_rx) = tokio::sync::mpsc::channel(8);

        let upstream = TcpStream::connect(server_addr).await.unwrap();

        // Write requests in background
        let writer = tokio::spawn(async move {
            test_writer.write_all(&all_requests).await.unwrap();
            test_writer.shutdown().await.unwrap();
        });

        // Read responses in background
        let reader = tokio::spawn(async move {
            let mut response = Vec::new();
            test_reader.read_to_end(&mut response).await.unwrap();
            response.len()
        });

        // Run proxy
        let proxy = tokio::spawn(async move {
            let client_buf = BufReader::new(client_stream);
            let upstream_buf = BufReader::new(upstream);
            proxy_http_keepalive(
                client_buf.into_inner(),
                upstream_buf.into_inner(),
                "test.local",
                &[],
                exchange_tx,
                None,
                DEFAULT_MAX_BODY_CAPTURE,
                DEFAULT_MAX_BODY_CAPTURE, // max_header_capture
                None,
                None, // serial_lock
                false,
                "http",
                HttpLimits::default(),
            )
            .await
            .map(|_| ())
        });

        proxy.await.unwrap().unwrap();
        writer.await.unwrap();
        let resp_len = reader.await.unwrap();
        server.await.unwrap();

        // All exchanges are now sitting in the unbounded channel
        stabilize_rss();
        let rss_peak = rss_bytes();
        let rss_delta = rss_peak.saturating_sub(rss_before);

        // Drain and count
        let mut exchanges = Vec::new();
        while let Ok(ex) = exchange_rx.try_recv() {
            exchanges.push(ex);
        }

        let total_captured: usize = exchanges
            .iter()
            .map(|e| e.request_body.len() + e.response_body.len())
            .sum();
        let raw_data_size = NUM_EXCHANGES * BODY_SIZE * 2;
        let amplification = rss_delta as f64 / raw_data_size as f64;

        println!("\n=== memory_diag_full_pipeline_peak ===");
        println!("  Exchanges:            {}", exchanges.len());
        println!(
            "  Body size:            {} MB each (req + resp)",
            BODY_SIZE * 2 / 1024 / 1024
        );
        println!("  Raw data total:       {} MB", raw_data_size / 1024 / 1024);
        println!(
            "  Captured data total:  {} MB",
            total_captured / 1024 / 1024
        );
        println!("  Response bytes read:  {} MB", resp_len / 1024 / 1024);
        println!("  RSS before:           {} MB", rss_before / 1024 / 1024);
        println!("  RSS peak:             {} MB", rss_peak / 1024 / 1024);
        println!("  RSS delta:            {} MB", rss_delta / 1024 / 1024);
        println!("  Amplification factor: {:.1}x", amplification);
        println!();

        assert_eq!(
            exchanges.len(),
            NUM_EXCHANGES,
            "expected {} exchanges",
            NUM_EXCHANGES
        );

        if amplification > 1.5 {
            println!(
                "  ** DIAGNOSIS: Peak memory amplification is {:.1}x.",
                amplification
            );
            println!(
                "     For {} exchanges x {} MB each = {} MB raw data,",
                NUM_EXCHANGES,
                BODY_SIZE * 2 / 1024 / 1024,
                raw_data_size / 1024 / 1024
            );
            println!("     the proxy used {} MB RSS.", rss_delta / 1024 / 1024);
            println!("     Sources: unbounded channel accumulation,");
            println!("     capture + body buffering.");
        }
    }

    #[tokio::test]
    async fn buffered_bodies_over_the_limit_are_refused_without_reading_them() {
        // A declared length over the limit is refused before any byte is read.
        let err = read_full_body_bounded(
            &mut tokio::io::BufReader::new(&b""[..]),
            BodyFraming::ContentLength(1 << 40),
            &[],
            16,
            1024,
        )
        .await
        .expect_err("a huge Content-Length must be refused");
        assert!(err.is::<BodyTooLarge>());

        // Chunked: the chunk that would cross the limit is refused.
        let chunked = b"200\r\n"
            .iter()
            .copied()
            .chain([b'a'; 0x200])
            .chain(*b"\r\n401\r\n");
        let chunked: Vec<u8> = chunked.collect();
        let err = read_full_body_bounded(
            &mut tokio::io::BufReader::new(&chunked[..]),
            BodyFraming::Chunked,
            &[],
            16,
            1024,
        )
        .await
        .expect_err("a chunk past the limit must be refused");
        assert!(err.is::<BodyTooLarge>());

        // Close-delimited: reading past the limit is refused.
        let body = vec![b'x'; 2048];
        let err = read_full_body_bounded(
            &mut tokio::io::BufReader::new(&body[..]),
            BodyFraming::CloseDelimited,
            &[],
            16,
            1024,
        )
        .await
        .expect_err("a close-delimited body past the limit must be refused");
        assert!(err.is::<BodyTooLarge>());

        // At the limit it is read and captured up to the capture cap.
        let body = vec![b'y'; 1024];
        let (full, captured, truncated) = read_full_body_bounded(
            &mut tokio::io::BufReader::new(&body[..]),
            BodyFraming::ContentLength(1024),
            &[],
            16,
            1024,
        )
        .await
        .expect("a body at the limit is read");
        assert_eq!((full.len(), captured.len(), truncated), (1024, 16, true));
    }

    /// Diagnose: read_full_body returns (full, captured) — reports the exact
    /// allocation sizes. With streaming, captured is a slice of full.
    ///
    /// This is deterministic (no RSS measurement) so it works regardless of
    /// test ordering or prior allocations.
    #[tokio::test]
    #[ignore = "memory diagnostic — run with --nocapture --ignored"]
    async fn memory_diag_read_body_allocation_sizes() {
        const BODY_SIZE: usize = 4 * 1024 * 1024; // 4 MB

        let body_data = vec![0x42u8; BODY_SIZE];
        let framing = BodyFraming::ContentLength(BODY_SIZE);

        // Call read_full_body (bounded incremental allocation)
        let (raw, captured, truncated) = read_full_body(
            &mut tokio::io::BufReader::new(&body_data[..]),
            framing,
            &[], // no extra bytes
            DEFAULT_MAX_BODY_CAPTURE,
        )
        .await
        .unwrap();

        let captured_cap = captured.len();
        let raw_cap = raw.len();

        println!("\n=== memory_diag_read_body_allocation_sizes ===");
        println!("  Input body:           {} MB", BODY_SIZE / 1024 / 1024);
        println!(
            "  captured.len():       {} MB",
            captured.len() / 1024 / 1024
        );
        println!("  captured.capacity():  {} MB", captured_cap / 1024 / 1024);
        println!("  raw.len():            {} MB", raw.len() / 1024 / 1024);
        println!("  raw.capacity():       {} MB", raw_cap / 1024 / 1024);
        println!(
            "  Total allocated:      {} MB (captured + raw)",
            (captured_cap + raw_cap) / 1024 / 1024
        );
        println!(
            "  Overhead:             {} MB above the {} MB input",
            (captured_cap + raw_cap).saturating_sub(BODY_SIZE) / 1024 / 1024,
            BODY_SIZE / 1024 / 1024
        );
        println!();

        assert_eq!(captured.len(), BODY_SIZE);
        assert_eq!(raw.len(), BODY_SIZE);
        assert!(!truncated);
    }

    /// Diagnose: backpressure failure cascade — the actual 2 GB killer.
    ///
    /// Simulates what happens in production when PostgreSQL is slow or
    /// the circuit breaker opens: the MITM unbounded channel, pipeline
    /// channel (cap 10k), and Postgres flusher channel (cap 10k) all
    /// fill with body data simultaneously.
    ///
    /// This is the realistic scenario: 20 sessions doing web scraping
    /// with modest 50-200 KB response bodies, but Postgres can't keep up.
    #[tokio::test]
    #[ignore = "memory diagnostic — run with --nocapture --ignored"]
    async fn memory_diag_backpressure_cascade() {
        // Simulate the layered queue system from production:
        //   MITM tunnel → unbounded_channel<CapturedExchange>
        //     → publisher clones into PipelineEvent
        //       → mpsc::channel<Box<PipelineEvent>>(10_000)
        //         → drain_task converts into CapturedRequest
        //           → XADD to Redis stream
        //
        // When Postgres stalls, all of these fill up.

        use crate::pipeline::{PipelineEvent, SessionMetadata, TimingInfo};

        // Realistic body sizes for web scraping: HTML pages, API responses
        const SMALL_BODY: usize = 20 * 1024; // 20 KB — typical API response
        const MEDIUM_BODY: usize = 200 * 1024; // 200 KB — typical HTML page
        const LARGE_BODY: usize = 2 * 1024 * 1024; // 2 MB — large page/JSON

        // Distribution: 70% small, 25% medium, 5% large (realistic scraping)
        const NUM_EVENTS: usize = 2000;

        fn body_size_for(i: usize) -> usize {
            match i % 20 {
                0 => LARGE_BODY,      // 5%
                1..=5 => MEDIUM_BODY, // 25%
                _ => SMALL_BODY,      // 70%
            }
        }

        stabilize_rss();
        let rss_before = rss_bytes();

        // Layer 1: Unbounded exchange channel (as in production)
        let mut exchanges: Vec<CapturedExchange> = Vec::new();
        for i in 0..NUM_EVENTS {
            let size = body_size_for(i);
            exchanges.push(CapturedExchange {
                event_id: uuid::Uuid::now_v7(),
                method: "GET".to_string(),
                path: format!("/page/{}", i),
                host: "target.com".to_string(),
                request_headers: vec![("Host".to_string(), "target.com".to_string())],
                request_body: Bytes::from(vec![0x41u8; size / 10]), // req body ~10% of resp
                request_body_truncated: false,
                status: 200,
                response_headers: vec![
                    ("Content-Type".to_string(), "text/html".to_string()),
                    ("Content-Length".to_string(), size.to_string()),
                ],
                response_body: Bytes::from(vec![0x42u8; size]),
                response_body_truncated: false,
                timestamp: time::OffsetDateTime::now_utc(),
                duration_ms: 100,
            });
        }

        let exchange_mem: usize = exchanges
            .iter()
            .map(|e| e.request_body.len() + e.response_body.len())
            .sum();

        // Layer 2: Clone into PipelineEvents (what the publisher task does)
        let mut pipeline_events: Vec<Box<PipelineEvent>> = Vec::new();
        for ex in exchanges.iter() {
            pipeline_events.push(Box::new(PipelineEvent {
                event_id: uuid::Uuid::now_v7(),
                session_id: uuid::Uuid::nil(),
                proxy_id: "proxy-1".to_string(),
                timestamp: time::OffsetDateTime::now_utc(),
                method: ex.method.clone(),
                scheme: "https".to_string(),
                host: ex.host.clone(),
                port: 443,
                path: ex.path.clone(),
                request_headers: ex.request_headers.clone(),
                request_body: ex.request_body.clone(), // CLONE
                request_body_size: ex.request_body.len() as u64,
                request_body_truncated: ex.request_body_truncated,
                response_status: ex.status as u32,
                response_status_text: String::new(),
                response_headers: ex.response_headers.clone(),
                response_body: ex.response_body.clone(), // CLONE
                response_body_size: ex.response_body.len() as u64,
                response_body_truncated: ex.response_body_truncated,
                timing: TimingInfo {
                    total_ms: ex.duration_ms,
                    ..Default::default()
                },
                metadata: SessionMetadata {
                    org_id: "org-1".to_string(),
                    source: "scan".to_string(),
                    source_id: "scan-1".to_string(),
                },
            }));
        }

        let pipeline_mem: usize = pipeline_events
            .iter()
            .map(|e| e.request_body.len() + e.response_body.len())
            .sum();

        // Layer 3: Convert into CapturedRequests (what drain_task does)
        let mut documents: Vec<common::wire::CapturedRequest> = Vec::new();
        for event in pipeline_events.iter() {
            documents.push(crate::pipeline::convert_event(event));
        }

        let doc_mem: usize = documents
            .iter()
            .map(|d| d.request_body.len() + d.response_body.len())
            .sum();

        stabilize_rss();
        let rss_peak = rss_bytes();
        let rss_delta = rss_peak.saturating_sub(rss_before);

        println!("\n=== memory_diag_backpressure_cascade ===");
        println!("  Simulating: {} events during Postgres stall", NUM_EVENTS);
        println!(
            "  Body distribution: 70% x {}KB, 25% x {}KB, 5% x {}MB",
            SMALL_BODY / 1024,
            MEDIUM_BODY / 1024,
            LARGE_BODY / 1024 / 1024
        );
        println!();
        println!(
            "  Layer 1 — CapturedExchange bodies:     {} MB",
            exchange_mem / 1024 / 1024
        );
        println!(
            "  Layer 2 — PipelineEvent cloned bodies:  {} MB",
            pipeline_mem / 1024 / 1024
        );
        println!(
            "  Layer 3 — CapturedRequest bodies:      {} MB",
            doc_mem / 1024 / 1024
        );
        println!(
            "  Total body data in queues:              {} MB",
            (exchange_mem + pipeline_mem + doc_mem) / 1024 / 1024
        );
        println!();
        println!("  RSS before:  {} MB", rss_before / 1024 / 1024);
        println!("  RSS peak:    {} MB", rss_peak / 1024 / 1024);
        println!("  RSS delta:   {} MB", rss_delta / 1024 / 1024);
        println!();

        // Scale up: in production with 20 sessions, multiply by 20
        let per_session_body = exchange_mem + pipeline_mem + doc_mem;
        let _twenty_sessions = per_session_body * 20 / NUM_EVENTS * 500;
        // In practice each session has its own unbounded channel but shares
        // the pipeline/flusher. Estimate: 20 sessions x unbounded channels
        // + shared pipeline(10k) + shared flusher(10k).
        let prod_estimate_exchange = exchange_mem * 20; // 20 unbounded channels
        let prod_estimate_total = prod_estimate_exchange + pipeline_mem + doc_mem;

        println!("  === Production estimate (20 sessions, Postgres stall) ===");
        println!(
            "  20 x unbounded exchange channels: {} MB",
            prod_estimate_exchange / 1024 / 1024
        );
        println!(
            "  + shared pipeline channel:        {} MB",
            pipeline_mem / 1024 / 1024
        );
        println!(
            "  + shared flusher buffer:          {} MB",
            doc_mem / 1024 / 1024
        );
        println!(
            "  Estimated total:                  {} MB",
            prod_estimate_total / 1024 / 1024
        );
        println!();

        if prod_estimate_total > 1024 * 1024 * 1024 {
            println!("  ** DIAGNOSIS: Production estimate exceeds 1 GB!");
            println!("     Root cause: No backpressure from Postgres → pipeline → MITM.");
            println!("     When Postgres stalls (circuit breaker, slow queries, network),");
            println!("     all three queue layers fill with body data simultaneously.");
            println!("     The unbounded MITM channel makes this worse — it never pushes");
            println!("     back on the tunnel, so exchanges accumulate without limit.");
        }

        // Cleanup
        drop(documents);
        drop(pipeline_events);
        drop(exchanges);
        stabilize_rss();
        let rss_after_cleanup = rss_bytes();
        println!(
            "  RSS after cleanup:   {} MB",
            rss_after_cleanup / 1024 / 1024
        );
        println!(
            "  Released:            {} MB",
            rss_peak.saturating_sub(rss_after_cleanup) / 1024 / 1024
        );
    }

    /// Diagnose: per-connection ServerConfig allocation overhead.
    ///
    /// Creates many ServerConfig instances (as happens per MITM connection)
    /// and measures the memory cost.
    #[tokio::test]
    #[ignore = "memory diagnostic — run with --nocapture --ignored"]
    async fn memory_diag_server_config_per_connection() {
        use crate::mitm::tls::make_server_config;

        // Install the default crypto provider (required by rustls)
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();

        // Generate a test CA
        let ca_key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
        let mut ca_params = rcgen::CertificateParams::default();
        ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        ca_params.distinguished_name = rcgen::DistinguishedName::new();
        ca_params.distinguished_name.push(
            rcgen::DnType::CommonName,
            rcgen::DnValue::Utf8String("Test CA".to_string()),
        );
        let ca_cert = ca_params.self_signed(&ca_key).unwrap();

        let ca = Arc::new(
            CertificateAuthority::from_der(ca_cert.der(), ca_key.serialize_der().as_slice())
                .unwrap(),
        );

        const NUM_CONFIGS: usize = 500;

        stabilize_rss();
        let rss_before = rss_bytes();

        // Simulate what used to happen: one ServerConfig per MITM connection.
        // After the optimization, only one is created and shared via Arc.
        let mut configs: Vec<rustls::ServerConfig> = Vec::with_capacity(NUM_CONFIGS);
        for _i in 0..NUM_CONFIGS {
            let config = make_server_config(ca.clone()).unwrap();
            configs.push(config);
        }

        stabilize_rss();
        let rss_after = rss_bytes();
        let rss_delta = rss_after.saturating_sub(rss_before);
        let per_config = rss_delta / NUM_CONFIGS;

        println!("\n=== memory_diag_server_config_per_connection ===");
        println!("  ServerConfigs created: {}", NUM_CONFIGS);
        println!("  RSS before:            {} MB", rss_before / 1024 / 1024);
        println!("  RSS after:             {} MB", rss_after / 1024 / 1024);
        println!("  RSS delta:             {} MB", rss_delta / 1024 / 1024);
        println!("  Per-config overhead:   {} KB", per_config / 1024);
        println!("  Cert cache size:       {} entries", ca.cache_len());
        println!();

        if per_config > 8 * 1024 {
            println!(
                "  ** DIAGNOSIS: Each MITM connection allocates ~{} KB for ServerConfig.",
                per_config / 1024
            );
            println!(
                "     At 200 concurrent connections, that's {} MB.",
                (per_config * 200) / 1024 / 1024
            );
            println!("     Fix: Share a single ServerConfig with dynamic cert resolution.");
        } else {
            println!(
                "  Per-config overhead is {} KB — not a primary memory driver.",
                per_config / 1024
            );
        }
    }

    // =========================================================================
    // Correctness tests for stream reading / body forwarding
    // =========================================================================

    /// Verify that a single request+response through the H1 proxy:
    /// 1. Forwards the request body byte-for-byte to upstream
    /// 2. Forwards the response body byte-for-byte to client
    /// 3. Captures the exchange with correct method, path, status, and bodies
    #[tokio::test]
    async fn test_h1_body_forwarding_correctness() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let server_addr = listener.local_addr().unwrap();

        // Use a distinctive body pattern so we'd catch any byte corruption
        let req_body: Vec<u8> = (0..4096).map(|i| (i % 251) as u8).collect();
        let resp_body: Vec<u8> = (0..8192).map(|i| ((i * 7 + 13) % 253) as u8).collect();

        let resp_raw = make_h1_response(&resp_body);
        let server = tokio::spawn(run_fake_http_server(listener, resp_raw));

        let (client_stream, test_end) = tokio::io::duplex(256 * 1024);
        let (mut test_reader, mut test_writer) = split(test_end);
        let (exchange_tx, mut exchange_rx) = tokio::sync::mpsc::channel(8);

        let upstream = TcpStream::connect(server_addr).await.unwrap();

        let proxy = tokio::spawn(async move {
            let client_buf = BufReader::new(client_stream);
            let upstream_buf = BufReader::new(upstream);
            proxy_http_keepalive(
                client_buf.into_inner(),
                upstream_buf.into_inner(),
                "test.local",
                &[],
                exchange_tx,
                None,
                DEFAULT_MAX_BODY_CAPTURE,
                DEFAULT_MAX_BODY_CAPTURE, // max_header_capture
                None,
                None, // serial_lock
                false,
                "http",
                HttpLimits::default(),
            )
            .await
            .map(|_| ())
        });

        // Send request
        let req_data = make_h1_request("test.local", "/api/data", &req_body);
        test_writer.write_all(&req_data).await.unwrap();
        test_writer.shutdown().await.unwrap();

        // Read response
        let mut response_data = Vec::new();
        test_reader.read_to_end(&mut response_data).await.unwrap();

        proxy.await.unwrap().unwrap();
        server.await.unwrap();

        // Verify response body forwarded correctly to client
        let resp_str = String::from_utf8_lossy(&response_data);
        let body_start = resp_str.find("\r\n\r\n").unwrap() + 4;
        let forwarded_resp_body = &response_data[body_start..];
        assert_eq!(
            forwarded_resp_body,
            &resp_body[..],
            "response body forwarded to client must match upstream response byte-for-byte"
        );

        // Verify captured exchange
        let exchange = exchange_rx.try_recv().expect("exchange must be captured");
        assert_eq!(exchange.method, "POST");
        assert_eq!(exchange.path, "/api/data");
        assert_eq!(exchange.status, 200);
        assert_eq!(
            &exchange.request_body[..],
            &req_body[..],
            "captured request body must match original"
        );
        assert_eq!(
            &exchange.response_body[..],
            &resp_body[..],
            "captured response body must match original"
        );
    }

    /// Verify multiple keep-alive requests on a single connection:
    /// - Each request/response is forwarded correctly
    /// - Each exchange is captured with the right data
    /// - Bodies don't bleed across requests
    ///
    /// Sends requests over a real TCP connection so buffering is realistic
    /// (the proxy's read_http_headers can consume extra bytes greedily from
    /// an in-memory duplex, so we use TCP here for faithful testing).
    #[tokio::test]
    async fn test_h1_keepalive_multiple_requests_correctness() {
        // Upstream server
        let upstream_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let upstream_addr = upstream_listener.local_addr().unwrap();

        let resp_body = b"response-data-keepalive";
        let resp_raw = make_h1_keepalive_response(resp_body);
        let server = tokio::spawn(run_fake_keepalive_server(upstream_listener, resp_raw, 3));

        // Client-facing listener (proxy sits in the middle)
        let client_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let client_addr = client_listener.local_addr().unwrap();

        let (exchange_tx, mut exchange_rx) = tokio::sync::mpsc::channel(8);

        let proxy = tokio::spawn(async move {
            let (client_stream, _) = client_listener.accept().await.unwrap();
            let upstream = TcpStream::connect(upstream_addr).await.unwrap();
            let client_buf = BufReader::new(client_stream);
            let upstream_buf = BufReader::new(upstream);
            proxy_http_keepalive(
                client_buf.into_inner(),
                upstream_buf.into_inner(),
                "test.local",
                &[],
                exchange_tx,
                None,
                DEFAULT_MAX_BODY_CAPTURE,
                DEFAULT_MAX_BODY_CAPTURE, // max_header_capture
                None,
                None, // serial_lock
                false,
                "http",
                HttpLimits::default(),
            )
            .await
            .map(|_| ())
        });

        // Connect as client
        let mut client = TcpStream::connect(client_addr).await.unwrap();

        let bodies: [&[u8]; 3] = [b"body-one", b"body-two-longer", b"3"];
        let paths = ["/first", "/second", "/third"];

        for i in 0..3 {
            // Send request
            let req = make_h1_keepalive_request("test.local", paths[i], bodies[i]);
            client.write_all(&req).await.unwrap();

            // Read response headers + body
            let mut resp_buf = vec![0u8; 4096];
            let mut resp_data = Vec::new();
            loop {
                let n = client.read(&mut resp_buf).await.unwrap();
                assert!(n > 0, "server closed before response #{}", i + 1);
                resp_data.extend_from_slice(&resp_buf[..n]);
                // Check if we have the complete response (headers + body)
                if let Some(hdr_end) = resp_data.windows(4).position(|w| w == b"\r\n\r\n") {
                    let hdr_str = String::from_utf8_lossy(&resp_data[..hdr_end]);
                    let cl: usize = hdr_str
                        .lines()
                        .find(|l| l.to_lowercase().starts_with("content-length:"))
                        .and_then(|l| l.split(':').nth(1)?.trim().parse().ok())
                        .unwrap_or(0);
                    if resp_data.len() >= hdr_end + 4 + cl {
                        break;
                    }
                }
            }
        }

        // Close client to trigger proxy to exit keepalive loop
        client.shutdown().await.unwrap();
        drop(client);

        proxy.await.unwrap().unwrap();
        server.await.unwrap();

        // Verify we got 3 captured exchanges with correct paths/bodies
        for i in 0..3 {
            let ex = exchange_rx
                .try_recv()
                .unwrap_or_else(|_| panic!("expected exchange #{}", i + 1));
            assert_eq!(ex.method, "POST", "exchange #{} method", i + 1);
            assert_eq!(ex.path, paths[i], "exchange #{} path", i + 1);
            assert_eq!(
                &ex.request_body[..],
                bodies[i],
                "exchange #{} request body must not bleed across requests",
                i + 1
            );
            assert_eq!(
                &ex.response_body[..],
                resp_body.as_slice(),
                "exchange #{} response body",
                i + 1
            );
            assert_eq!(ex.status, 200);
        }

        // No extra exchanges
        assert!(
            exchange_rx.try_recv().is_err(),
            "should have exactly 3 exchanges"
        );
    }

    /// Read one response (headers and Content-Length body) from `client`.
    async fn read_one_response(client: &mut TcpStream) -> String {
        let mut data = Vec::new();
        let mut buf = vec![0u8; 4096];
        loop {
            let n = client.read(&mut buf).await.unwrap();
            assert!(n > 0, "connection closed before a full response");
            data.extend_from_slice(&buf[..n]);
            if let Some(end) = data.windows(4).position(|w| w == b"\r\n\r\n") {
                let head = String::from_utf8_lossy(&data[..end]).to_string();
                let cl: usize = head
                    .lines()
                    .find(|l| l.to_lowercase().starts_with("content-length:"))
                    .and_then(|l| l.split(':').nth(1)?.trim().parse().ok())
                    .unwrap_or(0);
                if data.len() >= end + 4 + cl {
                    return String::from_utf8_lossy(&data).to_string();
                }
            }
        }
    }

    /// Run `proxy_http_keepalive` between a real client socket and a fake
    /// keep-alive server that answers `served` requests.
    async fn keepalive_pair(
        limits: HttpLimits,
        served: usize,
    ) -> (
        TcpStream,
        tokio::task::JoinHandle<Result<()>>,
        tokio::task::JoinHandle<()>,
    ) {
        let upstream_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let upstream_addr = upstream_listener.local_addr().unwrap();
        let server = tokio::spawn(run_fake_keepalive_server(
            upstream_listener,
            make_h1_keepalive_response(b"ok"),
            served,
        ));
        let client_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let client_addr = client_listener.local_addr().unwrap();
        let (exchange_tx, exchange_rx) = tokio::sync::mpsc::channel(8);
        // Keep the receiver alive so exchange sends never fail.
        tokio::spawn(async move {
            let mut exchange_rx = exchange_rx;
            while exchange_rx.recv().await.is_some() {}
        });
        let proxy = tokio::spawn(async move {
            let (client_stream, _) = client_listener.accept().await.unwrap();
            let upstream = TcpStream::connect(upstream_addr).await.unwrap();
            proxy_http_keepalive(
                client_stream,
                upstream,
                "test.local",
                &[],
                exchange_tx,
                None,
                DEFAULT_MAX_BODY_CAPTURE,
                DEFAULT_MAX_BODY_CAPTURE,
                None,
                None,
                false,
                "http",
                limits,
            )
            .await
            .map(|_| ())
        });
        let client = TcpStream::connect(client_addr).await.unwrap();
        (client, proxy, server)
    }

    /// An idle client connection is closed after
    /// `network.http_keepalive_idle_timeout_ms`, not left open.
    #[tokio::test]
    async fn keepalive_idle_timeout_closes_an_idle_connection() {
        let limits = HttpLimits {
            keepalive_idle: Duration::from_millis(300),
            ..HttpLimits::default()
        };
        let (mut client, proxy, server) = keepalive_pair(limits, 1).await;

        client
            .write_all(&make_h1_keepalive_request("test.local", "/one", b"x"))
            .await
            .unwrap();
        let response = read_one_response(&mut client).await;
        assert!(response.starts_with("HTTP/1.1 200"), "{response}");

        // Say nothing: the proxy has to hang up on its own.
        let started = std::time::Instant::now();
        let mut buf = [0u8; 64];
        let n = tokio::time::timeout(Duration::from_secs(5), client.read(&mut buf))
            .await
            .expect("proxy closed the idle connection")
            .unwrap();
        assert_eq!(n, 0, "EOF from the proxy");
        assert!(
            started.elapsed() >= Duration::from_millis(250),
            "closed after {:?}, before the idle limit",
            started.elapsed()
        );
        proxy.await.unwrap().unwrap();
        server.abort();
    }

    /// The connection closes after `network.http_keepalive_max_requests`
    /// requests, announced with `Connection: close` on the last response.
    #[tokio::test]
    async fn keepalive_max_requests_closes_after_n() {
        let limits = HttpLimits {
            max_requests: Some(2),
            ..HttpLimits::default()
        };
        let (mut client, proxy, server) = keepalive_pair(limits, 2).await;

        client
            .write_all(&make_h1_keepalive_request("test.local", "/one", b"x"))
            .await
            .unwrap();
        let first = read_one_response(&mut client).await;
        assert!(
            !first.to_lowercase().contains("connection: close"),
            "the first response keeps the connection open: {first}"
        );

        client
            .write_all(&make_h1_keepalive_request("test.local", "/two", b"y"))
            .await
            .unwrap();
        let second = read_one_response(&mut client).await;
        assert!(
            second.to_lowercase().contains("connection: close"),
            "the last response announces the close: {second}"
        );

        let mut buf = [0u8; 64];
        let n = tokio::time::timeout(Duration::from_secs(5), client.read(&mut buf))
            .await
            .expect("proxy closed after the quota")
            .unwrap();
        assert_eq!(n, 0, "EOF after the second request");
        proxy.await.unwrap().unwrap();
        server.abort();
    }

    /// Without a quota the connection serves any number of requests.
    #[tokio::test]
    async fn keepalive_without_quota_keeps_serving() {
        let (mut client, proxy, server) = keepalive_pair(HttpLimits::default(), 4).await;
        for i in 0..4 {
            client
                .write_all(&make_h1_keepalive_request(
                    "test.local",
                    &format!("/{i}"),
                    b"z",
                ))
                .await
                .unwrap();
            let response = read_one_response(&mut client).await;
            assert!(!response.to_lowercase().contains("connection: close"));
        }
        drop(client);
        proxy.await.unwrap().unwrap();
        server.await.unwrap();
    }

    /// Verify chunked transfer encoding is read and forwarded correctly.
    #[tokio::test]
    async fn test_h1_chunked_body_correctness() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let server_addr = listener.local_addr().unwrap();

        // Server sends a chunked response
        let chunk1 = b"Hello, ";
        let chunk2 = b"chunked world!";
        let chunked_response = format!(
            "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n\
             {:x}\r\n{}\r\n{:x}\r\n{}\r\n0\r\n\r\n",
            chunk1.len(),
            std::str::from_utf8(chunk1).unwrap(),
            chunk2.len(),
            std::str::from_utf8(chunk2).unwrap(),
        );

        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            // Drain request
            let mut buf = vec![0u8; 4096];
            let mut hdr = Vec::new();
            loop {
                let n = socket.read(&mut buf).await.unwrap();
                if n == 0 {
                    break;
                }
                hdr.extend_from_slice(&buf[..n]);
                if hdr.windows(4).any(|w| w == b"\r\n\r\n") {
                    break;
                }
            }
            // Send chunked response
            socket.write_all(chunked_response.as_bytes()).await.unwrap();
            socket.shutdown().await.unwrap();
        });

        let (client_stream, test_end) = tokio::io::duplex(64 * 1024);
        let (mut test_reader, mut test_writer) = split(test_end);
        let (exchange_tx, mut exchange_rx) = tokio::sync::mpsc::channel(8);

        let upstream = TcpStream::connect(server_addr).await.unwrap();

        let proxy = tokio::spawn(async move {
            let client_buf = BufReader::new(client_stream);
            let upstream_buf = BufReader::new(upstream);
            proxy_http_keepalive(
                client_buf.into_inner(),
                upstream_buf.into_inner(),
                "test.local",
                &[],
                exchange_tx,
                None,
                DEFAULT_MAX_BODY_CAPTURE,
                DEFAULT_MAX_BODY_CAPTURE, // max_header_capture
                None,
                None, // serial_lock
                false,
                "http",
                HttpLimits::default(),
            )
            .await
            .map(|_| ())
        });

        // Send a simple GET (no body)
        let req = b"GET /chunked HTTP/1.1\r\nHost: test.local\r\nConnection: close\r\n\r\n";
        test_writer.write_all(req).await.unwrap();
        test_writer.shutdown().await.unwrap();

        // Read response
        let mut response_data = Vec::new();
        test_reader.read_to_end(&mut response_data).await.unwrap();

        proxy.await.unwrap().unwrap();
        server.await.unwrap();

        // Verify captured exchange has the decoded chunked body
        let exchange = exchange_rx.try_recv().expect("exchange must be captured");
        assert_eq!(exchange.method, "GET");
        assert_eq!(exchange.path, "/chunked");
        assert_eq!(exchange.status, 200);
        let expected_body = b"Hello, chunked world!";
        assert_eq!(
            &exchange.response_body[..],
            expected_body.as_slice(),
            "chunked body must be decoded and captured correctly"
        );

        // Verify raw chunked encoding was forwarded to client
        let resp_str = String::from_utf8_lossy(&response_data);
        assert!(
            resp_str.contains("Transfer-Encoding: chunked"),
            "chunked header must be forwarded to client"
        );
    }

    /// Verify that large bodies (close to the capture limit) are read correctly.
    #[tokio::test]
    async fn test_h1_large_body_correctness() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let server_addr = listener.local_addr().unwrap();

        // 1 MB body with a predictable pattern
        let body_size = 1024 * 1024;
        let large_body: Vec<u8> = (0..body_size).map(|i| (i % 256) as u8).collect();
        let resp_raw = make_h1_response(&large_body);
        let server = tokio::spawn(run_fake_http_server(listener, resp_raw));

        let (client_stream, test_end) = tokio::io::duplex(2 * 1024 * 1024);
        let (mut test_reader, mut test_writer) = split(test_end);
        let (exchange_tx, mut exchange_rx) = tokio::sync::mpsc::channel(8);

        let upstream = TcpStream::connect(server_addr).await.unwrap();

        let req_body: Vec<u8> = (0..512 * 1024).map(|i| ((i * 3) % 256) as u8).collect();

        let proxy = tokio::spawn(async move {
            let client_buf = BufReader::new(client_stream);
            let upstream_buf = BufReader::new(upstream);
            proxy_http_keepalive(
                client_buf.into_inner(),
                upstream_buf.into_inner(),
                "test.local",
                &[],
                exchange_tx,
                None,
                DEFAULT_MAX_BODY_CAPTURE,
                DEFAULT_MAX_BODY_CAPTURE, // max_header_capture
                None,
                None, // serial_lock
                false,
                "http",
                HttpLimits::default(),
            )
            .await
            .map(|_| ())
        });

        let req_data = make_h1_request("test.local", "/large", &req_body);
        test_writer.write_all(&req_data).await.unwrap();
        test_writer.shutdown().await.unwrap();

        let mut response_data = Vec::new();
        test_reader.read_to_end(&mut response_data).await.unwrap();

        proxy.await.unwrap().unwrap();
        server.await.unwrap();

        // Verify response body (1 MB) forwarded correctly
        let resp_str = String::from_utf8_lossy(&response_data);
        let body_start = resp_str.find("\r\n\r\n").unwrap() + 4;
        let forwarded = &response_data[body_start..];
        assert_eq!(
            forwarded.len(),
            body_size,
            "forwarded body must be full 1 MB"
        );
        assert_eq!(
            forwarded,
            &large_body[..],
            "1 MB body must match byte-for-byte"
        );

        // Verify captured exchange
        let exchange = exchange_rx.try_recv().expect("exchange must be captured");
        assert_eq!(
            &exchange.request_body[..],
            &req_body[..],
            "512 KB request body must match"
        );
        assert_eq!(
            &exchange.response_body[..],
            &large_body[..],
            "1 MB response body must match"
        );
    }

    // =========================================================================
    // RFC 8441 Extended CONNECT (WS over H2) tests
    // =========================================================================

    /// Positive path: proxy issues an Extended CONNECT, upstream accepts (200),
    /// sends one WS text frame, then closes its send side.  The proxy should:
    ///   1. Return HTTP/1.1 101 Switching Protocols to the client.
    ///   2. Forward the WS frame bytes to the client.
    ///   3. Capture the 101 exchange with status=101 and the correct headers.
    #[tokio::test]
    async fn test_ws_upgrade_over_h2_success() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let server_addr = listener.local_addr().unwrap();

        // Minimal WS text frame: FIN=1, opcode=text (0x81), no mask, length=3, "ABC"
        let ws_frame: &[u8] = b"\x81\x03ABC";

        // Spawn the h2 server with ENABLE_CONNECT_PROTOCOL.
        let server = tokio::spawn(async move {
            let (socket, _) = listener.accept().await.unwrap();
            // RFC 8441: advertise ENABLE_CONNECT_PROTOCOL so the h2 client
            // is permitted to send Extended CONNECT requests.
            let mut conn = h2::server::Builder::new()
                .enable_connect_protocol()
                .handshake(socket)
                .await
                .unwrap();

            while let Some(result) = conn.accept().await {
                let (req, mut respond) = result.unwrap();

                // Must be CONNECT with :protocol = websocket.
                assert_eq!(
                    req.method(),
                    &http::Method::CONNECT,
                    "method must be CONNECT for Extended CONNECT"
                );
                let protocol = req.extensions().get::<h2::ext::Protocol>();
                assert_eq!(
                    protocol.map(|p| p.as_str()),
                    Some("websocket"),
                    ":protocol must be websocket"
                );
                // Sec-WebSocket-Key must NOT be forwarded (H1-only header).
                assert!(
                    req.headers().get("sec-websocket-key").is_none(),
                    "Sec-WebSocket-Key must be stripped before h2 upstream"
                );
                // Sec-WebSocket-Version must be forwarded.
                assert_eq!(
                    req.headers()
                        .get("sec-websocket-version")
                        .and_then(|v| v.to_str().ok()),
                    Some("13"),
                    "Sec-WebSocket-Version must be forwarded to h2 upstream"
                );

                // Respond with 200 (per RFC 8441 §4).
                let response = http::Response::builder().status(200).body(()).unwrap();
                let mut send_body = respond.send_response(response, false).unwrap();

                // Send one WS text frame as a DATA frame and signal END_STREAM.
                send_body
                    .send_data(bytes::Bytes::from_static(ws_frame), true)
                    .unwrap();
            }
        });

        let upstream = TcpStream::connect(server_addr).await.unwrap();
        let (client_stream, test_end) = tokio::io::duplex(65536);
        let (mut test_reader, mut test_writer) = split(test_end);
        let (exchange_tx, mut exchange_rx) = tokio::sync::mpsc::channel(8);

        // Provide a real WsCaptureSink so proxy_websocket is invoked, the WS
        // stream lifecycle is properly driven, and conn_handle exits cleanly.
        let (ws_tx, _ws_rx) = tokio::sync::mpsc::channel::<crate::pipeline::WsPipelineEvent>(16);
        let ws_sink = WsCaptureSink {
            tx: ws_tx,
            max_payload_capture: 1024,
            capture_control_frames: false,
            session_id: uuid::Uuid::nil(),
            org_id: "test-org".to_string(),
            source: "test".to_string(),
            source_id: "test-scan".to_string(),
            proxy_id: "test-proxy".to_string(),
            exchange_ratelimit: None,
        };

        let proxy = tokio::spawn(async move {
            let client_buf = BufReader::new(client_stream);
            proxy_h1_to_h2(
                client_buf,
                upstream,
                "ws.example.com",
                443,
                &[],
                exchange_tx,
                None,
                DEFAULT_MAX_BODY_CAPTURE,
                DEFAULT_MAX_BODY_CAPTURE, // max_header_capture
                // Pass a reference to the sink that was moved into this closure.
                Some(&ws_sink),
                None, // h1_fallback — not exercised here; server enables connect_protocol
                None, // serial_lock
                HttpLimits::default(),
            )
            .await
        });

        // Write an H1 WebSocket upgrade request.
        test_writer
            .write_all(
                b"GET /chat HTTP/1.1\r\nHost: ws.example.com\r\nUpgrade: websocket\r\n\
Connection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\
Sec-WebSocket-Version: 13\r\n\r\n",
            )
            .await
            .unwrap();
        // Shut down the write half so proxy_websocket's C2S direction loop
        // sees EOF and exits cleanly.
        test_writer.shutdown().await.unwrap();

        // read_to_end completes once the proxy closes its write side (after
        // proxy_websocket finishes both direction loops).
        let mut buf = Vec::new();
        test_reader.read_to_end(&mut buf).await.unwrap();
        let text = String::from_utf8_lossy(&buf);

        // Wait for proxy and server tasks.
        proxy.await.unwrap().unwrap();
        server.await.unwrap();

        // 1. Client received 101.
        assert!(
            text.contains("HTTP/1.1 101 Switching Protocols"),
            "client must receive 101, got: {text:?}"
        );
        assert!(
            text.to_lowercase().contains("upgrade: websocket"),
            "101 must contain Upgrade: websocket, got: {text:?}"
        );
        // Sec-WebSocket-Accept must be present and correct for the test key.
        // RFC 6455: accept = base64(SHA1("dGhlIHNhbXBsZSBub25jZQ==" + GUID))
        // = "s3pPLMBiTxaQ9kYGzzhZRbK+xOo="
        assert!(
            buf.windows(b"Sec-WebSocket-Accept".len())
                .any(|w| w.eq_ignore_ascii_case(b"Sec-WebSocket-Accept")),
            "101 must contain Sec-WebSocket-Accept"
        );
        assert!(
            text.contains("s3pPLMBiTxaQ9kYGzzhZRbK+xOo="),
            "Sec-WebSocket-Accept value must be correct per RFC 6455, got: {text:?}"
        );

        // 2. WS frame bytes were forwarded (by proxy_websocket) after the 101.
        let header_end = buf.windows(4).position(|w| w == b"\r\n\r\n").unwrap() + 4;
        let ws_bytes = &buf[header_end..];
        assert_eq!(
            ws_bytes, ws_frame,
            "WS frame bytes must be forwarded byte-for-byte"
        );

        // 3. Captured exchange has status=101.
        let exchange = exchange_rx
            .try_recv()
            .expect("101 exchange must be captured");
        assert_eq!(exchange.method, "GET");
        assert_eq!(exchange.path, "/chat");
        assert_eq!(exchange.host, "ws.example.com");
        assert_eq!(exchange.status, 101);
        assert!(
            exchange.request_body.is_empty(),
            "101 exchange must have empty request body"
        );
        assert!(
            exchange.response_body.is_empty(),
            "101 exchange must have empty response body"
        );
        assert!(
            exchange
                .response_headers
                .iter()
                .any(|(k, _)| k.eq_ignore_ascii_case("sec-websocket-accept")),
            "captured 101 response headers must include sec-websocket-accept"
        );
    }

    /// Negative path: upstream rejects the Extended CONNECT with a non-200 status.
    /// The proxy must forward a 502 to the client and produce no WS capture rows.
    #[tokio::test]
    async fn test_ws_upgrade_over_h2_upstream_rejects() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let server_addr = listener.local_addr().unwrap();

        let server = tokio::spawn(async move {
            let (socket, _) = listener.accept().await.unwrap();
            let mut conn = h2::server::handshake(socket).await.unwrap();

            while let Some(result) = conn.accept().await {
                let (_req, mut respond) = result.unwrap();
                // Reject the Extended CONNECT.
                let response = http::Response::builder()
                    .status(http::StatusCode::NOT_FOUND)
                    .body(())
                    .unwrap();
                respond.send_response(response, true).unwrap();
            }
        });

        let upstream = TcpStream::connect(server_addr).await.unwrap();
        let (client_stream, test_end) = tokio::io::duplex(65536);
        let (mut test_reader, mut test_writer) = split(test_end);
        let (exchange_tx, mut exchange_rx) = tokio::sync::mpsc::channel(8);

        let proxy = tokio::spawn(async move {
            let client_buf = BufReader::new(client_stream);
            proxy_h1_to_h2(
                client_buf,
                upstream,
                "ws.example.com",
                443,
                &[],
                exchange_tx,
                None,
                DEFAULT_MAX_BODY_CAPTURE,
                DEFAULT_MAX_BODY_CAPTURE, // max_header_capture
                None,
                None,
                None, // serial_lock
                HttpLimits::default(),
            )
            .await
        });

        // Write H1 WS upgrade.
        test_writer
            .write_all(
                b"GET /ws HTTP/1.1\r\n\
                  Host: ws.example.com\r\n\
                  Upgrade: websocket\r\n\
                  Connection: Upgrade\r\n\
                  Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\
                  Sec-WebSocket-Version: 13\r\n\
                  \r\n",
            )
            .await
            .unwrap();
        test_writer.shutdown().await.unwrap();

        let mut buf = Vec::new();
        test_reader.read_to_end(&mut buf).await.unwrap();
        let text = String::from_utf8_lossy(&buf);

        proxy.await.unwrap().unwrap();
        server.await.unwrap();

        // Client must get 502, not 101.
        assert!(
            text.starts_with("HTTP/1.1 502"),
            "client must receive 502 when upstream rejects, got: {text:?}"
        );
        assert!(
            !text.contains("101"),
            "client must NOT receive 101 when upstream rejects, got: {text:?}"
        );

        // No WS capture rows.
        assert!(
            exchange_rx.try_recv().is_err(),
            "no exchange must be captured when upstream rejects the ws upgrade"
        );
    }

    /// Fallback path: H2 upstream does NOT advertise SETTINGS_ENABLE_CONNECT_PROTOCOL,
    /// so when a WS upgrade arrives the proxy MUST NOT send Extended CONNECT
    /// (RFC 8441 §3 violation).  Instead, it dials a fresh H1.1 upstream via
    /// the supplied `h1_fallback` dialer and runs the WS upgrade there.
    ///
    /// Two servers run in this test:
    ///  - An h2 server that does NOT call `enable_connect_protocol()`.
    ///  - An h1.1 server (plain TCP, no TLS) that performs the WS handshake.
    /// The fallback dialer points the proxy at the h1.1 server so we can verify
    /// the full fallback flow without bringing a TLS stack into the test.
    #[tokio::test]
    async fn test_ws_upgrade_h1_fallback_when_h2_lacks_connect_protocol() {
        // 1. h2 upstream that does NOT advertise ENABLE_CONNECT_PROTOCOL.
        let h2_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let h2_addr = h2_listener.local_addr().unwrap();
        let h2_server = tokio::spawn(async move {
            let (socket, _) = h2_listener.accept().await.unwrap();
            // Default Builder — no enable_connect_protocol().
            let mut conn = h2::server::handshake(socket).await.unwrap();
            // Drive the connection until the proxy GOAWAYs (after fallback decision).
            // We never expect to receive a request here.
            while let Some(result) = conn.accept().await {
                // If the proxy mistakenly sent a request, fail loudly.
                let (_req, mut respond) = result.unwrap();
                let response = http::Response::builder().status(500).body(()).unwrap();
                let _ = respond.send_response(response, true);
            }
        });

        // 2. h1.1 upstream that performs the WS handshake.
        let h1_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let h1_addr = h1_listener.local_addr().unwrap();
        // Frame the upstream sends after the 101: a WS text frame "ABC".
        let ws_frame: &[u8] = b"\x81\x03ABC";
        let h1_server = tokio::spawn(async move {
            let (mut socket, _) = h1_listener.accept().await.unwrap();
            // Read until end of headers.
            let mut hdr = Vec::new();
            let mut buf = [0u8; 4096];
            loop {
                let n = socket.read(&mut buf).await.unwrap();
                if n == 0 {
                    return;
                }
                hdr.extend_from_slice(&buf[..n]);
                if hdr.windows(4).any(|w| w == b"\r\n\r\n") {
                    break;
                }
            }
            let hdr_str = String::from_utf8_lossy(&hdr);
            assert!(
                hdr_str.to_lowercase().contains("upgrade: websocket"),
                "h1 fallback upstream must receive WS upgrade headers, got: {hdr_str:?}"
            );
            // Send 101 + a WS text frame.
            let resp = b"HTTP/1.1 101 Switching Protocols\r\n\
Upgrade: websocket\r\n\
Connection: Upgrade\r\n\
Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n\r\n";
            socket.write_all(resp).await.unwrap();
            socket.write_all(ws_frame).await.unwrap();
            // Wait for client EOF then exit.
            let mut tail = [0u8; 4096];
            let _ = socket.read(&mut tail).await;
        });

        // 3. Proxy setup.
        let upstream = TcpStream::connect(h2_addr).await.unwrap();
        let (client_stream, test_end) = tokio::io::duplex(65536);
        let (mut test_reader, mut test_writer) = split(test_end);
        let (exchange_tx, mut exchange_rx) = tokio::sync::mpsc::channel(8);

        // WS sink so proxy_websocket gets called and frames get forwarded.
        let (ws_tx, _ws_rx) = tokio::sync::mpsc::channel::<crate::pipeline::WsPipelineEvent>(16);
        let ws_sink = WsCaptureSink {
            tx: ws_tx,
            max_payload_capture: 1024,
            capture_control_frames: false,
            session_id: uuid::Uuid::nil(),
            org_id: "test-org".to_string(),
            source: "test".to_string(),
            source_id: "test-scan".to_string(),
            proxy_id: "test-proxy".to_string(),
            exchange_ratelimit: None,
        };

        // H1 fallback dialer — connects to the h1.1 server (plain TCP, no TLS,
        // for test simplicity).  Production uses TLS via boring.
        let h1_dial: H1FallbackDial = Arc::new(move |_host: String, _port: u16| {
            Box::pin(async move {
                let stream = TcpStream::connect(h1_addr).await?;
                let boxed: BoxedUpstream = Box::new(stream);
                Ok(boxed)
            })
        });

        let proxy = tokio::spawn(async move {
            let client_buf = BufReader::new(client_stream);
            proxy_h1_to_h2(
                client_buf,
                upstream,
                "ws.example.com",
                443,
                &[],
                exchange_tx,
                None,
                DEFAULT_MAX_BODY_CAPTURE,
                DEFAULT_MAX_BODY_CAPTURE, // max_header_capture
                Some(&ws_sink),
                Some(h1_dial),
                None, // serial_lock
                HttpLimits::default(),
            )
            .await
        });

        // Send the WS upgrade.
        test_writer
            .write_all(
                b"GET /chat HTTP/1.1\r\nHost: ws.example.com\r\nUpgrade: websocket\r\n\
Connection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\
Sec-WebSocket-Version: 13\r\n\r\n",
            )
            .await
            .unwrap();
        test_writer.shutdown().await.unwrap();

        let mut buf = Vec::new();
        test_reader.read_to_end(&mut buf).await.unwrap();
        let text = String::from_utf8_lossy(&buf);

        proxy.await.unwrap().unwrap();
        h1_server.await.unwrap();
        // h2_server may panic on connection reset when the proxy GOAWAYs;
        // discard its result.
        h2_server.abort();
        let _ = h2_server.await;

        // Client received 101 from the h1.1 fallback path.
        assert!(
            text.contains("HTTP/1.1 101 Switching Protocols"),
            "client must receive 101 via h1 fallback, got: {text:?}"
        );
        assert!(
            text.contains("s3pPLMBiTxaQ9kYGzzhZRbK+xOo="),
            "client must receive the upstream's Sec-WebSocket-Accept, got: {text:?}"
        );

        // Client received the WS frame forwarded from the h1.1 upstream.
        let header_end = buf.windows(4).position(|w| w == b"\r\n\r\n").unwrap() + 4;
        assert_eq!(
            &buf[header_end..],
            ws_frame,
            "WS frame must be forwarded from h1.1 fallback upstream"
        );

        // 101 exchange row was captured.
        let exchange = exchange_rx
            .try_recv()
            .expect("101 exchange must be captured");
        assert_eq!(exchange.method, "GET");
        assert_eq!(exchange.path, "/chat");
        assert_eq!(exchange.status, 101);
    }

    // =========================================================================
    // H2 → H1 body framing tests (Content-Length integrity, chunked path,
    // bodyless responses).
    //
    // These tests cover the previous bug where the proxy buffered H2 response
    // bodies up to `max_body_capture`, then forwarded the upstream's
    // Content-Length verbatim while writing only the truncated bytes. The
    // current behaviour is stream-through: the wire body is never truncated,
    // capture is bounded, and framing is correct.
    // =========================================================================

    /// H2 → H1 body that exceeds `max_body_capture` MUST be forwarded in full
    /// to the client (zero truncation on the wire) while the captured copy
    /// is bounded by the cap and marked truncated.
    #[tokio::test]
    async fn test_h2_to_h1_body_exceeds_capture_cap_no_wire_truncation() {
        // 64 KB of distinctive bytes; cap at 1 KB.
        const BODY_SIZE: usize = 64 * 1024;
        const CAP: usize = 1024;
        let body: Vec<u8> = (0..BODY_SIZE).map(|i| (i % 251) as u8).collect();
        let body_arc = std::sync::Arc::new(body.clone());

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let server_addr = listener.local_addr().unwrap();

        let body_for_server = body_arc.clone();
        let server = tokio::spawn(async move {
            let (socket, _) = listener.accept().await.unwrap();
            let mut conn = h2::server::handshake(socket).await.unwrap();
            while let Some(result) = conn.accept().await {
                let (_req, mut respond) = result.unwrap();
                // Set Content-Length: BODY_SIZE explicitly so the proxy goes
                // through the CL-forwarding path.
                let response = http::Response::builder()
                    .status(200)
                    .header("content-length", BODY_SIZE.to_string())
                    .body(())
                    .unwrap();
                let mut send_body = respond.send_response(response, false).unwrap();
                // Send the body in two halves to exercise multi-chunk streaming.
                let half = BODY_SIZE / 2;
                send_body
                    .send_data(
                        bytes::Bytes::copy_from_slice(&body_for_server[..half]),
                        false,
                    )
                    .unwrap();
                send_body
                    .send_data(
                        bytes::Bytes::copy_from_slice(&body_for_server[half..]),
                        true,
                    )
                    .unwrap();
            }
        });

        let upstream = TcpStream::connect(server_addr).await.unwrap();
        let (client_stream, test_end) = tokio::io::duplex(BODY_SIZE * 2);
        let (mut test_reader, mut test_writer) = split(test_end);
        let (exchange_tx, mut exchange_rx) = tokio::sync::mpsc::channel(8);

        let proxy = tokio::spawn(async move {
            let client_buf = BufReader::new(client_stream);
            proxy_h1_to_h2(
                client_buf,
                upstream,
                "test.host",
                443,
                &[],
                exchange_tx,
                None,
                CAP, // <-- max_body_capture
                CAP, // max_header_capture
                None,
                None,
                None, // serial_lock
                HttpLimits::default(),
            )
            .await
        });

        test_writer
            .write_all(b"GET /big HTTP/1.1\r\nHost: test.host\r\n\r\n")
            .await
            .unwrap();
        test_writer.shutdown().await.unwrap();

        let mut response_bytes = Vec::new();
        test_reader.read_to_end(&mut response_bytes).await.unwrap();
        proxy.await.unwrap().unwrap();
        server.await.unwrap();

        // 1. The H1 response carries Content-Length: BODY_SIZE.
        let header_end = response_bytes
            .windows(4)
            .position(|w| w == b"\r\n\r\n")
            .expect("response must have header terminator")
            + 4;
        let header_block = std::str::from_utf8(&response_bytes[..header_end]).unwrap();
        assert!(
            header_block
                .to_lowercase()
                .contains(&format!("content-length: {}", BODY_SIZE)),
            "Content-Length must equal upstream's value, got headers: {header_block}"
        );
        assert!(
            !header_block
                .to_lowercase()
                .contains("transfer-encoding: chunked"),
            "must NOT use chunked when upstream supplied Content-Length"
        );

        // 2. The wire body is the FULL upstream body, byte-for-byte.
        let wire_body = &response_bytes[header_end..];
        assert_eq!(
            wire_body.len(),
            BODY_SIZE,
            "wire body length must match Content-Length and upstream payload"
        );
        assert_eq!(
            wire_body,
            &body[..],
            "wire body must be byte-for-byte upstream"
        );

        // 3. The captured copy is bounded by CAP and marked truncated.
        let exchange = exchange_rx.try_recv().expect("exchange must be captured");
        assert_eq!(exchange.status, 200);
        assert_eq!(
            exchange.response_body.len(),
            CAP,
            "captured body must be capped at max_body_capture"
        );
        assert_eq!(
            &exchange.response_body[..],
            &body[..CAP],
            "captured body must be the prefix of the upstream payload"
        );
        assert!(
            exchange.response_body_truncated,
            "exchange must be flagged as truncated"
        );
    }

    /// H2 response without Content-Length MUST be forwarded with
    /// `Transfer-Encoding: chunked` so the H1 client can frame the body.
    #[tokio::test]
    async fn test_h2_to_h1_no_content_length_uses_chunked_encoding() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let server_addr = listener.local_addr().unwrap();

        let server = tokio::spawn(async move {
            let (socket, _) = listener.accept().await.unwrap();
            let mut conn = h2::server::handshake(socket).await.unwrap();
            while let Some(result) = conn.accept().await {
                let (_req, mut respond) = result.unwrap();
                // Note: NO Content-Length header.
                let response = http::Response::builder().status(200).body(()).unwrap();
                let mut send_body = respond.send_response(response, false).unwrap();
                send_body
                    .send_data(bytes::Bytes::from_static(b"part1-"), false)
                    .unwrap();
                send_body
                    .send_data(bytes::Bytes::from_static(b"part2"), true)
                    .unwrap();
            }
        });

        let upstream = TcpStream::connect(server_addr).await.unwrap();
        let (client_stream, test_end) = tokio::io::duplex(65536);
        let (mut test_reader, mut test_writer) = split(test_end);
        let (exchange_tx, _exchange_rx) = tokio::sync::mpsc::channel(8);

        let proxy = tokio::spawn(async move {
            let client_buf = BufReader::new(client_stream);
            proxy_h1_to_h2(
                client_buf,
                upstream,
                "test.host",
                443,
                &[],
                exchange_tx,
                None,
                DEFAULT_MAX_BODY_CAPTURE,
                DEFAULT_MAX_BODY_CAPTURE, // max_header_capture
                None,
                None,
                None, // serial_lock
                HttpLimits::default(),
            )
            .await
        });

        test_writer
            .write_all(b"GET /stream HTTP/1.1\r\nHost: test.host\r\n\r\n")
            .await
            .unwrap();
        test_writer.shutdown().await.unwrap();

        let mut response_bytes = Vec::new();
        test_reader.read_to_end(&mut response_bytes).await.unwrap();
        proxy.await.unwrap().unwrap();
        server.await.unwrap();

        let response = String::from_utf8_lossy(&response_bytes);

        // Must advertise chunked encoding.
        assert!(
            response
                .to_lowercase()
                .contains("transfer-encoding: chunked"),
            "must use chunked encoding when upstream omits Content-Length, got: {response:?}"
        );
        // Must NOT include Content-Length (would conflict with chunked).
        assert!(
            !response.to_lowercase().contains("content-length"),
            "must NOT include Content-Length on chunked path, got: {response:?}"
        );

        // Body must be valid chunked encoding: "6\r\npart1-\r\n5\r\npart2\r\n0\r\n\r\n"
        let header_end = response_bytes
            .windows(4)
            .position(|w| w == b"\r\n\r\n")
            .unwrap()
            + 4;
        let body = &response_bytes[header_end..];
        assert_eq!(
            body, b"6\r\npart1-\r\n5\r\npart2\r\n0\r\n\r\n",
            "chunked body must be properly framed"
        );
    }

    /// HEAD request: H1 client must receive headers only, no body framing
    /// confusion even if upstream sent body bytes.
    #[tokio::test]
    async fn test_h2_to_h1_head_request_skips_body() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let server_addr = listener.local_addr().unwrap();

        let server = tokio::spawn(async move {
            let (socket, _) = listener.accept().await.unwrap();
            let mut conn = h2::server::handshake(socket).await.unwrap();
            while let Some(result) = conn.accept().await {
                let (req, mut respond) = result.unwrap();
                assert_eq!(req.method(), &http::Method::HEAD);
                // HEAD response: include Content-Length matching what GET
                // would return (per RFC 9110 §15).
                let response = http::Response::builder()
                    .status(200)
                    .header("content-length", "100")
                    .body(())
                    .unwrap();
                respond.send_response(response, true).unwrap();
            }
        });

        let upstream = TcpStream::connect(server_addr).await.unwrap();
        let (client_stream, test_end) = tokio::io::duplex(65536);
        let (mut test_reader, mut test_writer) = split(test_end);
        let (exchange_tx, _exchange_rx) = tokio::sync::mpsc::channel(8);

        let proxy = tokio::spawn(async move {
            let client_buf = BufReader::new(client_stream);
            proxy_h1_to_h2(
                client_buf,
                upstream,
                "test.host",
                443,
                &[],
                exchange_tx,
                None,
                DEFAULT_MAX_BODY_CAPTURE,
                DEFAULT_MAX_BODY_CAPTURE, // max_header_capture
                None,
                None,
                None, // serial_lock
                HttpLimits::default(),
            )
            .await
        });

        test_writer
            .write_all(b"HEAD /resource HTTP/1.1\r\nHost: test.host\r\n\r\n")
            .await
            .unwrap();
        test_writer.shutdown().await.unwrap();

        let mut response_bytes = Vec::new();
        test_reader.read_to_end(&mut response_bytes).await.unwrap();
        proxy.await.unwrap().unwrap();
        server.await.unwrap();

        let response = String::from_utf8_lossy(&response_bytes);

        // HEAD response: status, Content-Length: 100, but no body bytes after \r\n\r\n.
        assert!(
            response.starts_with("HTTP/1.1 200"),
            "expected 200 for HEAD, got: {response:?}"
        );
        assert!(
            response.to_lowercase().contains("content-length: 100"),
            "HEAD response must forward Content-Length, got: {response:?}"
        );
        assert!(
            !response
                .to_lowercase()
                .contains("transfer-encoding: chunked"),
            "HEAD response must NOT use chunked encoding, got: {response:?}"
        );
        let header_end = response_bytes
            .windows(4)
            .position(|w| w == b"\r\n\r\n")
            .unwrap()
            + 4;
        assert_eq!(
            response_bytes.len(),
            header_end,
            "HEAD response body must be empty (header_end = {header_end}, total = {})",
            response_bytes.len()
        );
    }
}
