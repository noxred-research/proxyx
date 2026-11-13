use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::AtomicBool;

use super::common::{
    ConnOutcome, MAX_HEADER_BYTES, MAX_HEADER_COUNT, PROXY_ERROR_HEADER, UpGuard, find_double_crlf,
    has_double_crlf, parse_absolute_url, parse_host_port, refuse_over_limit, write_error_response,
};
use crate::breaker::BreakerOpen;
use crate::context::{ProxyContext, Refusal};
use crate::egress::DialTimedOut;
use crate::mitm::{CapturedExchange, MitmParams, PrefixedStream, WsCaptureSink};
use crate::pipeline::{
    PipelineEvent, SessionMetadata, TimingInfo as PipelineTimingInfo, WsPipelineEvent,
};
use crate::ratelimit::OrgRateLimit;
use crate::state::{AuthError, AuthResult};
use anyhow::{Context, Result};
use bytes::BytesMut;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::time::timeout;
use tokio_util::sync::CancellationToken;
use tracing::Instrument as _;
use tracing::{debug, info, warn};

pub async fn serve(
    addr: SocketAddr,
    ctx: Arc<ProxyContext>,
    up: Arc<AtomicBool>,
    shutdown: CancellationToken,
) -> Result<()> {
    let listener = TcpListener::bind(addr)
        .await
        .with_context(|| format!("bind {}", addr))?;

    info!(%addr, "CONNECT proxy listening");

    let _up = UpGuard::new(&up);
    loop {
        let (stream, peer) = tokio::select! {
            result = listener.accept() => {
                match result {
                    Ok(pair) => pair,
                    Err(e) => {
                        warn!(error = %e, "accept error on CONNECT listener; backing off");
                        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
                        continue;
                    }
                }
            }
            _ = shutdown.cancelled() => {
                info!("CONNECT listener shutting down");
                return Ok(());
            }
        };

        let ctx = ctx.clone();
        let slot = match ctx.admit(&stream) {
            Ok(slot) => slot,
            Err(Refusal::LimitReached) => {
                refuse_over_limit(stream, "connect", true);
                continue;
            }
            Err(Refusal::Closed) => break, // semaphore closed — shutting down
        };

        tokio::spawn(async move {
            let outcome = match handle_client(stream, peer, ctx).await {
                Ok(outcome) => outcome.label(),
                Err(e) => {
                    debug!(%peer, error=?e, "connection ended with error");
                    "error"
                }
            };
            common::metrics::PROXY_CONNECTIONS_TOTAL
                .with_label_values(&[outcome, "connect"])
                .inc();
            drop(slot);
        });
    }
    Ok(())
}

/// Parsed proxy request -- either a CONNECT tunnel or an HTTP forward request.
#[derive(Debug)]
enum ProxyRequest {
    /// CONNECT host:port -- tunnel establishment (HTTPS).
    Connect {
        host: String,
        port: u16,
        proxy_authorization: Option<String>,
    },
    /// GET/POST/... http://host/path -- plain HTTP forward proxy.
    /// The raw request bytes are preserved for forwarding.
    Forward {
        host: String,
        port: u16,
        proxy_authorization: Option<String>,
        raw: BytesMut,
    },
}

impl ProxyRequest {
    fn host(&self) -> &str {
        match self {
            Self::Connect { host, .. } | Self::Forward { host, .. } => host,
        }
    }

    fn port(&self) -> u16 {
        match self {
            Self::Connect { port, .. } | Self::Forward { port, .. } => *port,
        }
    }

    fn proxy_authorization(&self) -> Option<&str> {
        match self {
            Self::Connect {
                proxy_authorization,
                ..
            }
            | Self::Forward {
                proxy_authorization,
                ..
            } => proxy_authorization.as_deref(),
        }
    }
}

/// Read request headers from the stream and classify as CONNECT or HTTP forward.
/// Returns the parsed request and any overflow bytes read past the header terminator
/// (e.g. a pipelined TLS ClientHello after a CONNECT request).
async fn read_and_parse_request(
    stream: &mut TcpStream,
    header_timeout: std::time::Duration,
) -> Result<(ProxyRequest, Vec<u8>)> {
    let mut buf = BytesMut::with_capacity(4096);

    timeout(header_timeout, async {
        loop {
            if buf.len() > MAX_HEADER_BYTES {
                anyhow::bail!("headers too large");
            }
            if has_double_crlf(&buf) {
                break;
            }
            let mut tmp = [0u8; 2048];
            let n = stream.read(&mut tmp).await?;
            if n == 0 {
                anyhow::bail!("client closed before headers complete");
            }
            buf.extend_from_slice(&tmp[..n]);
        }
        Ok::<_, anyhow::Error>(())
    })
    .await
    .context("header read timeout")??;

    // Split buffer at the end of headers. Everything past \r\n\r\n is overflow
    // (e.g. a TLS ClientHello that the client pipelined after CONNECT).
    let header_end = find_double_crlf(&buf).context("missing header terminator")?;
    let overflow = buf[header_end..].to_vec();
    buf.truncate(header_end);

    let req = parse_request(&buf)?;
    Ok((req, overflow))
}

/// Parse a raw request buffer into a `ProxyRequest`.
fn parse_request(buf: &BytesMut) -> Result<ProxyRequest> {
    let header_end = find_double_crlf(buf).context("missing header terminator")?;
    let header_block = &buf[..header_end];

    let mut headers = [httparse::EMPTY_HEADER; MAX_HEADER_COUNT];
    let mut req = httparse::Request::new(&mut headers);

    let status = req.parse(header_block)?;
    if !status.is_complete() {
        anyhow::bail!("incomplete request headers");
    }

    let method = req.method.unwrap_or("");
    let path = req.path.unwrap_or("");

    let proxy_authorization = req
        .headers
        .iter()
        .find(|h| h.name.eq_ignore_ascii_case("Proxy-Authorization"))
        .map(|h| String::from_utf8_lossy(h.value).trim().to_string());

    if method.eq_ignore_ascii_case("CONNECT") {
        let (host, port) = parse_host_port(path)?;
        Ok(ProxyRequest::Connect {
            host,
            port,
            proxy_authorization,
        })
    } else {
        let (host, port, _path) = parse_absolute_url(path)?;
        Ok(ProxyRequest::Forward {
            host,
            port,
            proxy_authorization,
            raw: buf.clone(),
        })
    }
}

pub async fn handle_client(
    mut stream: TcpStream,
    peer: SocketAddr,
    ctx: Arc<ProxyContext>,
) -> Result<ConnOutcome> {
    stream.set_nodelay(true).ok();

    // 1. Read & classify request (CONNECT vs HTTP forward)
    let (req, overflow) =
        read_and_parse_request(&mut stream, ctx.network.client_header_timeout()).await?;

    // 2. Authenticate & route
    let AuthResult {
        session_id,
        decision,
    } = match ctx
        .state
        .authenticate_and_route(req.proxy_authorization(), req.host(), req.port())
        .await
    {
        Ok(r) => r,
        Err(AuthError::BackendUnavailable) => {
            warn!(%peer, "auth backend unavailable");
            write_error_response(
                &mut stream,
                503,
                "Service Unavailable",
                &[("Connection", "close")],
                "session backend unavailable",
            )
            .await?;
            return Ok(ConnOutcome::BackendUnavailable);
        }
        Err(e) => {
            warn!(%peer, error=?e, "auth/routing failed");
            write_error_response(
                &mut stream,
                407,
                "Proxy Authentication Required",
                &[("Proxy-Authenticate", r#"Basic realm="proxy""#)],
                "proxy authentication required",
            )
            .await?;
            return Ok(ConnOutcome::Rejected);
        }
    };

    // 3.5 Serialization lock — passed into the MITM keepalive loop so it is
    // held per-exchange, not for the entire connection lifetime.
    let serial_lock = if decision.serialize {
        ctx.state.get_serial_lock(&session_id)
    } else {
        None
    };

    // 4. Build per-exchange rate limiter for the MITM tunnel
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

    // 5. Connect either to the logical origin or this session's exact private target.
    let mapped = decision.upstream_override.as_deref();
    let target = mapped.map_or((req.host(), req.port()), |route| {
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
            if let Some(open) = e.downcast_ref::<BreakerOpen>() {
                warn!(logical_host = %req.host(), logical_port = req.port(), upstream_host = %target.0, upstream_port = target.1, %session_id, kind = open.kind.label(), "upstream circuit breaker open; failing fast");
                let body = match open.kind {
                    _ if mapped.is_some() => "private upstream temporarily unavailable".to_string(),
                    crate::breaker::TargetKind::EgressProxy => {
                        "egress proxy temporarily unavailable".to_string()
                    }
                    _ => format!(
                        "upstream {}:{} temporarily unavailable",
                        req.host(),
                        req.port()
                    ),
                };
                let retry_after = open.retry_after_secs().to_string();
                write_error_response(
                    &mut stream,
                    503,
                    "Service Unavailable",
                    &[
                        ("Connection", "close"),
                        (PROXY_ERROR_HEADER, "upstream_unavailable"),
                        ("Retry-After", &retry_after),
                    ],
                    &body,
                )
                .await?;
                return Ok(ConnOutcome::UpstreamUnavailable);
            }
            if e.downcast_ref::<DialTimedOut>().is_some() {
                warn!(logical_host = %req.host(), logical_port = req.port(), upstream_host = %target.0, upstream_port = target.1, %session_id, "upstream connect timeout");
                let body = if mapped.is_some() {
                    "private upstream unavailable".to_string()
                } else {
                    format!(
                        "upstream connect to {}:{} timed out",
                        req.host(),
                        req.port()
                    )
                };
                write_error_response(
                    &mut stream,
                    504,
                    "Gateway Timeout",
                    &[("Connection", "close")],
                    &body,
                )
                .await?;
                return Ok(ConnOutcome::UpstreamTimeout);
            }
            warn!(logical_host = %req.host(), logical_port = req.port(), upstream_host = %target.0, upstream_port = target.1, %session_id, error=?e, "upstream connect failed");
            let body = if mapped.is_some() {
                "private upstream unavailable".to_string()
            } else {
                format!(
                    "upstream connect to {}:{} failed: {}",
                    req.host(),
                    req.port(),
                    e
                )
            };
            write_error_response(
                &mut stream,
                502,
                "Bad Gateway",
                &[("Connection", "close")],
                &body,
            )
            .await?;
            return Ok(ConnOutcome::UpstreamError);
        }
    };

    // 6. Protocol-specific handling
    match req {
        ProxyRequest::Connect { ref host, .. } => {
            // Send 200 Connection Established
            stream
                .write_all(b"HTTP/1.1 200 Connection Established\r\nConnection: keep-alive\r\n\r\n")
                .await?;

            if decision.mitm {
                let plaintext = req.port() == 80;
                let scheme = if plaintext { "http" } else { "https" };
                info!(%host, %scheme, "performing MITM interception");
                if plaintext {
                    // Port 80 — intercept as plaintext HTTP, no TLS handshake.
                    let prefix = overflow;
                    let prefixed = PrefixedStream::new(prefix, stream);
                    run_mitm_intercept(
                        &ctx,
                        Client {
                            session_id: &session_id,
                            sticky_key: decision.sticky_key.clone(),
                        },
                        scheme,
                        host,
                        req.port(),
                        exchange_ratelimit.clone(),
                        |captures| {
                            ctx.mitm.intercept_plaintext(
                                prefixed,
                                upstream,
                                host,
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
                } else if overflow.is_empty() {
                    run_mitm_intercept(
                        &ctx,
                        Client {
                            session_id: &session_id,
                            sticky_key: decision.sticky_key.clone(),
                        },
                        scheme,
                        host,
                        req.port(),
                        exchange_ratelimit.clone(),
                        |captures| {
                            ctx.mitm.intercept(
                                stream,
                                upstream,
                                MitmParams {
                                    host,
                                    port: req.port(),
                                    inject_headers: &decision.inject_headers,
                                    tls_profile: decision.tls_profile,
                                    exchange_tx: captures.exchange_tx,
                                    exchange_ratelimit: exchange_ratelimit.clone(),
                                    ws_sink: Some(captures.ws_sink),
                                    serial_lock: serial_lock.clone(),
                                    egress_proxy,
                                    upstream_tls: mapped.is_none(),
                                    insecure_upstream_tls: decision.insecure_upstream_tls,
                                },
                            )
                        },
                    )
                    .await;
                } else {
                    // The client pipelined data (e.g. TLS ClientHello) past the
                    // CONNECT headers. Prepend those bytes so rustls sees the
                    // complete handshake.
                    let prefixed = PrefixedStream::new(overflow, stream);
                    run_mitm_intercept(
                        &ctx,
                        Client {
                            session_id: &session_id,
                            sticky_key: decision.sticky_key.clone(),
                        },
                        scheme,
                        host,
                        req.port(),
                        exchange_ratelimit.clone(),
                        |captures| {
                            ctx.mitm.intercept(
                                prefixed,
                                upstream,
                                MitmParams {
                                    host,
                                    port: req.port(),
                                    inject_headers: &decision.inject_headers,
                                    tls_profile: decision.tls_profile,
                                    exchange_tx: captures.exchange_tx,
                                    exchange_ratelimit: exchange_ratelimit.clone(),
                                    ws_sink: Some(captures.ws_sink),
                                    serial_lock: serial_lock.clone(),
                                    egress_proxy,
                                    upstream_tls: mapped.is_none(),
                                    insecure_upstream_tls: decision.insecure_upstream_tls,
                                },
                            )
                        },
                    )
                    .await;
                }
            } else {
                let mut upstream = upstream;
                if overflow.is_empty() {
                    let _ = tokio::io::copy_bidirectional(&mut stream, &mut upstream).await;
                } else {
                    let mut prefixed = PrefixedStream::new(overflow, stream);
                    let _ = tokio::io::copy_bidirectional(&mut prefixed, &mut upstream).await;
                }
            }
        }
        ProxyRequest::Forward {
            ref host,
            port,
            raw,
            ..
        } => {
            if decision.mitm {
                info!(%host, "performing HTTP interception");
                let mut prefix = raw.to_vec();
                prefix.extend_from_slice(&overflow);
                let prefixed = PrefixedStream::new(prefix, stream);
                run_mitm_intercept(
                    &ctx,
                    Client {
                        session_id: &session_id,
                        sticky_key: decision.sticky_key.clone(),
                    },
                    "http",
                    host,
                    port,
                    exchange_ratelimit.clone(),
                    |captures| {
                        ctx.mitm.intercept_plaintext(
                            prefixed,
                            upstream,
                            host,
                            &decision.inject_headers,
                            captures.exchange_tx,
                            exchange_ratelimit.clone(),
                            Some(captures.ws_sink),
                            serial_lock.clone(),
                            decision.has_upstream_overrides,
                        )
                    },
                )
                .await;
            } else {
                // Frame exactly one exchange, then explicitly close both sides.
                // Overflow can contain another authority and its proxy credential;
                // never turn a forward-proxy connection into an unparsed tunnel.
                let mut prefix = raw.to_vec();
                prefix.extend_from_slice(&overflow);
                let prefixed = PrefixedStream::new(prefix, stream);
                ctx.mitm
                    .relay_plaintext_once(prefixed, upstream, host)
                    .await?;
            }
        }
    }

    Ok(ConnOutcome::Ok)
}

/// Aggregate of capture sinks handed to the per-tunnel intercept closure.
/// Both senders ride channels owned by `run_mitm_intercept`'s publisher task.
pub(crate) struct InterceptCaptures {
    pub exchange_tx: tokio::sync::mpsc::Sender<CapturedExchange>,
    pub ws_sink: WsCaptureSink,
}

/// Set the capture-only sticky-key header on a captured request. Any header of
/// that name the client sent is dropped first, so the value only ever comes
/// from the proxy credential. The header is not forwarded to the target.
fn tag_sticky_key(headers: &mut Vec<(String, String)>, sticky_key: Option<&str>) {
    headers.retain(|(name, _)| !name.eq_ignore_ascii_case(common::sticky::HEADER));
    if let Some(key) = sticky_key {
        headers.push((common::sticky::HEADER.to_string(), key.to_string()));
    }
}

/// Build a [`PipelineEvent`] from a [`CapturedExchange`], consuming the
/// exchange (fields are moved, not cloned).
fn build_pipeline_event(
    ex: CapturedExchange,
    session_id: common::types::SessionId,
    proxy_id: String,
    scheme: &'static str,
    port: u16,
    session: &crate::state::LocalSession,
    sticky_key: Option<&str>,
) -> PipelineEvent {
    let mut request_headers = ex.request_headers;
    tag_sticky_key(&mut request_headers, sticky_key);
    PipelineEvent {
        event_id: ex.event_id,
        session_id,
        proxy_id,
        timestamp: ex.timestamp,
        method: ex.method,
        scheme: scheme.to_string(),
        host: ex.host,
        port,
        path: ex.path,
        request_headers,
        request_body: ex.request_body,
        request_body_size: ex.request_body_size,
        request_body_truncated: ex.request_body_truncated,
        response_status: ex.status as u32,
        response_status_text: String::new(),
        response_headers: ex.response_headers,
        response_body: ex.response_body,
        response_body_size: ex.response_body_size,
        response_body_truncated: ex.response_body_truncated,
        timing: PipelineTimingInfo {
            total_ms: ex.duration_ms,
            ..Default::default()
        },
        metadata: SessionMetadata {
            org_id: session.org_id.to_string(),
            source: session.source.clone(),
            source_id: session.source_id.clone(),
        },
    }
}

/// Who a tunnel belongs to: the session, and the opaque sticky key of its credential, if any.
pub(crate) struct Client<'a> {
    pub session_id: &'a uuid::Uuid,
    pub sticky_key: Option<Arc<str>>,
}

/// Spawn a publisher task, run the MITM interception, wait for the publisher
/// to drain. Shared between CONNECT and HTTP paths.
pub(crate) async fn run_mitm_intercept<F, Fut>(
    ctx: &Arc<ProxyContext>,
    client: Client<'_>,
    scheme: &'static str,
    host: &str,
    port: u16,
    exchange_ratelimit: Option<Arc<dyn crate::ratelimit::ExchangeRateLimit>>,
    make_intercept: F,
) where
    F: FnOnce(InterceptCaptures) -> Fut,
    Fut: std::future::Future<Output = Result<()>>,
{
    let session_id = client.session_id;
    // Two bounded channels — HTTP exchanges and WS messages. Both apply
    // backpressure to the proxy when the publisher / broker stall.
    let (ex_tx, mut ex_rx) =
        tokio::sync::mpsc::channel::<CapturedExchange>(ctx.exchange_channel_capacity);
    let (ws_tx, mut ws_rx) =
        tokio::sync::mpsc::channel::<WsPipelineEvent>(ctx.exchange_channel_capacity);

    // Resolve session metadata before the tunnel starts
    let session = match ctx.state.get_session(session_id).await {
        crate::state::SessionLookup::Found(s) => s,
        crate::state::SessionLookup::NotFound | crate::state::SessionLookup::BackendUnavailable => {
            warn!(
                %session_id,
                "session not found at intercept time; capture stream dropped"
            );
            // Drain both channels so the MITM tunnel doesn't block.
            tokio::spawn(async move {
                loop {
                    tokio::select! {
                        m = ex_rx.recv() => if m.is_none() { break; },
                        m = ws_rx.recv() => if m.is_none() { break; },
                    }
                }
            });
            // Build a sink with empty session metadata; the publisher won't
            // run, but the closure still needs a valid sink to pass through.
            let ws_sink = WsCaptureSink {
                tx: ws_tx,
                max_payload_capture: ctx.max_ws_payload_capture,
                max_compressed_message_bytes: ctx.max_ws_compressed_message_bytes,
                capture_control_frames: ctx.capture_ws_control_frames,
                session_id: *session_id,
                org_id: String::new(),
                source: String::new(),
                source_id: String::new(),
                proxy_id: ctx.state.proxy_id.clone(),
                exchange_ratelimit: exchange_ratelimit.clone(),
            };
            let _ = make_intercept(InterceptCaptures {
                exchange_tx: ex_tx,
                ws_sink,
            })
            .await;
            return;
        }
    };
    let pipeline = ctx.pipeline.clone();
    let proxy_id = ctx.state.proxy_id.clone();

    // Build the WS sink with full session metadata for the closure.
    let ws_sink = WsCaptureSink {
        tx: ws_tx,
        max_payload_capture: ctx.max_ws_payload_capture,
        max_compressed_message_bytes: ctx.max_ws_compressed_message_bytes,
        capture_control_frames: ctx.capture_ws_control_frames,
        session_id: *session_id,
        org_id: session.org_id.to_string(),
        source: session.source.clone(),
        source_id: session.source_id.clone(),
        proxy_id: proxy_id.clone(),
        exchange_ratelimit,
    };

    // Publisher task: drain both channels concurrently. Either side closing
    // is enough to signal the loop to drain to empty and exit.
    let sid = *session_id;
    let publisher_session = session.clone();
    let publisher_proxy_id = proxy_id.clone();
    let publisher_sticky_key = client.sticky_key;
    let publisher_pipeline = pipeline.clone();
    let publish_task = tokio::spawn(async move {
        loop {
            tokio::select! {
                http_msg = ex_rx.recv() => match http_msg {
                    Some(ex) => {
                        debug!(
                            method = %ex.method,
                            host = %ex.host,
                            path = %ex.path,
                            status = ex.status,
                            event_id = %ex.event_id,
                            source = %publisher_session.source,
                            source_id = %publisher_session.source_id,
                            "captured http exchange"
                        );
                        let event = build_pipeline_event(
                            ex,
                            sid,
                            publisher_proxy_id.clone(),
                            scheme,
                            port,
                            &publisher_session,
                            publisher_sticky_key.as_deref(),
                        );
                        let send_start = tokio::time::Instant::now();
                        publisher_pipeline.send(event).await;
                        let send_elapsed = send_start.elapsed();
                        if send_elapsed > std::time::Duration::from_secs(5) {
                            warn!(
                                elapsed_ms = send_elapsed.as_millis() as u64,
                                "pipeline http send blocked >5s"
                            );
                        }
                    }
                    None => {
                        // Drain remaining ws messages then exit.
                        while let Some(ws) = ws_rx.recv().await {
                            publisher_pipeline.send_ws(ws).await;
                        }
                        break;
                    }
                },
                ws_msg = ws_rx.recv() => match ws_msg {
                    Some(ws) => {
                        debug!(
                            direction = ws.direction.as_str(),
                            event_id = %ws.event_id,
                            parent_event_id = %ws.parent_event_id,
                            payload_size = ws.payload_size,
                            was_compressed = ws.was_compressed,
                            "captured ws message"
                        );
                        let send_start = tokio::time::Instant::now();
                        publisher_pipeline.send_ws(ws).await;
                        let send_elapsed = send_start.elapsed();
                        if send_elapsed > std::time::Duration::from_secs(5) {
                            warn!(
                                elapsed_ms = send_elapsed.as_millis() as u64,
                                "pipeline ws send blocked >5s"
                            );
                        }
                    }
                    None => {
                        // Drain remaining http exchanges then exit.
                        while let Some(ex) = ex_rx.recv().await {
                            let event = build_pipeline_event(
                                ex,
                                sid,
                                publisher_proxy_id.clone(),
                                scheme,
                                port,
                                &publisher_session,
                                publisher_sticky_key.as_deref(),
                            );
                            publisher_pipeline.send(event).await;
                        }
                        break;
                    }
                },
            }
        }
    });

    // Run MITM interception -- exchanges stream through ex_tx, WS through ws_tx.
    // The span puts the session on every log line the MITM code writes. It is
    // WARN level so it stays enabled when RUST_LOG filters out INFO.
    let span = tracing::warn_span!(
        "proxyx.proxy.intercept",
        %session_id,
        %host,
        source = %session.source,
        source_id = %session.source_id,
    );
    let intercept_result = make_intercept(InterceptCaptures {
        exchange_tx: ex_tx,
        ws_sink,
    })
    .instrument(span)
    .await;

    // Wait for publisher to drain remaining exchanges/messages
    if let Err(e) = publish_task.await {
        warn!(error = ?e, %host, %session_id, "publish task panicked");
    }

    if let Err(e) = intercept_result {
        warn!(error=?e, %host, %session_id, "interception failed");
    }
}

#[cfg(test)]
#[path = "forward_tests.rs"]
mod forward_tests;
