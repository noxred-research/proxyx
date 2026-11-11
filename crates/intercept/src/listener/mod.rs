pub mod common;
pub(crate) mod connect;
pub(crate) mod http;
pub(crate) mod socks;

#[cfg(test)]
mod routing_tests {
    use std::future::Future;
    use std::path::PathBuf;
    use std::pin::Pin;
    use std::sync::Arc;
    use std::time::Duration;

    use base64::Engine;
    use boring::ssl::{SslConnector, SslMethod, SslVerifyMode};
    use bytes::Bytes;
    use common::log::CaptureLogProducer;
    use common::types::{ParsedUpstreamOverride, parse_upstream_override};
    use prost::Message;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::{TcpListener, TcpStream};
    use tokio::sync::mpsc;
    use tokio::time::timeout;
    use uuid::Uuid;

    use super::{connect, socks};
    use crate::config::{CaConfig, TuningConfig};
    use crate::context::{ProxyContext, ProxySettings};
    use crate::pipeline::{RequestLogConfig, RequestLogWriter};
    use crate::ratelimit::{RateLimitError, RateLimiter};
    use crate::state::{LocalSession, ProxyState};

    const LOGICAL_HOST: &str = "lab.example.test";
    const LOGICAL_PORT: u16 = 443;

    struct AllowAll;

    impl RateLimiter for AllowAll {
        fn acquire<'a>(
            &'a self,
            _org_id: &'a str,
            _limits: Option<&'a common::types::RateLimitSettings>,
        ) -> Pin<Box<dyn Future<Output = Result<Duration, RateLimitError>> + Send + 'a>> {
            Box::pin(async { Ok(Duration::ZERO) })
        }
    }

    struct ChannelProducer(mpsc::UnboundedSender<Bytes>);

    impl CaptureLogProducer for ChannelProducer {
        fn publish<'life0, 'life1, 'async_trait>(
            &'life0 self,
            _key: &'life1 [u8],
            payload: Bytes,
        ) -> Pin<Box<dyn Future<Output = anyhow::Result<()>> + Send + 'async_trait>>
        where
            'life0: 'async_trait,
            'life1: 'async_trait,
            Self: 'async_trait,
        {
            Box::pin(async move {
                self.0.send(payload).unwrap();
                Ok(())
            })
        }

        fn flush_and_close<'life0, 'async_trait>(
            &'life0 self,
            _timeout: Duration,
        ) -> Pin<Box<dyn Future<Output = ()> + Send + 'async_trait>>
        where
            'life0: 'async_trait,
            Self: 'async_trait,
        {
            Box::pin(async {})
        }
    }

    /// The settings these tests ran with before the context took a settings
    /// struct: 1 MiB body capture, 64 KiB header capture, 8 exchange slots, 8
    /// connections.
    fn route_test_settings() -> ProxySettings {
        ProxySettings {
            tuning: TuningConfig {
                max_body_capture: 1024 * 1024,
                max_header_capture: 64 * 1024,
                exchange_channel_capacity: 8,
                max_connections: 8,
                ..TuningConfig::default()
            },
            ..ProxySettings::default()
        }
    }

    async fn test_context(
        sessions: Vec<LocalSession>,
    ) -> (Arc<ProxyContext>, mpsc::UnboundedReceiver<Bytes>, PathBuf) {
        test_context_with(sessions, route_test_settings()).await
    }

    async fn test_context_with(
        sessions: Vec<LocalSession>,
        settings: ProxySettings,
    ) -> (Arc<ProxyContext>, mpsc::UnboundedReceiver<Bytes>, PathBuf) {
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
        let redis_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let redis_addr = redis_listener.local_addr().unwrap();
        tokio::spawn(async move {
            loop {
                let Ok((mut stream, _)) = redis_listener.accept().await else {
                    return;
                };
                tokio::spawn(async move {
                    let mut buf = [0u8; 1024];
                    while stream.read(&mut buf).await.unwrap_or(0) > 0 {
                        let _ = stream.write_all(b"+OK\r\n+OK\r\n+OK\r\n+OK\r\n").await;
                    }
                });
            }
        });
        let redis_client = redis::Client::open(format!("redis://{redis_addr}/")).unwrap();
        let redis = redis::aio::ConnectionManager::new(redis_client)
            .await
            .unwrap();
        let state = ProxyState::new("test-proxy".into(), redis, Vec::new(), "test".into());
        for session in sessions {
            state.sessions.insert(session.session_id, session);
        }

        let ca_dir = std::env::temp_dir().join(format!("proxyx-route-test-{}", Uuid::new_v4()));
        let ca = crate::ca::load(&CaConfig::Generate {
            data_dir: ca_dir.clone(),
        })
        .unwrap();
        let (capture_tx, capture_rx) = mpsc::unbounded_channel();
        let pipeline = Arc::new(RequestLogWriter::new(
            RequestLogConfig::default(),
            Box::new(ChannelProducer(capture_tx)),
        ));
        let ctx = ProxyContext::new(state, ca, Arc::new(AllowAll), pipeline, settings).unwrap();
        (Arc::new(ctx), capture_rx, ca_dir)
    }

    fn local_session(session_id: Uuid, route: ParsedUpstreamOverride) -> LocalSession {
        LocalSession {
            session_id,
            org_id: Arc::from("test-org"),
            source: "test".into(),
            source_id: session_id.to_string(),
            agent: None,
            captured_hosts: Vec::new(),
            excluded_hosts: Vec::new(),
            upstream_overrides: Arc::from(vec![Arc::new(route)]),
            insecure_upstream_tls: false,
            inject_headers: Arc::from([]),
            serialize: false,
            serial_lock: None,
            expires_at_ms: Arc::new(std::sync::atomic::AtomicI64::new(i64::MAX)),
            egress_proxy: None,
            rate_limit: None,
        }
    }

    #[tokio::test]
    async fn routing_preserves_explicit_upstream_tls_policy() {
        for insecure_upstream_tls in [false, true] {
            let session_id = Uuid::new_v4();
            let route =
                parse_upstream_override("lab.example.test:443", "http://127.0.0.1:8000").unwrap();
            let mut session = local_session(session_id, route);
            session.insecure_upstream_tls = insecure_upstream_tls;
            let (ctx, _captures, ca_dir) = test_context(vec![session]).await;
            let auth = format!(
                "Basic {}",
                base64::engine::general_purpose::STANDARD.encode(format!("{session_id}:password"))
            );
            let http = ctx
                .state
                .authenticate_and_route(Some(&auth), LOGICAL_HOST, LOGICAL_PORT)
                .await
                .unwrap();
            assert_eq!(http.decision.insecure_upstream_tls, insecure_upstream_tls);
            let socks = ctx
                .state
                .authenticate_socks_and_route(session_id, LOGICAL_HOST, LOGICAL_PORT)
                .await
                .unwrap();
            assert_eq!(socks.decision.insecure_upstream_tls, insecure_upstream_tls);
            let _ = std::fs::remove_dir_all(ca_dir);
        }
    }

    async fn upstream(body: &'static str) -> (String, tokio::task::JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let task = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let headers = read_headers(&mut stream).await;
            assert!(headers.contains(&format!("Host: {LOGICAL_HOST}")));
            stream
                .write_all(
                    format!(
                        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                        body.len(),
                        body
                    )
                    .as_bytes(),
                )
                .await
                .unwrap();
        });
        (format!("http://{addr}"), task)
    }

    async fn read_headers(stream: &mut TcpStream) -> String {
        let mut bytes = Vec::new();
        while !bytes.ends_with(b"\r\n\r\n") {
            let mut byte = [0u8; 1];
            stream.read_exact(&mut byte).await.unwrap();
            bytes.push(byte[0]);
        }
        String::from_utf8(bytes).unwrap()
    }

    async fn tls_request(stream: TcpStream) -> String {
        let mut builder = SslConnector::builder(SslMethod::tls()).unwrap();
        builder.set_verify(SslVerifyMode::NONE);
        let config = builder.build().configure().unwrap();
        let mut tls = tokio_boring::connect(config, LOGICAL_HOST, stream)
            .await
            .unwrap();
        tls.write_all(
            format!("GET / HTTP/1.1\r\nHost: {LOGICAL_HOST}\r\nConnection: close\r\n\r\n")
                .as_bytes(),
        )
        .await
        .unwrap();
        let mut response = Vec::new();
        tls.read_to_end(&mut response).await.unwrap();
        String::from_utf8(response).unwrap()
    }

    async fn connect_client(ctx: Arc<ProxyContext>, session_id: Uuid) -> String {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (stream, peer) = listener.accept().await.unwrap();
            connect::handle_client(stream, peer, ctx).await.unwrap();
        });
        let mut stream = TcpStream::connect(addr).await.unwrap();
        let auth = base64::engine::general_purpose::STANDARD.encode(format!("{session_id}:x"));
        stream
            .write_all(
                format!(
                    "CONNECT {LOGICAL_HOST}:{LOGICAL_PORT} HTTP/1.1\r\nProxy-Authorization: Basic {auth}\r\n\r\n"
                )
                .as_bytes(),
            )
            .await
            .unwrap();
        assert!(read_headers(&mut stream).await.starts_with("HTTP/1.1 200"));
        tls_request(stream).await
    }

    /// Run `handle_socks5` on one accepted connection, complete the SOCKS5
    /// handshake for `session_id` and `address` (ATYP, address, port), and
    /// assert the `0x00` replies.
    async fn socks_connect(
        ctx: Arc<ProxyContext>,
        session_id: Uuid,
        address: &[u8],
    ) -> (
        TcpStream,
        tokio::task::JoinHandle<super::common::ConnOutcome>,
    ) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let handler = tokio::spawn(async move {
            let (stream, peer) = listener.accept().await.unwrap();
            socks::handle_socks5(stream, peer, ctx).await.unwrap()
        });
        let mut stream = TcpStream::connect(addr).await.unwrap();
        stream.write_all(&[0x05, 0x01, 0x02]).await.unwrap();
        let mut reply = [0u8; 2];
        stream.read_exact(&mut reply).await.unwrap();
        assert_eq!(reply, [0x05, 0x02]);
        let username = session_id.to_string();
        let mut auth = vec![0x01, username.len() as u8];
        auth.extend_from_slice(username.as_bytes());
        auth.extend_from_slice(&[1, b'x']);
        stream.write_all(&auth).await.unwrap();
        stream.read_exact(&mut reply).await.unwrap();
        assert_eq!(reply, [0x01, 0x00]);
        let mut request = vec![0x05, 0x01, 0x00];
        request.extend_from_slice(address);
        stream.write_all(&request).await.unwrap();
        let mut connected = [0u8; 10];
        stream.read_exact(&mut connected).await.unwrap();
        assert_eq!(connected[1], 0x00);
        (stream, handler)
    }

    fn socks_domain(host: &str, port: u16) -> Vec<u8> {
        let mut address = vec![0x03, host.len() as u8];
        address.extend_from_slice(host.as_bytes());
        address.extend_from_slice(&port.to_be_bytes());
        address
    }

    fn socks_ipv4(addr: std::net::SocketAddr) -> Vec<u8> {
        let std::net::SocketAddr::V4(addr) = addr else {
            panic!("expected an IPv4 address: {addr}");
        };
        let mut address = vec![0x01];
        address.extend_from_slice(&addr.ip().octets());
        address.extend_from_slice(&addr.port().to_be_bytes());
        address
    }

    async fn socks_client(ctx: Arc<ProxyContext>, session_id: Uuid) -> String {
        let (stream, _handler) =
            socks_connect(ctx, session_id, &socks_domain(LOGICAL_HOST, LOGICAL_PORT)).await;
        tls_request(stream).await
    }

    /// A port nothing listens on: bind, then drop the listener.
    async fn closed_addr() -> std::net::SocketAddr {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        listener.local_addr().unwrap()
    }

    async fn forward_client(ctx: Arc<ProxyContext>, session_id: Uuid, logical_port: u16) -> String {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (stream, peer) = listener.accept().await.unwrap();
            connect::handle_client(stream, peer, ctx).await.unwrap();
        });
        let mut stream = TcpStream::connect(addr).await.unwrap();
        let auth = base64::engine::general_purpose::STANDARD.encode(format!("{session_id}:x"));
        stream
            .write_all(
                format!(
                    "GET http://{LOGICAL_HOST}:{logical_port}/doc HTTP/1.1\r\nHost: {LOGICAL_HOST}\r\nProxy-Authorization: Basic {auth}\r\nConnection: close\r\n\r\n"
                )
                .as_bytes(),
            )
            .await
            .unwrap();
        let mut response = Vec::new();
        stream.read_to_end(&mut response).await.unwrap();
        String::from_utf8(response).unwrap()
    }

    async fn captured_request(
        captures: &mut mpsc::UnboundedReceiver<Bytes>,
    ) -> common::wire::CapturedRequest {
        let payload = timeout(Duration::from_secs(2), captures.recv())
            .await
            .unwrap()
            .unwrap();
        let envelope = common::wire::RequestLogMessage::decode(payload).unwrap();
        match envelope.kind.unwrap() {
            common::wire::request_log_message::Kind::Request(request) => request,
            other => panic!("unexpected capture kind: {other:?}"),
        }
    }

    #[tokio::test]
    async fn connect_and_socks_sessions_route_same_https_authority_to_separate_http_upstreams() {
        let (destination_a, upstream_a) = upstream("connect-a").await;
        let (destination_b, upstream_b) = upstream("socks-b").await;
        let authority = format!("{LOGICAL_HOST}:{LOGICAL_PORT}");
        let session_a = Uuid::new_v4();
        let session_b = Uuid::new_v4();
        let sessions = vec![
            local_session(
                session_a,
                parse_upstream_override(&authority, &destination_a).unwrap(),
            ),
            local_session(
                session_b,
                parse_upstream_override(&authority, &destination_b).unwrap(),
            ),
        ];
        let (ctx, mut captures, ca_dir) = test_context(sessions).await;

        assert!(
            connect_client(ctx.clone(), session_a)
                .await
                .contains("connect-a")
        );
        let connect_capture = captured_request(&mut captures).await;
        assert_eq!(connect_capture.scheme, "https");
        assert_eq!(connect_capture.host, LOGICAL_HOST);
        assert_eq!(connect_capture.port, LOGICAL_PORT as u32);

        assert!(socks_client(ctx, session_b).await.contains("socks-b"));
        let socks_capture = captured_request(&mut captures).await;
        assert_eq!(socks_capture.scheme, "https");
        assert_eq!(socks_capture.host, LOGICAL_HOST);
        assert_eq!(socks_capture.port, LOGICAL_PORT as u32);

        upstream_a.await.unwrap();
        upstream_b.await.unwrap();
        let _ = std::fs::remove_dir_all(ca_dir);
    }

    /// A target cannot fake ProxyX's in-band proxy error through the MITM
    /// path; the capture still records what the target sent.
    #[tokio::test]
    async fn socks_mitm_strips_upstream_proxy_error_header() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let target = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            read_headers(&mut stream).await;
            stream
                .write_all(
                    b"HTTP/1.1 502 Bad Gateway\r\n\
X-ProxyX-Error: session_not_found\r\n\
Content-Length: 6\r\n\
Connection: close\r\n\r\n\
target",
                )
                .await
                .unwrap();
        });
        let session_id = Uuid::new_v4();
        let route = parse_upstream_override(
            &format!("{LOGICAL_HOST}:{LOGICAL_PORT}"),
            &format!("http://{addr}"),
        )
        .unwrap();
        let (ctx, mut captures, ca_dir) =
            test_context(vec![local_session(session_id, route)]).await;

        let response = socks_client(ctx, session_id).await;

        assert!(response.starts_with("HTTP/1.1 502 "), "{response}");
        assert!(response.ends_with("\r\n\r\ntarget"), "{response}");
        assert!(
            !response.to_ascii_lowercase().contains("x-proxyx-error"),
            "{response}"
        );
        let capture = captured_request(&mut captures).await;
        assert!(
            capture
                .response_headers
                .iter()
                .any(|h| h.name.eq_ignore_ascii_case("x-proxyx-error"))
        );
        target.await.unwrap();
        let _ = std::fs::remove_dir_all(ca_dir);
    }

    #[tokio::test]
    async fn absolute_http_request_uses_private_http_target_and_logical_capture() {
        let upstream_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let upstream_addr = upstream_listener.local_addr().unwrap();
        let upstream = tokio::spawn(async move {
            let (mut stream, _) = upstream_listener.accept().await.unwrap();
            let headers = read_headers(&mut stream).await;
            // The origin sees origin-form, not the absolute-form the client sent the proxy.
            assert!(headers.starts_with("GET /doc HTTP/1.1\r\n"), "{headers}");
            assert!(headers.contains(&format!("Host: {LOGICAL_HOST}\r\n")));
            stream
                .write_all(
                    b"HTTP/1.1 200 OK\r\nContent-Length: 8\r\nConnection: close\r\n\r\nabsolute",
                )
                .await
                .unwrap();
        });
        let authority = format!("{LOGICAL_HOST}:80");
        let destination = format!("http://{upstream_addr}");
        let session_id = Uuid::new_v4();
        let session = local_session(
            session_id,
            parse_upstream_override(&authority, &destination).unwrap(),
        );
        let (ctx, mut captures, ca_dir) = test_context(vec![session]).await;

        assert!(
            forward_client(ctx, session_id, 80)
                .await
                .contains("absolute")
        );
        let capture = captured_request(&mut captures).await;
        assert_eq!(capture.scheme, "http");
        assert_eq!(capture.host, LOGICAL_HOST);
        assert_eq!(capture.port, 80);
        upstream.await.unwrap();
        let _ = std::fs::remove_dir_all(ca_dir);
    }

    async fn assert_forward_connection_stops_after_first_authority(first_mapped: bool) {
        let public_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let public_addr = public_listener.local_addr().unwrap();
        let private_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let private_addr = private_listener.local_addr().unwrap();
        let authority = format!("{LOGICAL_HOST}:80");
        let session_id = Uuid::new_v4();
        let session = local_session(
            session_id,
            parse_upstream_override(&authority, &format!("http://{private_addr}")).unwrap(),
        );
        let (ctx, _captures, ca_dir) = test_context(vec![session]).await;
        let (expected_listener, untouched_listener, first_url, second_url) = if first_mapped {
            (
                private_listener,
                public_listener,
                format!("http://{LOGICAL_HOST}:80/first"),
                format!("http://{public_addr}/second"),
            )
        } else {
            (
                public_listener,
                private_listener,
                format!("http://{public_addr}/first"),
                format!("http://{LOGICAL_HOST}:80/second"),
            )
        };
        let first_path = &first_url[first_url.rfind('/').unwrap_or(0)..];
        let expected_first_line = format!("GET {first_path} HTTP/1.1\r\n");
        let upstream = tokio::spawn(async move {
            let (mut stream, _) = expected_listener.accept().await.unwrap();
            let headers = read_headers(&mut stream).await;
            assert!(headers.starts_with(&expected_first_line), "{headers}");
            stream
                .write_all(
                    b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\nConnection: keep-alive\r\n\r\nfirst",
                )
                .await
                .unwrap();
            let mut unexpected = Vec::new();
            stream.read_to_end(&mut unexpected).await.unwrap();
            unexpected
        });

        let proxy_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy_addr = proxy_listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (stream, peer) = proxy_listener.accept().await.unwrap();
            connect::handle_client(stream, peer, ctx).await.unwrap();
        });
        let auth = base64::engine::general_purpose::STANDARD.encode(format!("{session_id}:x"));
        let first_host = first_url
            .strip_prefix("http://")
            .unwrap()
            .split('/')
            .next()
            .unwrap();
        let second_host = second_url
            .strip_prefix("http://")
            .unwrap()
            .split('/')
            .next()
            .unwrap();
        let pipelined = format!(
            "GET {first_url} HTTP/1.1\r\nHost: {first_host}\r\nProxy-Authorization: Basic {auth}\r\n\r\n\
             GET {second_url} HTTP/1.1\r\nHost: {second_host}\r\nProxy-Authorization: Basic {auth}\r\n\r\n"
        );
        let mut client = TcpStream::connect(proxy_addr).await.unwrap();
        client.write_all(pipelined.as_bytes()).await.unwrap();
        let mut response = Vec::new();
        client.read_to_end(&mut response).await.unwrap();
        let response = String::from_utf8(response).unwrap();
        assert!(response.contains("first"));
        assert!(response.contains("Connection: close\r\n"));
        assert!(upstream.await.unwrap().is_empty());
        assert!(
            timeout(Duration::from_millis(100), untouched_listener.accept())
                .await
                .is_err()
        );
        let _ = std::fs::remove_dir_all(ca_dir);
    }

    #[tokio::test]
    async fn forward_keepalive_cannot_cross_mapped_authority_boundary() {
        assert_forward_connection_stops_after_first_authority(false).await;
        assert_forward_connection_stops_after_first_authority(true).await;
    }

    #[tokio::test]
    async fn failed_private_route_does_not_fall_back_to_logical_authority() {
        let logical_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let logical_addr = logical_listener.local_addr().unwrap();
        let closed_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let closed_addr = closed_listener.local_addr().unwrap();
        drop(closed_listener);
        let authority = logical_addr.to_string();
        let destination = format!("http://{closed_addr}");
        let session_id = Uuid::new_v4();
        let session = local_session(
            session_id,
            parse_upstream_override(&authority, &destination).unwrap(),
        );
        let (ctx, _captures, ca_dir) = test_context(vec![session]).await;

        let proxy_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy_addr = proxy_listener.local_addr().unwrap();
        let handler = tokio::spawn(async move {
            let (stream, peer) = proxy_listener.accept().await.unwrap();
            connect::handle_client(stream, peer, ctx).await.unwrap()
        });
        let mut client = TcpStream::connect(proxy_addr).await.unwrap();
        let auth = base64::engine::general_purpose::STANDARD.encode(format!("{session_id}:x"));
        client
            .write_all(
                format!(
                    "CONNECT {authority} HTTP/1.1\r\nProxy-Authorization: Basic {auth}\r\n\r\n"
                )
                .as_bytes(),
            )
            .await
            .unwrap();
        let response = read_headers(&mut client).await;
        assert!(response.starts_with("HTTP/1.1 502"));
        assert!(response.contains("private upstream unavailable"));
        assert!(
            timeout(Duration::from_millis(100), logical_listener.accept())
                .await
                .is_err()
        );
        assert_eq!(
            handler.await.unwrap(),
            super::common::ConnOutcome::UpstreamError
        );
        let _ = std::fs::remove_dir_all(ca_dir);
    }

    async fn plain_request(mut stream: TcpStream) -> String {
        stream
            .write_all(b"GET / HTTP/1.1\r\nHost: target\r\nX-ProxyX-Agent: corr-1\r\n\r\n")
            .await
            .unwrap();
        let mut response = Vec::new();
        stream.read_to_end(&mut response).await.unwrap();
        String::from_utf8(response).unwrap()
    }

    #[tokio::test]
    async fn socks_refused_upstream_is_reported_in_band() {
        let target = closed_addr().await;
        let session_id = Uuid::new_v4();
        let route = parse_upstream_override(
            &format!("{LOGICAL_HOST}:{LOGICAL_PORT}"),
            "http://127.0.0.1:1",
        )
        .unwrap();
        let (ctx, _captures, ca_dir) = test_context(vec![local_session(session_id, route)]).await;

        let (stream, handler) = socks_connect(ctx, session_id, &socks_ipv4(target)).await;
        let response = plain_request(stream).await;

        assert!(response.starts_with("HTTP/1.1 502 "), "{response}");
        let lower = response.to_ascii_lowercase();
        assert!(lower.contains("\r\nx-proxyx-error: upstream_refused\r\n"));
        assert!(lower.contains("\r\nserver: proxyx\r\n"));
        assert!(response.ends_with(&format!(
            "\r\n\r\nProxyX proxy error: upstream_refused {target}\n"
        )));
        assert_eq!(
            handler.await.unwrap(),
            super::common::ConnOutcome::UpstreamError
        );
        let _ = std::fs::remove_dir_all(ca_dir);
    }

    #[tokio::test]
    async fn socks_unknown_session_is_reported_in_band() {
        let (ctx, _captures, ca_dir) = test_context(Vec::new()).await;

        let (stream, handler) = socks_connect(
            ctx.clone(),
            Uuid::new_v4(),
            &socks_ipv4(closed_addr().await),
        )
        .await;
        let response = plain_request(stream).await;
        assert!(response.starts_with("HTTP/1.1 503 "), "{response}");
        assert!(
            response
                .to_ascii_lowercase()
                .contains("\r\nx-proxyx-error: session_not_found\r\n")
        );
        assert_eq!(handler.await.unwrap(), super::common::ConnOutcome::Rejected);

        // A TLS client gets the same answer behind ProxyX's certificate.
        let (stream, handler) = socks_connect(
            ctx,
            Uuid::new_v4(),
            &socks_domain(LOGICAL_HOST, LOGICAL_PORT),
        )
        .await;
        let response = tls_request(stream).await;
        assert!(response.starts_with("HTTP/1.1 503 "), "{response}");
        assert!(
            response
                .to_ascii_lowercase()
                .contains("\r\nx-proxyx-error: session_not_found\r\n")
        );
        assert_eq!(handler.await.unwrap(), super::common::ConnOutcome::Rejected);
        let _ = std::fs::remove_dir_all(ca_dir);
    }

    fn breaker_settings() -> ProxySettings {
        let mut settings = route_test_settings();
        settings.network.egress_retries = 1;
        settings.breaker = crate::breaker::BreakerConfig {
            consecutive_failures: 1,
            open_duration_ms: 60_000,
            max_open_duration_ms: 60_000,
            ..crate::breaker::BreakerConfig::default()
        };
        settings
    }

    fn rejected_total(kind: &str) -> f64 {
        common::metrics::PROXY_UPSTREAM_BREAKER_REJECTED_TOTAL
            .with_label_values(&[kind])
            .get()
    }

    /// CONNECT `authority` through `handle_client`; returns the 4xx/5xx
    /// reply and the handler's outcome.
    async fn connect_request(
        ctx: Arc<ProxyContext>,
        session_id: Uuid,
        authority: &str,
    ) -> (String, super::common::ConnOutcome) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let handler = tokio::spawn(async move {
            let (stream, peer) = listener.accept().await.unwrap();
            connect::handle_client(stream, peer, ctx).await.unwrap()
        });
        let mut client = TcpStream::connect(addr).await.unwrap();
        let auth = base64::engine::general_purpose::STANDARD.encode(format!("{session_id}:x"));
        client
            .write_all(
                format!(
                    "CONNECT {authority} HTTP/1.1\r\nProxy-Authorization: Basic {auth}\r\n\r\n"
                )
                .as_bytes(),
            )
            .await
            .unwrap();
        let response = read_headers(&mut client).await;
        (response, handler.await.unwrap())
    }

    #[tokio::test]
    async fn connect_fails_fast_when_the_private_upstream_breaker_is_open() {
        let target = closed_addr().await;
        let authority = format!("{LOGICAL_HOST}:{LOGICAL_PORT}");
        let session_id = Uuid::new_v4();
        let session = local_session(
            session_id,
            parse_upstream_override(&authority, &format!("http://{target}")).unwrap(),
        );
        let (ctx, _captures, ca_dir) = test_context_with(vec![session], breaker_settings()).await;

        let (first, outcome) = connect_request(ctx.clone(), session_id, &authority).await;
        assert!(first.starts_with("HTTP/1.1 502"), "{first}");
        assert_eq!(outcome, super::common::ConnOutcome::UpstreamError);

        // The target comes back, but the breaker is open: no dial happens.
        let revived = TcpListener::bind(target).await.unwrap();
        let rejected_before = rejected_total("private_override");
        let started = std::time::Instant::now();
        let (second, outcome) = connect_request(ctx, session_id, &authority).await;
        assert!(second.starts_with("HTTP/1.1 503 "), "{second}");
        let lower = second.to_ascii_lowercase();
        assert!(
            lower.contains("\r\nx-proxyx-error: upstream_unavailable\r\n"),
            "{second}"
        );
        assert!(lower.contains("\r\nretry-after: "), "{second}");
        assert!(second.contains("private upstream temporarily unavailable"));
        assert_eq!(outcome, super::common::ConnOutcome::UpstreamUnavailable);
        assert!(started.elapsed() < Duration::from_secs(1));
        assert!(
            timeout(Duration::from_millis(200), revived.accept())
                .await
                .is_err(),
            "an open breaker must not dial"
        );
        assert!(rejected_total("private_override") > rejected_before);
        let _ = std::fs::remove_dir_all(ca_dir);
    }

    #[tokio::test]
    async fn forward_fails_fast_when_the_origin_breaker_is_open() {
        let target = closed_addr().await;
        let session_id = Uuid::new_v4();
        // No override for this authority: the proxy dials the origin itself.
        let route = parse_upstream_override("other.example.test:80", "http://127.0.0.1:1").unwrap();
        let (ctx, _captures, ca_dir) =
            test_context_with(vec![local_session(session_id, route)], breaker_settings()).await;

        let request = |ctx: Arc<ProxyContext>| async move {
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let addr = listener.local_addr().unwrap();
            let handler = tokio::spawn(async move {
                let (stream, peer) = listener.accept().await.unwrap();
                connect::handle_client(stream, peer, ctx).await.unwrap()
            });
            let mut client = TcpStream::connect(addr).await.unwrap();
            let auth = base64::engine::general_purpose::STANDARD.encode(format!("{session_id}:x"));
            client
                .write_all(
                    format!(
                        "GET http://{target}/ HTTP/1.1\r\nHost: {target}\r\nProxy-Authorization: Basic {auth}\r\nConnection: close\r\n\r\n"
                    )
                    .as_bytes(),
                )
                .await
                .unwrap();
            let mut response = Vec::new();
            client.read_to_end(&mut response).await.unwrap();
            (String::from_utf8(response).unwrap(), handler.await.unwrap())
        };

        let (first, outcome) = request(ctx.clone()).await;
        assert!(first.starts_with("HTTP/1.1 502"), "{first}");
        assert_eq!(outcome, super::common::ConnOutcome::UpstreamError);
        let (second, outcome) = request(ctx).await;
        assert!(second.starts_with("HTTP/1.1 503 "), "{second}");
        assert!(
            second
                .to_ascii_lowercase()
                .contains("\r\nx-proxyx-error: upstream_unavailable\r\n"),
            "{second}"
        );
        assert!(second.contains(&format!("upstream {target} temporarily unavailable")));
        assert_eq!(outcome, super::common::ConnOutcome::UpstreamUnavailable);
        let _ = std::fs::remove_dir_all(ca_dir);
    }

    #[tokio::test]
    async fn socks_fails_fast_in_band_when_the_origin_breaker_is_open() {
        let target = closed_addr().await;
        let session_id = Uuid::new_v4();
        let route = parse_upstream_override(
            &format!("{LOGICAL_HOST}:{LOGICAL_PORT}"),
            "http://127.0.0.1:1",
        )
        .unwrap();
        let (ctx, _captures, ca_dir) =
            test_context_with(vec![local_session(session_id, route)], breaker_settings()).await;

        let (stream, handler) = socks_connect(ctx.clone(), session_id, &socks_ipv4(target)).await;
        let response = plain_request(stream).await;
        assert!(response.starts_with("HTTP/1.1 502 "), "{response}");
        assert_eq!(
            handler.await.unwrap(),
            super::common::ConnOutcome::UpstreamError
        );

        let revived = TcpListener::bind(target).await.unwrap();

        // Plaintext client.
        let (stream, handler) = socks_connect(ctx.clone(), session_id, &socks_ipv4(target)).await;
        let response = plain_request(stream).await;
        assert!(response.starts_with("HTTP/1.1 503 "), "{response}");
        let lower = response.to_ascii_lowercase();
        assert!(
            lower.contains("\r\nx-proxyx-error: upstream_unavailable\r\n"),
            "{response}"
        );
        assert!(response.ends_with(&format!(
            "\r\n\r\nProxyX proxy error: upstream_unavailable {target}\n"
        )));
        assert_eq!(
            handler.await.unwrap(),
            super::common::ConnOutcome::UpstreamUnavailable
        );

        // TLS client: the error arrives behind ProxyX's certificate.
        let (stream, handler) = socks_connect(ctx, session_id, &socks_ipv4(target)).await;
        let response = tls_request(stream).await;
        assert!(response.starts_with("HTTP/1.1 503 "), "{response}");
        assert!(
            response
                .to_ascii_lowercase()
                .contains("\r\nx-proxyx-error: upstream_unavailable\r\n"),
            "{response}"
        );
        assert_eq!(
            handler.await.unwrap(),
            super::common::ConnOutcome::UpstreamUnavailable
        );
        assert!(
            timeout(Duration::from_millis(200), revived.accept())
                .await
                .is_err(),
            "an open breaker must not dial"
        );
        let _ = std::fs::remove_dir_all(ca_dir);
    }

    #[tokio::test]
    async fn disabled_breaker_keeps_answering_bad_gateway() {
        let target = closed_addr().await;
        let session_id = Uuid::new_v4();
        let route = parse_upstream_override(
            &format!("{LOGICAL_HOST}:{LOGICAL_PORT}"),
            "http://127.0.0.1:1",
        )
        .unwrap();
        let mut settings = breaker_settings();
        settings.breaker.enabled = false;
        let (ctx, _captures, ca_dir) =
            test_context_with(vec![local_session(session_id, route)], settings).await;
        for _ in 0..3 {
            let (stream, handler) =
                socks_connect(ctx.clone(), session_id, &socks_ipv4(target)).await;
            let response = plain_request(stream).await;
            assert!(response.starts_with("HTTP/1.1 502 "), "{response}");
            assert_eq!(
                handler.await.unwrap(),
                super::common::ConnOutcome::UpstreamError
            );
        }
        let _ = std::fs::remove_dir_all(ca_dir);
    }

    #[tokio::test]
    async fn admit_refuses_at_the_limit_and_applies_client_keepalive() {
        use crate::net::test_support::{keepalive_of, socket_pair};

        let mut settings = route_test_settings();
        settings.tuning.max_connections = 2;
        settings.network.client_keepalive = crate::config::TcpKeepaliveConfig {
            enabled: true,
            time_secs: 55,
            interval_secs: 12,
            retries: 4,
        };
        let (ctx, _captures, ca_dir) = test_context_with(Vec::new(), settings).await;

        let (_c1, s1) = socket_pair().await;
        let (_c2, s2) = socket_pair().await;
        let (_c3, s3) = socket_pair().await;
        let refusals_before = common::metrics::PROXY_CONNECTION_LIMIT_REFUSALS_TOTAL.get();

        let first = ctx.admit(&s1).expect("first slot");
        assert_eq!(
            keepalive_of(&s1),
            (true, Duration::from_secs(55), Duration::from_secs(12), 4),
            "the accepted client socket carries the configured keepalive"
        );
        let _second = ctx.admit(&s2).expect("second slot");
        assert_eq!(ctx.active_connections(), 2);
        assert_eq!(
            ctx.admit(&s3).err(),
            Some(crate::context::Refusal::LimitReached),
            "no waiting at the limit"
        );
        assert!(common::metrics::PROXY_CONNECTION_LIMIT_REFUSALS_TOTAL.get() > refusals_before);

        drop(first);
        assert_eq!(ctx.active_connections(), 1);
        assert!(ctx.admit(&s3).is_ok(), "a freed slot is usable again");
        let _ = std::fs::remove_dir_all(ca_dir);
    }

    #[tokio::test]
    async fn listener_refuses_over_the_limit_without_queueing() {
        let mut settings = route_test_settings();
        settings.tuning.max_connections = 1;
        let (ctx, _captures, ca_dir) = test_context_with(Vec::new(), settings).await;

        let addr = closed_addr().await;
        let up = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let shutdown = tokio_util::sync::CancellationToken::new();
        let serve = tokio::spawn(connect::serve(
            addr,
            ctx.clone(),
            up.clone(),
            shutdown.clone(),
        ));
        for _ in 0..100 {
            if up.load(std::sync::atomic::Ordering::Acquire) {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        assert!(
            up.load(std::sync::atomic::Ordering::Acquire),
            "listener is up"
        );

        // The first client takes the only slot and says nothing.
        let _holder = TcpStream::connect(addr).await.unwrap();
        for _ in 0..100 {
            if ctx.active_connections() == 1 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        assert_eq!(ctx.active_connections(), 1);

        let mut second = TcpStream::connect(addr).await.unwrap();
        let mut response = Vec::new();
        timeout(Duration::from_secs(2), second.read_to_end(&mut response))
            .await
            .expect("refused at once, not queued")
            .unwrap();
        let response = String::from_utf8(response).unwrap();
        assert!(response.starts_with("HTTP/1.1 503 "), "{response}");
        assert!(
            response
                .to_ascii_lowercase()
                .contains("\r\nx-proxyx-error: connection_limit\r\n"),
            "{response}"
        );

        shutdown.cancel();
        serve.await.unwrap().unwrap();
        assert!(
            !up.load(std::sync::atomic::Ordering::Acquire),
            "a listener that returned reports down"
        );
        let _ = std::fs::remove_dir_all(ca_dir);
    }

    #[tokio::test]
    async fn client_header_timeout_follows_the_config() {
        let mut settings = route_test_settings();
        settings.network.client_header_timeout_ms = 200;
        let (ctx, _captures, ca_dir) = test_context_with(Vec::new(), settings).await;

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let handler = tokio::spawn(async move {
            let (stream, peer) = listener.accept().await.unwrap();
            connect::handle_client(stream, peer, ctx).await
        });
        let mut client = TcpStream::connect(addr).await.unwrap();
        client.write_all(b"CONNECT lab.exam").await.unwrap();
        let started = std::time::Instant::now();
        let err = timeout(Duration::from_secs(3), handler)
            .await
            .expect("the handler gave up")
            .unwrap()
            .unwrap_err();
        assert!(
            format!("{err:#}").contains("header read timeout"),
            "{err:#}"
        );
        assert!(started.elapsed() < Duration::from_secs(2));
        let _ = std::fs::remove_dir_all(ca_dir);
    }
}
