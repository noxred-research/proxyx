//! HTTPS proxy transport regressions. All endpoints are local; trust is explicit.

use std::sync::Arc;
use std::time::Duration;

use common::Secret;
use common::metrics::Metrics;
use common::types::{Target, UpstreamEndpoint, UpstreamScheme};
use proxyx_dial::{
    DialError, DialTimeouts, ProxyStream, Stage, dial_with_tls_config, handshake_with_tls_config,
    proxy_tls_config,
};
use rcgen::{CertificateParams, KeyPair};
use rustls::pki_types::PrivatePkcs8KeyDer;
use rustls::{ClientConfig, RootCertStore, ServerConfig};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::task::JoinHandle;
use tokio::time::timeout;
use tokio_rustls::TlsAcceptor;

const LIMIT: Duration = Duration::from_secs(5);

fn certificate(host: &str) -> (Arc<ServerConfig>, Arc<ClientConfig>) {
    let key = KeyPair::generate().expect("server key");
    let cert = CertificateParams::new(vec![host.to_owned()])
        .expect("certificate params")
        .self_signed(&key)
        .expect("server certificate");
    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    let mut server = ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .expect("TLS versions")
        .with_no_client_auth()
        .with_single_cert(
            vec![cert.der().clone()],
            PrivatePkcs8KeyDer::from(key.serialize_der()).into(),
        )
        .expect("server config");
    server.alpn_protocols = vec![b"http/1.1".to_vec()];
    let mut roots = RootCertStore::empty();
    roots.add(cert.der().clone()).expect("trust certificate");
    (
        Arc::new(server),
        proxy_tls_config(roots).expect("client config"),
    )
}

fn endpoint(host: &str, port: u16) -> UpstreamEndpoint {
    UpstreamEndpoint {
        provider: "tls-stub".parse().expect("provider"),
        scheme: UpstreamScheme::Https,
        host: host.to_owned(),
        port,
        username: Secret::new("user"),
        password: Secret::new("pa:ss"),
        public_only: false,
    }
}

fn target() -> Target {
    Target {
        host: "origin.example".to_owned(),
        port: 443,
    }
}

async fn head<S: AsyncRead + Unpin>(stream: &mut S) -> String {
    let mut bytes = Vec::new();
    while !bytes.ends_with(b"\r\n\r\n") {
        bytes.push(stream.read_u8().await.expect("CONNECT request"));
        assert!(bytes.len() < 8192, "request head cap");
    }
    String::from_utf8(bytes).expect("CONNECT UTF-8")
}

async fn serve<S: AsyncRead + AsyncWrite + Unpin>(stream: &mut S, reply: &[u8]) -> String {
    let request = head(stream).await;
    stream.write_all(reply).await.expect("CONNECT reply");
    stream.flush().await.expect("flush reply");
    if reply.starts_with(b"HTTP/1.1 200") {
        let mut bytes = [0; 64];
        loop {
            match stream.read(&mut bytes).await {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    stream.write_all(&bytes[..n]).await.expect("echo");
                    stream.flush().await.expect("flush echo");
                }
            }
        }
    }
    request
}

async fn proxy(
    config: Arc<ServerConfig>,
    reply: &'static [u8],
) -> (u16, JoinHandle<Option<String>>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("listen");
    let port = listener.local_addr().expect("address").port();
    let task = tokio::spawn(async move {
        timeout(LIMIT, async {
            let (tcp, _) = listener.accept().await.expect("accept");
            let mut tls = TlsAcceptor::from(config).accept(tcp).await.ok()?;
            assert_eq!(tls.get_ref().1.alpn_protocol(), Some(&b"http/1.1"[..]));
            Some(serve(&mut tls, reply).await)
        })
        .await
        .expect("server deadline")
    });
    (port, task)
}

async fn dial(up: &UpstreamEndpoint, config: Arc<ClientConfig>) -> Result<ProxyStream, DialError> {
    timeout(
        LIMIT,
        dial_with_tls_config(
            up,
            &target(),
            &DialTimeouts::default(),
            &Metrics::new("test"),
            config,
        ),
    )
    .await
    .expect("dial deadline")
}

async fn joined(task: JoinHandle<Option<String>>) -> Option<String> {
    timeout(LIMIT, task)
        .await
        .expect("server deadline")
        .expect("server task")
}

#[tokio::test]
async fn trusted_proxy_encrypts_connect_auth_and_preserves_tunnel_bytes() {
    for host in ["localhost", "127.0.0.1"] {
        let (server, client) = certificate(host);
        let (port, task) = proxy(server, b"HTTP/1.1 200 OK\r\n\r\n220 hello\r\n").await;
        let mut stream = dial(&endpoint(host, port), client)
            .await
            .expect("trusted proxy");
        assert_eq!(stream.peer_addr().expect("peer").port(), port);
        let mut early = [0; 11];
        timeout(LIMIT, stream.read_exact(&mut early))
            .await
            .expect("read deadline")
            .expect("greeting");
        assert_eq!(&early, b"220 hello\r\n");
        stream.write_all(b"ping").await.expect("tunnel write");
        stream.flush().await.expect("tunnel flush");
        let mut echo = [0; 4];
        timeout(LIMIT, stream.read_exact(&mut echo))
            .await
            .expect("echo deadline")
            .expect("tunnel echo");
        assert_eq!(&echo, b"ping");
        stream.shutdown().await.expect("TLS close");
        drop(stream);
        let request = joined(task).await.expect("TLS accepted");
        assert!(
            request.starts_with("CONNECT origin.example:443 HTTP/1.1\r\n"),
            "{request}"
        );
        assert!(
            request.contains("\r\nHost: origin.example:443\r\n"),
            "{request}"
        );
        assert!(
            request.contains("\r\nProxy-Authorization: Basic dXNlcjpwYTpzcw==\r\n"),
            "{request}"
        );
    }
}

#[tokio::test]
async fn untrusted_certificate_and_hostname_mismatch_send_no_connect() {
    for wrong_name in [false, true] {
        let (server, trusted) = certificate("localhost");
        let client = if wrong_name {
            trusted
        } else {
            certificate("localhost").1
        };
        let (port, task) = proxy(server, b"HTTP/1.1 200 OK\r\n\r\n").await;
        // Connecting by IP must check its IP SAN, not accept a DNS-only SAN.
        let host = if wrong_name { "127.0.0.1" } else { "localhost" };
        let error = dial(&endpoint(host, port), client)
            .await
            .expect_err("reject certificate");
        assert!(!error.is_retryable(), "{error:?}");
        let DialError::Io(error) = error else {
            panic!("expected TLS I/O error: {error:?}")
        };
        assert!(
            matches!(
                error
                    .get_ref()
                    .and_then(|source| source.downcast_ref::<rustls::Error>()),
                Some(rustls::Error::InvalidCertificate(_))
            ),
            "{error:?}"
        );
        assert!(
            joined(task).await.is_none(),
            "CONNECT must not follow failed TLS"
        );
    }
}

#[tokio::test]
async fn tls_connect_preserves_auth_status_and_protocol_errors() {
    for (reply, expected) in [
        (
            &b"HTTP/1.1 407 Proxy Authentication Required\r\n\r\n"[..],
            407,
        ),
        (&b"HTTP/1.1 429 Too Many Requests\r\n\r\n"[..], 429),
        (&b"HTTP/1.1 502 Bad Gateway\r\n\r\n"[..], 502),
        (&b"not-http\r\n\r\n"[..], 0),
    ] {
        let (server, client) = certificate("127.0.0.1");
        let (port, task) = proxy(server, reply).await;
        let error = dial(&endpoint("127.0.0.1", port), client)
            .await
            .expect_err("CONNECT refused");
        match expected {
            407 => assert!(matches!(error, DialError::Auth)),
            0 => assert!(matches!(error, DialError::Protocol(_))),
            code => assert!(matches!(error, DialError::Status(actual) if actual == code)),
        }
        assert_eq!(error.is_retryable(), expected == 429);
        assert!(joined(task).await.is_some(), "TLS handshake succeeded");
    }
}

#[tokio::test]
async fn silent_tls_peer_uses_handshake_timeout_and_records_stage() {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("listen");
    let port = listener.local_addr().expect("address").port();
    let task = tokio::spawn(async move {
        let (_tcp, _) = listener.accept().await.expect("accept");
        std::future::pending::<()>().await;
    });
    let metrics = Metrics::new("test");
    let limits = DialTimeouts {
        handshake: Duration::from_millis(25),
        ..DialTimeouts::default()
    };
    let error = timeout(
        LIMIT,
        dial_with_tls_config(
            &endpoint("127.0.0.1", port),
            &target(),
            &limits,
            &metrics,
            proxy_tls_config(RootCertStore::empty()).expect("client config"),
        ),
    )
    .await
    .expect("deadline")
    .expect_err("TLS stalled");
    assert!(matches!(
        error,
        DialError::Timeout {
            stage: Stage::Handshake,
            ..
        }
    ));
    assert_eq!(
        metrics
            .dial_duration_seconds
            .with_label_values(&["tls-stub", "handshake"])
            .get_sample_count(),
        1
    );
    task.abort();
}

#[tokio::test]
async fn tls_connect_reply_shares_handshake_timeout() {
    let (server, client) = certificate("127.0.0.1");
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("listen");
    let port = listener.local_addr().expect("address").port();
    let (sent, received) = tokio::sync::oneshot::channel();
    let task = tokio::spawn(async move {
        let (tcp, _) = listener.accept().await.expect("accept");
        let mut tls = TlsAcceptor::from(server)
            .accept(tcp)
            .await
            .expect("TLS accept");
        sent.send(head(&mut tls).await).expect("request observer");
        std::future::pending::<()>().await;
    });
    let limits = DialTimeouts {
        handshake: Duration::from_secs(1),
        ..DialTimeouts::default()
    };
    let error = timeout(
        LIMIT,
        dial_with_tls_config(
            &endpoint("127.0.0.1", port),
            &target(),
            &limits,
            &Metrics::new("test"),
            client,
        ),
    )
    .await
    .expect("deadline")
    .expect_err("CONNECT stalled");
    assert!(matches!(
        error,
        DialError::Timeout {
            stage: Stage::Handshake,
            ..
        }
    ));
    let request = timeout(LIMIT, received)
        .await
        .expect("request deadline")
        .expect("CONNECT observed");
    assert!(request.starts_with("CONNECT origin.example:443 HTTP/1.1\r\n"));
    task.abort();
}

#[tokio::test]
async fn https_tls_can_be_nested_inside_an_established_tls_tunnel() {
    let (outer_server, client) = certificate("127.0.0.1");
    let inner_server = Arc::clone(&outer_server);
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("listen");
    let port = listener.local_addr().expect("address").port();
    let task = tokio::spawn(async move {
        timeout(LIMIT, async {
            let (tcp, _) = listener.accept().await.expect("accept");
            let mut outer = TlsAcceptor::from(outer_server)
                .accept(tcp)
                .await
                .expect("outer TLS");
            let first = head(&mut outer).await;
            outer
                .write_all(b"HTTP/1.1 200 OK\r\n\r\n")
                .await
                .expect("first CONNECT");
            outer.flush().await.expect("first flush");
            let mut inner = TlsAcceptor::from(inner_server)
                .accept(outer)
                .await
                .expect("inner TLS");
            let second = serve(&mut inner, b"HTTP/1.1 200 OK\r\n\r\nready").await;
            (first, second)
        })
        .await
        .expect("nested server deadline")
    });
    let up = endpoint("127.0.0.1", port);
    let outer = dial(&up, Arc::clone(&client)).await.expect("outer tunnel");
    // Public dial covers ordinary TLS. This second transport exercises nested
    // ProxyStream I/O with the same explicit trust configuration.
    let nested_target = Target {
        host: "nested.example".to_owned(),
        port: 443,
    };
    let mut inner = timeout(
        LIMIT,
        handshake_with_tls_config(outer, &up, &nested_target, client),
    )
    .await
    .expect("inner deadline")
    .expect("inner TLS CONNECT");
    let mut ready = [0; 5];
    inner
        .read_exact(&mut ready)
        .await
        .expect("early nested bytes");
    assert_eq!(&ready, b"ready");
    inner.shutdown().await.expect("inner shutdown");
    drop(inner);
    let (first, second) = timeout(LIMIT, task)
        .await
        .expect("nested deadline")
        .expect("nested task");
    assert!(first.starts_with("CONNECT origin.example:443"));
    assert!(second.starts_with("CONNECT nested.example:443"));
}

#[tokio::test]
async fn https_never_downgrades_to_plaintext_connect() {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("listen");
    let port = listener.local_addr().expect("address").port();
    let task = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.expect("accept");
        let mut record = [0; 5];
        timeout(LIMIT, stream.read_exact(&mut record))
            .await
            .expect("TLS record deadline")
            .expect("TLS record");
        assert_eq!(record[0], 22, "TLS handshake record, never CONNECT");
        assert_eq!(record[1], 3, "TLS record version");
    });
    let client = proxy_tls_config(RootCertStore::empty()).expect("client config");
    assert!(dial(&endpoint("127.0.0.1", port), client).await.is_err());
    timeout(LIMIT, task)
        .await
        .expect("server deadline")
        .expect("server task");
}
