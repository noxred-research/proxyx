//! Protocol tests against in-process stub upstreams on loopback.

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as STANDARD_B64;
use common::Secret;
use common::metrics::Metrics;
use common::types::{ProviderId, Target, UpstreamEndpoint, UpstreamScheme};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::time::Instant;

use super::*;

const SHORT: DialTimeouts = DialTimeouts {
    dns: Duration::from_secs(5),
    tcp: Duration::from_secs(5),
    handshake: Duration::from_secs(5),
    keepalive: DEFAULT_KEEPALIVE,
};

fn endpoint(
    scheme: UpstreamScheme,
    host: &str,
    port: u16,
    user: &str,
    pass: &str,
) -> UpstreamEndpoint {
    UpstreamEndpoint {
        provider: "stub".parse().expect("valid provider id"),
        scheme,
        host: host.to_owned(),
        port,
        username: Secret::new(user),
        password: Secret::new(pass),
        public_only: false,
    }
}

/// A loopback upstream with the login `u:p`.
fn upstream(scheme: UpstreamScheme, port: u16) -> UpstreamEndpoint {
    endpoint(scheme, "127.0.0.1", port, "u", "p")
}

fn target(host: &str, port: u16) -> Target {
    Target {
        host: host.to_owned(),
        port,
    }
}

/// Dial `host:443` through `up` with the [`SHORT`] timeouts.
async fn try_dial(up: &UpstreamEndpoint, host: &str) -> Result<TcpStream, DialError> {
    dial(up, &target(host, 443), &SHORT, &Metrics::new("test")).await
}

async fn stub() -> (TcpListener, u16) {
    let l = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let port = l.local_addr().expect("addr").port();
    (l, port)
}

/// A port nothing listens on.
async fn closed_port() -> u16 {
    stub().await.1
}

/// Samples recorded in `dial_duration_seconds` for the stage of the `stub` provider.
fn stage_count(m: &Metrics, stage: &str) -> u64 {
    m.dial_duration_seconds
        .with_label_values(&["stub", stage])
        .get_sample_count()
}

/// Read the CONNECT request head the client sent.
async fn read_head(s: &mut TcpStream) -> String {
    let mut buf = Vec::new();
    while !buf.ends_with(b"\r\n\r\n") {
        buf.push(s.read_u8().await.expect("client closed early"));
    }
    String::from_utf8(buf).expect("utf8 head")
}

/// Echo until the client closes.
async fn echo(s: &mut TcpStream) {
    let mut buf = [0u8; 64];
    loop {
        match s.read(&mut buf).await {
            Ok(0) | Err(_) => break,
            Ok(n) => s.write_all(&buf[..n]).await.expect("echo"),
        }
    }
}

/// A CONNECT upstream that answers `reply` and, when it is a 200, echoes.
fn http_stub(l: TcpListener, reply: &'static str) -> tokio::task::JoinHandle<String> {
    tokio::spawn(async move {
        let (mut s, _) = l.accept().await.expect("accept");
        let head = read_head(&mut s).await;
        s.write_all(reply.as_bytes()).await.expect("reply");
        if reply.starts_with("HTTP/1.1 200") {
            echo(&mut s).await;
        }
        head
    })
}

#[tokio::test]
async fn connect_200_sends_basic_auth_and_keeps_early_tunnel_bytes() {
    let (l, port) = stub().await;
    // The upstream sends tunnel bytes in the same write as the 200 head
    // (a server-speaks-first protocol); the client must not swallow them.
    let server = http_stub(
        l,
        "HTTP/1.1 200 Connection established\r\nVia: stub\r\n\r\n220 hello\r\n",
    );
    let up = endpoint(UpstreamScheme::Http, "127.0.0.1", port, "user", "pa:ss");

    let mut stream = try_dial(&up, "example.com").await.expect("dial");

    let mut greeting = [0u8; 11];
    stream.read_exact(&mut greeting).await.expect("early bytes");
    assert_eq!(&greeting, b"220 hello\r\n");
    stream.write_all(b"ping").await.expect("write");
    let mut echoed = [0u8; 4];
    stream.read_exact(&mut echoed).await.expect("echo");
    assert_eq!(&echoed, b"ping");
    drop(stream);

    let head = server.await.expect("stub");
    let expected_auth = format!(
        "Proxy-Authorization: Basic {}",
        STANDARD_B64.encode("user:pa:ss")
    );
    assert!(
        head.starts_with("CONNECT example.com:443 HTTP/1.1\r\n"),
        "{head}"
    );
    assert!(head.contains("\r\nHost: example.com:443\r\n"), "{head}");
    assert!(head.contains(&expected_auth), "{head}");
}

#[tokio::test]
async fn connect_without_username_sends_no_auth_and_brackets_ipv6() {
    let (l, port) = stub().await;
    let server = http_stub(l, "HTTP/1.1 200 OK\r\n\r\n");
    let up = endpoint(UpstreamScheme::Http, "127.0.0.1", port, "", "");
    try_dial(&up, "[2606:4700::1111]").await.expect("dial");
    let head = server.await.expect("stub");
    assert!(
        head.starts_with("CONNECT [2606:4700::1111]:443 HTTP/1.1\r\n"),
        "{head}"
    );
    assert!(!head.contains("Proxy-Authorization"), "{head}");
}

#[tokio::test]
async fn connect_407_is_provider_auth_and_not_retryable() {
    let (l, port) = stub().await;
    http_stub(
        l,
        "HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic\r\n\r\n",
    );
    let err = try_dial(&upstream(UpstreamScheme::Http, port), "example.com")
        .await
        .expect_err("407");
    assert!(matches!(err, DialError::Auth), "{err:?}");
    assert_eq!(err.cause(), Cause::ProviderAuth);
    assert!(!err.is_retryable());
}

#[tokio::test]
async fn connect_other_statuses_are_upstream_errors() {
    for (reply, code, retryable) in [
        ("HTTP/1.1 502 Bad Gateway\r\n\r\n", 502, false),
        ("HTTP/1.1 429 Too Many Requests\r\n\r\n", 429, true),
        ("HTTP/1.1 403 Forbidden\r\n\r\n", 403, false),
        // only 200 opens a tunnel: another 2xx is not accepted
        ("HTTP/1.1 204 No Content\r\n\r\n", 204, false),
    ] {
        let (l, port) = stub().await;
        http_stub(l, reply);
        let err = try_dial(&upstream(UpstreamScheme::Http, port), "example.com")
            .await
            .expect_err(reply);
        assert!(matches!(err, DialError::Status(c) if c == code), "{err:?}");
        assert_eq!(err.cause(), Cause::UpstreamError, "{reply}");
        assert_eq!(err.is_retryable(), retryable, "{reply}");
    }
}

#[tokio::test]
async fn connect_garbage_and_early_close_are_upstream_errors() {
    let (l, port) = stub().await;
    http_stub(l, "SSH-2.0-OpenSSH\r\n\r\n");
    let err = try_dial(&upstream(UpstreamScheme::Http, port), "example.com")
        .await
        .expect_err("garbage");
    assert!(matches!(err, DialError::Protocol(_)), "{err:?}");
    assert_eq!(err.cause(), Cause::UpstreamError);

    // The upstream closes before the head is complete: end of stream, retryable.
    let (l, port) = stub().await;
    tokio::spawn(async move {
        let (mut s, _) = l.accept().await.expect("accept");
        read_head(&mut s).await;
        s.write_all(b"HTTP/1.1 200 OK\r\n").await.expect("write");
    });
    let err = try_dial(&upstream(UpstreamScheme::Http, port), "example.com")
        .await
        .expect_err("eof");
    assert!(matches!(err, DialError::Io(_)), "{err:?}");
    assert_eq!(err.cause(), Cause::UpstreamError);
    assert!(err.is_retryable());
}

#[tokio::test]
async fn connect_oversized_head_is_refused() {
    let (l, port) = stub().await;
    tokio::spawn(async move {
        let (mut s, _) = l.accept().await.expect("accept");
        read_head(&mut s).await;
        s.write_all(b"HTTP/1.1 200 OK\r\n").await.expect("write");
        // endless header line, never a blank line
        let _ = s.write_all(&vec![b'a'; 20_000]).await;
    });
    let err = try_dial(&upstream(UpstreamScheme::Http, port), "example.com")
        .await
        .expect_err("big head");
    assert!(matches!(err, DialError::Protocol(_)), "{err:?}");
}

#[tokio::test]
async fn silent_upstream_times_out_inside_the_handshake_limit() {
    let (l, port) = stub().await;
    tokio::spawn(async move {
        let (mut s, _) = l.accept().await.expect("accept");
        read_head(&mut s).await;
        tokio::time::sleep(Duration::from_secs(30)).await;
    });
    let t = DialTimeouts {
        handshake: Duration::from_millis(200),
        ..SHORT
    };
    let up = upstream(UpstreamScheme::Http, port);
    let m = Metrics::new("test");
    let start = Instant::now();
    let err = dial(&up, &target("example.com", 443), &t, &m)
        .await
        .expect_err("silent");
    let took = start.elapsed();

    assert!(
        matches!(
            err,
            DialError::Timeout {
                stage: Stage::Handshake,
                ..
            }
        ),
        "{err:?}"
    );
    assert_eq!(err.cause(), Cause::ProviderTimeout);
    assert!(
        !err.is_retryable(),
        "a silent provider does not answer a retry"
    );
    assert!(
        took >= Duration::from_millis(200) && took < Duration::from_secs(2),
        "{took:?}"
    );
    // The stalled stage is still recorded, so a slow provider shows up.
    let handshake = m
        .dial_duration_seconds
        .with_label_values(&["stub", "handshake"]);
    assert_eq!(handshake.get_sample_count(), 1);
    assert!(handshake.get_sample_sum() >= 0.2);
}

#[tokio::test]
async fn silent_socks5_upstream_times_out_at_the_greeting() {
    let (l, port) = stub().await;
    tokio::spawn(async move {
        let (mut s, _) = l.accept().await.expect("accept");
        let mut b = [0u8; 16];
        let _ = s.read(&mut b).await;
        tokio::time::sleep(Duration::from_secs(30)).await;
    });
    let t = DialTimeouts {
        handshake: Duration::from_millis(150),
        ..SHORT
    };
    let up = upstream(UpstreamScheme::Socks5, port);
    let err = dial(&up, &target("example.com", 443), &t, &Metrics::new("test"))
        .await
        .expect_err("silent");
    assert_eq!(err.cause(), Cause::ProviderTimeout);
}

/// SOCKS5 upstream: expects username/password when `creds` is set, checks
/// them, reads the CONNECT request and replies with `reply`. Returns the
/// request bytes it saw.
fn socks_stub(
    l: TcpListener,
    creds: Option<(&'static str, &'static str)>,
    reply: &'static [u8],
) -> tokio::task::JoinHandle<Vec<u8>> {
    tokio::spawn(async move {
        let (mut s, _) = l.accept().await.expect("accept");
        let mut hdr = [0u8; 2];
        s.read_exact(&mut hdr).await.expect("greeting");
        assert_eq!(hdr[0], 5);
        let mut methods = vec![0u8; usize::from(hdr[1])];
        s.read_exact(&mut methods).await.expect("methods");
        match creds {
            Some((user, pass)) => {
                assert!(
                    methods.contains(&2),
                    "client must offer user/pass: {methods:?}"
                );
                s.write_all(&[5, 2]).await.expect("method");
                let ver = s.read_u8().await.expect("auth ver");
                assert_eq!(ver, 1);
                let ulen = usize::from(s.read_u8().await.expect("ulen"));
                let mut u = vec![0u8; ulen];
                s.read_exact(&mut u).await.expect("user");
                let plen = usize::from(s.read_u8().await.expect("plen"));
                let mut p = vec![0u8; plen];
                s.read_exact(&mut p).await.expect("pass");
                if u != user.as_bytes() || p != pass.as_bytes() {
                    s.write_all(&[1, 1]).await.expect("auth fail");
                    return Vec::new();
                }
                s.write_all(&[1, 0]).await.expect("auth ok");
            }
            None => {
                assert_eq!(methods, [0], "no credential, only the no-auth method");
                s.write_all(&[5, 0]).await.expect("method");
            }
        }
        let mut req = vec![0u8; 4];
        s.read_exact(&mut req).await.expect("request head");
        let rest = match req[3] {
            1 => 4 + 2,
            4 => 16 + 2,
            3 => {
                let len = s.read_u8().await.expect("len");
                req.push(len);
                usize::from(len) + 2
            }
            other => panic!("atyp {other}"),
        };
        let mut tail = vec![0u8; rest];
        s.read_exact(&mut tail).await.expect("request tail");
        req.extend_from_slice(&tail);
        s.write_all(reply).await.expect("reply");
        if reply[1] == 0 {
            echo(&mut s).await;
        }
        req
    })
}

#[tokio::test]
async fn socks5_user_pass_success_then_relay() {
    let (l, port) = stub().await;
    // Domain bound address, then tunnel bytes in the same write.
    let server = socks_stub(
        l,
        Some(("user", "secret")),
        b"\x05\x00\x00\x03\x04host\x00\x50go!",
    );
    let up = endpoint(UpstreamScheme::Socks5, "127.0.0.1", port, "user", "secret");
    let mut stream = try_dial(&up, "example.com").await.expect("dial");

    let mut early = [0u8; 3];
    stream.read_exact(&mut early).await.expect("early");
    assert_eq!(&early, b"go!");
    stream.write_all(b"ping").await.expect("write");
    let mut echoed = [0u8; 4];
    stream.read_exact(&mut echoed).await.expect("echo");
    assert_eq!(&echoed, b"ping");
    drop(stream);

    let req = server.await.expect("stub");
    assert_eq!(
        req,
        [&[5, 1, 0, 3, 11][..], b"example.com", &[0x01, 0xbb]].concat()
    );
}

#[tokio::test]
async fn socks5_ip_literal_target_goes_as_address() {
    let (l, port) = stub().await;
    let server = socks_stub(l, None, b"\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00");
    let up = endpoint(UpstreamScheme::Socks5, "127.0.0.1", port, "", "");
    try_dial(&up, "93.184.216.34").await.expect("dial");
    assert_eq!(
        server.await.expect("stub"),
        [5, 1, 0, 1, 93, 184, 216, 34, 1, 187]
    );
}

#[tokio::test]
async fn socks5_wrong_password_is_provider_auth() {
    let (l, port) = stub().await;
    socks_stub(l, Some(("user", "secret")), b"unused");
    let up = endpoint(UpstreamScheme::Socks5, "127.0.0.1", port, "user", "wrong");
    let err = try_dial(&up, "example.com").await.expect_err("auth");
    assert!(matches!(err, DialError::Auth), "{err:?}");
    assert_eq!(err.cause(), Cause::ProviderAuth);
    assert!(!err.is_retryable());
}

#[tokio::test]
async fn socks5_server_demanding_login_we_lack_is_provider_auth() {
    for method in [2u8, 0xff] {
        let (l, port) = stub().await;
        tokio::spawn(async move {
            let (mut s, _) = l.accept().await.expect("accept");
            let mut b = [0u8; 3];
            s.read_exact(&mut b).await.expect("greeting");
            s.write_all(&[5, method]).await.expect("method");
        });
        let up = endpoint(UpstreamScheme::Socks5, "127.0.0.1", port, "", "");
        let err = try_dial(&up, "example.com").await.expect_err("method");
        assert_eq!(err.cause(), Cause::ProviderAuth, "method {method:#x}");
    }
}

#[tokio::test]
async fn socks5_failure_reply_is_upstream_error() {
    let (l, port) = stub().await;
    // 0x05: connection refused by the target
    socks_stub(l, None, b"\x05\x05\x00\x01\x00\x00\x00\x00\x00\x00");
    let up = endpoint(UpstreamScheme::Socks5, "127.0.0.1", port, "", "");
    let err = try_dial(&up, "example.com").await.expect_err("rep 5");
    assert!(matches!(err, DialError::SocksReply(5)), "{err:?}");
    assert_eq!(err.cause(), Cause::UpstreamError);
}

#[tokio::test]
async fn dns_failure_for_a_bad_upstream_host() {
    // `.invalid` never resolves (RFC 6761).
    let up = endpoint(UpstreamScheme::Http, "no-such-host.invalid", 8080, "u", "p");
    let m = Metrics::new("test");
    let err = dial(&up, &target("example.com", 443), &SHORT, &m)
        .await
        .expect_err("dns");
    assert!(matches!(err, DialError::Dns(_)), "{err:?}");
    assert_eq!(err.cause(), Cause::ProviderUnavailable);
    assert!(!err.is_retryable());
    assert_eq!(stage_count(&m, "dns"), 1);
    assert_eq!(stage_count(&m, "tcp"), 0, "no TCP stage ran");
}

#[tokio::test]
async fn refused_connection_is_provider_unavailable() {
    let up = upstream(UpstreamScheme::Http, closed_port().await);
    let m = Metrics::new("test");
    let err = dial(&up, &target("example.com", 443), &SHORT, &m)
        .await
        .expect_err("refused");
    assert!(matches!(err, DialError::Connect(_)), "{err:?}");
    assert_eq!(err.cause(), Cause::ProviderUnavailable);
    assert_eq!(
        stage_count(&m, "dns"),
        0,
        "an IP-literal upstream has no dns stage"
    );
    assert_eq!(stage_count(&m, "tcp"), 1);
}

#[tokio::test]
async fn success_records_every_stage_once_for_a_named_upstream() {
    // Bind through the name so the stub listens on an address `localhost`
    // resolves to, whichever families the host has.
    let l = TcpListener::bind(("localhost", 0)).await.expect("bind");
    let port = l.local_addr().expect("addr").port();
    http_stub(l, "HTTP/1.1 200 OK\r\n\r\n");
    let up = endpoint(UpstreamScheme::Http, "localhost", port, "u", "p");
    let m = Metrics::new("test");
    dial(&up, &target("example.com", 443), &SHORT, &m)
        .await
        .expect("dial");

    for stage in ["dns", "tcp", "handshake"] {
        assert_eq!(stage_count(&m, stage), 1, "{stage}");
    }
    assert_eq!(
        stage_count(&m, "first_byte"),
        0,
        "first_byte belongs to the gateway"
    );

    let provider: ProviderId = "stub".parse().expect("id");
    record_first_byte(&m, &provider, Duration::from_millis(40));
    let fb = m
        .dial_duration_seconds
        .with_label_values(&["stub", "first_byte"]);
    assert_eq!(fb.get_sample_count(), 1);
    assert!((fb.get_sample_sum() - 0.04).abs() < 1e-9);
}

#[tokio::test]
async fn unsendable_requests_are_refused_before_any_connection() {
    // Port 1 would fail with Connect if a socket were opened.
    let http = upstream(UpstreamScheme::Http, 1);
    for host in ["exa mple.com", "evil.com\r\nX: y", "a\0b", "", "[]"] {
        let err = try_dial(&http, host).await.expect_err(host);
        assert!(matches!(err, DialError::BadTarget(_)), "{host:?}: {err:?}");
        assert_eq!(err.cause(), Cause::DestinationDenied);
    }

    let socks = upstream(UpstreamScheme::Socks5, 1);
    let err = try_dial(&socks, &"a".repeat(256))
        .await
        .expect_err("long host");
    assert!(matches!(err, DialError::BadTarget(_)), "{err:?}");

    let long_pass = endpoint(
        UpstreamScheme::Socks5,
        "127.0.0.1",
        1,
        "u",
        &"p".repeat(256),
    );
    let err = try_dial(&long_pass, "example.com")
        .await
        .expect_err("long password");
    assert!(matches!(err, DialError::BadCredential(_)), "{err:?}");
    assert_eq!(err.cause(), Cause::ProviderAuth);
}

#[test]
fn every_error_maps_to_the_contract_cause() {
    let io = || io::Error::from(io::ErrorKind::ConnectionRefused);
    let t = |stage| DialError::Timeout {
        stage,
        after: Duration::from_secs(1),
    };
    for (err, cause) in [
        (t(Stage::Dns), Cause::ProviderTimeout),
        (t(Stage::Tcp), Cause::ProviderTimeout),
        (t(Stage::Handshake), Cause::ProviderTimeout),
        (DialError::Connect(io()), Cause::ProviderUnavailable),
        (
            DialError::Connect(io::Error::from(io::ErrorKind::TimedOut)),
            Cause::ProviderTimeout,
        ),
        (DialError::Dns(io()), Cause::ProviderUnavailable),
        (DialError::Auth, Cause::ProviderAuth),
        (DialError::Status(500), Cause::UpstreamError),
        (DialError::SocksReply(1), Cause::UpstreamError),
        (DialError::Protocol("x"), Cause::UpstreamError),
        (DialError::Io(io()), Cause::UpstreamError),
    ] {
        assert_eq!(err.cause(), cause, "{err:?}");
    }
    // retry set: reset, end of stream, 429, timeout; nothing else
    for kind in [
        io::ErrorKind::ConnectionReset,
        io::ErrorKind::UnexpectedEof,
        io::ErrorKind::BrokenPipe,
    ] {
        assert!(
            DialError::Io(io::Error::from(kind)).is_retryable(),
            "{kind:?}"
        );
    }
    assert!(!DialError::Io(io::Error::from(io::ErrorKind::PermissionDenied)).is_retryable());
    assert!(!DialError::Connect(io()).is_retryable());
    assert!(!DialError::Status(500).is_retryable());
    assert!(!DialError::SocksReply(1).is_retryable());
    // a timeout is retried before the connect is sent, not after
    assert!(t(Stage::Dns).is_retryable() && t(Stage::Tcp).is_retryable());
    assert!(!t(Stage::Handshake).is_retryable() && !t(Stage::FirstByte).is_retryable());
}

/// Dial `127.0.0.1:port` as an HTTP upstream with short timeouts.
async fn dial_http(port: u16) -> DialError {
    let t = DialTimeouts {
        dns: Duration::from_millis(200),
        tcp: Duration::from_millis(200),
        handshake: Duration::from_millis(200),
        keepalive: DEFAULT_KEEPALIVE,
    };
    dial(
        &upstream(UpstreamScheme::Http, port),
        &target("example.test", 443),
        &t,
        &Metrics::new("test"),
    )
    .await
    .expect_err("the dial fails")
}

#[tokio::test]
async fn only_an_unreachable_provider_counts_for_the_breaker() {
    // nothing listens: the connect is refused
    let refused = dial_http(closed_port().await).await;
    assert!(refused.provider_unreachable(), "{refused:?}");

    // the provider accepts and never answers the CONNECT: it may be waiting
    // for a dead target, which is no reason to open a route class
    let (hung, port) = stub().await;
    tokio::spawn(async move {
        let (_held, _) = hung.accept().await.expect("accept");
        tokio::time::sleep(Duration::from_secs(5)).await;
    });
    let timed_out = dial_http(port).await;
    assert!(
        matches!(
            timed_out,
            DialError::Timeout {
                stage: Stage::Handshake,
                ..
            }
        ),
        "{timed_out:?}"
    );
    assert!(!timed_out.provider_unreachable());

    // an answer, even an error, is not unreachable
    let (bad, port) = stub().await;
    http_stub(bad, "HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n");
    let status = dial_http(port).await;
    assert!(matches!(status, DialError::Status(502)), "{status:?}");
    assert!(!status.provider_unreachable());

    assert!(
        DialError::Timeout {
            stage: Stage::Tcp,
            after: Duration::from_secs(2)
        }
        .provider_unreachable()
    );

    // A refused login and a dropped connection are the
    // provider refusing to serve, and count for the breaker too
    assert!(DialError::Auth.provider_rejected());
    assert!(DialError::Io(io::Error::from(io::ErrorKind::UnexpectedEof)).provider_rejected());
    assert!(!status.provider_rejected());
    assert!(!refused.provider_rejected());

    // What a unit does wrong on its own (not the breaker's, not
    // the target's)
    assert!(DialError::Auth.unit_misbehaves());
    assert!(DialError::Io(io::Error::from(io::ErrorKind::ConnectionReset)).unit_misbehaves());
    assert!(timed_out.unit_misbehaves());
    assert!(!status.unit_misbehaves());
    assert!(!refused.unit_misbehaves());

    // R1b: another IP may get through after any of those, and after a
    // status or SOCKS reply; not after an unreachable endpoint
    assert!(timed_out.ip_level());
    assert!(status.ip_level());
    assert!(DialError::SocksReply(5).ip_level());
    assert!(!refused.ip_level());
    assert!(!DialError::BadTarget("x").ip_level());
}

#[tokio::test]
async fn a_local_connect_failure_is_not_the_providers_and_not_retried() {
    let local = [
        libc::EADDRNOTAVAIL,
        libc::EADDRINUSE,
        libc::EMFILE,
        libc::ENFILE,
        libc::ENOBUFS,
    ];
    let up = upstream(UpstreamScheme::Http, 8080);
    let m = Metrics::new("test");
    for errno in local {
        let calls = Arc::new(AtomicUsize::new(0));
        let seen = Arc::clone(&calls);
        let connector = move |_: Vec<SocketAddr>| {
            seen.fetch_add(1, Ordering::SeqCst);
            std::future::ready(Err(DialError::Connect(io::Error::from_raw_os_error(errno))))
        };
        let err = dial_with(
            &up,
            &target("example.test", 443),
            &SHORT,
            &m,
            fixed_resolver(Vec::new(), Arc::new(AtomicUsize::new(0))),
            connector,
        )
        .await
        .expect_err("the connect fails");
        assert!(err.is_local(), "errno {errno}: {err:?}");
        assert!(!err.provider_unreachable(), "errno {errno}: {err:?}");
        assert!(!err.is_retryable(), "errno {errno}: {err:?}");
        assert_eq!(err.cause(), Cause::ProviderUnavailable, "errno {errno}");
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }

    // a refusal by the provider is still the provider's
    let refused = DialError::Connect(io::Error::from_raw_os_error(libc::ECONNREFUSED));
    assert!(!refused.is_local() && refused.provider_unreachable());
}

/// A resolver that answers `addrs` whatever the name, and counts its calls.
fn fixed_resolver(
    addrs: Vec<SocketAddr>,
    calls: Arc<AtomicUsize>,
) -> impl FnOnce(String, u16) -> std::future::Ready<Result<Vec<SocketAddr>, DialError>> {
    move |_, _| {
        calls.fetch_add(1, Ordering::SeqCst);
        std::future::ready(Ok(addrs))
    }
}

#[tokio::test]
async fn a_public_only_name_that_resolves_to_a_private_address_is_refused_before_connecting() {
    let (listener, port) = stub().await;
    let local: SocketAddr = ([127, 0, 0, 1], port).into();
    let accepted = Arc::new(AtomicUsize::new(0));
    let seen = Arc::clone(&accepted);
    tokio::spawn(async move {
        while listener.accept().await.is_ok() {
            seen.fetch_add(1, Ordering::SeqCst);
        }
    });
    let mut up = endpoint(
        UpstreamScheme::Http,
        "proxy.customer.example",
        8080,
        "u",
        "p",
    );
    up.public_only = true;
    let public: SocketAddr = "8.8.8.8:8080".parse().expect("addr");
    let calls = Arc::new(AtomicUsize::new(0));
    let m = Metrics::new("test");
    let t = DialTimeouts {
        dns: Duration::from_millis(200),
        tcp: Duration::from_millis(500),
        handshake: Duration::from_millis(500),
        keepalive: DEFAULT_KEEPALIVE,
    };

    // one private address among public ones is enough to refuse
    for addrs in [vec![local], vec![public, local]] {
        let err = dial_with(
            &up,
            &target("example.test", 443),
            &t,
            &m,
            fixed_resolver(addrs, Arc::clone(&calls)),
            |a| connect_from(a, None),
        )
        .await
        .expect_err("refused");
        assert!(matches!(err, DialError::DeniedAddress), "{err:?}");
        assert_eq!(err.cause(), Cause::DestinationDenied);
        assert!(!err.is_retryable() && !err.provider_unreachable());
    }
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert_eq!(accepted.load(Ordering::SeqCst), 0, "never connected");
    assert_eq!(calls.load(Ordering::SeqCst), 2, "one resolution per dial");

    // without public_only the same answer is dialed: the check is the difference
    let up = endpoint(
        UpstreamScheme::Http,
        "proxy.customer.example",
        port,
        "u",
        "p",
    );
    let _ = dial_with(
        &up,
        &target("example.test", 443),
        &t,
        &m,
        fixed_resolver(vec![local], calls),
        |a| connect_from(a, None),
    )
    .await;
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert_eq!(accepted.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn a_public_only_ip_literal_upstream_in_a_private_range_is_refused() {
    for host in [
        "127.0.0.1",
        "10.1.2.3",
        "169.254.169.254",
        "::ffff:127.0.0.1",
        "fd00::1",
    ] {
        let mut up = endpoint(UpstreamScheme::Http, host, 8080, "u", "p");
        up.public_only = true;
        let err = dial(
            &up,
            &target("example.test", 443),
            &SHORT,
            &Metrics::new("test"),
        )
        .await
        .expect_err(host);
        assert!(matches!(err, DialError::DeniedAddress), "{host}: {err:?}");
    }
}

#[test]
fn io_failures_print_their_cause_once() {
    for err in [
        DialError::Dns(io::Error::other("no such host")),
        DialError::Connect(io::Error::other("no such host")),
        DialError::Io(io::Error::other("no such host")),
    ] {
        // the message holds the cause, so a `source` would repeat it under `{:#}`
        assert!(std::error::Error::source(&err).is_none(), "{err}");
        assert_eq!(err.to_string().matches("no such host").count(), 1, "{err}");
    }
}

#[tokio::test]
async fn a_dialed_socket_has_keepalive_on() {
    let (_listener, port) = stub().await;
    let stream = connect_from(vec![([127, 0, 0, 1], port).into()], None)
        .await
        .expect("connect");
    let sock = socket2::SockRef::from(&stream);
    assert!(sock.keepalive().expect("keepalive"));
    assert_eq!(
        sock.tcp_keepalive_time().expect("time"),
        Duration::from_secs(60)
    );
    assert_eq!(
        sock.tcp_keepalive_interval().expect("interval"),
        Duration::from_secs(15)
    );
    assert_eq!(sock.tcp_keepalive_retries().expect("retries"), 4);
}

// --- Local scheme: no upstream proxy, the host is the source address ---

/// A `Local` endpoint binding `source`.
fn local(source: &str) -> UpstreamEndpoint {
    endpoint(UpstreamScheme::Local, source, 0, "", "")
}

/// Accept one connection on `l`, give its peer address and what the dialer
/// sent on its own (a handshake would show up there).
fn accept_peer(l: TcpListener) -> tokio::task::JoinHandle<(SocketAddr, Vec<u8>)> {
    tokio::spawn(async move {
        let (mut s, peer) = l.accept().await.expect("accept");
        let mut got = Vec::new();
        let _ = tokio::time::timeout(Duration::from_millis(200), s.read_to_end(&mut got)).await;
        (peer, got)
    })
}

#[tokio::test]
async fn a_local_dial_refuses_private_and_internal_targets_before_connecting() {
    let (listener, port) = stub().await;
    let accepted = Arc::new(AtomicUsize::new(0));
    let seen = Arc::clone(&accepted);
    tokio::spawn(async move {
        while listener.accept().await.is_ok() {
            seen.fetch_add(1, Ordering::SeqCst);
        }
    });
    // names resolve here (`localhost`), literals are checked as they are
    for host in [
        "127.0.0.1",
        "localhost",
        "10.1.2.3",
        "192.168.0.1",
        "169.254.169.254",
        "::1",
        "fd00::1",
        "::ffff:127.0.0.1",
        "[::1]",
    ] {
        let err = dial(
            &local("127.0.0.2"),
            &target(host, port),
            &SHORT,
            &Metrics::new("test"),
        )
        .await
        .expect_err(host);
        assert!(matches!(err, DialError::DeniedAddress), "{host}: {err:?}");
        assert_eq!(err.cause(), Cause::DestinationDenied, "{host}");
        assert!(!err.is_retryable() && !err.provider_unreachable(), "{host}");
    }
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert_eq!(accepted.load(Ordering::SeqCst), 0, "never connected");
}

#[tokio::test]
async fn a_local_source_that_is_no_unicast_ip_literal_is_refused() {
    for host in [
        "",
        "proxy.example.com",
        "localhost",
        "0.0.0.0",
        "::",
        "224.0.0.1",
        "ff02::1",
    ] {
        // a public target: only the source can be the reason
        let err = try_dial(&local(host), "8.8.8.8").await.expect_err(host);
        assert!(
            matches!(err, DialError::LocalSource(_)),
            "{host:?}: {err:?}"
        );
        assert_eq!(err.cause(), Cause::ProviderUnavailable);
        assert!(err.source_unusable(), "{host:?}");
        assert!(!err.provider_unreachable() && !err.is_retryable());
    }
}

#[tokio::test]
async fn connect_from_leaves_from_the_chosen_source_address() {
    for src in ["127.0.0.2", "127.0.0.3"] {
        let (l, port) = stub().await;
        let peer = accept_peer(l);
        let source: IpAddr = src.parse().expect("ip");
        let stream = connect_from(vec![([127, 0, 0, 1], port).into()], Some(source))
            .await
            .expect("connect");
        assert_eq!(stream.local_addr().expect("local").ip(), source);
        // keepalive and nodelay are set as for a proxied dial
        assert!(stream.nodelay().expect("nodelay"));
        assert!(
            socket2::SockRef::from(&stream)
                .keepalive()
                .expect("keepalive")
        );
        drop(stream);
        let (seen, _) = peer.await.expect("task");
        assert_eq!(seen.ip(), source, "the listener sees the bound source");
        assert_ne!(seen.port(), 0);
    }
}

#[tokio::test]
async fn connect_from_with_an_ipv6_source_reaches_an_ipv6_listener() {
    let Ok(l) = TcpListener::bind("[::1]:0").await else {
        eprintln!("skipped: no IPv6 loopback on this host");
        return;
    };
    let port = l.local_addr().expect("addr").port();
    let peer = accept_peer(l);
    let stream = connect_from(
        vec![SocketAddr::new(
            IpAddr::V6(std::net::Ipv6Addr::LOCALHOST),
            port,
        )],
        Some(IpAddr::V6(std::net::Ipv6Addr::LOCALHOST)),
    )
    .await
    .expect("connect");
    drop(stream);
    let (seen, _) = peer.await.expect("task");
    assert!(seen.ip().is_loopback() && seen.is_ipv6(), "{seen}");
}

/// Addresses of the other IP family are skipped; none left is a local
/// failure (a source that cannot reach the target), never the provider's.
#[tokio::test]
async fn connect_from_skips_the_other_family_and_fails_locally_without_a_match() {
    let (l, port) = stub().await;
    let peer = accept_peer(l);
    let v6: SocketAddr = "[::1]:9".parse().expect("addr");
    // a v6 address first: skipped, the v4 one is dialed
    let stream = connect_from(
        vec![v6, ([127, 0, 0, 1], port).into()],
        Some("127.0.0.2".parse().expect("ip")),
    )
    .await
    .expect("connect");
    drop(stream);
    assert_eq!(peer.await.expect("task").0.ip().to_string(), "127.0.0.2");

    let err = connect_from(vec![v6], Some("127.0.0.2".parse().expect("ip")))
        .await
        .expect_err("family mismatch");
    let DialError::Connect(io) = &err else {
        panic!("{err:?}")
    };
    assert_eq!(io.raw_os_error(), Some(libc::EADDRNOTAVAIL));
    assert!(err.is_local() && err.source_unusable());
    assert!(!err.provider_unreachable() && !err.is_retryable());

    // the same through a v4 target and a v6 source
    let err = connect_from(
        vec![([127, 0, 0, 1], port).into()],
        Some("::1".parse().expect("ip")),
    )
    .await
    .expect_err("family mismatch");
    assert!(matches!(&err, DialError::Connect(e) if e.raw_os_error() == Some(libc::EADDRNOTAVAIL)));
}

/// A source address no interface owns cannot be bound. 203.0.113.0/24 is
/// documentation space, so the machine has no such address.
#[tokio::test]
async fn connect_from_an_address_the_machine_does_not_own_fails_locally() {
    let (_l, port) = stub().await;
    let err = connect_from(
        vec![([127, 0, 0, 1], port).into()],
        Some("203.0.113.77".parse().expect("ip")),
    )
    .await
    .expect_err("cannot bind");
    assert!(
        matches!(&err, DialError::Connect(e) if e.raw_os_error() == Some(libc::EADDRNOTAVAIL)),
        "{err:?}"
    );
    assert!(err.source_unusable() && !err.provider_unreachable());
    let refused = DialError::Connect(io::Error::from_raw_os_error(libc::ECONNREFUSED));
    assert!(!refused.source_unusable());
}

/// The whole `Local` flow with an injected resolver and connector: the target
/// is resolved once, its addresses are checked, the connection leaves from
/// the bound source, no handshake follows, and the stages are recorded.
#[tokio::test]
async fn a_local_dial_resolves_the_target_and_connects_from_the_source_without_a_handshake() {
    let (l, port) = stub().await;
    let peer = accept_peer(l);
    let listener_addr: SocketAddr = ([127, 0, 0, 1], port).into();
    let public: SocketAddr = "93.184.216.34:443".parse().expect("addr");
    let up = local("127.0.0.2");
    let calls = Arc::new(AtomicUsize::new(0));
    let dialed = Arc::new(std::sync::Mutex::new(Vec::new()));
    let log = Arc::clone(&dialed);
    let m = Metrics::new("test");
    let stream = dial_with(
        &up,
        &target("example.test", 443),
        &SHORT,
        &m,
        fixed_resolver(vec![public], Arc::clone(&calls)),
        move |addrs| {
            // the checked addresses are what the connector gets; the test
            // then dials its own listener from the unit's source address
            log.lock().expect("log").push(addrs);
            connect_from(vec![listener_addr], Some("127.0.0.2".parse().expect("ip")))
        },
    )
    .await
    .expect("dial");
    assert_eq!(calls.load(Ordering::SeqCst), 1, "target resolved once");
    assert_eq!(*dialed.lock().expect("log"), vec![vec![public]]);
    assert_eq!(
        stream.local_addr().expect("local").ip().to_string(),
        "127.0.0.2"
    );
    drop(stream);
    let (seen, sent) = peer.await.expect("task");
    assert_eq!(seen.ip().to_string(), "127.0.0.2");
    assert!(
        sent.is_empty(),
        "no CONNECT or SOCKS bytes are sent: {sent:?}"
    );
    assert_eq!(stage_count(&m, "dns"), 1);
    assert_eq!(stage_count(&m, "tcp"), 1);
    assert_eq!(stage_count(&m, "handshake"), 0);

    // an IP literal target is not resolved
    let calls = Arc::new(AtomicUsize::new(0));
    let (l, port) = stub().await;
    let peer = accept_peer(l);
    let listener_addr: SocketAddr = ([127, 0, 0, 1], port).into();
    let seen_addrs = Arc::new(std::sync::Mutex::new(Vec::new()));
    let log = Arc::clone(&seen_addrs);
    let stream = dial_with(
        &up,
        &target("93.184.216.34", 8443),
        &SHORT,
        &Metrics::new("test"),
        fixed_resolver(Vec::new(), Arc::clone(&calls)),
        move |addrs| {
            log.lock().expect("log").push(addrs);
            connect_from(vec![listener_addr], Some("127.0.0.3".parse().expect("ip")))
        },
    )
    .await
    .expect("dial");
    drop(stream);
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    let expect: SocketAddr = "93.184.216.34:8443".parse().expect("addr");
    assert_eq!(*seen_addrs.lock().expect("log"), vec![vec![expect]]);
    assert_eq!(peer.await.expect("task").0.ip().to_string(), "127.0.0.3");
}

#[tokio::test]
async fn a_local_dial_refuses_a_name_that_resolves_to_an_internal_address() {
    let public: SocketAddr = "93.184.216.34:443".parse().expect("addr");
    for private in [
        "127.0.0.1:443",
        "10.0.0.9:443",
        "[fd00::1]:443",
        "169.254.169.254:443",
    ] {
        let private: SocketAddr = private.parse().expect("addr");
        let connected = Arc::new(AtomicUsize::new(0));
        let seen = Arc::clone(&connected);
        let err = dial_with(
            &local("127.0.0.2"),
            &target("rebind.example.test", 443),
            &SHORT,
            &Metrics::new("test"),
            fixed_resolver(vec![public, private], Arc::new(AtomicUsize::new(0))),
            move |_| {
                seen.fetch_add(1, Ordering::SeqCst);
                std::future::ready(Err(DialError::Protocol("must not connect")))
            },
        )
        .await
        .expect_err("refused");
        assert!(
            matches!(err, DialError::DeniedAddress),
            "{private}: {err:?}"
        );
        assert_eq!(connected.load(Ordering::SeqCst), 0, "{private}");
    }
}

#[tokio::test]
async fn handshake_has_no_proxy_to_talk_to_for_a_local_endpoint() {
    let (l, port) = stub().await;
    let _peer = accept_peer(l);
    let mut stream = TcpStream::connect(("127.0.0.1", port))
        .await
        .expect("connect");
    let err = handshake(
        &mut stream,
        &local("127.0.0.2"),
        &target("example.com", 443),
    )
    .await
    .expect_err("no proxy");
    assert!(matches!(err, DialError::LocalSource(_)), "{err:?}");
}

#[tokio::test]
async fn a_dialed_socket_takes_the_configured_keepalive_or_none() {
    let (_listener, port) = stub().await;
    let custom = TcpKeepalive {
        time: Duration::from_secs(33),
        interval: Duration::from_secs(7),
        retries: 3,
    };
    let stream = connect_from_with(vec![([127, 0, 0, 1], port).into()], None, Some(custom))
        .await
        .expect("connect");
    let sock = socket2::SockRef::from(&stream);
    assert!(sock.keepalive().expect("keepalive"));
    assert_eq!(sock.tcp_keepalive_time().expect("time"), custom.time);
    assert_eq!(
        sock.tcp_keepalive_interval().expect("interval"),
        custom.interval
    );
    assert_eq!(sock.tcp_keepalive_retries().expect("retries"), 3);

    let off = connect_from_with(vec![([127, 0, 0, 1], port).into()], None, None)
        .await
        .expect("connect");
    assert!(!socket2::SockRef::from(&off).keepalive().expect("keepalive"));
}
