//! TLS listeners and RFC 1928 reverse TCP tunnels, without external networks.
#![allow(clippy::unwrap_used)]

mod common;
#[path = "common/tls_fixture.rs"]
mod tls_fixture;

use std::time::Duration;

use common::{Edge, banner_origin, http_origin};
use rustls::pki_types::ServerName;
use tls_fixture::{TlsFixture, greeting, head, reply5, request5, response};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpSocket, TcpStream};

const ALLOW: &str = "[[rule]]\naction = \"allow\"\nallow_internal = true\n";

#[tokio::test]
async fn tls_http_forward_and_connect_preserve_plaintext_origin_bytes() {
    let fixture = TlsFixture::new();
    let edge = Edge::start(&format!("{}\n{ALLOW}", fixture.listener("http", "none"))).await;
    let origin = http_origin("127.0.0.1:0").await;
    let mut forward = fixture.connect(edge.addr("main"), &[b"http/1.1"]).await;
    forward
        .write_all(
            format!(
                "GET http://origin.test:{}/ip HTTP/1.1\r\nHost: origin.test\r\n\r\n",
                origin.port()
            )
            .as_bytes(),
        )
        .await
        .unwrap();
    let (status, body) = response(&mut forward).await;
    assert!(status.starts_with("HTTP/1.1 200"));
    assert_eq!(body, b"127.0.0.1");

    let mut tunnel = fixture.connect(edge.addr("main"), &[b"http/1.1"]).await;
    tunnel
        .write_all(
            format!(
                "CONNECT origin.test:{} HTTP/1.1\r\nHost: origin.test\r\n\r\n",
                origin.port()
            )
            .as_bytes(),
        )
        .await
        .unwrap();
    assert!(head(&mut tunnel).await.starts_with("HTTP/1.1 200"));
    tunnel
        .write_all(b"GET /ip HTTP/1.1\r\nHost: origin.test\r\n\r\n")
        .await
        .unwrap();
    assert_eq!(response(&mut tunnel).await.1, b"127.0.0.1");
    edge.server.shutdown(Duration::from_millis(20)).await;
}

#[tokio::test]
async fn mixed_tls_detects_http_and_socks_without_alpn() {
    let fixture = TlsFixture::new();
    let edge = Edge::start(&format!("{}\n{ALLOW}", fixture.listener("auto", "none"))).await;
    let origin = http_origin("127.0.0.1:0").await;
    let mut http = fixture.connect(edge.addr("main"), &[]).await;
    http.write_all(
        format!(
            "GET http://127.0.0.1:{}/ip HTTP/1.1\r\nHost: origin.test\r\n\r\n",
            origin.port()
        )
        .as_bytes(),
    )
    .await
    .unwrap();
    assert_eq!(response(&mut http).await.1, b"127.0.0.1");
    let mut socks = fixture.connect(edge.addr("main"), &[]).await;
    greeting(&mut socks).await;
    request5(&mut socks, 1, origin).await;
    assert_eq!(reply5(&mut socks).await.0, 0);
    socks
        .write_all(b"GET /ip HTTP/1.1\r\nHost: origin.test\r\n\r\n")
        .await
        .unwrap();
    assert_eq!(response(&mut socks).await.1, b"127.0.0.1");
    edge.server.shutdown(Duration::from_millis(20)).await;
}

#[tokio::test]
async fn socks_tls_authentication_requires_correct_password() {
    let fixture = TlsFixture::new();
    let edge = Edge::start(&format!(
        "{}\n{ALLOW}\n[[user]]\nname = \"alice\"\npassword = \"pw\"\n",
        fixture.listener("socks", "users")
    ))
    .await;
    for (password, expected) in [(b"no".as_slice(), 1), (b"pw".as_slice(), 0)] {
        let mut socks = fixture.connect(edge.addr("main"), &[]).await;
        socks.write_all(&[5, 1, 2]).await.unwrap();
        let mut reply = [0; 2];
        socks.read_exact(&mut reply).await.unwrap();
        assert_eq!(reply, [5, 2]);
        let mut auth = b"\x01\x05alice\x02".to_vec();
        auth.extend_from_slice(password);
        socks.write_all(&auth).await.unwrap();
        socks.read_exact(&mut reply).await.unwrap();
        assert_eq!(reply, [1, expected]);
    }
    edge.server.shutdown(Duration::from_millis(20)).await;
}

#[tokio::test]
async fn trusted_proxy_header_precedes_tls_and_supplies_acl_client_identity() {
    let fixture = TlsFixture::new();
    let config = format!(
        "{}proxy_protocol = \"required\"\ntrusted_proxies = [\"127.0.0.1/32\"]\n[[rule]]\naction = \"allow\"\nallow_internal = true\n[rule.when]\nsrc = [\"192.0.2.25/32\"]\n",
        fixture.listener("http", "none")
    );
    let edge = Edge::start(&config).await;
    let origin = http_origin("127.0.0.1:0").await;
    let mut tcp = TcpStream::connect(edge.addr("main")).await.unwrap();
    tcp.write_all(b"PROXY TCP4 192.0.2.25 127.0.0.1 40100 443\r\n")
        .await
        .unwrap();
    let mut tls = fixture.wrap(tcp, &[b"http/1.1"]).await;
    tls.write_all(
        format!(
            "GET http://127.0.0.1:{}/ip HTTP/1.1\r\nHost: origin.test\r\n\r\n",
            origin.port()
        )
        .as_bytes(),
    )
    .await
    .unwrap();
    assert!(response(&mut tls).await.0.starts_with("HTTP/1.1 200"));
    let tcp = TcpStream::connect(edge.addr("main")).await.unwrap();
    assert!(
        tokio::time::timeout(
            Duration::from_secs(3),
            fixture
                .connector(&[b"http/1.1"], true)
                .connect(ServerName::try_from("localhost").unwrap(), tcp)
        )
        .await
        .unwrap()
        .is_err()
    );
    edge.server.shutdown(Duration::from_millis(20)).await;
}

#[tokio::test]
async fn tls_rejects_untrusted_certificate_and_bad_reload_keeps_current_listener() {
    let fixture = TlsFixture::new();
    let config = format!("{}\n{ALLOW}", fixture.listener("http", "none"));
    let edge = Edge::start(&config).await;
    let tcp = TcpStream::connect(edge.addr("main")).await.unwrap();
    assert!(
        fixture
            .connector(&[b"http/1.1"], false)
            .connect(ServerName::try_from("localhost").unwrap(), tcp)
            .await
            .is_err()
    );
    edge.rewrite(&config.replace("cert.pem", "missing.pem"));
    assert!(edge.server.reload().await.is_err());
    let origin = http_origin("127.0.0.1:0").await;
    let mut tls = fixture.connect(edge.addr("main"), &[b"http/1.1"]).await;
    tls.write_all(
        format!(
            "GET http://127.0.0.1:{}/ip HTTP/1.1\r\nHost: origin.test\r\n\r\n",
            origin.port()
        )
        .as_bytes(),
    )
    .await
    .unwrap();
    assert_eq!(response(&mut tls).await.1, b"127.0.0.1");
    edge.server.shutdown(Duration::from_millis(20)).await;
}

#[tokio::test]
async fn bind_tls_sends_two_replies_checks_peer_and_uses_selected_egress() {
    let fixture = TlsFixture::new();
    let config = format!(
        "{}pool = \"reverse\"\n[[pool]]\nname = \"reverse\"\naddresses = [\"127.0.0.3\"]\n{ALLOW}",
        fixture.listener("socks", "none")
    );
    let edge = Edge::start(&config).await;
    let mut control = fixture.connect(edge.addr("main"), &[]).await;
    greeting(&mut control).await;
    let expected = TcpSocket::new_v4().unwrap();
    expected.bind("127.0.0.1:0".parse().unwrap()).unwrap();
    let expected_addr = expected.local_addr().unwrap();
    request5(&mut control, 2, expected_addr).await;
    let (code, bound) = reply5(&mut control).await;
    assert_eq!(code, 0);
    assert_eq!(bound.ip().to_string(), "127.0.0.3");
    assert_ne!(bound.port(), 0);
    // Early application bytes remain bounded and reach only the checked peer.
    control.write_all(b"client-to-peer").await.unwrap();
    let wrong = TcpSocket::new_v4().unwrap();
    wrong.bind("127.0.0.2:0".parse().unwrap()).unwrap();
    let mut wrong = wrong.connect(bound).await.unwrap();
    assert_eq!(
        tokio::time::timeout(Duration::from_secs(3), wrong.read_u8())
            .await
            .unwrap()
            .unwrap_err()
            .kind(),
        std::io::ErrorKind::UnexpectedEof
    );
    let mut remote = expected.connect(bound).await.unwrap();
    let (code, accepted) = reply5(&mut control).await;
    assert_eq!((code, accepted), (0, expected_addr));
    remote.write_all(b"peer-to-client").await.unwrap();
    let mut buf = [0; 14];
    control.read_exact(&mut buf).await.unwrap();
    assert_eq!(&buf, b"peer-to-client");
    // The payload was sent before the reverse connection arrived.
    remote.read_exact(&mut buf).await.unwrap();
    assert_eq!(&buf, b"client-to-peer");
    drop(remote);
    drop(control);
    edge.server.shutdown(Duration::from_millis(20)).await;
}

#[tokio::test]
async fn plain_bind_times_out_with_second_failure_reply() {
    let edge = Edge::start(&format!(
        "{}\n[timeouts]\nconnect = \"80ms\"\n",
        common::OPEN
    ))
    .await;
    let mut control = TcpStream::connect(edge.addr("main")).await.unwrap();
    greeting(&mut control).await;
    request5(&mut control, 2, "127.0.0.1:0".parse().unwrap()).await;
    assert_eq!(reply5(&mut control).await.0, 0);
    assert_eq!(reply5(&mut control).await.0, 6);
    assert!(
        tokio::time::timeout(Duration::from_secs(1), control.read_u8())
            .await
            .unwrap()
            .is_err()
    );
    edge.server.shutdown(Duration::from_millis(20)).await;
}

#[tokio::test]
async fn tls_connect_keeps_default_internal_destination_protection() {
    let fixture = TlsFixture::new();
    let edge = Edge::start(&format!(
        "{}\n[[rule]]\naction = \"allow\"\n",
        fixture.listener("http", "none")
    ))
    .await;
    let origin = banner_origin("127.0.0.1:0").await;
    let mut tls = fixture.connect(edge.addr("main"), &[b"http/1.1"]).await;
    tls.write_all(format!("CONNECT {origin} HTTP/1.1\r\nHost: {origin}\r\n\r\n").as_bytes())
        .await
        .unwrap();
    assert!(head(&mut tls).await.starts_with("HTTP/1.1 403"));
    edge.server.shutdown(Duration::from_millis(20)).await;
}

#[tokio::test]
async fn bind_preserves_default_internal_destination_denial_before_listening() {
    let edge = Edge::start(
        "[[listener]]\nname = \"main\"\nlisten = \"127.0.0.1:0\"\nauth = \"none\"\n[[rule]]\naction = \"allow\"\n",
    ).await;
    let mut control = TcpStream::connect(edge.addr("main")).await.unwrap();
    greeting(&mut control).await;
    request5(&mut control, 2, "127.0.0.1:0".parse().unwrap()).await;
    assert_eq!(reply5(&mut control).await.0, 2);
    edge.server.shutdown(Duration::from_millis(20)).await;
}

#[tokio::test]
async fn socks_tls_udp_association_uses_encrypted_control_and_plain_datagrams() {
    let fixture = TlsFixture::new();
    let edge = Edge::start(&format!(
        "{}udp = true\n{ALLOW}",
        fixture.listener("socks", "none")
    ))
    .await;
    let origin = common::udp_origin("127.0.0.1:0").await;
    let mut control = fixture.connect(edge.addr("main"), &[]).await;
    greeting(&mut control).await;
    request5(&mut control, 3, "0.0.0.0:0".parse().unwrap()).await;
    let (code, relay) = reply5(&mut control).await;
    assert_eq!(code, 0);
    assert_eq!(relay.ip().to_string(), "127.0.0.1");
    let udp = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let mut packet = vec![0, 0, 0, 1, 127, 0, 0, 1];
    packet.extend_from_slice(&origin.port().to_be_bytes());
    packet.extend_from_slice(b"payload");
    udp.send_to(&packet, relay).await.unwrap();
    let mut reply = [0; 128];
    let (n, source) = tokio::time::timeout(Duration::from_secs(3), udp.recv_from(&mut reply))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(source, relay);
    assert_eq!(&reply[..4], &[0, 0, 0, 1]);
    assert_eq!(&reply[10..n], b"from:127.0.0.1");
    drop(control);
    edge.server.shutdown(Duration::from_millis(20)).await;
}
