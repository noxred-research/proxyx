//! Lifecycle ACL enforcement and BIND preparation without an outgoing peer connection.
#![allow(clippy::unwrap_used)]

mod common;

use std::net::SocketAddr;
use std::time::Duration;

use common::*;
use proxyx_edge::acl::Proto;
use proxyx_edge::conn::{self, RefusalKind, ReqCtx};
use proxyx_edge::connect::Mode;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::time::timeout;

#[tokio::test]
async fn source_stage_denies_before_any_protocol_bytes_arrive() {
    let edge = Edge::start(&format!(
        "{OPEN}\n[[rule]]\nstage = \"pre_negotiation\"\naction = \"allow\"\nwhen = {{ src = [\"192.0.2.0/24\"] }}\n"
    ))
    .await;
    let mut client = TcpStream::connect(edge.addr("main")).await.unwrap();
    let mut byte = [0];
    let result = timeout(Duration::from_secs(2), client.read(&mut byte))
        .await
        .expect("source ACL must run before waiting for negotiation");
    assert!(matches!(result, Ok(0) | Err(_)), "{result:?}");
}

#[tokio::test]
async fn post_auth_stage_denies_valid_user_without_changing_request_rules() {
    let origin = http_origin("127.0.0.1:0").await;
    let edge = Edge::start(
        r#"
[[listener]]
name = "main"
listen = "127.0.0.1:0"
[[user]]
name = "alice"
password = "pw"
[[user]]
name = "bob"
password = "pw"
[[rule]]
action = "allow"
allow_internal = true
[[rule]]
stage = "post_auth"
action = "allow"
when = { user = ["alice"], authenticated = true }
"#,
    )
    .await;
    let target = format!("origin.test:{}", origin.port());
    assert_eq!(
        get(edge.addr("main"), &target, "/ip", Some(("alice", "pw")))
            .await
            .status,
        200
    );
    let denied = get(edge.addr("main"), &target, "/ip", Some(("bob", "pw"))).await;
    assert_eq!(denied.status, 403);
    assert_eq!(denied.header("x-proxyx-error"), Some("forbidden"));
}

fn request<'a>(
    edge: &'a Edge,
    state: &'a std::sync::Arc<proxyx_edge::state::State>,
    host: &'a str,
    port: u16,
    proto: Proto,
) -> ReqCtx<'a> {
    ReqCtx {
        shared: &edge.server.shared,
        state,
        listener: &state.listeners["main"],
        client: "127.0.0.1:12345".parse().unwrap(),
        proto,
        method: if proto == Proto::Udp { "UDP" } else { "BIND" },
        host,
        port,
        login: None,
        mode: Mode::Tunnel,
        reuse: false,
    }
}

#[tokio::test]
async fn bind_preparation_checks_stage_and_pins_dns_without_connecting() {
    let expected = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = expected.local_addr().unwrap().port();
    let edge = Edge::start(&format!(
        r#"
{OPEN}
[[pool]]
name = "bind-source"
addresses = ["127.0.0.2"]
[[egress]]
pool = "bind-source"
[[rule]]
stage = "bind"
action = "allow"
allow_internal = true
when = {{ port = ["{port}"], dst = ["127.0.0.1"] }}
"#
    ))
    .await;
    let state = edge.server.shared.state();
    let allowed = request(&edge, &state, "origin.test", port, Proto::Socks5);
    let bound = conn::bind_prepare(&allowed).await.unwrap();
    assert_eq!(
        bound.expected_ips,
        vec!["127.0.0.1".parse::<std::net::IpAddr>().unwrap()]
    );
    assert_eq!(bound.egress, Some("127.0.0.2".parse().unwrap()));
    assert_eq!(bound.pool.as_deref(), Some("bind-source"));
    assert!(
        timeout(Duration::from_millis(100), expected.accept())
            .await
            .is_err(),
        "BIND must not connect to requested peer"
    );
    let incoming = TcpStream::connect(bound.listener.local_addr().unwrap())
        .await
        .unwrap();
    let (_, peer) = bound.listener.accept().await.unwrap();
    assert_eq!(peer.ip(), incoming.local_addr().unwrap().ip());
    let denied = request(&edge, &state, "origin.test", 1, Proto::Socks5);
    assert!(
        matches!(conn::bind_prepare(&denied).await, Err(error) if matches!(error.kind, RefusalKind::Forbidden))
    );
}

#[tokio::test]
async fn bind_keeps_connection_budgets_until_its_listener_is_dropped() {
    let edge = Edge::start(&format!("{OPEN}\n[[limit]]\nmax_connections = 1\n")).await;
    let state = edge.server.shared.state();
    let req = request(&edge, &state, "origin.test", 443, Proto::Socks5);
    let bound = conn::bind_prepare(&req).await.unwrap();
    assert!(
        matches!(conn::bind_prepare(&req).await, Err(error) if matches!(error.kind, RefusalKind::LimitConnections))
    );
    drop(bound);
    assert!(conn::bind_prepare(&req).await.is_ok());
    let wildcard_port = request(&edge, &state, "origin.test", 0, Proto::Socks5);
    assert!(conn::bind_prepare(&wildcard_port).await.is_ok());
}

#[tokio::test]
async fn bind_enforces_user_slots_and_request_rate() {
    let edge = Edge::start(
        r#"
[[listener]]
name = "main"
listen = "127.0.0.1:0"
[[user]]
name = "alice"
password = "pw"
max_connections = 1
[[rule]]
action = "allow"
allow_internal = true
[[limit]]
request_rate = "2/min"
"#,
    )
    .await;
    let state = edge.server.shared.state();
    let login = conn::authenticate(
        &edge.server.shared,
        &state,
        &state.listeners["main"],
        "127.0.0.1".parse().unwrap(),
        Some(("alice", "pw")),
    )
    .await
    .unwrap();
    let mut req = request(&edge, &state, "origin.test", 443, Proto::Socks5);
    req.login = login.as_ref();
    let first = conn::bind_prepare(&req).await.unwrap();
    assert!(
        matches!(conn::bind_prepare(&req).await, Err(error) if matches!(error.kind, RefusalKind::LimitConnections))
    );
    drop(first);
    drop(conn::bind_prepare(&req).await.unwrap());
    assert!(
        matches!(conn::bind_prepare(&req).await, Err(error) if matches!(error.kind, RefusalKind::LimitRate))
    );
}

#[tokio::test]
async fn bind_never_bypasses_internal_denial_or_uses_parent_route() {
    let edge = Edge::start(
        r#"
[[listener]]
name = "main"
listen = "127.0.0.1:0"
auth = "none"
[[rule]]
action = "allow"
"#,
    )
    .await;
    let state = edge.server.shared.state();
    let req = request(&edge, &state, "origin.test", 443, Proto::Socks5);
    assert!(
        matches!(conn::bind_prepare(&req).await, Err(error) if matches!(error.kind, RefusalKind::DestinationDenied))
    );
    let parent = Edge::start(&format!(
        "{OPEN}\n[[parent]]\nname = \"unused\"\ntype = \"http\"\naddress = \"127.0.0.1:9\"\n[server]\ndefault_route = \"parent\"\n"
    )).await;
    let state = parent.server.shared.state();
    let req = request(&parent, &state, "origin.test", 443, Proto::Socks5);
    assert!(
        matches!(conn::bind_prepare(&req).await, Err(error) if matches!(error.kind, RefusalKind::OptionDenied))
    );
    let wildcard = request(&parent, &state, "0.0.0.0", 0, Proto::Socks5);
    assert!(
        matches!(conn::bind_prepare(&wildcard).await, Err(error) if matches!(error.kind, RefusalKind::DestinationDenied))
    );
}

#[tokio::test]
async fn udp_stage_checks_each_datagram_in_one_association() {
    let denied_origin = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let allowed_origin = udp_origin("127.0.0.1:0").await;
    let edge = Edge::start(&format!(
        r#"
[[listener]]
name = "main"
listen = "127.0.0.1:0"
protocol = "socks"
auth = "none"
udp = true
[[rule]]
action = "allow"
allow_internal = true
[[rule]]
stage = "udp"
action = "allow"
allow_internal = true
when = {{ port = ["{}"] }}
"#,
        allowed_origin.port()
    ))
    .await;
    let mut control = TcpStream::connect(edge.addr("main")).await.unwrap();
    control.write_all(&[5, 1, 0]).await.unwrap();
    let mut method = [0; 2];
    control.read_exact(&mut method).await.unwrap();
    assert_eq!(method, [5, 0]);
    control
        .write_all(&[5, 3, 0, 1, 0, 0, 0, 0, 0, 0])
        .await
        .unwrap();
    let (code, relay) = read_socks5_reply(&mut control).await;
    assert_eq!(code, 0);
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let packet = |target: SocketAddr| {
        let mut bytes = vec![0, 0, 0, 1, 127, 0, 0, 1];
        bytes.extend_from_slice(&target.port().to_be_bytes());
        bytes.extend_from_slice(b"probe");
        bytes
    };
    socket
        .send_to(&packet(denied_origin.local_addr().unwrap()), relay)
        .await
        .unwrap();
    let mut buf = [0; 1024];
    assert!(
        timeout(
            Duration::from_millis(200),
            denied_origin.recv_from(&mut buf)
        )
        .await
        .is_err()
    );
    socket
        .send_to(&packet(allowed_origin), relay)
        .await
        .unwrap();
    let (count, _) = timeout(Duration::from_secs(2), socket.recv_from(&mut buf))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(&buf[10..count], b"from:127.0.0.1");
}
