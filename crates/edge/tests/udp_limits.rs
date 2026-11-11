//! UDP associations share connection admission with TCP and BIND.
#![allow(clippy::unwrap_used)]

mod common;

use std::net::SocketAddr;
use std::sync::atomic::Ordering;
use std::time::Duration;

use common::*;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};
use tokio::time::{sleep, timeout};

const USER: &str = r#"
[[listener]]
name = "main"
listen = "127.0.0.1:0"
udp = true
[[user]]
name = "alice"
password = "pw"
max_connections = 1
[[rule]]
action = "allow"
allow_internal = true
"#;

const OPEN_UDP: &str = r#"
[[listener]]
name = "main"
listen = "127.0.0.1:0"
auth = "none"
udp = true
[[rule]]
action = "allow"
allow_internal = true
"#;

async fn command(proxy: SocketAddr, cmd: u8, authenticated: bool) -> (TcpStream, u8, SocketAddr) {
    timeout(Duration::from_secs(2), async {
        let mut control = TcpStream::connect(proxy).await.unwrap();
        let method = if authenticated { 2 } else { 0 };
        control.write_all(&[5, 1, method]).await.unwrap();
        let mut reply = [0; 2];
        control.read_exact(&mut reply).await.unwrap();
        assert_eq!(reply, [5, method]);
        if authenticated {
            control.write_all(b"\x01\x05alice\x02pw").await.unwrap();
            control.read_exact(&mut reply).await.unwrap();
            assert_eq!(reply, [1, 0]);
        }
        control
            .write_all(&[5, cmd, 0, 1, 127, 0, 0, 1, 0, 0])
            .await
            .unwrap();
        let (code, bound) = read_socks5_reply(&mut control).await;
        (control, code, bound)
    })
    .await
    .expect("SOCKS command completes")
}

async fn assert_refused(mut control: TcpStream, code: u8) {
    assert_eq!(code, 2, "admission must fail before a success reply");
    let mut byte = [0; 1];
    let read = timeout(Duration::from_secs(2), control.read(&mut byte))
        .await
        .expect("refused control connection closes");
    assert!(matches!(read, Ok(0) | Err(_)), "unexpected data: {read:?}");
}

async fn wait_closed(edge: &Edge) {
    timeout(Duration::from_secs(2), async {
        while edge.server.shared.conns.total.load(Ordering::Relaxed) != 0 {
            sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("closing control releases connection guards");
}

async fn udp_round_trip(relay: SocketAddr, origin: SocketAddr) {
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let mut packet = vec![0, 0, 0, 1, 127, 0, 0, 1];
    packet.extend_from_slice(&origin.port().to_be_bytes());
    packet.extend_from_slice(b"probe");
    socket.send_to(&packet, relay).await.unwrap();
    let mut reply = [0; 1024];
    let (count, from) = timeout(Duration::from_secs(2), socket.recv_from(&mut reply))
        .await
        .expect("admitted UDP association relays traffic")
        .unwrap();
    assert_eq!(from, relay);
    assert_eq!(&reply[..10], &packet[..10]);
    assert_eq!(&reply[10..count], b"from:127.0.0.1");
}

#[tokio::test]
async fn udp_user_slot_blocks_udp_tcp_and_bind_until_control_closes() {
    let origin = udp_origin("127.0.0.1:0").await;
    let tcp_origin = banner_origin("127.0.0.1:0").await;
    let edge = Edge::start(USER).await;
    let proxy = edge.addr("main");
    let (control, code, relay) = command(proxy, 3, true).await;
    assert_eq!(code, 0);
    assert_eq!(
        edge.server
            .shared
            .conns
            .per_user
            .current(&"alice".to_owned()),
        1
    );
    udp_round_trip(relay, origin).await;

    let (denied, code, _) = command(proxy, 3, true).await;
    assert_refused(denied, code).await;
    assert_eq!(
        tunnel(proxy, &tcp_origin.to_string(), Some(("alice", "pw")))
            .await
            .err(),
        Some(429)
    );
    let (denied, code, _) = command(proxy, 2, true).await;
    assert_refused(denied, code).await;

    drop(control);
    wait_closed(&edge).await;
    assert_eq!(
        edge.server
            .shared
            .conns
            .per_user
            .current(&"alice".to_owned()),
        0
    );
    let (control, code, relay) = command(proxy, 3, true).await;
    assert_eq!(code, 0, "control close releases the user slot");
    udp_round_trip(relay, origin).await;
    drop(control);
    wait_closed(&edge).await;
}

#[tokio::test]
async fn tcp_and_bind_user_slots_refuse_udp_before_success() {
    let origin = banner_origin("127.0.0.1:0").await;
    let edge = Edge::start(USER).await;
    let proxy = edge.addr("main");
    let mut tcp = tunnel(proxy, &origin.to_string(), Some(("alice", "pw")))
        .await
        .unwrap();
    assert!(read_line(&mut tcp).await.starts_with("ip:"));
    let (denied, code, _) = command(proxy, 3, true).await;
    assert_refused(denied, code).await;
    drop(tcp);
    wait_closed(&edge).await;

    let (bind, code, _) = command(proxy, 2, true).await;
    assert_eq!(code, 0);
    let (denied, code, _) = command(proxy, 3, true).await;
    assert_refused(denied, code).await;
    drop(bind);
    wait_closed(&edge).await;

    let (control, code, _) = command(proxy, 3, true).await;
    assert_eq!(code, 0, "BIND close releases the shared user slot");
    drop(control);
    wait_closed(&edge).await;
}

#[tokio::test]
async fn udp_source_limit_refuses_before_success_and_releases_on_control_close() {
    let edge = Edge::start(&format!(
        "{OPEN_UDP}\n[[limit]]\nscope = \"src\"\nmax_connections = 1\n"
    ))
    .await;
    let proxy = edge.addr("main");
    let (control, code, _) = command(proxy, 3, false).await;
    assert_eq!(code, 0);
    let (denied, code, _) = command(proxy, 3, false).await;
    assert_refused(denied, code).await;
    assert!(edge.metrics().contains(
        "proxyx_edge_limit_rejections_total{kind=\"limit_connections\",service=\"proxyx-edge\"} 1"
    ));
    drop(control);
    wait_closed(&edge).await;

    let (control, code, _) = command(proxy, 3, false).await;
    assert_eq!(code, 0, "control close releases the source budget");
    drop(control);
    wait_closed(&edge).await;
}

#[tokio::test]
async fn udp_rate_limit_refuses_before_success_without_leaking_user_slot() {
    let edge = Edge::start(&format!("{USER}\n[[limit]]\nrequest_rate = \"1/min\"\n")).await;
    let proxy = edge.addr("main");
    let (control, code, _) = command(proxy, 3, true).await;
    assert_eq!(code, 0);
    drop(control);
    wait_closed(&edge).await;

    let (denied, code, _) = command(proxy, 3, true).await;
    assert_refused(denied, code).await;
    wait_closed(&edge).await;
    assert_eq!(
        edge.server
            .shared
            .conns
            .per_user
            .current(&"alice".to_owned()),
        0
    );
    assert!(edge.metrics().contains(
        "proxyx_edge_limit_rejections_total{kind=\"limit_rate\",service=\"proxyx-edge\"} 1"
    ));
}

#[tokio::test]
async fn listener_source_cap_counts_udp_control_connections() {
    let edge = Edge::start(&format!(
        "{OPEN_UDP}\n[server]\nmax_connections_per_src = 1\n"
    ))
    .await;
    let proxy = edge.addr("main");
    let (control, code, _) = command(proxy, 3, false).await;
    assert_eq!(code, 0);
    let mut denied = TcpStream::connect(proxy).await.unwrap();
    let _ = denied.write_all(&[5, 1, 0]).await;
    let mut reply = [0; 2];
    let read = timeout(Duration::from_secs(2), denied.read(&mut reply))
        .await
        .expect("source-capped control closes");
    assert!(matches!(read, Ok(0) | Err(_)), "unexpected reply: {read:?}");
    assert!(edge.metrics().contains("outcome=\"over_limit\""));
    drop(denied);
    drop(control);
    wait_closed(&edge).await;

    let (control, code, _) = command(proxy, 3, false).await;
    assert_eq!(code, 0);
    drop(control);
    wait_closed(&edge).await;
}
