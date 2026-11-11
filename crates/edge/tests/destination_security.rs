//! Address-local authorization and parent destination pinning regressions.
#![allow(clippy::unwrap_used)]

mod common;

use std::net::IpAddr;
use std::time::Duration;

use common::*;
use proxyx_edge::acl::Proto;
use proxyx_edge::conn::{self, ReqCtx};
use proxyx_edge::connect::Mode;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::time::timeout;

const LISTENER: &str = r#"
[[listener]]
name = "main"
listen = "127.0.0.1:0"
auth = "none"
[health]
interval = "0"
"#;

fn request<'a>(
    edge: &'a Edge,
    state: &'a std::sync::Arc<proxyx_edge::state::State>,
    proto: Proto,
) -> ReqCtx<'a> {
    ReqCtx {
        shared: &edge.server.shared,
        state,
        listener: &state.listeners["main"],
        client: "127.0.0.1:12345".parse().unwrap(),
        proto,
        method: if proto == Proto::Udp { "UDP" } else { "BIND" },
        host: "mixed.test",
        port: 80,
        login: None,
        mode: Mode::Tunnel,
        reuse: false,
    }
}

#[tokio::test]
async fn mixed_dns_answers_never_dial_forbidden_candidates_in_either_order_or_fallback() {
    for addresses in [
        "[\"127.0.0.2\", \"127.0.0.1\"]",
        "[\"127.0.0.1\", \"127.0.0.2\"]",
    ] {
        let allowed = http_origin("127.0.0.1:0").await;
        let forbidden = TcpListener::bind(("127.0.0.2", allowed.port()))
            .await
            .unwrap();
        let edge = Edge::start(&format!(
            "\"mixed.test\" = {addresses}\n{LISTENER}\n[[rule]]\naction = \"allow\"\nallow_internal = true\nwhen = {{ dst = [\"127.0.0.1\"] }}\n"
        )).await;
        let response = get(
            edge.addr("main"),
            &format!("mixed.test:{}", allowed.port()),
            "/ip",
            None,
        )
        .await;
        assert_eq!(response.status, 200);
        assert!(
            timeout(Duration::from_millis(100), forbidden.accept())
                .await
                .is_err()
        );

        // A failed approved address must not fall through to a forbidden answer.
        let dead = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = dead.local_addr().unwrap().port();
        let forbidden = TcpListener::bind(("127.0.0.2", port)).await.unwrap();
        drop(dead);
        let response = get(edge.addr("main"), &format!("mixed.test:{port}"), "/", None).await;
        assert_eq!(response.status, 502);
        assert!(
            timeout(Duration::from_millis(100), forbidden.accept())
                .await
                .is_err()
        );
    }
}

#[tokio::test]
async fn one_internal_exception_does_not_authorize_another_internal_address() {
    let edge = Edge::start(&format!(
        "\"mixed.test\" = [\"127.0.0.2\", \"127.0.0.1\"]\n{LISTENER}\n[[rule]]\naction = \"allow\"\nallow_internal = true\nwhen = {{ dst = [\"127.0.0.1\"] }}\n[[rule]]\naction = \"allow\"\n"
    )).await;
    let state = edge.server.shared.state();
    let checked = conn::check(&request(&edge, &state, Proto::Http))
        .await
        .unwrap();
    assert_eq!(checked.ips, vec![ip("127.0.0.1")]);
    let mut forbidden = request(&edge, &state, Proto::Http);
    forbidden.host = "127.0.0.2";
    assert!(conn::check(&forbidden).await.is_err());
}

#[tokio::test]
async fn udp_and_bind_stages_filter_each_answer_independently() {
    for stage in ["udp", "bind"] {
        for addresses in [
            "[\"127.0.0.2\", \"127.0.0.1\"]",
            "[\"127.0.0.1\", \"127.0.0.2\"]",
        ] {
            let edge = Edge::start(&format!(
                "\"mixed.test\" = {addresses}\n{LISTENER}\n[[rule]]\naction = \"allow\"\nallow_internal = true\n[[rule]]\nstage = \"{stage}\"\naction = \"allow\"\nallow_internal = true\nwhen = {{ dst = [\"127.0.0.1\"] }}\n"
            )).await;
            let state = edge.server.shared.state();
            let req = request(
                &edge,
                &state,
                if stage == "udp" {
                    Proto::Udp
                } else {
                    Proto::Socks5
                },
            );
            let ips = if stage == "udp" {
                conn::check(&req).await.unwrap().ips
            } else {
                conn::bind_prepare(&req).await.unwrap().expected_ips
            };
            assert_eq!(ips, vec![ip("127.0.0.1")]);
        }
    }
}

async fn read_head(stream: &mut TcpStream) -> String {
    let mut bytes = Vec::new();
    loop {
        let mut byte = [0];
        stream.read_exact(&mut byte).await.unwrap();
        bytes.push(byte[0]);
        if bytes.ends_with(b"\r\n\r\n") {
            return String::from_utf8(bytes).unwrap();
        }
        assert!(bytes.len() < 16_384);
    }
}

#[tokio::test]
async fn http_parents_receive_numeric_targets_and_logical_host_headers() {
    for address in ["127.0.0.1", "::1"] {
        for tunnel_request in [false, true] {
            let parent = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let parent_addr = parent.local_addr().unwrap();
            let recorded = tokio::spawn(async move {
                let (mut stream, _) = parent.accept().await.unwrap();
                let head = read_head(&mut stream).await;
                stream
                    .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
                    .await
                    .unwrap();
                head
            });
            let edge = Edge::start(&format!(
                "\"pinned.test\" = [\"{address}\"]\n{LISTENER}\n[[rule]]\naction = \"allow\"\nallow_internal = true\n[server]\ndefault_route = \"parent\"\n[[parent]]\nname = \"p\"\ntype = \"http\"\naddress = \"{parent_addr}\"\n"
            )).await;
            if tunnel_request {
                let _stream = tunnel(edge.addr("main"), "pinned.test:8080", None)
                    .await
                    .unwrap();
            } else {
                assert_eq!(
                    get(edge.addr("main"), "pinned.test:8080", "/headers?x=1", None)
                        .await
                        .status,
                    200
                );
            }
            let head = timeout(Duration::from_secs(2), recorded)
                .await
                .unwrap()
                .unwrap();
            let authority = std::net::SocketAddr::new(address.parse().unwrap(), 8080);
            if tunnel_request {
                assert!(
                    head.starts_with(&format!("CONNECT {authority} HTTP/1.1\r\n")),
                    "{head}"
                );
            } else {
                assert!(
                    head.starts_with(&format!("GET http://{authority}/headers?x=1 HTTP/1.1\r\n")),
                    "{head}"
                );
                assert!(head.contains("Host: pinned.test:8080\r\n"), "{head}");
            }
        }
    }
}

#[tokio::test]
async fn socks5_parents_receive_numeric_ipv4_and_ipv6_address_types() {
    for address in ["127.0.0.1", "::1"] {
        let parent = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let parent_addr = parent.local_addr().unwrap();
        let recorded = tokio::spawn(async move {
            let (mut stream, _) = parent.accept().await.unwrap();
            let mut greeting = [0; 2];
            stream.read_exact(&mut greeting).await.unwrap();
            assert_eq!(greeting[0], 5);
            let mut methods = vec![0; usize::from(greeting[1])];
            stream.read_exact(&mut methods).await.unwrap();
            stream.write_all(&[5, 0]).await.unwrap();
            let mut head = [0; 4];
            stream.read_exact(&mut head).await.unwrap();
            assert_eq!(&head[..3], &[5, 1, 0]);
            let size = match head[3] {
                1 => 4,
                4 => 16,
                other => panic!("parent received nonnumeric ATYP {other}"),
            };
            let mut destination = vec![0; size + 2];
            stream.read_exact(&mut destination).await.unwrap();
            stream
                .write_all(&[5, 0, 0, 1, 127, 0, 0, 1, 0, 0])
                .await
                .unwrap();
            (head[3], destination)
        });
        let edge = Edge::start(&format!(
            "\"pinned.test\" = [\"{address}\"]\n{LISTENER}\n[[rule]]\naction = \"allow\"\nallow_internal = true\n[server]\ndefault_route = \"parent\"\n[[parent]]\nname = \"p\"\ntype = \"socks5\"\naddress = \"{parent_addr}\"\n"
        )).await;
        let _stream = tunnel(edge.addr("main"), "pinned.test:8080", None)
            .await
            .unwrap();
        let (atyp, destination) = timeout(Duration::from_secs(2), recorded)
            .await
            .unwrap()
            .unwrap();
        let expected: IpAddr = address.parse().unwrap();
        let mut bytes = match expected {
            IpAddr::V4(ip) => {
                assert_eq!(atyp, 1);
                ip.octets().to_vec()
            }
            IpAddr::V6(ip) => {
                assert_eq!(atyp, 4);
                ip.octets().to_vec()
            }
        };
        bytes.extend_from_slice(&8080u16.to_be_bytes());
        assert_eq!(destination, bytes);
    }
}

#[tokio::test]
async fn final_chain_hop_receives_approved_numeric_destination() {
    let parent = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let parent_addr = parent.local_addr().unwrap();
    let recorded = tokio::spawn(async move {
        let (mut stream, _) = parent.accept().await.unwrap();
        let first = read_head(&mut stream).await;
        stream.write_all(b"HTTP/1.1 200 OK\r\n\r\n").await.unwrap();
        let last = read_head(&mut stream).await;
        stream.write_all(b"HTTP/1.1 200 OK\r\n\r\n").await.unwrap();
        (first, last)
    });
    let edge = Edge::start(&format!(
        "{LISTENER}\n[[rule]]\naction = \"allow\"\nallow_internal = true\n[[parent]]\nname = \"first\"\ntype = \"http\"\naddress = \"{parent_addr}\"\n[[parent]]\nname = \"last\"\ntype = \"http\"\naddress = \"127.0.0.3:3128\"\n[[chain]]\nname = \"two\"\nhops = [{{ parents = [\"first\"] }}, {{ parents = [\"last\"] }}]\n[[route]]\nroute = \"parent\"\nchain = \"two\"\n"
    )).await;
    let _stream = tunnel(edge.addr("main"), "origin.test:8080", None)
        .await
        .unwrap();
    let (first, last) = timeout(Duration::from_secs(2), recorded)
        .await
        .unwrap()
        .unwrap();
    assert!(
        first.starts_with("CONNECT 127.0.0.3:3128 HTTP/1.1\r\n"),
        "{first}"
    );
    assert!(
        last.starts_with("CONNECT 127.0.0.1:8080 HTTP/1.1\r\n"),
        "{last}"
    );
}
