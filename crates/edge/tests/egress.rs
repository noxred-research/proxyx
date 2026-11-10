//! Outgoing-address selection and the wire protocols, end to end on loopback
//! aliases (127.0.0.2, 127.0.0.3, ... are all local on Linux): an origin
//! reports the address that connected to it, so each assertion is the
//! egress IP the target really saw.
#![allow(clippy::unwrap_used)]

mod common;

use std::collections::HashSet;
use std::net::IpAddr;

use common::*;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

fn pool(name: &str, addrs: &[&str], strategy: &str) -> String {
    let list: Vec<String> = addrs.iter().map(|a| format!("\"{a}\"")).collect();
    format!(
        "[[pool]]\nname = \"{name}\"\naddresses = [{}]\nstrategy = \"{strategy}\"\n",
        list.join(", ")
    )
}

#[tokio::test]
async fn a_fixed_pool_makes_the_target_see_that_address() {
    let origin = http_origin("127.0.0.1:0").await;
    let edge = Edge::start(&format!(
        "{OPEN}\n{}\n[server]\ndefault_pool = \"a\"\n",
        pool("a", &["127.0.0.2"], "first")
    ))
    .await;
    let target = format!("origin.test:{}", origin.port());
    for _ in 0..3 {
        assert_eq!(
            get_ip(edge.addr("main"), &target, None).await,
            ip("127.0.0.2")
        );
    }
}

#[tokio::test]
async fn round_robin_walks_the_pool_and_least_connections_spreads_open_tunnels() {
    let origin = http_origin("127.0.0.1:0").await;
    let banner = banner_origin("127.0.0.1:0").await;
    let edge = Edge::start(&format!(
        "{OPEN}\n{}\n{}\n[server]\ndefault_pool = \"rr\"\n",
        pool(
            "rr",
            &["127.0.0.2", "127.0.0.3", "127.0.0.4"],
            "round_robin"
        ),
        pool(
            "lc",
            &["127.0.0.5", "127.0.0.6", "127.0.0.7"],
            "least_connections"
        ),
    ))
    .await;
    let target = format!("origin.test:{}", origin.port());
    let seen: Vec<IpAddr> = {
        let mut v = Vec::new();
        for _ in 0..6 {
            v.push(get_ip(edge.addr("main"), &target, None).await);
        }
        v
    };
    assert_eq!(
        seen[..3].iter().collect::<HashSet<_>>().len(),
        3,
        "{seen:?}"
    );
    assert_eq!(seen[..3], seen[3..], "the cycle repeats: {seen:?}");

    // Open tunnels hold their address: least_connections gives three different ones.
    edge.rewrite(&format!(
        "{OPEN}\n{}\n[server]\ndefault_pool = \"lc\"\n",
        pool(
            "lc",
            &["127.0.0.5", "127.0.0.6", "127.0.0.7"],
            "least_connections"
        ),
    ));
    edge.server.reload().await.expect("reload");
    let mut held = Vec::new();
    let mut ips = HashSet::new();
    for _ in 0..3 {
        let mut s = tunnel(
            edge.addr("main"),
            &format!("127.0.0.1:{}", banner.port()),
            None,
        )
        .await
        .unwrap();
        let line = read_line(&mut s).await;
        ips.insert(line);
        held.push(s);
    }
    assert_eq!(ips.len(), 3, "{ips:?}");
}

#[tokio::test]
async fn random_reaches_every_address() {
    let origin = http_origin("127.0.0.1:0").await;
    let edge = Edge::start(&format!(
        "{OPEN}\n{}\n[server]\ndefault_pool = \"r\"\n",
        pool("r", &["127.0.0.2", "127.0.0.3", "127.0.0.4"], "random")
    ))
    .await;
    let target = format!("origin.test:{}", origin.port());
    let mut seen = HashSet::new();
    for _ in 0..60 {
        seen.insert(get_ip(edge.addr("main"), &target, None).await);
    }
    assert_eq!(seen.len(), 3, "{seen:?}");
}

#[tokio::test]
async fn each_listener_each_user_and_each_rule_has_its_own_egress() {
    let origin = http_origin("127.0.0.1:0").await;
    let other = http_origin("127.0.0.1:0").await;
    let edge = Edge::start(&format!(
        r#"
{p1}
{p2}
{p3}
{p4}
[[listener]]
name = "l2"
listen = "127.0.0.1:0"
auth = "none"
pool = "p2"
[[listener]]
name = "users"
listen = "127.0.0.1:0"
auth = "users"
pool = "p1"
[[user]]
name = "alice"
password = "pw"
pool = "p3"
[[user]]
name = "bob"
password = "pw"
[[egress]]
when = {{ domain = ["origin2.test"] }}
pool = "p4"
[[egress]]
when = {{ domain = ["origin3.test"] }}
address = "127.0.0.9"
[[rule]]
action = "allow"
allow_internal = true
"#,
        p1 = pool("p1", &["127.0.0.2"], "first"),
        p2 = pool("p2", &["127.0.0.3"], "first"),
        p3 = pool("p3", &["127.0.0.4"], "first"),
        p4 = pool("p4", &["127.0.0.5"], "first"),
    ))
    .await;
    let t = |h: &str, o: std::net::SocketAddr| format!("{h}:{}", o.port());
    // listener
    assert_eq!(
        get_ip(edge.addr("l2"), &t("origin.test", origin), None).await,
        ip("127.0.0.3")
    );
    // user pool beats listener pool; a user without a pool falls back to the listener's
    assert_eq!(
        get_ip(
            edge.addr("users"),
            &t("origin.test", origin),
            Some(("alice", "pw"))
        )
        .await,
        ip("127.0.0.4")
    );
    assert_eq!(
        get_ip(
            edge.addr("users"),
            &t("origin.test", origin),
            Some(("bob", "pw"))
        )
        .await,
        ip("127.0.0.2")
    );
    // egress rule beats everything, by pool and by fixed address
    assert_eq!(
        get_ip(
            edge.addr("users"),
            &t("origin2.test", other),
            Some(("alice", "pw"))
        )
        .await,
        ip("127.0.0.5")
    );
    assert_eq!(
        get_ip(
            edge.addr("users"),
            &t("origin3.test", other),
            Some(("bob", "pw"))
        )
        .await,
        ip("127.0.0.9")
    );
}

#[tokio::test]
async fn login_options_pick_a_session_pool_and_address() {
    let origin = http_origin("127.0.0.1:0").await;
    let edge = Edge::start(&format!(
        r#"
[auth]
login_options = true
[[listener]]
name = "main"
listen = "127.0.0.1:0"
{p1}
{p2}
[[user]]
name = "alice"
password = "pw"
pool = "p1"
allowed_pools = ["p2"]
allow_ip_select = true
[[user]]
name = "team-b"
password = "pw"
pool = "p1"
[[rule]]
action = "allow"
allow_internal = true
"#,
        p1 = pool(
            "p1",
            &["127.0.0.2", "127.0.0.3", "127.0.0.4", "127.0.0.5"],
            "sticky"
        ),
        p2 = pool("p2", &["127.0.0.6", "127.0.0.7"], "first"),
    ))
    .await;
    let target = format!("origin.test:{}", origin.port());
    let l = edge.addr("main");
    // same session id, same address; different ids spread over the pool
    let mut by_sid = std::collections::HashMap::new();
    for sid in ["s1", "s2", "s3", "s4", "s5", "s6", "s7", "s8"] {
        let a = get_ip(l, &target, Some((&format!("alice-sid-{sid}"), "pw"))).await;
        let b = get_ip(l, &target, Some((&format!("alice-sid-{sid}"), "pw"))).await;
        assert_eq!(a, b, "session {sid} moved");
        by_sid.insert(sid, a);
    }
    assert!(
        by_sid.values().collect::<HashSet<_>>().len() >= 2,
        "{by_sid:?}"
    );
    // the pool option, an address by position, both
    assert!(
        [ip("127.0.0.6"), ip("127.0.0.7")]
            .contains(&get_ip(l, &target, Some(("alice-pool-p2", "pw"))).await)
    );
    assert_eq!(
        get_ip(l, &target, Some(("alice-ip-3", "pw"))).await,
        ip("127.0.0.4")
    );
    assert_eq!(
        get_ip(l, &target, Some(("alice-pool-p2-ip-2", "pw"))).await,
        ip("127.0.0.7")
    );
    // user names with dashes still work; options the user may not use are refused
    assert!(
        get_ip(l, &target, Some(("team-b-sid-x", "pw")))
            .await
            .to_string()
            .starts_with("127.0.0.")
    );
    let r = get(l, &target, "/ip", Some(("team-b-ip-1", "pw"))).await;
    assert_eq!(r.status, 403);
    assert_eq!(r.header("x-proxyx-error"), Some("option_denied"));
    let r = get(l, &target, "/ip", Some(("alice-pool-nope", "pw"))).await;
    assert_eq!(r.status, 403);
    let r = get(l, &target, "/ip", Some(("alice-ip-9", "pw"))).await;
    assert_eq!(r.status, 403, "no such address: {r:?}");
}

#[tokio::test]
async fn ipv6_and_ipv4_destinations_use_a_source_of_their_own_family() {
    if !ipv6_available() {
        eprintln!("no IPv6 loopback: skipped");
        return;
    }
    let v4 = http_origin("127.0.0.1:0").await;
    let v6 = http_origin("[::1]:0").await;
    let edge = Edge::start(&format!(
        "{OPEN}\n{}\n[server]\ndefault_pool = \"dual\"\n",
        pool("dual", &["127.0.0.2", "::1"], "first")
    ))
    .await;
    assert_eq!(
        get_ip(
            edge.addr("main"),
            &format!("origin.test:{}", v4.port()),
            None
        )
        .await,
        ip("127.0.0.2")
    );
    assert_eq!(
        get_ip(
            edge.addr("main"),
            &format!("origin6.test:{}", v6.port()),
            None
        )
        .await,
        ip("::1")
    );
    // a literal IPv6 target
    assert_eq!(
        get_ip(edge.addr("main"), &format!("[::1]:{}", v6.port()), None).await,
        ip("::1")
    );
    // a pool with no IPv6 address cannot reach an IPv6 target: a clear 502, no fallback to a wrong source
    edge.rewrite(&format!(
        "{OPEN}\n{}\n[server]\ndefault_pool = \"v4\"\n",
        pool("v4", &["127.0.0.2"], "first")
    ));
    edge.server.reload().await.unwrap();
    let r = get(
        edge.addr("main"),
        &format!("origin6.test:{}", v6.port()),
        "/ip",
        None,
    )
    .await;
    assert_eq!(r.status, 502);
    assert_eq!(r.header("x-proxyx-error"), Some("no_egress_address"));
}

#[tokio::test]
async fn an_interface_pool_discovers_its_addresses() {
    let origin = http_origin("127.0.0.1:0").await;
    let edge = Edge::start(&format!(
        "{OPEN}\n[[pool]]\nname = \"lo\"\ninterface = \"lo\"\nipv6 = false\nstrategy = \"first\"\n[server]\ndefault_pool = \"lo\"\n"
    ))
    .await;
    assert_eq!(
        get_ip(
            edge.addr("main"),
            &format!("origin.test:{}", origin.port()),
            None
        )
        .await,
        ip("127.0.0.1")
    );
}

#[tokio::test]
async fn connect_tunnels_leave_from_the_pool_address() {
    let banner = banner_origin("127.0.0.1:0").await;
    let edge = Edge::start(&format!(
        "{OPEN}\n{}\n[server]\ndefault_pool = \"a\"\n",
        pool("a", &["127.0.0.3"], "first")
    ))
    .await;
    let mut s = tunnel(
        edge.addr("main"),
        &format!("origin.test:{}", banner.port()),
        None,
    )
    .await
    .unwrap();
    assert_eq!(read_line(&mut s).await, "ip:127.0.0.3");
    s.write_all(b"ping").await.unwrap();
    let mut b = [0u8; 4];
    s.read_exact(&mut b).await.unwrap();
    assert_eq!(&b, b"ping");
}

#[tokio::test]
async fn socks5_connect_reports_the_egress_address_and_relays() {
    let banner = banner_origin("127.0.0.1:0").await;
    let edge = Edge::start(&format!(
        r#"
{OPEN}
[[listener]]
name = "login"
listen = "127.0.0.1:0"
{p}
[[user]]
name = "alice"
password = "pw"
pool = "a"
"#,
        p = pool("a", &["127.0.0.4"], "first"),
    ))
    .await;
    // no login: domain target
    let (mut s, bound) = socks5(edge.addr("main"), "origin.test", banner.port(), None)
        .await
        .unwrap();
    assert!(
        bound.ip().is_loopback(),
        "the reply carries the local address of the outgoing socket: {bound}"
    );
    let line = read_line(&mut s).await;
    assert!(line.starts_with("ip:127.0.0."), "{line}");
    assert_eq!(
        socks5(edge.addr("login"), "origin.test", 1, Some(("alice", "bad")))
            .await
            .err(),
        Some(0xfe)
    );
    assert_eq!(
        socks5(edge.addr("login"), "origin.test", 1, None)
            .await
            .err(),
        Some(0xff),
        "login required"
    );
}

#[tokio::test]
async fn socks5_with_a_login_and_rules_that_allow_internal() {
    let banner = banner_origin("127.0.0.1:0").await;
    let edge = Edge::start(&format!(
        r#"
[[listener]]
name = "main"
listen = "127.0.0.1:0"
{p}
[[user]]
name = "alice"
password = "pw"
pool = "a"
[[rule]]
action = "allow"
allow_internal = true
"#,
        p = pool("a", &["127.0.0.4"], "first"),
    ))
    .await;
    let (mut s, bound) = socks5(
        edge.addr("main"),
        "origin.test",
        banner.port(),
        Some(("alice", "pw")),
    )
    .await
    .unwrap();
    assert_eq!(bound.ip(), ip("127.0.0.4"));
    assert_eq!(read_line(&mut s).await, "ip:127.0.0.4");
    // a connection refused by the target is reply 5, an unresolvable name reply 4
    let dead = {
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        l.local_addr().unwrap().port()
    };
    assert_eq!(
        socks5(
            edge.addr("main"),
            "origin.test",
            dead,
            Some(("alice", "pw"))
        )
        .await
        .err(),
        Some(0x05)
    );
}

#[tokio::test]
async fn socks4_and_4a_connect_with_a_user_id() {
    let banner = banner_origin("127.0.0.1:0").await;
    let edge = Edge::start(&format!(
        r#"
[[listener]]
name = "main"
listen = "127.0.0.1:0"
protocol = "socks"
{p}
[[user]]
name = "legacy"
password = "unused"
pool = "a"
socks4 = true
[[user]]
name = "strict"
password = "pw"
pool = "a"
[[rule]]
action = "allow"
allow_internal = true
"#,
        p = pool("a", &["127.0.0.5"], "first"),
    ))
    .await;
    let mut s = socks4(edge.addr("main"), "127.0.0.1", banner.port(), "legacy")
        .await
        .unwrap();
    assert_eq!(read_line(&mut s).await, "ip:127.0.0.5");
    let mut s = socks4(edge.addr("main"), "origin.test", banner.port(), "legacy")
        .await
        .unwrap();
    assert_eq!(read_line(&mut s).await, "ip:127.0.0.5");
    // a user without `socks4 = true` and an unknown user are refused with 93
    assert_eq!(
        socks4(edge.addr("main"), "127.0.0.1", banner.port(), "strict")
            .await
            .err(),
        Some(93)
    );
    assert_eq!(
        socks4(edge.addr("main"), "127.0.0.1", banner.port(), "ghost")
            .await
            .err(),
        Some(93)
    );
}

#[tokio::test]
async fn one_port_serves_http_and_socks_by_the_first_byte() {
    let origin = http_origin("127.0.0.1:0").await;
    let banner = banner_origin("127.0.0.1:0").await;
    let edge = Edge::start(OPEN).await;
    assert_eq!(
        get_ip(
            edge.addr("main"),
            &format!("origin.test:{}", origin.port()),
            None
        )
        .await,
        ip("127.0.0.1")
    );
    let (mut s, _) = socks5(edge.addr("main"), "origin.test", banner.port(), None)
        .await
        .unwrap();
    assert!(read_line(&mut s).await.starts_with("ip:"));
    let mut s = socks4(edge.addr("main"), "127.0.0.1", banner.port(), "x")
        .await
        .unwrap();
    assert!(read_line(&mut s).await.starts_with("ip:"));
    // an http-only listener refuses SOCKS, a socks-only listener refuses HTTP
    edge.rewrite(&format!("{OPEN}\n[[listener]]\nname = \"h\"\nlisten = \"127.0.0.1:0\"\nauth = \"none\"\nprotocol = \"http\"\n[[listener]]\nname = \"s\"\nlisten = \"127.0.0.1:0\"\nauth = \"none\"\nprotocol = \"socks\"\n"));
    edge.server.reload().await.unwrap();
    let mut c = tokio::net::TcpStream::connect(edge.addr("h"))
        .await
        .unwrap();
    c.write_all(&[5, 1, 0]).await.unwrap();
    let mut rest = Vec::new();
    let _ = tokio::time::timeout(std::time::Duration::from_secs(2), c.read_to_end(&mut rest)).await;
    assert!(
        String::from_utf8_lossy(&rest).starts_with("HTTP/1.1 400"),
        "{rest:?}"
    );
    let mut c = tokio::net::TcpStream::connect(edge.addr("s"))
        .await
        .unwrap();
    c.write_all(b"GET http://x/ HTTP/1.1\r\n\r\n")
        .await
        .unwrap();
    let mut rest = Vec::new();
    let _ = tokio::time::timeout(std::time::Duration::from_secs(2), c.read_to_end(&mut rest)).await;
    assert!(rest.is_empty(), "{rest:?}");
}

#[tokio::test]
async fn udp_associate_sends_from_the_pool_address() {
    let udp = udp_origin("127.0.0.1:0").await;
    let edge = Edge::start(&format!(
        r#"
[[listener]]
name = "main"
listen = "127.0.0.1:0"
auth = "none"
udp = true
{p}
[[rule]]
action = "allow"
allow_internal = true
[server]
default_pool = "a"
"#,
        p = pool("a", &["127.0.0.6"], "first"),
    ))
    .await;
    let mut c = tokio::net::TcpStream::connect(edge.addr("main"))
        .await
        .unwrap();
    c.write_all(&[5, 1, 0]).await.unwrap();
    let mut m = [0u8; 2];
    c.read_exact(&mut m).await.unwrap();
    c.write_all(&[5, 3, 0, 1, 0, 0, 0, 0, 0, 0]).await.unwrap();
    let (code, relay) = read_socks5_reply(&mut c).await;
    assert_eq!(code, 0);
    let sock = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let mut d = vec![0, 0, 0, 1, 127, 0, 0, 1];
    d.extend_from_slice(&udp.port().to_be_bytes());
    d.extend_from_slice(b"hello");
    sock.send_to(&d, relay).await.unwrap();
    let mut buf = [0u8; 2048];
    let (n, _) = tokio::time::timeout(std::time::Duration::from_secs(5), sock.recv_from(&mut buf))
        .await
        .expect("reply in time")
        .unwrap();
    assert_eq!(&buf[..4], &[0, 0, 0, 1], "SOCKS5 UDP header");
    assert_eq!(&buf[10..n], b"from:127.0.0.6");
    // a datagram from another source address is ignored
    let stranger = tokio::net::UdpSocket::bind("127.0.0.2:0").await.unwrap();
    stranger.send_to(&d, relay).await.unwrap();
    assert!(
        tokio::time::timeout(
            std::time::Duration::from_millis(400),
            sock.recv_from(&mut buf)
        )
        .await
        .is_err()
    );
    drop(c);
}

#[tokio::test]
async fn a_prefix_pool_draws_a_different_address_per_connection_and_keeps_a_session() {
    let origin = http_origin("127.0.0.1:0").await;
    let edge = Edge::start(&String::from(
        r#"
[auth]
login_options = true
[[listener]]
name = "main"
listen = "127.0.0.1:0"
[[user]]
name = "alice"
password = "pw"
pool = "block"
allow_ip_select = true
[[pool]]
name = "block"
prefixes = ["127.0.7.0/24"]
strategy = "sticky"
[[rule]]
action = "allow"
allow_internal = true
"#,
    ))
    .await;
    let target = format!("origin.test:{}", origin.port());
    let l = edge.addr("main");
    let net: ipnet::IpNet = "127.0.7.0/24".parse().unwrap();
    let mut seen = HashSet::new();
    for i in 0..24 {
        let a = get_ip(l, &target, Some((&format!("alice-sid-s{i}"), "pw"))).await;
        assert!(net.contains(&a), "{a}");
        let b = get_ip(l, &target, Some((&format!("alice-sid-s{i}"), "pw"))).await;
        assert_eq!(a, b, "session s{i} moved");
        seen.insert(a);
    }
    assert!(seen.len() > 10, "{} distinct addresses", seen.len());
    // a login can ask for an address of the block by position
    assert_eq!(
        get_ip(l, &target, Some(("alice-ip-9", "pw"))).await,
        ip("127.0.7.9")
    );
}
