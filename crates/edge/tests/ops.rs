//! Parent chaining, configuration reload, PROXY protocol, access logs, the
//! ops endpoints and `--check`, end to end.
#![allow(clippy::unwrap_used)]

mod common;

use std::net::SocketAddr;
use std::time::Duration;

use common::*;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

fn free_port() -> u16 {
    let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    l.local_addr().unwrap().port()
}

/// An edge that acts as the upstream: logins required, leaves from 127.0.0.3.
async fn parent_edge(extra: &str) -> Edge {
    Edge::start(&format!(
        r#"
[[listener]]
name = "main"
listen = "127.0.0.1:0"
[[user]]
name = "relay"
password = "relaypw"
[[pool]]
name = "up"
addresses = ["127.0.0.3"]
[server]
default_pool = "up"
[[rule]]
action = "allow"
allow_internal = true
{extra}
"#
    ))
    .await
}

fn http_parent(name: &str, addr: SocketAddr, extra: &str) -> String {
    format!(
        "[[parent]]\nname = \"{name}\"\ntype = \"http\"\naddress = \"{addr}\"\nusername = \"relay\"\npassword = \"relaypw\"\n{extra}\n"
    )
}

#[tokio::test]
async fn an_http_parent_carries_http_requests_and_connect_tunnels() {
    let origin = http_origin("127.0.0.1:0").await;
    let banner = banner_origin("127.0.0.1:0").await;
    let parent = parent_edge("").await;
    let child = Edge::start(&format!(
        "{OPEN}\n[[pool]]\nname = \"own\"\naddresses = [\"127.0.0.2\"]\n[server]\ndefault_pool = \"own\"\ndefault_route = \"parent\"\n{}",
        http_parent("p", parent.addr("main"), "")
    ))
    .await;
    // the target sees the PARENT's address, not the child's
    assert_eq!(
        get_ip(
            child.addr("main"),
            &format!("origin.test:{}", origin.port()),
            None
        )
        .await,
        ip("127.0.0.3")
    );
    let mut s = tunnel(
        child.addr("main"),
        &format!("origin.test:{}", banner.port()),
        None,
    )
    .await
    .unwrap();
    assert_eq!(read_line(&mut s).await, "ip:127.0.0.3");
    let (mut s, _) = socks5(child.addr("main"), "origin.test", banner.port(), None)
        .await
        .unwrap();
    assert_eq!(read_line(&mut s).await, "ip:127.0.0.3");
    let m = child.metrics();
    assert!(
        m.contains(
            "proxyx_edge_parent_requests_total{outcome=\"ok\",parent=\"p\",service=\"proxyx-edge\"}"
        ),
        "{m}"
    );
    assert!(
        m.contains("proxyx_edge_parent_up{parent=\"p\",service=\"proxyx-edge\"} 1"),
        "{m}"
    );
}

#[tokio::test]
async fn a_socks5_parent_and_a_bad_parent_login() {
    let origin = http_origin("127.0.0.1:0").await;
    let parent = parent_edge("").await;
    let socks_parent = |pw: &str| {
        format!(
            "[[parent]]\nname = \"p\"\ntype = \"socks5\"\naddress = \"{}\"\nusername = \"relay\"\npassword = \"{pw}\"\n",
            parent.addr("main")
        )
    };
    let child = |pw: &str| {
        format!(
            "{OPEN}\n[[pool]]\nname = \"own\"\naddresses = [\"127.0.0.2\"]\n[server]\ndefault_pool = \"own\"\ndefault_route = \"parent\"\n{}",
            socks_parent(pw)
        )
    };
    let c = Edge::start(&child("relaypw")).await;
    let t = format!("origin.test:{}", origin.port());
    assert_eq!(get_ip(c.addr("main"), &t, None).await, ip("127.0.0.3"));
    let c = Edge::start(&child("wrong")).await;
    let r = get(c.addr("main"), &t, "/ip", None).await;
    assert_eq!(
        (r.status, r.header("x-proxyx-error")),
        (502, Some("parent_error")),
        "{r:?}"
    );
    // an HTTP parent that refuses the login: its 407 is the proxy's 502, never passed to the client
    let c = Edge::start(&format!(
        "{OPEN}\n[server]\ndefault_route = \"parent\"\n{}",
        http_parent("p", parent.addr("main"), "").replace("relaypw", "wrong")
    ))
    .await;
    let r = get(c.addr("main"), &t, "/ip", None).await;
    assert_eq!(r.status, 502, "{r:?}");
    assert!(r.header("proxy-authenticate").is_none());
}

#[tokio::test]
async fn parents_fail_over_by_priority_and_routes_pick_parents_per_rule() {
    let origin = http_origin("127.0.0.1:0").await;
    let parent = parent_edge("").await;
    let dead: SocketAddr = format!("127.0.0.1:{}", free_port()).parse().unwrap();
    let t = format!("origin.test:{}", origin.port());
    let t2 = format!("origin2.test:{}", origin.port());

    // a dead first-tier parent, a good backup: requests still succeed, the dead one goes down
    let c = Edge::start(&format!(
        "{OPEN}\n[breaker.parent]\nfailure_threshold = 2\n[[pool]]\nname = \"own\"\naddresses = [\"127.0.0.2\"]\n[server]\ndefault_pool = \"own\"\ndefault_route = \"parent\"\n{}{}",
        http_parent("dead", dead, ""),
        http_parent("backup", parent.addr("main"), "priority = 1\n"),
    ))
    .await;
    for _ in 0..4 {
        assert_eq!(get_ip(c.addr("main"), &t, None).await, ip("127.0.0.3"));
    }
    let m = c.metrics();
    assert!(
        m.contains("proxyx_edge_parent_up{parent=\"dead\",service=\"proxyx-edge\"} 0"),
        "{m}"
    );
    assert!(
        m.contains("proxyx_edge_parent_up{parent=\"backup\",service=\"proxyx-edge\"} 1"),
        "{m}"
    );
    assert!(m.contains("proxyx_edge_parent_requests_total{outcome=\"failed\",parent=\"dead\",service=\"proxyx-edge\"} 2"), "{m}");

    // route = parent with nothing up: 502 (never direct); parent_or_direct falls back to direct
    let only_dead = |route: &str| {
        format!(
            "{OPEN}\n[[pool]]\nname = \"own\"\naddresses = [\"127.0.0.2\"]\n[server]\ndefault_pool = \"own\"\ndefault_route = \"{route}\"\n{}",
            http_parent("dead", dead, "")
        )
    };
    let c = Edge::start(&only_dead("parent")).await;
    let r = get(c.addr("main"), &t, "/ip", None).await;
    assert_eq!(r.status, 502, "{r:?}");
    let c = Edge::start(&only_dead("parent_or_direct")).await;
    assert_eq!(get_ip(c.addr("main"), &t, None).await, ip("127.0.0.2"));

    // per-rule routing: origin2.test goes through the parent, the rest direct
    let c = Edge::start(&format!(
        "{OPEN}\n[[pool]]\nname = \"own\"\naddresses = [\"127.0.0.2\"]\n[server]\ndefault_pool = \"own\"\n[[route]]\nwhen = {{ domain = [\"origin2.test\"] }}\nroute = \"parent\"\nparents = [\"p\"]\n{}",
        http_parent("p", parent.addr("main"), "")
    ))
    .await;
    assert_eq!(get_ip(c.addr("main"), &t, None).await, ip("127.0.0.2"));
    assert_eq!(get_ip(c.addr("main"), &t2, None).await, ip("127.0.0.3"));
}

#[tokio::test]
async fn the_client_address_travels_to_a_parent_by_proxy_protocol() {
    let origin = http_origin("127.0.0.1:0").await;
    // the parent refuses clients from loopback, unless a trusted proxy says the client is elsewhere
    let parent = Edge::start(
        r#"
[[listener]]
name = "main"
listen = "127.0.0.1:0"
auth = "none"
proxy_protocol = "required"
trusted_proxies = ["127.0.0.0/8"]
[[rule]]
action = "deny"
when = { src = ["127.0.0.0/8"] }
[[rule]]
action = "allow"
allow_internal = true
"#,
    )
    .await;
    let c = Edge::start(&format!(
        "[[listener]]\nname = \"main\"\nlisten = \"127.0.0.1:0\"\nauth = \"none\"\nproxy_protocol = \"required\"\ntrusted_proxies = [\"127.0.0.0/8\"]\n[server]\ndefault_route = \"parent\"\n[[rule]]\naction = \"allow\"\nallow_internal = true\n[[parent]]\nname = \"p\"\ntype = \"http\"\naddress = \"{}\"\nsend_proxy_protocol = \"v2\"\n",
        parent.addr("main")
    ))
    .await;
    let t = format!("origin.test:{}", origin.port());
    let mut s = TcpStream::connect(c.addr("main")).await.unwrap();
    s.write_all(format!("PROXY TCP4 203.0.113.9 127.0.0.1 40000 3128\r\nGET http://{t}/ip HTTP/1.1\r\nHost: {t}\r\nConnection: close\r\n\r\n").as_bytes())
        .await
        .unwrap();
    let r = read_response(&mut s, false).await;
    assert_eq!(r.status, 200, "{r:?}");
    // without the header the child itself refuses (required)
    let mut s = TcpStream::connect(c.addr("main")).await.unwrap();
    s.write_all(format!("GET http://{t}/ip HTTP/1.1\r\nHost: {t}\r\n\r\n").as_bytes())
        .await
        .unwrap();
    let mut buf = Vec::new();
    let _ = tokio::time::timeout(Duration::from_secs(2), s.read_to_end(&mut buf)).await;
    assert!(buf.is_empty());
}

#[tokio::test]
async fn proxy_protocol_sets_the_client_address_only_from_trusted_peers() {
    let origin = http_origin("127.0.0.1:0").await;
    let t = format!("origin.test:{}", origin.port());
    let cfg = |mode: &str, trusted: &str| {
        format!(
            "[[listener]]\nname = \"main\"\nlisten = \"127.0.0.1:0\"\nauth = \"none\"\nproxy_protocol = \"{mode}\"\ntrusted_proxies = [\"{trusted}\"]\n[[rule]]\naction = \"allow\"\nallow_internal = true\nwhen = {{ src = [\"203.0.113.0/24\"] }}\n[[rule]]\naction = \"deny\"\n"
        )
    };
    let req = format!("GET http://{t}/ip HTTP/1.1\r\nHost: {t}\r\nConnection: close\r\n\r\n");
    let with_header = format!("PROXY TCP4 203.0.113.9 127.0.0.1 40000 3128\r\n{req}");

    let e = Edge::start(&cfg("optional", "127.0.0.0/8")).await;
    assert_eq!(
        via_proxy(e.addr("main"), &with_header).await.status,
        200,
        "header from a trusted peer"
    );
    assert_eq!(
        via_proxy(e.addr("main"), &req).await.status,
        403,
        "no header: the real source is not allowed"
    );
    let v2 = {
        let mut h = b"\r\n\r\n\0\r\nQUIT\n".to_vec();
        h.extend_from_slice(&[
            0x21, 0x11, 0, 12, 203, 0, 113, 9, 127, 0, 0, 1, 0x9c, 0x40, 0x0c, 0x38,
        ]);
        h.extend_from_slice(req.as_bytes());
        h
    };
    let mut s = TcpStream::connect(e.addr("main")).await.unwrap();
    s.write_all(&v2).await.unwrap();
    assert_eq!(
        read_response(&mut s, false).await.status,
        200,
        "PROXY protocol v2"
    );

    // the peer is not trusted: its header is not believed
    let e = Edge::start(&cfg("optional", "10.0.0.0/8")).await;
    assert_eq!(via_proxy(e.addr("main"), &req).await.status, 403);
    let e = Edge::start(&cfg("required", "10.0.0.0/8")).await;
    let mut s = TcpStream::connect(e.addr("main")).await.unwrap();
    s.write_all(with_header.as_bytes()).await.unwrap();
    let mut buf = Vec::new();
    let _ = tokio::time::timeout(Duration::from_secs(2), s.read_to_end(&mut buf)).await;
    assert!(buf.is_empty(), "closed unanswered");
    assert!(e.metrics().contains("outcome=\"proxy_protocol_error\""));
}

#[tokio::test]
async fn a_reload_changes_users_rules_and_listeners_without_dropping_tunnels() {
    let banner = banner_origin("127.0.0.1:0").await;
    let origin = http_origin("127.0.0.1:0").await;
    let t = format!("origin.test:{}", origin.port());
    let bt = format!("origin.test:{}", banner.port());
    let (p1, p2) = (free_port(), free_port());
    let cfg = |user: &str, port: u16, extra: &str| {
        format!(
            "[[listener]]\nname = \"main\"\nlisten = \"127.0.0.1:{port}\"\n[[user]]\nname = \"{user}\"\npassword = \"pw\"\n[[rule]]\naction = \"allow\"\nallow_internal = true\n{extra}\n"
        )
    };
    let e = Edge::start(&cfg("alice", p1, "")).await;
    let main1: SocketAddr = format!("127.0.0.1:{p1}").parse().unwrap();
    let main2: SocketAddr = format!("127.0.0.1:{p2}").parse().unwrap();
    let mut held = tunnel(main1, &bt, Some(("alice", "pw"))).await.unwrap();
    let _ = read_line(&mut held).await;
    assert_eq!(
        get(main1, &t, "/ip", Some(("alice", "pw"))).await.status,
        200
    );

    // new user, new listener address, and the old user is gone
    e.rewrite(&cfg("bob", p2, ""));
    e.server.reload().await.unwrap();
    assert_eq!(get(main2, &t, "/ip", Some(("bob", "pw"))).await.status, 200);
    assert_eq!(
        get(main2, &t, "/ip", Some(("alice", "pw"))).await.status,
        407
    );
    assert!(
        TcpStream::connect(main1).await.is_err(),
        "the old listener is closed"
    );
    // the tunnel that was open across the reload still relays
    held.write_all(b"still here").await.unwrap();
    let mut b = [0u8; 10];
    held.read_exact(&mut b).await.unwrap();
    assert_eq!(&b, b"still here");

    // a broken file is refused as a whole and the running configuration stays
    e.rewrite(&cfg("carol", p2, "[[egress]]\npool = \"missing\"\n"));
    let err = e.server.reload().await.unwrap_err();
    assert!(format!("{err:#}").contains("missing"), "{err:#}");
    assert_eq!(get(main2, &t, "/ip", Some(("bob", "pw"))).await.status, 200);
    // so is a listener that cannot bind: nothing of the new file is applied
    let busy = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let busy_port = busy.local_addr().unwrap().port();
    e.rewrite(&cfg("dave", busy_port, ""));
    assert!(e.server.reload().await.is_err());
    assert_eq!(get(main2, &t, "/ip", Some(("bob", "pw"))).await.status, 200);
    let m = e.metrics();
    assert!(
        m.contains("proxyx_edge_config_reloads_total{result=\"ok\",service=\"proxyx-edge\"} 1"),
        "{m}"
    );
    assert!(
        m.contains("proxyx_edge_config_reloads_total{result=\"failed\",service=\"proxyx-edge\"} 2"),
        "{m}"
    );
}

#[tokio::test]
async fn the_access_log_records_requests_in_each_format_and_reopens_after_rotation() {
    let origin = http_origin("127.0.0.1:0").await;
    let t = format!("origin.test:{}", origin.port());
    let dir = std::env::temp_dir().join(format!("edge-it-log-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let log = dir.join("access.log");
    let cfg = |fmt: &str| {
        format!(
            r#"
[access_log]
output = "{}"
format = "{fmt}"
[[listener]]
name = "main"
listen = "127.0.0.1:0"
[[user]]
name = "alice"
password = "pw"
[[pool]]
name = "a"
addresses = ["127.0.0.4"]
[server]
default_pool = "a"
[[rule]]
name = "web"
action = "allow"
allow_internal = true
when = {{ port = ["{}"] }}
"#,
            log.display(),
            origin.port()
        )
    };
    let e = Edge::start(&cfg("json")).await;
    let l = e.addr("main");
    assert_eq!(
        get(l, &t, "/big?n=5000", Some(("alice", "pw")))
            .await
            .body
            .len(),
        5000
    );
    assert_eq!(
        get(l, "origin.test:81", "/", Some(("alice", "pw")))
            .await
            .status,
        403
    );
    assert_eq!(get(l, &t, "/", None).await.status, 407);
    tokio::time::sleep(Duration::from_millis(600)).await;
    let text = std::fs::read_to_string(&log).unwrap();
    let rows: Vec<serde_json::Value> = text
        .lines()
        .map(|l| serde_json::from_str(l).unwrap())
        .collect();
    assert_eq!(rows.len(), 3, "{text}");
    let ok = &rows[0];
    assert_eq!(ok["status"], 200);
    assert_eq!(ok["user"], "alice");
    assert_eq!(ok["egress_ip"], "127.0.0.4");
    assert_eq!(ok["pool"], "a");
    assert_eq!(ok["rule"], "web");
    assert_eq!(ok["bytes_down"], 5000);
    assert_eq!(ok["protocol"], "http");
    assert_eq!(ok["method"], "GET");
    assert_eq!(ok["target_ip"], "127.0.0.1");
    assert_eq!(ok["result"], "ok");
    assert_eq!(rows[1]["status"], 403);
    assert_eq!(rows[1]["result"], "denied");
    assert_eq!(rows[2]["status"], 407);
    assert_eq!(rows[2]["user"], serde_json::Value::Null);

    // rotate: move the file away, reload, and new lines go to a fresh file
    let rotated = dir.join("access.log.1");
    std::fs::rename(&log, &rotated).unwrap();
    e.rewrite(&cfg("squid"));
    e.server.reload().await.unwrap();
    assert_eq!(get(l, &t, "/ip", Some(("alice", "pw"))).await.status, 200);
    tokio::time::sleep(Duration::from_millis(600)).await;
    let line = std::fs::read_to_string(&log).unwrap();
    let f: Vec<&str> = line.split_whitespace().collect();
    // time elapsed client code/status bytes method url user hier/peer mime
    assert_eq!(f[2], "127.0.0.1", "{line}");
    assert_eq!(f[3], "TCP_MISS/200");
    assert_eq!(f[5], "GET");
    assert_eq!(f[6], format!("http://{t}/ip"));
    assert_eq!(f[7], "alice");
    assert_eq!(f[8], "HIER_DIRECT/127.0.0.1");
    assert_eq!(f[9], "text/plain");
    assert_eq!(
        std::fs::read_to_string(&rotated).unwrap().lines().count(),
        3
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn the_ops_listener_serves_metrics_and_health() {
    let origin = http_origin("127.0.0.1:0").await;
    let e = Edge::start(&format!("{OPEN}\n")).await;
    let ops = proxyx_edge::ops::serve(e.server.clone(), "127.0.0.1:0".parse().unwrap())
        .await
        .unwrap();
    assert_eq!(
        get_ip(
            e.addr("main"),
            &format!("origin.test:{}", origin.port()),
            None
        )
        .await,
        ip("127.0.0.1")
    );
    let r = via_ops(ops, "/healthz").await;
    assert_eq!((r.status, r.text().as_str()), (200, "ok\n"));
    assert_eq!(via_ops(ops, "/readyz").await.status, 200);
    let r = via_ops(ops, "/metrics").await;
    assert_eq!(r.status, 200);
    assert_eq!(
        r.header("content-type"),
        Some("text/plain; version=0.0.4; charset=utf-8")
    );
    let m = r.text();
    for needle in [
        "proxyx_edge_connections_total{listener=\"main\",outcome=\"accepted\",service=\"proxyx-edge\"} 1",
        "proxyx_edge_requests_total{listener=\"main\",protocol=\"http\",result=\"ok\",service=\"proxyx-edge\"} 1",
        "proxyx_edge_acl_decisions_total{action=\"allow\",service=\"proxyx-edge\"} 1",
        "proxyx_edge_dns_lookups_total{result=\"ok\",service=\"proxyx-edge\"}",
    ] {
        assert!(m.contains(needle), "missing {needle}:\n{m}");
    }
    e.server.shutdown(Duration::from_secs(1)).await;
    assert_eq!(via_ops(ops, "/readyz").await.status, 503);
}

async fn via_ops(addr: SocketAddr, path: &str) -> Resp {
    let mut s = TcpStream::connect(addr).await.unwrap();
    s.write_all(
        format!("GET {path} HTTP/1.1\r\nHost: ops\r\nConnection: close\r\n\r\n").as_bytes(),
    )
    .await
    .unwrap();
    read_response(&mut s, false).await
}

#[tokio::test]
async fn check_validates_without_binding() {
    let dir = std::env::temp_dir().join(format!("edge-it-check-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("edge.toml");
    let write = |t: &str| std::fs::write(&path, t).unwrap();
    write(
        "[[listener]]\nname = \"main\"\nlisten = \"127.0.0.1:3128\"\nauth = \"none\"\n[[pool]]\nname = \"a\"\naddresses = [\"127.0.0.2\", \"127.0.0.3\"]\n[[rule]]\naction = \"allow\"\n",
    );
    let report = proxyx_edge::check(&path).unwrap();
    assert_eq!((report.listeners, report.rules), (1, 1));
    assert_eq!(report.pools[0].1.len(), 2);
    // an address this machine does not have
    write(
        "[[listener]]\nname = \"main\"\nlisten = \"127.0.0.1:3128\"\nauth = \"none\"\n[[pool]]\nname = \"a\"\naddresses = [\"203.0.113.77\"]\n",
    );
    let err = format!("{:#}", proxyx_edge::check(&path).unwrap_err());
    assert!(
        err.contains("203.0.113.77") && err.contains("not assigned"),
        "{err}"
    );
    // a typo in a key, a missing user source, an unsupported hash
    for bad in [
        "[[listener]]\nname = \"m\"\nlisten = \"127.0.0.1:1\"\nauth = \"none\"\nprotocl = \"http\"\n",
        "[[listener]]\nname = \"m\"\nlisten = \"127.0.0.1:1\"\n",
        "[[listener]]\nname = \"m\"\nlisten = \"127.0.0.1:1\"\n[[user]]\nname = \"a\"\npassword_hash = \"$9$nope\"\n",
        "[[listener]]\nname = \"m\"\nlisten = \"127.0.0.1:1\"\nauth = \"none\"\n[[rule]]\naction = \"allow\"\nwhen = { domain = [\"re:(\"] }\n",
    ] {
        write(bad);
        assert!(proxyx_edge::check(&path).is_err(), "{bad}");
    }
    let _ = std::fs::remove_dir_all(&dir);
}
