//! Circuit breakers, active health checks, readiness, keepalive and timeouts,
//! end to end.
#![allow(clippy::unwrap_used)]

mod common;

use std::net::SocketAddr;
use std::time::{Duration, Instant};

use common::*;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

/// An edge that serves as the upstream: logins required, leaves from 127.0.0.3.
async fn parent_edge(listen: &str, extra: &str) -> Edge {
    Edge::start(&format!(
        r#"
[[listener]]
name = "main"
listen = "{listen}"
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

fn http_parent(addr: SocketAddr, extra: &str) -> String {
    format!(
        "[[parent]]\nname = \"p\"\ntype = \"http\"\naddress = \"{addr}\"\nusername = \"relay\"\npassword = \"relaypw\"\n{extra}\n"
    )
}

fn child(extra: &str, parents: &str) -> String {
    format!("{OPEN}\n[server]\ndefault_route = \"parent\"\n{extra}\n{parents}")
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

async fn probe_round(e: &Edge) {
    let state = e.server.shared.state();
    proxyx_edge::health::round(&e.server.shared, &state).await;
}

#[tokio::test]
async fn a_parent_that_comes_back_goes_through_half_open_to_closed() {
    let origin = http_origin("127.0.0.1:0").await;
    let port = free_port();
    let addr: SocketAddr = format!("127.0.0.1:{port}").parse().unwrap();
    let up = parent_edge(&addr.to_string(), "").await;
    let c = Edge::start(&child(
        "[breaker.parent]\nfailure_threshold = 1\nopen_duration = \"300ms\"\n[health]\ninterval = \"0\"\n[http]\nparent_keepalive = false\n",
        &http_parent(addr, ""),
    ))
    .await;
    let t = format!("origin.test:{}", origin.port());
    assert_eq!(get_ip(c.addr("main"), &t, None).await, ip("127.0.0.3"));

    // the parent goes away: the first failure opens the breaker, later requests fail fast
    up.server.shutdown(Duration::from_millis(100)).await;
    drop(up);
    let r = get(c.addr("main"), &t, "/ip", None).await;
    assert_eq!(r.status, 502, "{r:?}");
    let start = Instant::now();
    let r = get(c.addr("main"), &t, "/ip", None).await;
    assert_eq!(
        (r.status, r.header("x-proxyx-error")),
        (503, Some("no_parent")),
        "{r:?}"
    );
    assert!(
        start.elapsed() < Duration::from_millis(250),
        "an open breaker answers without connecting"
    );
    let m = c.metrics();
    assert!(
        m.contains("proxyx_edge_parent_breaker_state{parent=\"p\",service=\"proxyx-edge\"} 2"),
        "{m}"
    );
    assert!(m.contains("proxyx_edge_breaker_transitions_total{kind=\"parent\",state=\"open\",service=\"proxyx-edge\"} 1"), "{m}");

    // it comes back on the same address: after the open time one probe request closes the breaker
    let _up2 = parent_edge(&addr.to_string(), "").await;
    tokio::time::sleep(Duration::from_millis(400)).await;
    assert_eq!(get_ip(c.addr("main"), &t, None).await, ip("127.0.0.3"));
    let m = c.metrics();
    assert!(
        m.contains("proxyx_edge_parent_breaker_state{parent=\"p\",service=\"proxyx-edge\"} 0"),
        "{m}"
    );
    assert!(m.contains("proxyx_edge_breaker_transitions_total{kind=\"parent\",state=\"half_open\",service=\"proxyx-edge\"} 1"), "{m}");
    assert!(m.contains("proxyx_edge_breaker_transitions_total{kind=\"parent\",state=\"closed\",service=\"proxyx-edge\"} 1"), "{m}");
}

#[tokio::test]
async fn failover_to_the_next_parent_while_the_first_is_shut_out() {
    let origin = http_origin("127.0.0.1:0").await;
    let good = parent_edge("127.0.0.1:0", "").await;
    let dead: SocketAddr = format!("127.0.0.1:{}", free_port()).parse().unwrap();
    let parents = format!(
        "[[parent]]\nname = \"first\"\ntype = \"http\"\naddress = \"{dead}\"\n[[parent]]\nname = \"second\"\ntype = \"http\"\naddress = \"{}\"\nusername = \"relay\"\npassword = \"relaypw\"\npriority = 1\n",
        good.addr("main")
    );
    let c = Edge::start(&child(
        "[breaker.parent]\nfailure_threshold = 2\n[health]\ninterval = \"0\"\n",
        &parents,
    ))
    .await;
    let t = format!("origin.test:{}", origin.port());
    for _ in 0..5 {
        assert_eq!(get_ip(c.addr("main"), &t, None).await, ip("127.0.0.3"));
    }
    let m = c.metrics();
    // two failures opened the breaker of `first`; after that it was not tried again
    assert!(m.contains("proxyx_edge_parent_requests_total{outcome=\"failed\",parent=\"first\",service=\"proxyx-edge\"} 2"), "{m}");
    assert!(m.contains("proxyx_edge_parent_requests_total{outcome=\"ok\",parent=\"second\",service=\"proxyx-edge\"} 5"), "{m}");
}

#[tokio::test]
async fn active_probes_take_a_parent_out_and_bring_it_back_and_readyz_follows() {
    let banner = banner_origin("127.0.0.1:0").await;
    let port = free_port();
    let addr: SocketAddr = format!("127.0.0.1:{port}").parse().unwrap();
    let up = parent_edge(&addr.to_string(), "").await;
    // the probe opens a tunnel to a target through the parent: it needs the parent AND the path to work
    let c = Edge::start(&child(
        &format!(
            "[health]\ninterval = \"0\"\ntimeout = \"2s\"\nparent_target = \"origin.test:{}\"\nunhealthy_threshold = 2\nhealthy_threshold = 1\n[server]\nops_listen = \"127.0.0.1:0\"\n",
            banner.port()
        )
        .replace("[server]\nops_listen = \"127.0.0.1:0\"\n", ""),
        &http_parent(addr, ""),
    ))
    .await;
    let ops = proxyx_edge::ops::serve(c.server.clone(), "127.0.0.1:0".parse().unwrap())
        .await
        .unwrap();
    probe_round(&c).await;
    let m = c.metrics();
    assert!(m.contains("proxyx_edge_health_checks_total{kind=\"parent\",result=\"ok\",service=\"proxyx-edge\"} 1"), "{m}");
    assert!(
        m.contains("proxyx_edge_parent_healthy{parent=\"p\",service=\"proxyx-edge\"} 1"),
        "{m}"
    );
    let r = via_ops(ops, "/readyz").await;
    assert_eq!(
        (r.status, r.text().contains("ok   egress path")),
        (200, true),
        "{}",
        r.text()
    );

    // the parent goes away: two failed probes in a row mark it unhealthy; the route needs a parent, so not ready
    up.server.shutdown(Duration::from_millis(100)).await;
    drop(up);
    probe_round(&c).await;
    assert_eq!(
        via_ops(ops, "/readyz").await.status,
        200,
        "one failed probe is not enough"
    );
    probe_round(&c).await;
    let r = via_ops(ops, "/readyz").await;
    assert_eq!(r.status, 503, "{}", r.text());
    assert!(r.text().contains("FAIL egress path"), "{}", r.text());
    assert!(
        r.text().contains("ok   listeners bound") && r.text().contains("ok   config loaded"),
        "{}",
        r.text()
    );
    let m = c.metrics();
    assert!(
        m.contains("proxyx_edge_parent_healthy{parent=\"p\",service=\"proxyx-edge\"} 0"),
        "{m}"
    );
    assert!(
        m.contains("proxyx_edge_parent_up{parent=\"p\",service=\"proxyx-edge\"} 0"),
        "{m}"
    );
    assert!(m.contains("proxyx_edge_health_checks_total{kind=\"parent\",result=\"failed\",service=\"proxyx-edge\"} 2"), "{m}");
    // liveness does not depend on any of it
    assert_eq!(via_ops(ops, "/healthz").await.status, 200);

    // it returns: one good probe is enough
    let _up2 = parent_edge(&addr.to_string(), "").await;
    probe_round(&c).await;
    assert_eq!(via_ops(ops, "/readyz").await.status, 200);
}

#[tokio::test]
async fn a_probe_through_the_parent_fails_when_the_parent_cannot_reach_the_target() {
    let up = parent_edge("127.0.0.1:0", "").await;
    let dead_target = free_port();
    let c = Edge::start(&child(
        &format!("[health]\ninterval = \"0\"\ntimeout = \"2s\"\nparent_target = \"origin.test:{dead_target}\"\nunhealthy_threshold = 1\n"),
        &http_parent(up.addr("main"), ""),
    ))
    .await;
    probe_round(&c).await;
    let m = c.metrics();
    assert!(
        m.contains("proxyx_edge_parent_healthy{parent=\"p\",service=\"proxyx-edge\"} 0"),
        "{m}"
    );
    // without a target the probe only needs the TCP connection to the parent
    let c = Edge::start(&child(
        "[health]\ninterval = \"0\"\nunhealthy_threshold = 1\n",
        &http_parent(up.addr("main"), ""),
    ))
    .await;
    probe_round(&c).await;
    assert!(
        c.metrics()
            .contains("proxyx_edge_parent_healthy{parent=\"p\",service=\"proxyx-edge\"} 1")
    );
}

#[tokio::test]
async fn the_background_checker_runs_by_itself() {
    let dead: SocketAddr = format!("127.0.0.1:{}", free_port()).parse().unwrap();
    let c = Edge::start(&child(
        "[health]\ninterval = \"100ms\"\ntimeout = \"1s\"\nunhealthy_threshold = 2\n",
        &format!("[[parent]]\nname = \"p\"\ntype = \"http\"\naddress = \"{dead}\"\n"),
    ))
    .await;
    let end = Instant::now() + Duration::from_secs(5);
    loop {
        if c.metrics()
            .contains("proxyx_edge_parent_healthy{parent=\"p\",service=\"proxyx-edge\"} 0")
        {
            break;
        }
        assert!(
            Instant::now() < end,
            "the checker never marked the dead parent: {}",
            c.metrics()
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert!(!c.server.readiness().is_ready());
}

#[tokio::test]
async fn readiness_reports_each_condition() {
    let e = Edge::start(&format!("{OPEN}\n")).await;
    let r = e.server.readiness();
    assert!(r.is_ready(), "{}", r.report());
    assert_eq!(r.report().lines().count(), 4);
    e.server.shutdown(Duration::from_millis(50)).await;
    let r = e.server.readiness();
    assert!(
        !r.is_ready() && r.report().contains("FAIL running"),
        "{}",
        r.report()
    );
}

#[tokio::test]
async fn parent_connections_are_reused_for_bodyless_requests() {
    let origin = http_origin("127.0.0.1:0").await;
    let up = parent_edge("127.0.0.1:0", "").await;
    let c = Edge::start(&child(
        "[health]\ninterval = \"0\"\n",
        &http_parent(up.addr("main"), ""),
    ))
    .await;
    let t = format!("origin.test:{}", origin.port());
    for _ in 0..4 {
        assert_eq!(get_ip(c.addr("main"), &t, None).await, ip("127.0.0.3"));
    }
    // four requests, one connection to the parent
    let pm = up.metrics();
    assert!(pm.contains("proxyx_edge_connections_total{listener=\"main\",outcome=\"accepted\",service=\"proxyx-edge\"} 1"), "{pm}");
    let m = c.metrics();
    assert!(
        m.contains(
            "proxyx_edge_parent_conn_reuse_total{outcome=\"reused\",service=\"proxyx-edge\"} 3"
        ),
        "{m}"
    );
    assert!(
        m.contains(
            "proxyx_edge_parent_conn_reuse_total{outcome=\"new\",service=\"proxyx-edge\"} 1"
        ),
        "{m}"
    );

    // a request with a body does not use (or leave) an idle connection
    let r = via_proxy(
        c.addr("main"),
        &format!("POST http://{t}/echo HTTP/1.1\r\nHost: {t}\r\nContent-Length: 2\r\nConnection: close\r\n\r\nhi"),
    )
    .await;
    assert_eq!((r.status, r.text().as_str()), (200, "hi"));

    // keep-alive off: every request opens a connection
    let c2 = Edge::start(&child(
        "[http]\nparent_keepalive = false\n[health]\ninterval = \"0\"\n",
        &http_parent(up.addr("main"), ""),
    ))
    .await;
    let before = up.metrics();
    let n = |m: &str| {
        m.lines()
            .find(|l| {
                l.starts_with(
                    "proxyx_edge_connections_total{listener=\"main\",outcome=\"accepted\"",
                )
            })
            .and_then(|l| l.rsplit(' ').next())
            .and_then(|v| v.parse::<u32>().ok())
            .unwrap()
    };
    for _ in 0..3 {
        get_ip(c2.addr("main"), &t, None).await;
    }
    assert_eq!(n(&up.metrics()) - n(&before), 3);
}

#[tokio::test]
async fn a_parent_connection_closed_while_idle_is_not_reused() {
    let origin = http_origin("127.0.0.1:0").await;
    let up = parent_edge("127.0.0.1:0", "[timeouts]\nkeepalive = \"1s\"\n").await;
    let c = Edge::start(&child(
        "[health]\ninterval = \"0\"\n",
        &http_parent(up.addr("main"), ""),
    ))
    .await;
    let t = format!("origin.test:{}", origin.port());
    assert_eq!(get_ip(c.addr("main"), &t, None).await, ip("127.0.0.3"));
    tokio::time::sleep(Duration::from_millis(1600)).await; // the parent closed its idle connection
    assert_eq!(
        get_ip(c.addr("main"), &t, None).await,
        ip("127.0.0.3"),
        "no 502 from a stale connection"
    );
    let m = c.metrics();
    assert!(
        m.contains(
            "proxyx_edge_parent_conn_reuse_total{outcome=\"new\",service=\"proxyx-edge\"} 2"
        ),
        "{m}"
    );
}

#[tokio::test]
async fn a_client_connection_closes_after_max_requests() {
    let origin = http_origin("127.0.0.1:0").await;
    let e = Edge::start(&format!("{OPEN}\n[http]\nclient_max_requests = 2\n")).await;
    let t = format!("origin.test:{}", origin.port());
    let mut s = TcpStream::connect(e.addr("main")).await.unwrap();
    let req = format!("GET http://{t}/ip HTTP/1.1\r\nHost: {t}\r\n\r\n");
    s.write_all(req.as_bytes()).await.unwrap();
    let r = read_response(&mut s, false).await;
    assert_eq!(
        r.header("connection"),
        None,
        "the first answer keeps the connection"
    );
    s.write_all(req.as_bytes()).await.unwrap();
    let r = read_response(&mut s, false).await;
    assert_eq!(
        (r.status, r.header("connection")),
        (200, Some("close")),
        "the second is the last"
    );
    let mut rest = Vec::new();
    let n = tokio::time::timeout(Duration::from_secs(2), s.read_to_end(&mut rest))
        .await
        .expect("closed")
        .unwrap();
    assert_eq!(n, 0);
}

#[tokio::test]
async fn an_idle_keepalive_connection_is_closed_after_the_keepalive_timeout() {
    let origin = http_origin("127.0.0.1:0").await;
    let e = Edge::start(&format!("{OPEN}\n[timeouts]\nkeepalive = \"1s\"\n")).await;
    let t = format!("origin.test:{}", origin.port());
    let mut s = TcpStream::connect(e.addr("main")).await.unwrap();
    s.write_all(format!("GET http://{t}/ip HTTP/1.1\r\nHost: {t}\r\n\r\n").as_bytes())
        .await
        .unwrap();
    assert_eq!(read_response(&mut s, false).await.status, 200);
    let start = Instant::now();
    let mut buf = [0u8; 4];
    let n = tokio::time::timeout(Duration::from_secs(5), s.read(&mut buf))
        .await
        .expect("closed")
        .unwrap_or(0);
    assert_eq!(n, 0);
    assert!(
        start.elapsed() >= Duration::from_millis(800) && start.elapsed() < Duration::from_secs(3)
    );
}

#[tokio::test]
async fn the_total_timeout_ends_a_busy_tunnel() {
    let banner = banner_origin("127.0.0.1:0").await;
    let e = Edge::start(&format!(
        "{OPEN}\n[timeouts]\ntotal = \"1s\"\nidle = \"30s\"\n"
    ))
    .await;
    let mut s = tunnel(
        e.addr("main"),
        &format!("origin.test:{}", banner.port()),
        None,
    )
    .await
    .unwrap();
    let _ = read_line(&mut s).await;
    let start = Instant::now();
    let (mut rd, mut wr) = s.split();
    let writer = async {
        // traffic never stops, so only the total limit can end the tunnel
        while wr.write_all(b"ping\n").await.is_ok() {
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    };
    let reader = async {
        let mut b = [0u8; 256];
        while rd.read(&mut b).await.is_ok_and(|n| n > 0) {}
    };
    tokio::time::timeout(Duration::from_secs(6), async {
        tokio::join!(writer, reader)
    })
    .await
    .expect("closed by the total limit");
    let took = start.elapsed();
    assert!(
        took >= Duration::from_millis(900) && took < Duration::from_secs(4),
        "{took:?}"
    );
}

#[tokio::test]
async fn the_total_timeout_also_bounds_a_plain_http_request() {
    // an origin that answers only after 3 s
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = l.local_addr().unwrap().port();
    tokio::spawn(async move {
        loop {
            let Ok((mut s, _)) = l.accept().await else {
                return;
            };
            tokio::spawn(async move {
                let mut b = [0u8; 4096];
                let _ = s.read(&mut b).await;
                tokio::time::sleep(Duration::from_secs(3)).await;
                let _ = s
                    .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
                    .await;
            });
        }
    });
    let e = Edge::start(&format!("{OPEN}\n[timeouts]\ntotal = \"1s\"\n")).await;
    let start = Instant::now();
    let mut s = TcpStream::connect(e.addr("main")).await.unwrap();
    let t = format!("origin.test:{port}");
    s.write_all(
        format!("GET http://{t}/ HTTP/1.1\r\nHost: {t}\r\nConnection: close\r\n\r\n").as_bytes(),
    )
    .await
    .unwrap();
    let mut out = Vec::new();
    let _ = tokio::time::timeout(Duration::from_secs(5), s.read_to_end(&mut out))
        .await
        .expect("closed");
    assert!(
        start.elapsed() < Duration::from_millis(2500),
        "{:?}",
        start.elapsed()
    );
    let wire = String::from_utf8_lossy(&out);
    assert!(
        wire.starts_with("HTTP/1.1 504 Gateway Timeout\r\n"),
        "{wire}"
    );
    assert!(wire.contains("X-ProxyX-Error: timeout\r\n"), "{wire}");
}

#[tokio::test]
async fn a_total_timeout_never_appends_an_error_to_a_started_response() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let target = format!("origin.test:{}", listener.local_addr().unwrap().port());
    tokio::spawn(async move {
        let (mut upstream, _) = listener.accept().await.unwrap();
        let mut request = [0; 4096];
        assert!(upstream.read(&mut request).await.unwrap() > 0);
        upstream
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 1000\r\n\r\npartial")
            .await
            .unwrap();
        tokio::time::sleep(Duration::from_secs(3)).await;
    });
    let edge = Edge::start(&format!("{OPEN}\n[timeouts]\ntotal = \"200ms\"\n")).await;
    let mut client = TcpStream::connect(edge.addr("main")).await.unwrap();
    client
        .write_all(
            format!("GET http://{target}/ HTTP/1.1\r\nHost: {target}\r\nConnection: close\r\n\r\n")
                .as_bytes(),
        )
        .await
        .unwrap();
    let mut wire = Vec::new();
    tokio::time::timeout(Duration::from_secs(3), client.read_to_end(&mut wire))
        .await
        .unwrap()
        .unwrap();
    let wire = String::from_utf8_lossy(&wire);
    assert!(wire.starts_with("HTTP/1.1 200 OK\r\n"), "{wire}");
    assert!(wire.ends_with("partial"), "{wire}");
    assert!(!wire.contains("504"), "{wire}");
}

#[tokio::test]
async fn a_silent_origin_gets_a_504_after_the_response_header_timeout() {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = l.local_addr().unwrap().port();
    tokio::spawn(async move {
        let mut held = Vec::new();
        loop {
            let Ok((s, _)) = l.accept().await else { return };
            held.push(s);
        }
    });
    let e = Edge::start(&format!("{OPEN}\n[timeouts]\nresponse_header = \"1s\"\n")).await;
    let start = Instant::now();
    let r = get(e.addr("main"), &format!("origin.test:{port}"), "/", None).await;
    assert_eq!(r.status, 504, "{r:?}");
    assert!(
        start.elapsed() >= Duration::from_millis(900) && start.elapsed() < Duration::from_secs(4)
    );
}

#[tokio::test]
async fn connect_timeout_is_configurable() {
    // 203.0.113.1 (TEST-NET-3) is routed nowhere: the connect hangs or fails; either way it is bounded by connect
    let e = Edge::start("[[listener]]\nname = \"main\"\nlisten = \"127.0.0.1:0\"\nauth = \"none\"\n[[rule]]\naction = \"allow\"\nallow_internal = true\n[timeouts]\nconnect = \"1s\"\n")
    .await;
    let start = Instant::now();
    let r = get(e.addr("main"), "203.0.113.1:81", "/", None).await;
    assert!(r.status == 504 || r.status == 502, "{r:?}");
    assert!(
        start.elapsed() < Duration::from_secs(4),
        "{:?}",
        start.elapsed()
    );
}

#[tokio::test]
async fn invalid_resilience_settings_are_refused_at_check_time() {
    let dir = std::env::temp_dir().join(format!("edge-it-res-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("edge.toml");
    for bad in [
        "[breaker.parent]\nfailure_threshold = 0\n",
        "[breaker.egress]\nopen_duration = \"0\"\n",
        "[breaker.egress]\nhalf_open_probes = 0\n",
        "[tcp.client]\nkeepalive_retries = 0\n",
        "[tcp.upstream]\nkeepalive_time = \"0\"\n",
        "[timeouts]\nconnect = \"0\"\n",
        "[health]\nparent_target = \"nohostport\"\n",
        "[health]\nunhealthy_threshold = 0\n",
        "[health]\ninterval = \"5s\"\ntimeout = \"0\"\n",
        "[[pool]]\nname = \"p\"\naddresses = [\"127.0.0.2\"]\nquarantine = \"5s\"\n",
    ] {
        std::fs::write(&path, format!("{OPEN}\n{bad}")).unwrap();
        assert!(proxyx_edge::check(&path).is_err(), "{bad}");
    }
    // zero is allowed where it means "no limit" and where the check is off
    std::fs::write(&path, format!("{OPEN}\n[timeouts]\ntotal = \"0\"\n[health]\ninterval = \"0\"\ntimeout = \"0\"\n[http]\nclient_max_requests = 0\n[tcp.client]\nkeepalive = false\nkeepalive_time = \"0\"\n")).unwrap();
    proxyx_edge::check(&path).unwrap();
    let _ = std::fs::remove_dir_all(&dir);
}
