//! Authentication, access rules, destination denial, limits, header policy
//! and HTTP message handling, end to end.
#![allow(clippy::unwrap_used)]

mod common;

use std::time::{Duration, Instant};

use common::*;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

const USERS: &str = r#"
[[listener]]
name = "main"
listen = "127.0.0.1:0"
[[user]]
name = "alice"
password = "pw"
groups = ["staff"]
[[user]]
name = "guest"
password = "pw"
"#;

fn allow_all() -> &'static str {
    "[[rule]]\naction = \"allow\"\nallow_internal = true\n"
}

#[tokio::test]
async fn proxy_authentication_challenges_checks_and_blocks_a_guessing_source() {
    let origin = http_origin("127.0.0.1:0").await;
    let edge = Edge::start(&format!(
        "{USERS}\n{}\n[auth]\nfail_limit = 3\n",
        allow_all()
    ))
    .await;
    let target = format!("origin.test:{}", origin.port());
    let l = edge.addr("main");

    let r = get(l, &target, "/ip", None).await;
    assert_eq!(r.status, 407);
    assert_eq!(
        r.header("proxy-authenticate"),
        Some("Basic realm=\"proxyx\"")
    );
    assert_eq!(r.header("x-proxyx-error"), Some("auth_required"));
    assert_eq!(
        get(l, &target, "/ip", Some(("alice", "wrong")))
            .await
            .status,
        407
    );
    assert_eq!(
        get(l, &target, "/ip", Some(("nobody", "pw"))).await.status,
        407
    );
    assert_eq!(
        get(l, &target, "/ip", Some(("alice", "pw"))).await.status,
        200
    );

    // CONNECT and SOCKS5 use the same users
    assert_eq!(tunnel(l, &target, None).await.err(), Some(407));
    assert_eq!(
        tunnel(l, &target, Some(("alice", "bad"))).await.err(),
        Some(407)
    );
    // 3 wrong logins so far from this source: the limit refuses even a right one
    let r = get(l, &target, "/ip", Some(("alice", "pw"))).await;
    assert_eq!(r.status, 429, "{r:?}");
    assert_eq!(r.header("x-proxyx-error"), Some("auth_blocked"));
    let m = edge.metrics();
    assert!(m.contains("proxyx_edge_auth_failures_total{listener=\"main\",reason=\"invalid\",service=\"proxyx-edge\"} 3"), "{m}");
    assert!(m.contains("reason=\"blocked\""), "{m}");
}

#[tokio::test]
async fn a_407_keeps_the_connection_so_the_client_can_retry_with_credentials() {
    let origin = http_origin("127.0.0.1:0").await;
    let edge = Edge::start(&format!("{USERS}\n{}\n", allow_all())).await;
    let target = format!("origin.test:{}", origin.port());
    let mut s = TcpStream::connect(edge.addr("main")).await.unwrap();
    s.write_all(format!("GET http://{target}/ip HTTP/1.1\r\nHost: {target}\r\n\r\n").as_bytes())
        .await
        .unwrap();
    assert_eq!(read_response(&mut s, false).await.status, 407);
    let a = basic("alice", "pw");
    s.write_all(format!("GET http://{target}/ip HTTP/1.1\r\nHost: {target}\r\n{a}\r\n").as_bytes())
        .await
        .unwrap();
    let r = read_response(&mut s, false).await;
    assert_eq!((r.status, r.text().as_str()), (200, "127.0.0.1"));
    // and a third request on the same connection still works (client keep-alive)
    s.write_all(format!("GET http://{target}/ip HTTP/1.1\r\nHost: {target}\r\n{a}\r\n").as_bytes())
        .await
        .unwrap();
    assert_eq!(read_response(&mut s, false).await.status, 200);
}

#[tokio::test]
async fn htpasswd_files_with_bcrypt_and_sha_hashes_log_users_in() {
    let origin = http_origin("127.0.0.1:0").await;
    let dir = std::env::temp_dir().join(format!("edge-it-htpasswd-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let file = dir.join("users");
    let bcrypt = pwhash::bcrypt::hash_with(
        pwhash::bcrypt::BcryptSetup {
            cost: Some(4),
            ..Default::default()
        },
        "s3cret",
    )
    .unwrap();
    // {SHA} of "legacy"
    let sha = "{SHA}mzMEbtOdGC462vqQRa1nh9S7wyE=";
    std::fs::write(&file, format!("# comment\nbob:{bcrypt}\ncarol:{sha}\n")).unwrap();
    let edge = Edge::start(&format!(
        "[[listener]]\nname = \"main\"\nlisten = \"127.0.0.1:0\"\n[auth]\nusers_file = \"{}\"\n{}\n",
        file.display(),
        allow_all()
    ))
    .await;
    let target = format!("origin.test:{}", origin.port());
    let l = edge.addr("main");
    assert_eq!(
        get(l, &target, "/ip", Some(("bob", "s3cret"))).await.status,
        200
    );
    assert_eq!(
        get(l, &target, "/ip", Some(("bob", "S3cret"))).await.status,
        407
    );
    assert_eq!(
        get(l, &target, "/ip", Some(("carol", "legacy")))
            .await
            .status,
        200
    );
    assert_eq!(
        get(l, &target, "/ip", Some(("carol", "nope"))).await.status,
        407
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn access_rules_decide_in_order_and_default_to_deny() {
    let origin = http_origin("127.0.0.1:0").await;
    let port = origin.port();
    let edge = Edge::start(&format!(
        r#"
{USERS}
[[rule]]
name = "no-bad-domain"
action = "deny"
when = {{ domain = [".bad.test"] }}
[[rule]]
name = "no-post-for-guests"
action = "deny"
when = {{ method = ["POST"], user = ["guest"] }}
[[rule]]
name = "staff-anywhere"
action = "allow"
allow_internal = true
when = {{ group = ["staff"] }}
[[rule]]
name = "guests-web-only"
action = "allow"
allow_internal = true
when = {{ user = ["guest"], port = ["{port}"], protocol = ["http"] }}
"#
    ))
    .await;
    let l = edge.addr("main");
    let t = format!("origin.test:{port}");
    let code = |r: &Resp| (r.status, r.header("x-proxyx-error").map(str::to_owned));
    assert_eq!(get(l, &t, "/ip", Some(("alice", "pw"))).await.status, 200);
    assert_eq!(get(l, &t, "/ip", Some(("guest", "pw"))).await.status, 200);
    // an explicit deny comes first, even for staff
    let r = get(
        l,
        &format!("x.bad.test:{port}"),
        "/ip",
        Some(("alice", "pw")),
    )
    .await;
    assert_eq!(code(&r), (403, Some("forbidden".into())));
    // POST is denied for guests only
    let post = |u: &str| {
        let a = basic(u, "pw");
        format!(
            "POST http://{t}/echo HTTP/1.1\r\nHost: {t}\r\n{a}Content-Length: 2\r\nConnection: close\r\n\r\nhi"
        )
    };
    assert_eq!(via_proxy(l, &post("guest")).await.status, 403);
    assert_eq!(via_proxy(l, &post("alice")).await.status, 200);
    // guests have no CONNECT (protocol rule) and no other port
    assert_eq!(tunnel(l, &t, Some(("guest", "pw"))).await.err(), Some(403));
    assert!(tunnel(l, &t, Some(("alice", "pw"))).await.is_ok());
    assert_eq!(
        get(l, "origin.test:81", "/ip", Some(("guest", "pw")))
            .await
            .status,
        403
    );
    let m = edge.metrics();
    assert!(
        m.contains("proxyx_edge_acl_decisions_total{action=\"deny\",service=\"proxyx-edge\"}"),
        "{m}"
    );
}

#[tokio::test]
async fn time_windows_gate_a_rule() {
    let origin = http_origin("127.0.0.1:0").await;
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let days = ["thu", "fri", "sat", "sun", "mon", "tue", "wed"];
    let today = days[((now / 86_400) % 7) as usize];
    let tomorrow = days[((now / 86_400 + 1) % 7) as usize];
    let edge = Edge::start(&format!(
        r#"
[[listener]]
name = "main"
listen = "127.0.0.1:0"
auth = "none"
[[rule]]
action = "allow"
allow_internal = true
when = {{ time = [{{ days = ["{tomorrow}"] }}], port = ["1"] }}
[[rule]]
action = "allow"
allow_internal = true
when = {{ time = [{{ days = ["{today}"] }}] }}
"#
    ))
    .await;
    // the first rule's window is tomorrow (never matches today), the second is today
    assert_eq!(
        get(
            edge.addr("main"),
            &format!("origin.test:{}", origin.port()),
            "/ip",
            None
        )
        .await
        .status,
        200
    );
    edge.rewrite(&format!(
        "[[listener]]\nname = \"main\"\nlisten = \"127.0.0.1:0\"\nauth = \"none\"\n[[rule]]\naction = \"allow\"\nallow_internal = true\nwhen = {{ time = [{{ days = [\"{tomorrow}\"] }}] }}\n"
    ));
    edge.server.reload().await.unwrap();
    assert_eq!(
        get(
            edge.addr("main"),
            &format!("origin.test:{}", origin.port()),
            "/ip",
            None
        )
        .await
        .status,
        403
    );
}

#[tokio::test]
async fn src_and_dst_conditions_use_the_client_and_the_resolved_address() {
    let origin = http_origin("127.0.0.1:0").await;
    let edge = Edge::start(&String::from(
        r#"
[[listener]]
name = "main"
listen = "127.0.0.1:0"
auth = "none"
[[rule]]
action = "deny"
when = { dst = ["127.0.0.0/8"], src = ["10.0.0.0/8"] }
[[rule]]
action = "deny"
when = { src = ["203.0.113.0/24"] }
[[rule]]
action = "allow"
allow_internal = true
when = { src = ["127.0.0.1"], dst = ["127.0.0.1"] }
"#,
    ))
    .await;
    // origin.test resolves to 127.0.0.1; the client is 127.0.0.1: only the last rule fits
    assert_eq!(
        get(
            edge.addr("main"),
            &format!("origin.test:{}", origin.port()),
            "/ip",
            None
        )
        .await
        .status,
        200
    );
    edge.rewrite(&String::from(
        "[[listener]]\nname = \"main\"\nlisten = \"127.0.0.1:0\"\nauth = \"none\"\n[[rule]]\naction = \"deny\"\nwhen = { dst = [\"127.0.0.0/8\"] }\n[[rule]]\naction = \"allow\"\nallow_internal = true\n"
    ));
    edge.server.reload().await.unwrap();
    assert_eq!(
        get(
            edge.addr("main"),
            &format!("origin.test:{}", origin.port()),
            "/ip",
            None
        )
        .await
        .status,
        403
    );
}

#[tokio::test]
async fn private_and_internal_destinations_stay_denied_unless_a_rule_opts_out() {
    let origin = http_origin("127.0.0.1:0").await;
    let port = origin.port();
    let edge = Edge::start("[[listener]]\nname = \"main\"\nlisten = \"127.0.0.1:0\"\nauth = \"none\"\n[[rule]]\naction = \"allow\"\n").await;
    let l = edge.addr("main");
    for target in [
        format!("127.0.0.1:{port}"),
        format!("origin.test:{port}"), // a name that resolves to loopback
        "169.254.169.254:80".to_owned(),
        "10.1.2.3:80".to_owned(),
        "localhost:80".to_owned(),
        "db.internal:5432".to_owned(),
        "[::1]:80".to_owned(),
        "[fd00:ec2::254]:80".to_owned(),
    ] {
        let r = get(l, &target, "/ip", None).await;
        assert_eq!(
            (r.status, r.header("x-proxyx-error")),
            (403, Some("destination_denied")),
            "{target}: {r:?}"
        );
        assert_eq!(tunnel(l, &target, None).await.err(), Some(403), "{target}");
    }
    assert!(
        edge.metrics()
            .contains("proxyx_edge_destination_denied_total")
    );
    // the opt-out is per rule: only the rule for the internal network lets it through
    edge.rewrite(&String::from(
        "[[listener]]\nname = \"main\"\nlisten = \"127.0.0.1:0\"\nauth = \"none\"\n[[rule]]\naction = \"allow\"\nallow_internal = true\nwhen = { domain = [\"origin.test\"] }\n[[rule]]\naction = \"allow\"\n"
    ));
    edge.server.reload().await.unwrap();
    assert_eq!(
        get(l, &format!("origin.test:{port}"), "/ip", None)
            .await
            .status,
        200
    );
    assert_eq!(
        get(l, &format!("127.0.0.1:{port}"), "/ip", None)
            .await
            .status,
        403
    );
}

#[tokio::test]
async fn bad_requests_are_refused() {
    let edge = Edge::start(&format!("{OPEN}\n")).await;
    let l = edge.addr("main");
    // a request for the proxy itself
    assert_eq!(
        via_proxy(l, "GET /ip HTTP/1.1\r\nHost: x\r\n\r\n")
            .await
            .status,
        400
    );
    // https:// in absolute form needs CONNECT
    assert_eq!(
        via_proxy(l, "GET https://example.com/ HTTP/1.1\r\nHost: x\r\n\r\n")
            .await
            .status,
        400
    );
    // userinfo in the URL
    assert_eq!(
        via_proxy(l, "GET http://u:p@example.com/ HTTP/1.1\r\nHost: x\r\n\r\n")
            .await
            .status,
        400
    );
    // request smuggling shapes
    assert_eq!(
        via_proxy(l, "POST http://example.com/ HTTP/1.1\r\nHost: x\r\nContent-Length: 4\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n").await.status,
        400
    );
    assert_eq!(
        via_proxy(l, "POST http://example.com/ HTTP/1.1\r\nHost: x\r\nContent-Length: 4\r\nContent-Length: 5\r\n\r\n").await.status,
        400
    );
    // garbage and a CONNECT without a port
    let mut s = TcpStream::connect(l).await.unwrap();
    s.write_all(b"\x16\x03\x01garbage\r\n\r\n").await.unwrap();
    let mut out = Vec::new();
    let _ = tokio::time::timeout(Duration::from_secs(2), s.read_to_end(&mut out)).await;
    assert!(
        String::from_utf8_lossy(&out).starts_with("HTTP/1.1 400"),
        "{out:?}"
    );
    assert_eq!(tunnel(l, "example.com", None).await.err(), Some(400));
    // a head over the limit
    let big = format!(
        "GET http://example.com/ HTTP/1.1\r\nX: {}\r\n\r\n",
        "a".repeat(40_000)
    );
    assert_eq!(via_proxy(l, &big).await.status, 431);
}

#[tokio::test]
async fn unsafe_connection_options_fail_before_authentication_or_dial() {
    let origin = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let target = origin.local_addr().unwrap();
    let edge = Edge::start(&format!("{USERS}\n{}\n", allow_all())).await;
    for options in [
        "Connection: keep-alive\r\ncOnNeCtIoN: CoNtEnT-LeNgTh\r\n",
        "Connection: TRANSFER-ENCODING\r\n",
        "Connection: Host\r\n",
        "Connection: tE\r\n",
        "Connection: Trailer\r\n",
        "Connection: Proxy-Authorization\r\n",
        "Connection: PROXY-CONNECTION\r\n",
        "Connection: pRoXy-Custom\r\n",
        "Connection: keep-alive\r\nCONNECTION: UpGrAdE\r\n",
    ] {
        let request = format!("GET http://{target}/ HTTP/1.1\r\nHost: {target}\r\n{options}\r\n");
        let response = via_proxy(edge.addr("main"), &request).await;
        assert_eq!(response.status, 400, "{options:?}");
        assert_eq!(response.header("x-proxyx-error"), Some("bad_request"));
        assert_eq!(response.header("connection"), Some("close"));
    }
    assert!(
        tokio::time::timeout(Duration::from_millis(100), origin.accept())
            .await
            .is_err(),
        "invalid Connection options must not reach the origin"
    );
}

#[tokio::test]
async fn upgrade_content_length_smuggling_is_rejected_before_origin_connection() {
    let origin = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let target = origin.local_addr().unwrap();
    let edge = Edge::start(
        r#"
[[listener]]
name = "main"
listen = "127.0.0.1:0"
auth = "none"
[[rule]]
action = "deny"
when = { method = ["POST"] }
[[rule]]
action = "allow"
allow_internal = true
"#,
    )
    .await;
    let forbidden =
        format!("POST /forbidden HTTP/1.1\r\nHost: {target}\r\nContent-Length: 0\r\n\r\n");
    let direct_post = format!(
        "POST http://{target}/forbidden HTTP/1.1\r\nHost: {target}\r\nContent-Length: 0\r\n\r\n"
    );
    assert_eq!(via_proxy(edge.addr("main"), &direct_post).await.status, 403);
    let smuggling = format!(
        "GET http://{target}/ HTTP/1.1\r\nHost: {target}\r\nConnection: upgrade,content-length\r\nUpgrade: unsupported\r\nContent-Length: {}\r\n\r\n{forbidden}",
        forbidden.len()
    );
    let response = via_proxy(edge.addr("main"), &smuggling).await;
    assert_eq!(response.status, 400);
    assert_eq!(response.header("x-proxyx-error"), Some("bad_request"));
    assert_eq!(response.header("connection"), Some("close"));
    assert!(
        tokio::time::timeout(Duration::from_millis(100), origin.accept())
            .await
            .is_err(),
        "the smuggling request must not open an origin connection"
    );
}

#[tokio::test]
async fn http_bodies_keepalive_and_framing_pass_through() {
    let origin = http_origin("127.0.0.1:0").await;
    let edge = Edge::start(&format!("{OPEN}\n")).await;
    let t = format!("origin.test:{}", origin.port());
    let mut s = TcpStream::connect(edge.addr("main")).await.unwrap();

    // fixed-length request body, then a chunked response, on one client connection
    s.write_all(
        format!(
            "POST http://{t}/echo HTTP/1.1\r\nHost: {t}\r\nContent-Length: 11\r\n\r\nhello world"
        )
        .as_bytes(),
    )
    .await
    .unwrap();
    let r = read_response(&mut s, false).await;
    assert_eq!((r.status, r.text().as_str()), (200, "hello world"));
    s.write_all(format!("GET http://{t}/chunked HTTP/1.1\r\nHost: {t}\r\n\r\n").as_bytes())
        .await
        .unwrap();
    let r = read_response(&mut s, false).await;
    assert_eq!((r.status, r.text().as_str()), (200, "helloworld"));
    assert_eq!(r.header("transfer-encoding"), Some("chunked"));
    // chunked request body
    s.write_all(format!("POST http://{t}/echo HTTP/1.1\r\nHost: {t}\r\nTransfer-Encoding: chunked\r\n\r\n4\r\nwiki\r\n5\r\npedia\r\n0\r\n\r\n").as_bytes()).await.unwrap();
    let r = read_response(&mut s, false).await;
    assert_eq!(r.text(), "wikipedia");
    // HEAD has no body and keeps the connection
    s.write_all(format!("HEAD http://{t}/ip HTTP/1.1\r\nHost: {t}\r\n\r\n").as_bytes())
        .await
        .unwrap();
    let r = read_response(&mut s, true).await;
    assert_eq!(r.status, 200);
    // a large body, byte exact
    s.write_all(format!("GET http://{t}/big?n=300000 HTTP/1.1\r\nHost: {t}\r\n\r\n").as_bytes())
        .await
        .unwrap();
    let r = read_response(&mut s, false).await;
    assert_eq!(r.body.len(), 300_000);
    // the connection is still usable
    s.write_all(
        format!("GET http://{t}/ip HTTP/1.1\r\nHost: {t}\r\nConnection: close\r\n\r\n").as_bytes(),
    )
    .await
    .unwrap();
    let r = read_response(&mut s, false).await;
    assert_eq!(r.status, 200);
    assert_eq!(r.header("connection"), Some("close"));
}

#[tokio::test]
async fn expect_continue_and_upgrade_work_through_the_proxy() {
    let origin = http_origin("127.0.0.1:0").await;
    let edge = Edge::start(&format!("{OPEN}\n")).await;
    let t = format!("origin.test:{}", origin.port());
    // Expect: 100-continue: the client waits for 100 before it sends the body
    let mut s = TcpStream::connect(edge.addr("main")).await.unwrap();
    s.write_all(format!("POST http://{t}/continue HTTP/1.1\r\nHost: {t}\r\nContent-Length: 5\r\nExpect: 100-continue\r\n\r\n").as_bytes()).await.unwrap();
    let mut got = Vec::new();
    while !got.ends_with(b"\r\n\r\n") {
        let mut b = [0u8; 1];
        assert_eq!(s.read(&mut b).await.unwrap(), 1);
        got.push(b[0]);
    }
    // the origin does not send 100 itself: it reads the body first. Send it anyway.
    let _ = got;
    s.write_all(b"12345").await.unwrap();
    let r = read_response(&mut s, false).await;
    assert_eq!(r.text(), "got 5");

    // Upgrade: 101 then raw bytes both ways
    let mut s = TcpStream::connect(edge.addr("main")).await.unwrap();
    s.write_all(format!("GET http://{t}/upgrade HTTP/1.1\r\nHost: {t}\r\nConnection: Upgrade\r\nUpgrade: echo\r\n\r\n").as_bytes()).await.unwrap();
    let r = read_response(&mut s, false).await;
    assert_eq!(r.status, 101);
    assert_eq!(r.header("upgrade"), Some("echo"));
    s.write_all(b"frame-1").await.unwrap();
    let mut b = [0u8; 7];
    s.read_exact(&mut b).await.unwrap();
    assert_eq!(&b, b"frame-1");
}

#[tokio::test]
async fn header_policy_hides_the_client_and_applies_operator_edits() {
    let origin = http_origin("127.0.0.1:0").await;
    let t = format!("origin.test:{}", origin.port());
    let send = |extra: &'static str| {
        let t = t.clone();
        move || {
            format!(
                "GET http://{t}/headers HTTP/1.1\r\nHost: {t}\r\nProxy-Authorization: Basic YTpi\r\nX-Forwarded-For: 9.9.9.9\r\nVia: 1.0 someone\r\nProxy-Connection: keep-alive\r\nConnection: keep-alive, X-Hop\r\nX-Hop: 1\r\nUser-Agent: Mozilla\r\nReferer: http://r/\r\n{extra}\r\n"
            )
        }
    };
    let edge = Edge::start(&format!("{OPEN}\n")).await;
    let r = via_proxy(edge.addr("main"), &send("")()).await;
    let h = r.text().to_ascii_lowercase();
    for gone in [
        "x-forwarded-for",
        "proxy-authorization",
        "proxy-connection",
        "x-hop",
        "keep-alive",
    ] {
        assert!(!h.contains(gone), "{gone} leaked:\n{h}");
    }
    assert!(
        h.contains("via: 1.0 someone"),
        "client's own Via is not ours to drop:\n{h}"
    );
    assert!(h.contains("connection: close"), "{h}");
    assert!(
        h.contains(&format!("host: {}", t.to_ascii_lowercase())),
        "{h}"
    );

    edge.rewrite(&format!(
        "{OPEN}\n[http]\nforwarded_for = \"on\"\nvia = true\nproxy_name = \"edge1\"\nrequest_headers_remove = [\"Referer\"]\n[http.request_headers_set]\n\"User-Agent\" = \"probe/1\"\n[http.response_headers_set]\n\"X-Served-By\" = \"edge\"\n"
    ));
    edge.server.reload().await.unwrap();
    let r = via_proxy(edge.addr("main"), &send("")()).await;
    let h = r.text().to_ascii_lowercase();
    assert!(h.contains("x-forwarded-for: 9.9.9.9, 127.0.0.1"), "{h}");
    assert!(h.contains("via: 1.0 someone, 1.1 edge1"), "{h}");
    assert!(
        h.contains("user-agent: probe/1") && !h.contains("mozilla"),
        "{h}"
    );
    assert!(!h.contains("referer"), "{h}");
    assert_eq!(r.header("x-served-by"), Some("edge"));
    assert_eq!(r.header("via"), Some("1.1 edge1"));
}

#[tokio::test]
async fn bandwidth_limits_slow_a_download_and_an_upload() {
    let origin = http_origin("127.0.0.1:0").await;
    let banner = banner_origin("127.0.0.1:0").await;
    let edge = Edge::start(&format!(
        r#"
{OPEN}
[[limit]]
name = "slow-down"
when = {{ port = ["{hp}"] }}
bandwidth_down = "128KB"
[[limit]]
name = "slow-up"
when = {{ port = ["{bp}"] }}
bandwidth_up = "64KB"
"#,
        hp = origin.port(),
        bp = banner.port()
    ))
    .await;
    // 256 KB at 128 KB/s with a 12.8 KB burst: about 1.9 s
    let t = format!("origin.test:{}", origin.port());
    let start = Instant::now();
    let r = get(edge.addr("main"), &t, "/big?n=256000", None).await;
    let took = start.elapsed();
    assert_eq!(r.body.len(), 256_000);
    assert!(
        took >= Duration::from_millis(1400),
        "limit not applied: {took:?}"
    );
    assert!(took <= Duration::from_secs(8), "far too slow: {took:?}");

    // upload through a tunnel: 128 KB at 64 KB/s, the echo comes back unshaped
    let mut s = tunnel(
        edge.addr("main"),
        &format!("origin.test:{}", banner.port()),
        None,
    )
    .await
    .unwrap();
    let _ = read_line(&mut s).await;
    let start = Instant::now();
    let payload = vec![7u8; 128 * 1024];
    let (mut rd, mut wr) = s.split();
    let writer = async {
        wr.write_all(&payload).await.unwrap();
    };
    let reader = async {
        let mut got = 0usize;
        let mut buf = vec![0u8; 16384];
        while got < payload.len() {
            let n = rd.read(&mut buf).await.unwrap();
            assert!(n > 0);
            got += n;
        }
    };
    tokio::join!(writer, reader);
    let took = start.elapsed();
    assert!(
        took >= Duration::from_millis(1000),
        "upload not limited: {took:?}"
    );
    assert!(took <= Duration::from_secs(8), "{took:?}");

    // an unlimited port is fast
    let start = Instant::now();
    let origin2 = http_origin("127.0.0.1:0").await;
    let r = get(
        edge.addr("main"),
        &format!("origin.test:{}", origin2.port()),
        "/big?n=256000",
        None,
    )
    .await;
    assert_eq!(r.body.len(), 256_000);
    assert!(
        start.elapsed() < Duration::from_millis(800),
        "{:?}",
        start.elapsed()
    );
}

#[tokio::test]
async fn connection_and_rate_limits_refuse_with_429() {
    let banner = banner_origin("127.0.0.1:0").await;
    let origin = http_origin("127.0.0.1:0").await;
    let edge = Edge::start(&format!(
        r#"
{USERS}
{rules}
[server]
max_connections = 5
[[limit]]
when = {{ user = ["guest"] }}
max_connections = 1
[[limit]]
when = {{ user = ["alice"] }}
request_rate = "3/min"
"#,
        rules = allow_all(),
    ))
    .await;
    let l = edge.addr("main");
    let bt = format!("origin.test:{}", banner.port());
    // guest: one tunnel at a time
    let first = tunnel(l, &bt, Some(("guest", "pw"))).await.unwrap();
    assert_eq!(tunnel(l, &bt, Some(("guest", "pw"))).await.err(), Some(429));
    drop(first);
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert!(
        tunnel(l, &bt, Some(("guest", "pw"))).await.is_ok(),
        "the slot is released with the tunnel"
    );
    // alice: 3 requests per minute
    let ot = format!("origin.test:{}", origin.port());
    for _ in 0..3 {
        assert_eq!(get(l, &ot, "/ip", Some(("alice", "pw"))).await.status, 200);
    }
    let r = get(l, &ot, "/ip", Some(("alice", "pw"))).await;
    assert_eq!(
        (r.status, r.header("x-proxyx-error")),
        (429, Some("rate_limited"))
    );
    let m = edge.metrics();
    assert!(
        m.contains(
            "proxyx_edge_limit_rejections_total{kind=\"limit_connections\",service=\"proxyx-edge\"}"
        ),
        "{m}"
    );
    assert!(
        m.contains(
            "proxyx_edge_limit_rejections_total{kind=\"limit_rate\",service=\"proxyx-edge\"}"
        ),
        "{m}"
    );
}

#[tokio::test]
async fn user_global_and_per_source_connection_caps() {
    let banner = banner_origin("127.0.0.1:0").await;
    let edge = Edge::start(&format!(
        r#"
[[listener]]
name = "main"
listen = "127.0.0.1:0"
[[user]]
name = "alice"
password = "pw"
max_connections = 1
{rules}
[server]
max_connections = 4
max_connections_per_src = 3
"#,
        rules = allow_all(),
    ))
    .await;
    let l = edge.addr("main");
    let bt = format!("origin.test:{}", banner.port());
    let t1 = tunnel(l, &bt, Some(("alice", "pw"))).await.unwrap();
    assert_eq!(
        tunnel(l, &bt, Some(("alice", "pw"))).await.err(),
        Some(429),
        "per-user cap"
    );
    // per source: three connections are open (t1 and two idle ones); the fourth from this source is closed unanswered
    let _idle1 = TcpStream::connect(l).await.unwrap();
    let _idle2 = TcpStream::connect(l).await.unwrap();
    tokio::time::sleep(Duration::from_millis(200)).await;
    let mut over = TcpStream::connect(l).await.unwrap();
    over.write_all(b"GET http://x/ HTTP/1.1\r\n\r\n").await.ok();
    let mut buf = Vec::new();
    let _ = tokio::time::timeout(Duration::from_secs(2), over.read_to_end(&mut buf)).await;
    assert!(buf.is_empty(), "{:?}", String::from_utf8_lossy(&buf));
    assert!(edge.metrics().contains("outcome=\"over_limit\""));
    drop(t1);
}

#[tokio::test]
async fn dns_failures_and_refused_targets_are_bad_gateway() {
    let edge = Edge::start(&format!("{OPEN}\n")).await;
    let l = edge.addr("main");
    let r = get(l, "no-such-host.invalid:80", "/", None).await;
    assert_eq!(
        (r.status, r.header("x-proxyx-error")),
        (502, Some("dns_error")),
        "{r:?}"
    );
    let dead = {
        let s = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        s.local_addr().unwrap().port()
    };
    let r = get(l, &format!("origin.test:{dead}"), "/", None).await;
    assert_eq!(
        (r.status, r.header("x-proxyx-error")),
        (502, Some("connect_failed")),
        "{r:?}"
    );
    assert_eq!(
        tunnel(l, &format!("origin.test:{dead}"), None).await.err(),
        Some(502)
    );
}

#[tokio::test]
async fn an_idle_tunnel_is_closed() {
    let banner = banner_origin("127.0.0.1:0").await;
    let edge = Edge::start(&format!("{OPEN}\n[timeouts]\nidle = \"1s\"\n")).await;
    let mut s = tunnel(
        edge.addr("main"),
        &format!("origin.test:{}", banner.port()),
        None,
    )
    .await
    .unwrap();
    let _ = read_line(&mut s).await;
    let start = Instant::now();
    let mut buf = [0u8; 8];
    let n = tokio::time::timeout(Duration::from_secs(6), s.read(&mut buf))
        .await
        .expect("closed by the proxy")
        .unwrap_or(0);
    assert_eq!(n, 0);
    assert!(
        start.elapsed() < Duration::from_secs(5),
        "{:?}",
        start.elapsed()
    );
}
