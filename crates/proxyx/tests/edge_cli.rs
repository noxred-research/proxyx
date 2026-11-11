//! `proxyx edge` as a process: `--check`, serving, SIGHUP reload and SIGTERM.
#![allow(clippy::unwrap_used)]

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

const BIN: &str = env!("CARGO_BIN_EXE_proxyx");

fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

fn workdir(name: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("proxyx-edge-cli-{name}-{}", std::process::id()));
    std::fs::create_dir_all(&d).unwrap();
    d
}

/// A one-thread HTTP origin that answers with the peer address.
fn origin() -> u16 {
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = l.local_addr().unwrap().port();
    std::thread::spawn(move || {
        for s in l.incoming() {
            let Ok(mut s) = s else { return };
            std::thread::spawn(move || {
                let peer = s.peer_addr().unwrap().ip().to_string();
                let mut buf = [0u8; 4096];
                let _ = s.read(&mut buf);
                let _ = write!(
                    s,
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{peer}",
                    peer.len()
                );
            });
        }
    });
    port
}

fn config(listen: u16, ops: u16, user: &str, pool_addr: &str) -> String {
    format!(
        r#"
[dns]
nameservers = ["127.0.0.1"]
[dns.hosts]
"origin.test" = ["127.0.0.1"]
[server]
ops_listen = "127.0.0.1:{ops}"
default_pool = "own"
[[listener]]
name = "main"
listen = "127.0.0.1:{listen}"
[[user]]
name = "{user}"
password = "pw"
[[pool]]
name = "own"
addresses = ["{pool_addr}"]
[[rule]]
action = "allow"
allow_internal = true
"#
    )
}

fn http(proxy: u16, target: &str, user: &str) -> (u16, String) {
    use base64::Engine as _;
    let auth = base64::engine::general_purpose::STANDARD.encode(format!("{user}:pw"));
    let mut s = TcpStream::connect(("127.0.0.1", proxy)).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    write!(s, "GET http://{target}/ HTTP/1.1\r\nHost: {target}\r\nProxy-Authorization: Basic {auth}\r\nConnection: close\r\n\r\n").unwrap();
    let mut out = String::new();
    s.read_to_string(&mut out).unwrap();
    let status = out.split(' ').nth(1).unwrap().parse().unwrap();
    (
        status,
        out.split("\r\n\r\n").nth(1).unwrap_or_default().to_owned(),
    )
}

fn wait_for_port(port: u16) {
    let end = Instant::now() + Duration::from_secs(10);
    while TcpStream::connect(("127.0.0.1", port)).is_err() {
        assert!(Instant::now() < end, "port {port} never opened");
        std::thread::sleep(Duration::from_millis(50));
    }
}

fn signal(child: &Child, sig: &str) {
    let st = Command::new("kill")
        .args([&format!("-{sig}"), &child.id().to_string()])
        .status()
        .unwrap();
    assert!(st.success());
}

#[test]
fn check_reports_pools_and_fails_on_a_bad_file() {
    let dir = workdir("check");
    let path = dir.join("edge.toml");
    std::fs::write(
        &path,
        config(free_port(), free_port(), "alice", "127.0.0.2"),
    )
    .unwrap();
    let out = Command::new(BIN)
        .args(["edge", "--check", "--config"])
        .arg(&path)
        .output()
        .unwrap();
    let text = String::from_utf8_lossy(&out.stdout);
    assert!(
        out.status.success(),
        "{text} {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        text.contains("ok: 1 listener(s), 1 user(s), 1 rule(s), 0 parent(s)"),
        "{text}"
    );
    assert!(text.contains("pool own: 127.0.0.2"), "{text}");

    std::fs::write(
        &path,
        config(free_port(), free_port(), "alice", "203.0.113.50"),
    )
    .unwrap();
    let out = Command::new(BIN)
        .args(["edge", "--check", "--config"])
        .arg(&path)
        .output()
        .unwrap();
    assert!(!out.status.success());
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(
        err.contains("203.0.113.50") && err.contains("not assigned"),
        "{err}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn serves_reloads_on_sighup_and_stops_on_sigterm() {
    let dir = workdir("run");
    let path = dir.join("edge.toml");
    let (listen, ops, origin_port) = (free_port(), free_port(), origin());
    std::fs::write(&path, config(listen, ops, "alice", "127.0.0.2")).unwrap();
    let mut child = Command::new(BIN)
        .args(["edge", "--config"])
        .arg(&path)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    wait_for_port(listen);
    wait_for_port(ops);
    let target = format!("origin.test:{origin_port}");

    // the target sees the pool address
    assert_eq!(
        http(listen, &target, "alice"),
        (200, "127.0.0.2".to_owned())
    );
    assert_eq!(http(listen, &target, "bob").0, 407);

    // SIGHUP: new user and a new egress address, no restart
    std::fs::write(&path, config(listen, ops, "bob", "127.0.0.3")).unwrap();
    signal(&child, "HUP");
    let end = Instant::now() + Duration::from_secs(10);
    loop {
        if http(listen, &target, "bob") == (200, "127.0.0.3".to_owned()) {
            break;
        }
        assert!(Instant::now() < end, "reload never took effect");
        std::thread::sleep(Duration::from_millis(100));
    }
    assert_eq!(http(listen, &target, "alice").0, 407);

    // a broken file is ignored on reload; the process keeps serving
    std::fs::write(&path, "this is not toml [").unwrap();
    signal(&child, "HUP");
    std::thread::sleep(Duration::from_millis(500));
    assert_eq!(http(listen, &target, "bob"), (200, "127.0.0.3".to_owned()));
    assert!(child.try_wait().unwrap().is_none(), "still running");

    // metrics are served on the ops port
    let mut m = TcpStream::connect(("127.0.0.1", ops)).unwrap();
    write!(
        m,
        "GET /metrics HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n"
    )
    .unwrap();
    let mut body = String::new();
    m.read_to_string(&mut body).unwrap();
    assert!(
        body.contains(
            "proxyx_edge_config_reloads_total{result=\"failed\",service=\"proxyx-edge\"} 1"
        ),
        "{body}"
    );
    assert!(
        body.contains("proxyx_edge_config_reloads_total{result=\"ok\",service=\"proxyx-edge\"} 1"),
        "{body}"
    );

    signal(&child, "TERM");
    let end = Instant::now() + Duration::from_secs(10);
    let status = loop {
        if let Some(s) = child.try_wait().unwrap() {
            break s;
        }
        assert!(Instant::now() < end, "did not stop on SIGTERM");
        std::thread::sleep(Duration::from_millis(50));
    };
    assert!(status.success(), "{status:?}");
    let _ = std::fs::remove_dir_all(&dir);
}

struct EdgeProcess(Child);

impl Drop for EdgeProcess {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn ops_body(port: u16, path: &str) -> String {
    let mut stream = TcpStream::connect(("127.0.0.1", port)).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    write!(
        stream,
        "GET {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n"
    )
    .unwrap();
    let mut response = String::new();
    stream.read_to_string(&mut response).unwrap();
    response
}

#[test]
fn sticky_egress_affinity_survives_real_sighup_with_reordered_pool() {
    let dir = workdir("affinity");
    let path = dir.join("edge.toml");
    let listen = free_port();
    let ops = loop {
        let port = free_port();
        if port != listen {
            break port;
        }
    };
    let origin_port = origin();
    let cfg = |addresses: &str| {
        format!(
            r#"
[dns]
nameservers = ["127.0.0.1"]
[dns.hosts]
"origin.test" = ["127.0.0.1"]
[server]
ops_listen = "127.0.0.1:{ops}"
default_pool = "own"
[selector]
strategy = "sticky"
[stick]
capacity = 32
ttl = "10m"
[auth]
login_options = true
[[listener]]
name = "main"
listen = "127.0.0.1:{listen}"
[[user]]
name = "alice"
password = "pw"
[[pool]]
name = "own"
addresses = {addresses}
strategy = "round_robin"
[[rule]]
action = "allow"
allow_internal = true
"#
        )
    };
    std::fs::write(&path, cfg(r#"["127.0.0.2", "127.0.0.3"]"#)).unwrap();
    let mut process = EdgeProcess(
        Command::new(BIN)
            .args(["edge", "--config"])
            .arg(&path)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap(),
    );
    wait_for_port(listen);
    wait_for_port(ops);
    let target = format!("origin.test:{origin_port}");
    let login = "alice-sid-signal";
    for _ in 0..3 {
        assert_eq!(http(listen, &target, login), (200, "127.0.0.2".to_owned()));
    }

    // A fresh table would pick the new first address; preserving only the index is also wrong.
    std::fs::write(&path, cfg(r#"["127.0.0.3", "127.0.0.2"]"#)).unwrap();
    signal(&process.0, "HUP");
    let end = Instant::now() + Duration::from_secs(10);
    while !ops_body(ops, "/metrics")
        .contains("proxyx_edge_config_reloads_total{result=\"ok\",service=\"proxyx-edge\"} 1")
    {
        assert!(Instant::now() < end, "SIGHUP did not complete");
        std::thread::sleep(Duration::from_millis(25));
    }
    for _ in 0..3 {
        assert_eq!(http(listen, &target, login), (200, "127.0.0.2".to_owned()));
    }

    signal(&process.0, "TERM");
    let end = Instant::now() + Duration::from_secs(10);
    loop {
        if let Some(status) = process.0.try_wait().unwrap() {
            assert!(status.success(), "{status:?}");
            break;
        }
        assert!(Instant::now() < end, "edge did not stop");
        std::thread::sleep(Duration::from_millis(25));
    }
    let _ = std::fs::remove_dir_all(dir);
}
