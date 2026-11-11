//! Shared harness: a started edge server, origin servers that report who
//! connected to them, and small raw clients for each protocol.
#![allow(dead_code, clippy::unwrap_used)]

use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use proxyx_edge::Server;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};

static SEQ: AtomicUsize = AtomicUsize::new(0);

/// Names every test config resolves without DNS.
pub const BASE: &str = r#"
[dns]
nameservers = ["127.0.0.1"]
timeout = "1s"
attempts = 1
[dns.hosts]
"origin.test" = ["127.0.0.1"]
"origin6.test" = ["::1"]
"origin2.test" = ["127.0.0.1"]
"origin3.test" = ["127.0.0.1"]
"x.bad.test" = ["127.0.0.1"]
"#;

pub fn ipv6_available() -> bool {
    std::net::TcpListener::bind("[::1]:0").is_ok()
}

pub struct Edge {
    pub server: Arc<Server>,
    pub dir: PathBuf,
    pub path: PathBuf,
}

impl Edge {
    /// Start with `BASE` + `toml`. Listeners should bind port 0.
    pub async fn start(toml: &str) -> Edge {
        let dir = std::env::temp_dir().join(format!(
            "edge-it-{}-{}",
            std::process::id(),
            SEQ.fetch_add(1, Ordering::SeqCst)
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("edge.toml");
        std::fs::write(&path, format!("{BASE}\n{toml}")).unwrap();
        let server = Server::start(&path).await.expect("edge starts");
        Edge { server, dir, path }
    }

    pub fn addr(&self, listener: &str) -> SocketAddr {
        self.server.local_addrs()[listener]
    }

    pub fn rewrite(&self, toml: &str) {
        std::fs::write(&self.path, format!("{BASE}\n{toml}")).unwrap();
    }

    pub fn metrics(&self) -> String {
        proxyx_edge::ops::render_metrics(&self.server.shared)
    }
}

impl Drop for Edge {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

/// A listener on `main` that needs no login and lets everything through,
/// private destinations included (the origins live on loopback).
pub const OPEN: &str = r#"
[[listener]]
name = "main"
listen = "127.0.0.1:0"
auth = "none"
[[rule]]
action = "allow"
allow_internal = true
"#;

// ---------------------------------------------------------------- origins

/// An HTTP origin. Paths: `/ip` (the peer address), `/headers` (the request
/// head), `/big?n=N`, `/chunked`, `/echo` (the request body), `/upgrade`.
pub async fn http_origin(bind: &str) -> SocketAddr {
    let l = TcpListener::bind(bind).await.unwrap();
    let addr = l.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let Ok((s, peer)) = l.accept().await else {
                return;
            };
            tokio::spawn(origin_conn(s, peer));
        }
    });
    addr
}

async fn origin_conn(mut s: TcpStream, peer: SocketAddr) {
    let mut buf = Vec::new();
    loop {
        let head_end = loop {
            if let Some(i) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                break i + 4;
            }
            let mut tmp = [0u8; 4096];
            match s.read(&mut tmp).await {
                Ok(0) | Err(_) => return,
                Ok(n) => buf.extend_from_slice(&tmp[..n]),
            }
        };
        let head = String::from_utf8_lossy(&buf[..head_end]).to_string();
        buf.drain(..head_end);
        let mut lines = head.split("\r\n");
        let reqline = lines.next().unwrap_or_default().to_owned();
        let path = reqline.split(' ').nth(1).unwrap_or("/").to_owned();
        let hdr = |name: &str| -> Option<String> {
            head.split("\r\n").skip(1).find_map(|l| {
                let (k, v) = l.split_once(':')?;
                k.trim()
                    .eq_ignore_ascii_case(name)
                    .then(|| v.trim().to_owned())
            })
        };
        // request body
        let mut body = Vec::new();
        if let Some(cl) = hdr("content-length").and_then(|v| v.parse::<usize>().ok()) {
            while buf.len() < cl {
                let mut tmp = [0u8; 4096];
                match s.read(&mut tmp).await {
                    Ok(0) | Err(_) => return,
                    Ok(n) => buf.extend_from_slice(&tmp[..n]),
                }
            }
            body = buf.drain(..cl).collect();
        } else if hdr("transfer-encoding").is_some_and(|v| v.eq_ignore_ascii_case("chunked")) {
            loop {
                while !buf.windows(2).any(|w| w == b"\r\n") {
                    let mut tmp = [0u8; 4096];
                    match s.read(&mut tmp).await {
                        Ok(0) | Err(_) => return,
                        Ok(n) => buf.extend_from_slice(&tmp[..n]),
                    }
                }
                let i = buf.windows(2).position(|w| w == b"\r\n").unwrap();
                let size =
                    usize::from_str_radix(std::str::from_utf8(&buf[..i]).unwrap().trim(), 16)
                        .unwrap();
                buf.drain(..i + 2);
                while buf.len() < size + 2 {
                    let mut tmp = [0u8; 4096];
                    match s.read(&mut tmp).await {
                        Ok(0) | Err(_) => return,
                        Ok(n) => buf.extend_from_slice(&tmp[..n]),
                    }
                }
                body.extend_from_slice(&buf[..size]);
                buf.drain(..size + 2);
                if size == 0 {
                    break;
                }
            }
        }
        let close = hdr("connection").is_some_and(|v| v.eq_ignore_ascii_case("close"));
        let (route, query) = path.split_once('?').unwrap_or((&path, ""));
        match route {
            "/ip" => {
                let b = peer.ip().to_string();
                let r = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: {}\r\n\r\n{b}",
                    b.len()
                );
                s.write_all(r.as_bytes()).await.ok();
            }
            "/headers" => {
                let b = head.clone();
                let r = format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n{b}", b.len());
                s.write_all(r.as_bytes()).await.ok();
            }
            "/big" => {
                let n: usize = query
                    .strip_prefix("n=")
                    .and_then(|v| v.parse().ok())
                    .unwrap_or(1000);
                let r = format!("HTTP/1.1 200 OK\r\nContent-Length: {n}\r\n\r\n");
                s.write_all(r.as_bytes()).await.ok();
                let chunk = vec![b'x'; 16 * 1024];
                let mut left = n;
                while left > 0 {
                    let k = left.min(chunk.len());
                    if s.write_all(&chunk[..k]).await.is_err() {
                        return;
                    }
                    left -= k;
                }
            }
            "/chunked" => {
                s.write_all(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n5\r\nworld\r\n0\r\n\r\n")
                    .await
                    .ok();
            }
            "/echo" => {
                let r = format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n", body.len());
                s.write_all(r.as_bytes()).await.ok();
                s.write_all(&body).await.ok();
            }
            "/upgrade" => {
                s.write_all(b"HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: echo\r\n\r\n")
                    .await
                    .ok();
                let mut tmp = [0u8; 4096];
                loop {
                    match s.read(&mut tmp).await {
                        Ok(0) | Err(_) => return,
                        Ok(n) => {
                            if s.write_all(&tmp[..n]).await.is_err() {
                                return;
                            }
                        }
                    }
                }
            }
            "/continue" => {
                // the body was already read; answer with its length
                let b = format!("got {}", body.len());
                let r = format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n{b}", b.len());
                s.write_all(r.as_bytes()).await.ok();
            }
            _ => {
                s.write_all(b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n")
                    .await
                    .ok();
            }
        }
        if close {
            return;
        }
    }
}

/// A server that speaks first: `ip:<peer>\n`, then echoes.
pub async fn banner_origin(bind: &str) -> SocketAddr {
    let l = TcpListener::bind(bind).await.unwrap();
    let addr = l.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let Ok((mut s, peer)) = l.accept().await else {
                return;
            };
            tokio::spawn(async move {
                if s.write_all(format!("ip:{}\n", peer.ip()).as_bytes())
                    .await
                    .is_err()
                {
                    return;
                }
                let mut tmp = [0u8; 8192];
                loop {
                    match s.read(&mut tmp).await {
                        Ok(0) | Err(_) => return,
                        Ok(n) => {
                            if s.write_all(&tmp[..n]).await.is_err() {
                                return;
                            }
                        }
                    }
                }
            });
        }
    });
    addr
}

/// A UDP echo that answers `from:<peer ip>`.
pub async fn udp_origin(bind: &str) -> SocketAddr {
    let s = UdpSocket::bind(bind).await.unwrap();
    let addr = s.local_addr().unwrap();
    tokio::spawn(async move {
        let mut buf = [0u8; 2048];
        loop {
            let Ok((_, peer)) = s.recv_from(&mut buf).await else {
                return;
            };
            let _ = s
                .send_to(format!("from:{}", peer.ip()).as_bytes(), peer)
                .await;
        }
    });
    addr
}

// ---------------------------------------------------------------- clients

#[derive(Debug)]
pub struct Resp {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

impl Resp {
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }

    pub fn text(&self) -> String {
        String::from_utf8_lossy(&self.body).to_string()
    }
}

pub fn basic(user: &str, pass: &str) -> String {
    format!(
        "Proxy-Authorization: Basic {}\r\n",
        STANDARD.encode(format!("{user}:{pass}"))
    )
}

/// Read one response (any framing) from `s`; leaves extra bytes unread only if the framing ends.
pub async fn read_response(s: &mut TcpStream, head_request: bool) -> Resp {
    let mut buf = Vec::new();
    let end = loop {
        if let Some(i) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            break i + 4;
        }
        let mut tmp = [0u8; 4096];
        let n = tokio::time::timeout(Duration::from_secs(10), s.read(&mut tmp))
            .await
            .expect("response head in time")
            .expect("read");
        assert!(
            n > 0,
            "closed before a response head: {:?}",
            String::from_utf8_lossy(&buf)
        );
        buf.extend_from_slice(&tmp[..n]);
    };
    let head = String::from_utf8_lossy(&buf[..end]).to_string();
    buf.drain(..end);
    let mut lines = head.split("\r\n");
    let status: u16 = lines
        .next()
        .unwrap()
        .split(' ')
        .nth(1)
        .unwrap()
        .parse()
        .unwrap();
    let headers: Vec<(String, String)> = lines
        .filter_map(|l| {
            l.split_once(':')
                .map(|(k, v)| (k.trim().to_owned(), v.trim().to_owned()))
        })
        .collect();
    let get = |n: &str| {
        headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(n))
            .map(|(_, v)| v.clone())
    };
    let mut body = Vec::new();
    if head_request || status == 204 || status == 304 || (100..200).contains(&status) {
        // no body
    } else if let Some(cl) = get("content-length").and_then(|v| v.parse::<usize>().ok()) {
        while buf.len() < cl {
            let mut tmp = [0u8; 16384];
            let n = s.read(&mut tmp).await.expect("read body");
            assert!(n > 0, "closed inside the body");
            buf.extend_from_slice(&tmp[..n]);
        }
        body = buf.drain(..cl).collect();
    } else if get("transfer-encoding").is_some_and(|v| v.eq_ignore_ascii_case("chunked")) {
        loop {
            while !buf.windows(2).any(|w| w == b"\r\n") {
                let mut tmp = [0u8; 4096];
                let n = s.read(&mut tmp).await.expect("read chunk");
                assert!(n > 0, "closed inside chunks");
                buf.extend_from_slice(&tmp[..n]);
            }
            let i = buf.windows(2).position(|w| w == b"\r\n").unwrap();
            let size =
                usize::from_str_radix(std::str::from_utf8(&buf[..i]).unwrap().trim(), 16).unwrap();
            buf.drain(..i + 2);
            while buf.len() < size + 2 {
                let mut tmp = [0u8; 4096];
                let n = s.read(&mut tmp).await.expect("read chunk");
                assert!(n > 0);
                buf.extend_from_slice(&tmp[..n]);
            }
            body.extend_from_slice(&buf[..size]);
            buf.drain(..size + 2);
            if size == 0 {
                break;
            }
        }
    } else {
        body = buf;
        let _ = s.read_to_end(&mut body).await;
    }
    Resp {
        status,
        headers,
        body,
    }
}

/// One request on a fresh connection to the proxy.
pub async fn via_proxy(proxy: SocketAddr, raw: &str) -> Resp {
    let mut s = TcpStream::connect(proxy).await.unwrap();
    s.write_all(raw.as_bytes()).await.unwrap();
    read_response(&mut s, raw.starts_with("HEAD ")).await
}

/// `GET http://<target><path>` with optional login.
pub async fn get(proxy: SocketAddr, target: &str, path: &str, auth: Option<(&str, &str)>) -> Resp {
    let a = auth.map(|(u, p)| basic(u, p)).unwrap_or_default();
    via_proxy(
        proxy,
        &format!(
            "GET http://{target}{path} HTTP/1.1\r\nHost: {target}\r\n{a}Connection: close\r\n\r\n"
        ),
    )
    .await
}

pub async fn get_ip(proxy: SocketAddr, target: &str, auth: Option<(&str, &str)>) -> IpAddr {
    let r = get(proxy, target, "/ip", auth).await;
    assert_eq!(r.status, 200, "{r:?}");
    r.text().parse().unwrap()
}

/// CONNECT; `Ok(stream)` after a 200, `Err(status)` otherwise.
pub async fn tunnel(
    proxy: SocketAddr,
    target: &str,
    auth: Option<(&str, &str)>,
) -> Result<TcpStream, u16> {
    let a = auth.map(|(u, p)| basic(u, p)).unwrap_or_default();
    let mut s = TcpStream::connect(proxy).await.unwrap();
    s.write_all(format!("CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n{a}\r\n").as_bytes())
        .await
        .unwrap();
    let mut head = Vec::new();
    while !head.ends_with(b"\r\n\r\n") {
        let mut b = [0u8; 1];
        let n = s.read(&mut b).await.unwrap();
        assert!(n > 0, "closed in CONNECT reply");
        head.push(b[0]);
    }
    let text = String::from_utf8_lossy(&head).to_string();
    let status: u16 = text.split(' ').nth(1).unwrap().parse().unwrap();
    if status == 200 { Ok(s) } else { Err(status) }
}

pub async fn read_line(s: &mut TcpStream) -> String {
    let mut out = Vec::new();
    loop {
        let mut b = [0u8; 1];
        let n = tokio::time::timeout(Duration::from_secs(10), s.read(&mut b))
            .await
            .expect("line in time")
            .unwrap();
        assert!(
            n > 0,
            "closed before newline: {:?}",
            String::from_utf8_lossy(&out)
        );
        if b[0] == b'\n' {
            return String::from_utf8_lossy(&out).to_string();
        }
        out.push(b[0]);
    }
}

/// SOCKS5 CONNECT; `Ok((stream, bound address))` or `Err(reply code)` (`0xff` for a refused method, `0xfe` for a refused login).
pub async fn socks5(
    proxy: SocketAddr,
    host: &str,
    port: u16,
    auth: Option<(&str, &str)>,
) -> Result<(TcpStream, SocketAddr), u8> {
    let mut s = TcpStream::connect(proxy).await.unwrap();
    let greeting: &[u8] = if auth.is_some() {
        &[5, 2, 0, 2]
    } else {
        &[5, 1, 0]
    };
    s.write_all(greeting).await.unwrap();
    let mut m = [0u8; 2];
    s.read_exact(&mut m).await.unwrap();
    if m[1] == 0xff {
        return Err(0xff);
    }
    if m[1] == 2 {
        let (u, p) = auth.expect("server asked for a login");
        let mut msg = vec![1, u.len() as u8];
        msg.extend_from_slice(u.as_bytes());
        msg.push(p.len() as u8);
        msg.extend_from_slice(p.as_bytes());
        s.write_all(&msg).await.unwrap();
        let mut r = [0u8; 2];
        s.read_exact(&mut r).await.unwrap();
        if r[1] != 0 {
            return Err(0xfe);
        }
    }
    let mut req = vec![5, 1, 0];
    match host.parse::<IpAddr>() {
        Ok(IpAddr::V4(ip)) => {
            req.push(1);
            req.extend_from_slice(&ip.octets());
        }
        Ok(IpAddr::V6(ip)) => {
            req.push(4);
            req.extend_from_slice(&ip.octets());
        }
        Err(_) => {
            req.push(3);
            req.push(host.len() as u8);
            req.extend_from_slice(host.as_bytes());
        }
    }
    req.extend_from_slice(&port.to_be_bytes());
    s.write_all(&req).await.unwrap();
    let (code, bound) = read_socks5_reply(&mut s).await;
    if code != 0 {
        return Err(code);
    }
    Ok((s, bound))
}

pub async fn read_socks5_reply(s: &mut TcpStream) -> (u8, SocketAddr) {
    let mut h = [0u8; 4];
    s.read_exact(&mut h).await.unwrap();
    let ip: IpAddr = match h[3] {
        1 => {
            let mut b = [0u8; 4];
            s.read_exact(&mut b).await.unwrap();
            IpAddr::from(b)
        }
        4 => {
            let mut b = [0u8; 16];
            s.read_exact(&mut b).await.unwrap();
            IpAddr::from(b)
        }
        other => panic!("reply address type {other}"),
    };
    let mut p = [0u8; 2];
    s.read_exact(&mut p).await.unwrap();
    (h[1], SocketAddr::new(ip, u16::from_be_bytes(p)))
}

/// SOCKS4 / 4a CONNECT. `Ok(stream)` on 90, else `Err(code)`.
pub async fn socks4(
    proxy: SocketAddr,
    host: &str,
    port: u16,
    userid: &str,
) -> Result<TcpStream, u8> {
    let mut s = TcpStream::connect(proxy).await.unwrap();
    let mut req = vec![4, 1];
    req.extend_from_slice(&port.to_be_bytes());
    let name = match host.parse::<std::net::Ipv4Addr>() {
        Ok(ip) => {
            req.extend_from_slice(&ip.octets());
            None
        }
        Err(_) => {
            req.extend_from_slice(&[0, 0, 0, 1]);
            Some(host)
        }
    };
    req.extend_from_slice(userid.as_bytes());
    req.push(0);
    if let Some(n) = name {
        req.extend_from_slice(n.as_bytes());
        req.push(0);
    }
    s.write_all(&req).await.unwrap();
    let mut r = [0u8; 8];
    s.read_exact(&mut r).await.unwrap();
    if r[1] == 90 { Ok(s) } else { Err(r[1]) }
}

pub fn ip(s: &str) -> IpAddr {
    s.parse().unwrap()
}

pub fn http_get_text(h: &SocketAddr) -> String {
    h.to_string()
}
