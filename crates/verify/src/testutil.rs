//! Local stub servers for tests: an HTTP server that also works as a plain
//! HTTP proxy (absolute-form requests), and the same behind SOCKS5. Upstream
//! credentials are always `u` / `p`.

use std::net::SocketAddr;
use std::sync::Arc;

use common::Secret;
use common::metrics::Metrics;
use common::types::{UpstreamEndpoint, UpstreamScheme};
use parking_lot::Mutex;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

use crate::reputation::{Reputation, ReputationConfig, ScorerSlot};
use crate::score::{Scorer, ScorerAccount};

const USER: &str = "u";
const PASS: &str = "p";

#[derive(Debug, Clone)]
pub struct Req {
    pub method: String,
    /// Request target as sent: origin-form for a direct call, absolute-form
    /// through the stub as an HTTP proxy.
    pub target: String,
    pub headers: Vec<(String, String)>,
}

impl Req {
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }

    /// `Host` header without the port.
    pub fn host(&self) -> String {
        let host = self.header("host").unwrap_or_default();
        host.rsplit_once(':').map_or(host, |(h, _)| h).to_owned()
    }

    /// Path and query of the target, whatever its form.
    pub fn path(&self) -> String {
        match self.target.split_once("://") {
            Some((_, rest)) => rest.find('/').map_or("/", |i| &rest[i..]).to_owned(),
            None => self.target.clone(),
        }
    }
}

pub struct Resp {
    status: u16,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
}

impl Resp {
    pub fn ok(body: impl Into<Vec<u8>>) -> Self {
        Self::status(200, body)
    }

    pub fn status(status: u16, body: impl Into<Vec<u8>>) -> Self {
        Self {
            status,
            headers: Vec::new(),
            body: body.into(),
        }
    }

    #[must_use]
    pub fn header(mut self, name: &str, value: &str) -> Self {
        self.headers.push((name.to_owned(), value.to_owned()));
        self
    }
}

type Handler = Arc<dyn Fn(&Req) -> Resp + Send + Sync>;
type Log = Arc<Mutex<Vec<Req>>>;

pub struct Stub {
    pub addr: SocketAddr,
    log: Log,
}

impl Stub {
    /// Serve plain HTTP. Must run inside a Tokio runtime.
    pub fn spawn(handler: impl Fn(&Req) -> Resp + Send + Sync + 'static) -> Self {
        Self::start(Arc::new(handler), false)
    }

    /// Serve the same HTTP behind SOCKS5 with username/password auth.
    pub fn spawn_socks5(handler: impl Fn(&Req) -> Resp + Send + Sync + 'static) -> Self {
        Self::start(Arc::new(handler), true)
    }

    /// Accept connections and never answer: a service that is down slowly.
    pub fn hanging() -> Self {
        let (listener, addr) = bind();
        tokio::spawn(async move {
            // Held open until the test ends and the runtime drops the task.
            let mut held = Vec::new();
            while let Ok((stream, _)) = listener.accept().await {
                held.push(stream);
            }
        });
        Self {
            addr,
            log: Log::default(),
        }
    }

    fn start(handler: Handler, socks: bool) -> Self {
        let (listener, addr) = bind();
        let log = Log::default();
        let task_log = Arc::clone(&log);
        tokio::spawn(async move {
            while let Ok((stream, _)) = listener.accept().await {
                let (handler, log) = (Arc::clone(&handler), Arc::clone(&task_log));
                tokio::spawn(async move {
                    // Test stub: a broken connection just ends the exchange.
                    let _ = if socks {
                        serve_socks5(stream, &handler, &log).await
                    } else {
                        serve_http(stream, &handler, &log).await
                    };
                });
            }
        });
        Self { addr, log }
    }

    pub fn requests(&self) -> Vec<Req> {
        self.log.lock().clone()
    }

    pub fn hits(&self) -> usize {
        self.log.lock().len()
    }
}

fn bind() -> (TcpListener, SocketAddr) {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind stub");
    listener.set_nonblocking(true).expect("nonblocking stub");
    let addr = listener.local_addr().expect("stub addr");
    (
        TcpListener::from_std(listener).expect("tokio stub listener"),
        addr,
    )
}

/// An HTTP server on 127.0.0.1 that answers every request with the IP it saw
/// the client connect from, as `{"ip":"<peer>","country":"fr"}` (the shape of
/// the ipinfo and ipify services). Must run inside a Tokio runtime.
pub fn peer_echo() -> SocketAddr {
    let (listener, addr) = bind();
    tokio::spawn(async move {
        while let Ok((mut stream, peer)) = listener.accept().await {
            tokio::spawn(async move {
                let mut head = Vec::new();
                while !head.ends_with(b"\r\n\r\n") {
                    match stream.read_u8().await {
                        Ok(b) => head.push(b),
                        Err(_) => return,
                    }
                }
                let body = format!(r#"{{"ip":"{}","country":"fr"}}"#, peer.ip());
                let reply = format!(
                    "HTTP/1.1 200 Echo\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                // Test stub: a client that left early ends the exchange.
                let _ = stream.write_all(reply.as_bytes()).await;
                let _ = stream.shutdown().await;
            });
        }
    });
    addr
}

/// A `Local` upstream that binds `source`.
pub fn local_upstream(source: &str) -> UpstreamEndpoint {
    UpstreamEndpoint {
        provider: "local".parse().expect("provider id"),
        scheme: UpstreamScheme::Local,
        host: source.to_owned(),
        port: 0,
        username: Secret::new(""),
        password: Secret::new(""),
        public_only: false,
    }
}

/// An HTTP upstream (or SOCKS5 after changing `scheme`) pointing at `stub`.
pub fn upstream(stub: &Stub) -> UpstreamEndpoint {
    UpstreamEndpoint {
        provider: "stub".parse().expect("provider id"),
        scheme: UpstreamScheme::Http,
        host: "127.0.0.1".to_owned(),
        port: stub.addr.port(),
        username: Secret::new(USER),
        password: Secret::new(PASS),
        public_only: false,
    }
}

/// An IPQS stub scoring every IP `fraud_score`.
pub fn ipqs(fraud_score: u32) -> Stub {
    Stub::spawn(move |_| {
        Resp::ok(format!(
            r#"{{"success":true,"fraud_score":{fraud_score},"tor":false}}"#
        ))
    })
}

pub fn account(stub: &Stub, key: &str) -> ScorerAccount {
    ScorerAccount {
        base_url: format!("http://{}", stub.addr),
        key: Secret::new(key),
    }
}

pub fn ipqs_slot(stub: &Stub, daily_budget: u32) -> ScorerSlot {
    ScorerSlot {
        scorer: Scorer::Ipqs(account(stub, "key")),
        daily_budget,
    }
}

/// A `Reputation` with the default config and its metrics.
pub fn reputation(slots: Vec<ScorerSlot>) -> (Reputation, Arc<Metrics>) {
    let metrics = Arc::new(Metrics::new("test"));
    let rep = Reputation::new(ReputationConfig::default(), slots, Arc::clone(&metrics))
        .expect("reputation");
    (rep, metrics)
}

/// Failed calls counted against the `service` label.
pub fn failures(metrics: &Metrics, service: &str) -> u64 {
    metrics
        .check_failures_total
        .with_label_values(&[service])
        .get()
}

async fn serve_http(mut s: TcpStream, handler: &Handler, log: &Log) -> std::io::Result<()> {
    let mut head = Vec::new();
    while !head.ends_with(b"\r\n\r\n") {
        let b = s.read_u8().await?;
        head.push(b);
        if head.len() > 16 * 1024 {
            return Err(std::io::ErrorKind::InvalidData.into());
        }
    }
    let text = String::from_utf8_lossy(&head);
    let mut lines = text.split("\r\n");
    let mut first = lines.next().unwrap_or_default().split(' ');
    let req = Req {
        method: first.next().unwrap_or_default().to_owned(),
        target: first.next().unwrap_or_default().to_owned(),
        headers: lines
            .filter_map(|l| l.split_once(':'))
            .map(|(k, v)| (k.trim().to_owned(), v.trim().to_owned()))
            .collect(),
    };
    log.lock().push(req.clone());
    let resp = handler(&req);
    let mut out = format!(
        "HTTP/1.1 {} Stub\r\nContent-Length: {}\r\nConnection: close\r\n",
        resp.status,
        resp.body.len()
    );
    for (k, v) in &resp.headers {
        out.push_str(&format!("{k}: {v}\r\n"));
    }
    out.push_str("\r\n");
    s.write_all(out.as_bytes()).await?;
    s.write_all(&resp.body).await?;
    s.shutdown().await
}

async fn serve_socks5(mut s: TcpStream, handler: &Handler, log: &Log) -> std::io::Result<()> {
    let invalid = || std::io::Error::from(std::io::ErrorKind::InvalidData);
    // Greeting: only username/password (2) is acceptable.
    let mut hello = [0u8; 2];
    s.read_exact(&mut hello).await?;
    let mut methods = vec![0u8; usize::from(hello[1])];
    s.read_exact(&mut methods).await?;
    if hello[0] != 5 || !methods.contains(&2) {
        s.write_all(&[5, 0xff]).await?;
        return Err(invalid());
    }
    s.write_all(&[5, 2]).await?;
    // RFC 1929 sub-negotiation.
    let mut ver = [0u8; 2];
    s.read_exact(&mut ver).await?;
    let mut got_user = vec![0u8; usize::from(ver[1])];
    s.read_exact(&mut got_user).await?;
    let plen = s.read_u8().await?;
    let mut got_pass = vec![0u8; usize::from(plen)];
    s.read_exact(&mut got_pass).await?;
    if got_user != USER.as_bytes() || got_pass != PASS.as_bytes() {
        s.write_all(&[1, 1]).await?;
        return Err(invalid());
    }
    s.write_all(&[1, 0]).await?;
    // CONNECT request; only a domain name (ATYP 3) is expected from `socks5h`.
    let mut req = [0u8; 4];
    s.read_exact(&mut req).await?;
    if req[1] != 1 || req[3] != 3 {
        return Err(invalid());
    }
    let dlen = s.read_u8().await?;
    let mut domain = vec![0u8; usize::from(dlen) + 2];
    s.read_exact(&mut domain).await?;
    s.write_all(&[5, 0, 0, 1, 0, 0, 0, 0, 0, 0]).await?;
    serve_http(s, handler, log).await
}
