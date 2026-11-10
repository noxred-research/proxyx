//! Opening the connection to the target: directly from a pool address, or
//! through a parent proxy.
//!
//! The destination addresses were resolved and checked before this runs, and
//! this connects to exactly those addresses (a second resolution could answer
//! differently). Each address gets a source address of its own IP family
//! from the pool, bound before `connect`.

use std::collections::HashMap;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::time::Duration;

use common::types::Target;
use dial::DialError;
use parking_lot::Mutex;
use tokio::io::AsyncWriteExt as _;
use tokio::net::TcpStream;
use tokio::time::{Instant, timeout};

use crate::config::{ParentKind, Route, SendProxyProtocol, SocketOptions};
use crate::dns::DnsError;
use crate::egress::{Family, Lease, PickError, PickKey, Pool};
use crate::metrics::Metrics;
use crate::parent::Parent;
use crate::proxy_protocol;
use crate::sockopt;
use crate::state::State;

/// What the connection is for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    /// A raw tunnel (CONNECT, SOCKS): the stream ends at the target.
    Tunnel,
    /// A plain HTTP request: an HTTP parent gets the request itself, no CONNECT.
    Http,
}

#[derive(Debug, thiserror::Error)]
pub enum ConnectError {
    #[error("{0}")]
    Dns(#[from] DnsError),
    #[error("no local address of the destination's IP family")]
    NoAddressOfFamily,
    #[error("every local address of the destination's IP family is out of service")]
    EgressUnavailable,
    #[error("the requested local address does not exist or has the wrong IP family")]
    BadIndex,
    #[error("connect failed: {0}")]
    Connect(io::Error),
    #[error("connect timed out")]
    Timeout,
    #[error("parent {name}: {reason}")]
    Parent { name: String, reason: String },
    #[error("no parent proxy is available")]
    NoParent,
}

pub struct Plan<'a> {
    pub host: &'a str,
    pub port: u16,
    /// Resolved and checked destination addresses (never empty).
    pub ips: &'a [IpAddr],
    pub pool: Option<&'a Arc<Pool>>,
    pub index: Option<usize>,
    pub key: PickKey<'a>,
    pub route: Route,
    /// Parents the route allows; empty is all.
    pub parents: &'a [usize],
    pub mode: Mode,
    pub client: SocketAddr,
    /// The request is bodyless and may use (and leave) an idle connection to an HTTP parent.
    pub reuse: bool,
}

pub struct Upstream {
    pub stream: TcpStream,
    /// Keeps the local address counted as in use.
    pub lease: Option<Lease>,
    pub parent: Option<Arc<Parent>>,
    /// The address the stream is connected to (the parent's, when via a parent).
    pub peer: IpAddr,
    /// The stream speaks to an HTTP proxy: send the request in absolute form.
    pub http_proxy: bool,
    /// Set when the stream may go back to the idle pool after the response:
    /// the key it is filed under.
    pub reuse_key: Option<String>,
    /// The stream came out of the idle pool (it may have gone stale).
    pub reused: bool,
}

impl Upstream {
    pub fn local_ip(&self) -> Option<IpAddr> {
        self.stream.local_addr().ok().map(|a| a.ip())
    }
}

fn pool_label(pool: Option<&Arc<Pool>>) -> &str {
    pool.map_or("none", |p| p.name())
}

/// Connect to `ips`, one source address per destination address.
async fn connect_ips(
    ips: &[IpAddr],
    port: u16,
    pool: Option<&Arc<Pool>>,
    key: &PickKey<'_>,
    index: Option<usize>,
    budget: Duration,
    sock: &SocketOptions,
) -> Result<(TcpStream, Option<Lease>, IpAddr), ConnectError> {
    let deadline = Instant::now() + budget;
    let per_try = (budget / 3).max(Duration::from_secs(1));
    let mut last: Option<ConnectError> = None;
    let mut avoid: Vec<IpAddr> = Vec::new();
    for ip in ips {
        let ip = match ip {
            IpAddr::V6(v6) => v6.to_ipv4_mapped().map_or(*ip, IpAddr::V4),
            v4 => *v4,
        };
        let sa = SocketAddr::new(ip, port);
        let Some(pool) = pool else {
            let left = deadline.saturating_duration_since(Instant::now());
            if left.is_zero() {
                return Err(ConnectError::Timeout);
            }
            match timeout(left.min(per_try), dial::connect_from(vec![sa], None)).await {
                Ok(Ok(s)) => {
                    let _ = sockopt::apply(&s, sock);
                    return Ok((s, None, ip));
                }
                Ok(Err(e)) => last = Some(ConnectError::Connect(dial_io(e))),
                Err(_) => last = Some(ConnectError::Timeout),
            }
            continue;
        };
        for _ in 0..3 {
            let left = deadline.saturating_duration_since(Instant::now());
            if left.is_zero() {
                return Err(ConnectError::Timeout);
            }
            let mut lease = match pool.pick(Family::of(ip), key, index, &avoid) {
                Ok(l) => l,
                Err(PickError::NoAddressOfFamily) => {
                    last = Some(ConnectError::NoAddressOfFamily);
                    break;
                }
                Err(PickError::Unavailable) => {
                    last = Some(ConnectError::EgressUnavailable);
                    break;
                }
                Err(PickError::BadIndex) => return Err(ConnectError::BadIndex),
            };
            let src = lease.ip();
            match timeout(left.min(per_try), dial::connect_from(vec![sa], Some(src))).await {
                Ok(Ok(s)) => {
                    lease.report(true);
                    let _ = sockopt::apply(&s, sock);
                    return Ok((s, Some(lease), ip));
                }
                Ok(Err(e)) => {
                    let e = dial_io(e);
                    // The source address itself is unusable (it cannot be bound, or has no
                    // route): that counts against its breaker and another one is tried.
                    // Anything else is the destination's answer and is nobody's fault here.
                    if matches!(
                        e.kind(),
                        io::ErrorKind::AddrNotAvailable | io::ErrorKind::NetworkUnreachable
                    ) {
                        lease.report(false);
                        avoid.push(src);
                        last = Some(ConnectError::Connect(e));
                        continue;
                    }
                    last = Some(ConnectError::Connect(e));
                    break;
                }
                Err(_) => {
                    last = Some(ConnectError::Timeout);
                    break;
                }
            }
        }
    }
    Err(last.unwrap_or(ConnectError::NoAddressOfFamily))
}

fn dial_io(e: DialError) -> io::Error {
    match e {
        DialError::Connect(e) => e,
        other => io::Error::other(other.to_string()),
    }
}

/// Connect for `plan`: through a parent when the route says so, else direct.
pub async fn connect(
    state: &State,
    metrics: &Metrics,
    idle: &ParentConns,
    connect_timeout: Duration,
    plan: &Plan<'_>,
) -> Result<Upstream, ConnectError> {
    let started = Instant::now();
    let work = async {
        if plan.route != Route::Direct {
            let mut tried: Vec<usize> = Vec::new();
            let mut last: Option<ConnectError> = None;
            let mut attempts = 0;
            while attempts < 3 {
                let Some(i) = state.parents.select(plan.parents, &tried) else {
                    break;
                };
                tried.push(i);
                let Some(parent) = state.parents.get(i) else {
                    break;
                };
                // A half-open breaker lets only a few requests through.
                if !parent.breaker.try_acquire() {
                    continue;
                }
                attempts += 1;
                match via_parent(state, metrics, idle, connect_timeout, plan, parent).await {
                    Ok(up) => {
                        parent.report(true);
                        metrics
                            .parent_requests_total
                            .with_label_values(&[&parent.name, "ok"])
                            .inc();
                        return Ok(up);
                    }
                    // Our own egress is out of service: not the parent's fault.
                    Err(
                        e @ (ConnectError::NoAddressOfFamily
                        | ConnectError::EgressUnavailable
                        | ConnectError::BadIndex),
                    ) => {
                        parent.breaker.cancel();
                        last = Some(e);
                        if matches!(last, Some(ConnectError::BadIndex)) {
                            break;
                        }
                    }
                    Err(e) => {
                        parent.report(false);
                        metrics
                            .parent_requests_total
                            .with_label_values(&[&parent.name, "failed"])
                            .inc();
                        last = Some(e);
                    }
                }
            }
            if plan.route == Route::Parent {
                return Err(last.unwrap_or(ConnectError::NoParent));
            }
        }
        direct(plan, connect_timeout, &state.cfg.tcp.upstream).await
    };
    let out = timeout(connect_timeout, work)
        .await
        .unwrap_or(Err(ConnectError::Timeout));
    let label = pool_label(plan.pool);
    metrics
        .egress_connections_total
        .with_label_values(&[
            label,
            match &out {
                Ok(_) => "ok",
                Err(ConnectError::NoAddressOfFamily | ConnectError::BadIndex) => "no_address",
                Err(ConnectError::EgressUnavailable) => "unavailable",
                Err(_) => "failed",
            },
        ])
        .inc();
    if out.is_ok() {
        metrics
            .connect_duration_seconds
            .with_label_values(&[label])
            .observe(started.elapsed().as_secs_f64());
    }
    out
}

async fn direct(
    plan: &Plan<'_>,
    budget: Duration,
    sock: &SocketOptions,
) -> Result<Upstream, ConnectError> {
    let (stream, lease, peer) = connect_ips(
        plan.ips, plan.port, plan.pool, &plan.key, plan.index, budget, sock,
    )
    .await?;
    Ok(Upstream {
        stream,
        lease,
        parent: None,
        peer,
        http_proxy: false,
        reuse_key: None,
        reused: false,
    })
}

async fn via_parent(
    state: &State,
    metrics: &Metrics,
    idle: &ParentConns,
    budget: Duration,
    plan: &Plan<'_>,
    parent: &Arc<Parent>,
) -> Result<Upstream, ConnectError> {
    let fail = |reason: String| ConnectError::Parent {
        name: parent.name.clone(),
        reason,
    };
    let addrs = match state.resolver.resolve(&parent.host).await {
        Ok(a) => {
            metrics.dns_lookups_total.with_label_values(&["ok"]).inc();
            a
        }
        Err(e) => {
            metrics
                .dns_lookups_total
                .with_label_values(&["error"])
                .inc();
            return Err(fail(e.to_string()));
        }
    };
    // The connection to the parent leaves from the parent's own pool, else the request's.
    let own = parent.pool.as_ref().and_then(|n| state.pools.get(n));
    let pool = own.or(plan.pool);
    let http_parent = parent.kind == ParentKind::Http && plan.mode == Mode::Http;
    let reuse_key = (http_parent
        && plan.reuse
        && state.cfg.http.parent_keepalive
        && parent.send_proxy_protocol == SendProxyProtocol::Off)
        .then(|| {
            format!(
                "{}|{}|{:?}|{}",
                parent.name,
                pool_label(pool),
                plan.index,
                String::from_utf8_lossy(&plan.key.bytes_for_reuse())
            )
        });
    if let Some(key) = &reuse_key {
        if let Some((stream, lease, peer)) = idle.take(key) {
            metrics
                .parent_conn_reuse_total
                .with_label_values(&["reused"])
                .inc();
            return Ok(Upstream {
                stream,
                lease,
                parent: Some(Arc::clone(parent)),
                peer,
                http_proxy: true,
                reuse_key,
                reused: true,
            });
        }
        metrics
            .parent_conn_reuse_total
            .with_label_values(&["new"])
            .inc();
    }
    let (mut stream, lease, peer) = match connect_ips(
        &addrs,
        parent.port,
        pool,
        &plan.key,
        plan.index,
        budget,
        &state.cfg.tcp.upstream,
    )
    .await
    {
        Ok(c) => c,
        Err(
            e @ (ConnectError::NoAddressOfFamily
            | ConnectError::EgressUnavailable
            | ConnectError::BadIndex),
        ) => return Err(e),
        Err(e) => return Err(fail(e.to_string())),
    };

    if parent.send_proxy_protocol != SendProxyProtocol::Off
        && let Ok(dst) = stream.peer_addr()
    {
        let header = match parent.send_proxy_protocol {
            SendProxyProtocol::V1 => proxy_protocol::encode_v1(plan.client, dst),
            _ => proxy_protocol::encode_v2(plan.client, dst),
        };
        stream
            .write_all(&header)
            .await
            .map_err(|e| fail(format!("send PROXY header: {e}")))?;
    }

    let target = Target {
        host: plan.host.to_owned(),
        port: plan.port,
    };
    if !http_parent {
        dial::handshake(&mut stream, parent.endpoint(), &target)
            .await
            .map_err(|e| fail(e.to_string()))?;
    }
    Ok(Upstream {
        stream,
        lease,
        parent: Some(Arc::clone(parent)),
        peer,
        http_proxy: http_parent,
        reuse_key,
        reused: false,
    })
}

/// Probe a parent: connect to it from its egress pool and, with `target`, open
/// a tunnel to that `host:port` through it. Used by the active health checks.
pub async fn probe_parent(
    state: &State,
    parent: &Arc<Parent>,
    target: Option<&Target>,
    budget: Duration,
) -> Result<(), ConnectError> {
    let fail = |reason: String| ConnectError::Parent {
        name: parent.name.clone(),
        reason,
    };
    let addrs = state
        .resolver
        .resolve(&parent.host)
        .await
        .map_err(|e| fail(e.to_string()))?;
    let own = parent.pool.as_ref().and_then(|n| state.pools.get(n));
    let key = PickKey {
        session: None,
        user: None,
        client: IpAddr::from([0, 0, 0, 0]),
    };
    let work = async {
        let (mut stream, _lease, _) = connect_ips(
            &addrs,
            parent.port,
            own.or(state.default_pool().as_ref()),
            &key,
            None,
            budget,
            &state.cfg.tcp.upstream,
        )
        .await?;
        if let Some(t) = target {
            dial::handshake(&mut stream, parent.endpoint(), t)
                .await
                .map_err(|e| fail(e.to_string()))?;
        }
        Ok(())
    };
    timeout(budget, work)
        .await
        .unwrap_or(Err(ConnectError::Timeout))
}

struct IdleConn {
    stream: TcpStream,
    lease: Option<Lease>,
    peer: IpAddr,
    since: Instant,
}

/// Idle keep-alive connections to HTTP parents, filed by parent, egress pool
/// and the client key the egress strategy hashes, so a reused connection
/// leaves from an address that strategy could have chosen for the request.
pub struct ParentConns {
    map: Mutex<HashMap<String, Vec<IdleConn>>>,
    max_age: AtomicU64,
    max_total: AtomicUsize,
}

impl Default for ParentConns {
    fn default() -> Self {
        Self {
            map: Mutex::new(HashMap::new()),
            max_age: AtomicU64::new(30_000),
            max_total: AtomicUsize::new(64),
        }
    }
}

/// Idle connections kept per key.
const MAX_PER_KEY: usize = 4;

impl ParentConns {
    /// Take the settings from the running configuration.
    pub fn configure(&self, idle_timeout: Duration, max_total: usize) {
        self.max_age.store(
            u64::try_from(idle_timeout.as_millis()).unwrap_or(u64::MAX),
            Ordering::Relaxed,
        );
        self.max_total.store(max_total, Ordering::Relaxed);
    }

    fn max_age(&self) -> Duration {
        Duration::from_millis(self.max_age.load(Ordering::Relaxed))
    }

    /// An idle connection that is still open and has sent nothing.
    fn take(&self, key: &str) -> Option<(TcpStream, Option<Lease>, IpAddr)> {
        let max_age = self.max_age();
        let mut map = self.map.lock();
        let list = map.get_mut(key)?;
        while let Some(c) = list.pop() {
            if c.since.elapsed() >= max_age {
                continue;
            }
            // A closed peer reads 0 bytes; a live idle one has nothing to read.
            let mut probe = [0u8; 1];
            if matches!(c.stream.try_read(&mut probe), Err(e) if e.kind() == io::ErrorKind::WouldBlock)
            {
                return Some((c.stream, c.lease, c.peer));
            }
        }
        if list.is_empty() {
            map.remove(key);
        }
        None
    }

    /// File a connection for the next request. Dropped when the pool is full.
    pub fn put(&self, key: String, stream: TcpStream, lease: Option<Lease>, peer: IpAddr) {
        let mut map = self.map.lock();
        let total: usize = map.values().map(Vec::len).sum();
        if total >= self.max_total.load(Ordering::Relaxed) {
            return;
        }
        let list = map.entry(key).or_default();
        if list.len() >= MAX_PER_KEY {
            return;
        }
        list.push(IdleConn {
            stream,
            lease,
            peer,
            since: Instant::now(),
        });
    }

    /// Drop connections idle past the limit.
    pub fn reap(&self) {
        let max_age = self.max_age();
        let mut map = self.map.lock();
        for list in map.values_mut() {
            list.retain(|c| c.since.elapsed() < max_age);
        }
        map.retain(|_, l| !l.is_empty());
    }

    pub fn len(&self) -> usize {
        self.map.lock().values().map(Vec::len).sum()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}
