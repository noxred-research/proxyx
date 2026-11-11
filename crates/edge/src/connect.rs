//! Opening the connection to the target: directly from a pool address, or
//! through a parent proxy.
//!
//! The destination addresses were resolved and checked before this runs, and
//! this connects to exactly those addresses (a second resolution could answer
//! differently). Each address gets a source address of its own IP family
//! from the pool, bound before `connect`.

use std::collections::HashMap;
use std::future::{Future, poll_fn};
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::task::{Context, Poll, Waker};
use std::time::Duration;

use common::types::Target;
use dial::{DialError, ProxyStream};
use parking_lot::Mutex;
use tokio::io::{AsyncRead, AsyncReadExt as _, AsyncWrite, AsyncWriteExt as _, ReadBuf};
use tokio::net::TcpStream;
use tokio::time::{Instant, timeout};

use crate::config::{
    HashKey, ParentKind, ProbeConfig, Route, SendProxyProtocol, SocketOptions, Strategy,
};
use crate::dns::DnsError;
use crate::egress::{Family, Lease, PickError, PickKey, Pool};
use crate::metrics::Metrics;
use crate::parent::{Attempt, Parent, ParentUse, Selector, split_host_port};
use crate::proxy_protocol;
use crate::sockopt;
use crate::state::{Chain, State};
use crate::stick::Mapping;

#[path = "parent_connect.rs"]
mod parent_connect;
pub use parent_connect::{check_probe, probe_chain};
use parent_connect::{
    connect_chain, connect_group, execute_probe, first_success, handshake, probe_key,
};

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
    #[error("stick affinity unavailable: {0}")]
    Stick(String),
}

#[derive(Clone, Copy)]
pub struct Plan<'a> {
    pub port: u16,
    /// Resolved and checked destination addresses (never empty).
    pub ips: &'a [IpAddr],
    pub pool: Option<&'a Arc<Pool>>,
    pub index: Option<usize>,
    pub key: PickKey<'a>,
    pub route: Route,
    /// Parents the route allows; empty is all.
    pub parents: &'a [usize],
    pub chain: Option<&'a Chain>,
    pub pinned: Option<&'a [String]>,
    pub mode: Mode,
    pub client: SocketAddr,
    /// The request is bodyless and may use (and leave) an idle connection to an HTTP parent.
    pub reuse: bool,
}

impl Plan<'_> {
    /// Pin the parent request to an address already approved by the edge.
    fn target(&self) -> Result<Target, ConnectError> {
        Ok(Target {
            host: self
                .ips
                .first()
                .ok_or(ConnectError::NoAddressOfFamily)?
                .to_string(),
            port: self.port,
        })
    }
}

pub struct Upstream {
    pub stream: ProxyStream,
    pub bound_addr: Option<SocketAddr>,
    pub chain: Vec<String>,
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
        self.bound_addr.map(|a| a.ip())
    }
}

fn pool_label(pool: Option<&Arc<Pool>>) -> &str {
    pool.map_or("none", |p| p.name())
}

/// All affinity attributes participate: a SID must not mask client-IP or host hashing.
fn parent_reuse_key(
    state: &State,
    plan: &Plan<'_>,
    parents: &[Arc<Parent>],
    pool: Option<&Arc<Pool>>,
) -> String {
    use base64::Engine as _;
    use sha2::{Digest as _, Sha256};
    let mut hash = Sha256::new();
    hash.update(state.generation.to_be_bytes());
    hash.update(
        u64::try_from(parents.len())
            .unwrap_or(u64::MAX)
            .to_be_bytes(),
    );
    for parent in parents {
        hash.update(
            u64::try_from(parent.name.len())
                .unwrap_or(u64::MAX)
                .to_be_bytes(),
        );
        hash.update(parent.name.as_bytes());
    }
    let pool = pool_label(pool);
    hash.update(u64::try_from(pool.len()).unwrap_or(u64::MAX).to_be_bytes());
    hash.update(pool.as_bytes());
    hash.update(
        u64::try_from(plan.index.unwrap_or(0))
            .unwrap_or(u64::MAX)
            .to_be_bytes(),
    );
    for attribute in [
        HashKey::ClientIp,
        HashKey::TargetHost,
        HashKey::User,
        HashKey::SessionId,
    ] {
        hash.update(plan.key.hash_bytes(attribute));
    }
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(hash.finalize())
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
            if pool.strategy() == Strategy::Race {
                let leases = match pool.candidates(Family::of(ip), key, index, &avoid) {
                    Ok(leases) => leases,
                    Err(PickError::NoAddressOfFamily) => {
                        last = Some(ConnectError::NoAddressOfFamily);
                        break;
                    }
                    Err(PickError::Unavailable) => {
                        last = Some(ConnectError::EgressUnavailable);
                        break;
                    }
                    Err(PickError::BadIndex) => {
                        last = Some(ConnectError::BadIndex);
                        break;
                    }
                };
                let attempted: Vec<_> = leases.iter().map(Lease::ip).collect();
                let futures = leases
                    .into_iter()
                    .map(|mut lease| async move {
                        let started = Instant::now();
                        match timeout(
                            per_try.min(deadline.saturating_duration_since(started)),
                            dial::connect_from(vec![sa], Some(lease.ip())),
                        )
                        .await
                        {
                            Ok(Ok(stream)) => {
                                lease.report_latency(started.elapsed());
                                lease.report(true);
                                let _ = sockopt::apply(&stream, sock);
                                Ok((stream, Some(lease), ip))
                            }
                            Ok(Err(e)) => {
                                let e = dial_io(e);
                                if matches!(
                                    e.kind(),
                                    io::ErrorKind::AddrNotAvailable
                                        | io::ErrorKind::NetworkUnreachable
                                ) {
                                    lease.report(false);
                                }
                                Err(ConnectError::Connect(e))
                            }
                            Err(_) => Err(ConnectError::Timeout),
                        }
                    })
                    .collect();
                match first_success(futures).await {
                    Ok(result) => return Ok(result),
                    Err(error) => {
                        last = Some(error);
                        avoid.extend(attempted);
                        continue;
                    }
                }
            }
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
                Err(PickError::BadIndex) => {
                    last = Some(ConnectError::BadIndex);
                    break;
                }
            };
            let src = lease.ip();
            let dial_started = Instant::now();
            match timeout(left.min(per_try), dial::connect_from(vec![sa], Some(src))).await {
                Ok(Ok(s)) => {
                    lease.report(true);
                    lease.report_latency(dial_started.elapsed());
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
    let selector = plan
        .chain
        .and_then(|c| c.hops.first().map(|h| &h.selector))
        .unwrap_or(&state.selector);
    let work = async {
        if plan.route != Route::Direct {
            let result = if let Some(chain) = plan.chain {
                connect_chain(state, metrics, idle, connect_timeout, plan, chain).await
            } else {
                connect_group(state, metrics, idle, connect_timeout, plan, selector).await
            };
            match result {
                Ok(up) => return Ok(up),
                Err(error @ ConnectError::Stick(_)) => return Err(error),
                Err(error) if plan.route == Route::Parent => return Err(error),
                Err(_) => {}
            }
        }
        direct(state, plan, connect_timeout, &state.cfg.tcp.upstream).await
    };
    let out = timeout(selector.cfg.forward_timeout, work)
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
    state: &State,
    plan: &Plan<'_>,
    budget: Duration,
    sock: &SocketOptions,
) -> Result<Upstream, ConnectError> {
    let index = parent_connect::direct_index(state, plan).await?;
    let (stream, lease, peer) = connect_ips(
        plan.ips, plan.port, plan.pool, &plan.key, index, budget, sock,
    )
    .await?;
    Ok(Upstream {
        bound_addr: stream.local_addr().ok(),
        stream: stream.into(),
        chain: Vec::new(),
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
    let Some(attempt) = Attempt::start(parent) else {
        return Err(ConnectError::NoParent);
    };
    let fail = |reason: String| ConnectError::Parent {
        name: parent.name.clone(),
        reason,
    };
    let work = async {
        let addrs = match state.resolver.resolve(&parent.host).await {
            Ok(addrs) => {
                metrics.dns_lookups_total.with_label_values(&["ok"]).inc();
                addrs
            }
            Err(error) => {
                metrics
                    .dns_lookups_total
                    .with_label_values(&["error"])
                    .inc();
                return Err(fail(error.to_string()));
            }
        };
        let own = parent.pool.as_ref().and_then(|n| state.pools.get(n));
        let pool = own.or(plan.pool);
        let http_parent =
            matches!(parent.kind, ParentKind::Http | ParentKind::Https) && plan.mode == Mode::Http;
        let reuse_key = (http_parent
            && plan.reuse
            && state.cfg.http.parent_keepalive
            && parent.send_proxy_protocol == SendProxyProtocol::Off)
            .then(|| parent_reuse_key(state, plan, std::slice::from_ref(parent), pool));
        if let Some(key) = &reuse_key {
            if let Some((stream, lease, peer, bound_addr)) = idle.take(key) {
                metrics
                    .parent_conn_reuse_total
                    .with_label_values(&["reused"])
                    .inc();
                return Ok(Upstream {
                    stream,
                    bound_addr,
                    chain: vec![parent.name.clone()],
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
        let (mut tcp, lease, peer) = connect_ips(
            &addrs,
            parent.port,
            pool,
            &plan.key,
            plan.index,
            budget,
            &state.cfg.tcp.upstream,
        )
        .await?;
        let bound_addr = tcp.local_addr().ok();
        if parent.send_proxy_protocol != SendProxyProtocol::Off
            && let Ok(dst) = tcp.peer_addr()
        {
            let header = match parent.send_proxy_protocol {
                SendProxyProtocol::V1 => proxy_protocol::encode_v1(plan.client, dst),
                _ => proxy_protocol::encode_v2(plan.client, dst),
            };
            tcp.write_all(&header)
                .await
                .map_err(|e| fail(format!("send PROXY header: {e}")))?;
        }
        let target = plan.target()?;
        let stream = if http_parent {
            dial::proxy_transport(tcp, parent.endpoint())
                .await
                .map_err(|e| fail(e.to_string()))?
        } else {
            handshake(tcp.into(), parent, &target).await?
        };
        Ok(Upstream {
            stream,
            bound_addr,
            chain: vec![parent.name.clone()],
            lease,
            parent: Some(Arc::clone(parent)),
            peer,
            http_proxy: http_parent,
            reuse_key,
            reused: false,
        })
    };
    let result = timeout(budget, work)
        .await
        .unwrap_or(Err(ConnectError::Timeout));
    match &result {
        Err(
            ConnectError::NoAddressOfFamily
            | ConnectError::EgressUnavailable
            | ConnectError::BadIndex,
        ) => drop(attempt),
        Ok(upstream) if upstream.http_proxy => attempt.defer_http(upstream.reused),
        _ => attempt.finish(result.is_ok()),
    }
    metrics
        .parent_requests_total
        .with_label_values(&[&parent.name, if result.is_ok() { "ok" } else { "failed" }])
        .inc();
    result
}

/// Probe a parent: connect to it from its egress pool and, with `target`, open
/// a tunnel to that `host:port` through it. Used by the active health checks.
pub async fn probe_parent(
    state: &State,
    parent: &Arc<Parent>,
    target: Option<&Target>,
    budget: Duration,
) -> Result<(), ConnectError> {
    let work = async {
        if let Some(probe) = &parent.probe {
            return execute_probe(state, std::slice::from_ref(parent), probe, budget).await;
        }
        let tunnel = target.is_some();
        let target = target.cloned().unwrap_or_else(|| Target {
            host: parent.host.clone(),
            port: parent.port,
        });
        let addrs = state.resolver.resolve(&parent.host).await?;
        let own = parent.pool.as_ref().and_then(|n| state.pools.get(n));
        let key = probe_key(&target.host);
        let default = state.default_pool();
        let (tcp, _lease, _) = connect_ips(
            &addrs,
            parent.port,
            own.or(default.as_ref()),
            &key,
            None,
            budget,
            &state.cfg.tcp.upstream,
        )
        .await?;
        if tunnel {
            handshake(tcp.into(), parent, &target).await?;
        }
        Ok(())
    };
    timeout(budget, work)
        .await
        .unwrap_or(Err(ConnectError::Timeout))
}

struct IdleConn {
    stream: ProxyStream,
    local_ip: Option<IpAddr>,
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
    fn take(&self, key: &str) -> Option<(ProxyStream, Option<Lease>, IpAddr, Option<SocketAddr>)> {
        let max_age = self.max_age();
        let mut map = self.map.lock();
        let list = map.get_mut(key)?;
        while let Some(c) = list.pop() {
            if c.since.elapsed() >= max_age {
                continue;
            }
            // A closed peer reads 0 bytes; a live idle one has nothing to read.
            let mut probe = [0u8; 1];
            let mut probe = ReadBuf::new(&mut probe);
            let mut stream = c.stream;
            let mut cx = Context::from_waker(Waker::noop());
            if Pin::new(&mut stream)
                .poll_read(&mut cx, &mut probe)
                .is_pending()
            {
                let bound_addr = stream
                    .local_addr()
                    .ok()
                    .or_else(|| c.local_ip.map(|ip| SocketAddr::new(ip, 0)));
                return Some((stream, c.lease, c.peer, bound_addr));
            }
        }
        if list.is_empty() {
            map.remove(key);
        }
        None
    }

    /// File a connection for the next request. Dropped when the pool is full.
    pub fn put(
        &self,
        key: String,
        stream: ProxyStream,
        lease: Option<Lease>,
        peer: IpAddr,
        local_ip: Option<IpAddr>,
    ) {
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
            local_ip,
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
