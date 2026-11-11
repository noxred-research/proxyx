//! Listeners, the accept loop, protocol detection and configuration reload.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use anyhow::Context as _;
use parking_lot::Mutex;
use tokio::io::{AsyncBufReadExt as _, BufReader};
use tokio::net::{TcpListener, TcpStream};
use tokio::time::timeout;
use tokio_util::sync::CancellationToken;

use crate::accesslog::AccessLog;
use crate::config::{Config, ListenerProtocol, ProxyProtocolMode};
use crate::conn::Shared;
use crate::health;
use crate::metrics::Metrics;
use crate::proxy_protocol::{self, ProxyProtocolError};
use crate::state::{ListenerRt, State};
use crate::transport::Transport;
use crate::{http, socks};

/// The conditions of readiness.
#[derive(Debug)]
pub struct Readiness {
    pub stopping: bool,
    /// Configured listeners that are not bound.
    pub unbound: Vec<String>,
    pub config_loaded: bool,
    /// At least one egress path (a usable pool address, or a parent that is up) can serve.
    pub egress: bool,
}

impl Readiness {
    pub fn is_ready(&self) -> bool {
        !self.stopping && self.unbound.is_empty() && self.config_loaded && self.egress
    }

    /// One line per condition, for the `/readyz` body.
    pub fn report(&self) -> String {
        let line = |ok: bool, what: &str, detail: String| {
            format!("{} {what}{detail}\n", if ok { "ok  " } else { "FAIL" })
        };
        let mut out = line(
            !self.stopping,
            "running",
            if self.stopping {
                ": shutting down".into()
            } else {
                String::new()
            },
        );
        out += &line(self.config_loaded, "config loaded", String::new());
        out += &line(
            self.unbound.is_empty(),
            "listeners bound",
            if self.unbound.is_empty() {
                String::new()
            } else {
                format!(": not bound: {}", self.unbound.join(", "))
            },
        );
        out += &line(
            self.egress,
            "egress path",
            if self.egress {
                String::new()
            } else {
                ": no healthy local address or parent".into()
            },
        );
        out
    }
}

struct Running {
    addr: SocketAddr,
    stop: CancellationToken,
}

/// The running proxy: its shared state and listeners.
pub struct Server {
    pub shared: Arc<Shared>,
    path: PathBuf,
    listeners: Mutex<HashMap<String, Running>>,
}

impl Server {
    /// Load `path`, build the state and bind every listener.
    pub async fn start(path: &Path) -> anyhow::Result<Arc<Self>> {
        let cfg = Config::load(path)?;
        let access = AccessLog::open(&cfg.access_log).context("open the access log")?;
        let metrics = Arc::new(Metrics::new());
        let state = Arc::new(
            State::build(cfg, None, &metrics)
                .with_context(|| format!("config {}", path.display()))?,
        );
        let shared = Shared::new(Arc::clone(&state), access, metrics);
        let server = Arc::new(Self {
            shared,
            path: path.to_owned(),
            listeners: Mutex::new(HashMap::new()),
        });
        let bound = bind_all(&state, &HashMap::new()).await?;
        server.spawn_listeners(&state, bound);
        // Active health checks and the idle parent connection reaper.
        tokio::spawn(health::run(Arc::clone(&server.shared)));
        Ok(server)
    }

    /// What `/readyz` reports.
    pub fn readiness(&self) -> Readiness {
        let state = self.shared.state();
        let running = self.listeners.lock();
        let unbound: Vec<String> = state
            .listeners
            .keys()
            .filter(|n| !running.contains_key(*n))
            .cloned()
            .collect();
        Readiness {
            stopping: self.shared.shutdown.is_cancelled(),
            unbound,
            config_loaded: !state.listeners.is_empty(),
            egress: state.egress_healthy(),
        }
    }

    /// Address each listener is bound to (resolves port 0).
    pub fn local_addrs(&self) -> HashMap<String, SocketAddr> {
        self.listeners
            .lock()
            .iter()
            .map(|(k, v)| (k.clone(), v.addr))
            .collect()
    }

    fn spawn_listeners(self: &Arc<Self>, state: &State, bound: Vec<(String, TcpListener)>) {
        let mut running = self.listeners.lock();
        for (name, listener) in bound {
            let addr = listener
                .local_addr()
                .unwrap_or_else(|_| state.listeners[&name].cfg.listen);
            let stop = CancellationToken::new();
            tracing::info!(listener = %name, %addr, "listening");
            let shared = Arc::clone(&self.shared);
            let token = stop.clone();
            let lname = name.clone();
            self.shared
                .tracker
                .spawn(accept_loop(shared, lname, listener, token));
            running.insert(name, Running { addr, stop });
        }
    }

    /// Re-read the configuration file and apply it. Existing tunnels keep
    /// running; listeners that are new or moved are bound first, so a failure
    /// leaves the running configuration untouched. Also reopens the access log.
    pub async fn reload(self: &Arc<Self>) -> anyhow::Result<()> {
        let result = self.reload_inner().await;
        let label = if result.is_ok() { "ok" } else { "failed" };
        self.shared
            .metrics
            .config_reloads_total
            .with_label_values(&[label])
            .inc();
        if let Err(e) = &result {
            tracing::error!(error = %format!("{e:#}"), "configuration reload failed; keeping the running configuration");
        }
        result
    }

    async fn reload_inner(self: &Arc<Self>) -> anyhow::Result<()> {
        let old = self.shared.state();
        let cfg = Config::load(&self.path)?;
        let new_access = (cfg.access_log != old.cfg.access_log)
            .then(|| AccessLog::open(&cfg.access_log))
            .transpose()
            .context("open the access log")?;
        let new = Arc::new(State::build(cfg, Some(&old), &self.shared.metrics)?);

        let current: HashMap<String, SocketAddr> = self.local_addrs();
        let bound = bind_all(&new, &current).await?;

        self.shared.set_state(Arc::clone(&new));
        // Stop listeners that are gone or moved; their open tunnels go on.
        {
            let mut running = self.listeners.lock();
            running.retain(|name, r| {
                let keep =
                    new.listeners.contains_key(name) && !bound.iter().any(|(n, _)| n == name);
                if !keep {
                    r.stop.cancel();
                    tracing::info!(listener = %name, "listener stopped");
                }
                keep
            });
        }
        self.spawn_listeners(&new, bound);

        match new_access {
            Some(log) => self.shared.set_access_log(log),
            None => {
                if let Err(e) = self.shared.access_log().reopen() {
                    tracing::warn!(error = %e, "cannot reopen the access log");
                }
            }
        }
        if new.cfg.server.ops_listen != old.cfg.server.ops_listen {
            tracing::warn!("server.ops_listen changed: restart to move the ops listener");
        }
        tracing::info!(
            listeners = new.listeners.len(),
            pools = new.pools.len(),
            parents = new.parents.all().len(),
            "configuration reloaded"
        );
        Ok(())
    }

    /// Stop accepting and wait for open connections, up to `grace`.
    pub async fn shutdown(&self, grace: Duration) {
        self.shared.shutdown.cancel();
        self.shared.tracker.close();
        if timeout(grace, self.shared.tracker.wait()).await.is_err() {
            tracing::warn!("grace period over: closing the remaining connections");
        }
    }
}

/// Bind the listeners that are new or whose address changed. `current` is what runs now.
async fn bind_all(
    state: &State,
    current: &HashMap<String, SocketAddr>,
) -> anyhow::Result<Vec<(String, TcpListener)>> {
    let mut out = Vec::new();
    for (name, rt) in &state.listeners {
        let want = rt.cfg.listen;
        let same = current
            .get(name)
            .is_some_and(|have| *have == want || (want.port() == 0 && have.ip() == want.ip()));
        if same {
            continue;
        }
        let l = TcpListener::bind(want)
            .await
            .with_context(|| format!("listener {name}: bind {want}"))?;
        out.push((name.clone(), l));
    }
    Ok(out)
}

async fn accept_loop(
    shared: Arc<Shared>,
    name: String,
    listener: TcpListener,
    stop: CancellationToken,
) {
    loop {
        let accepted = tokio::select! {
            _ = stop.cancelled() => return,
            _ = shared.shutdown.cancelled() => return,
            r = listener.accept() => r,
        };
        let (stream, addr) = match accepted {
            Ok(a) => a,
            Err(e) => {
                tracing::warn!(listener = %name, error = %e, "accept failed");
                // Out of descriptors and the like: do not spin.
                tokio::time::sleep(Duration::from_millis(100)).await;
                continue;
            }
        };
        let state = shared.state();
        let Some(rt) = state.listeners.get(&name).cloned() else {
            continue;
        };
        let metrics = &shared.metrics;
        let Some(total) = shared.conns.acquire_total(state.cfg.server.max_connections) else {
            metrics
                .connections_total
                .with_label_values(&[&name, "over_limit"])
                .inc();
            metrics
                .limit_rejections_total
                .with_label_values(&["global"])
                .inc();
            continue;
        };
        let Some(per_listener) = shared
            .conns
            .per_listener
            .acquire(name.clone(), rt.cfg.max_connections)
        else {
            metrics
                .connections_total
                .with_label_values(&[&name, "over_limit"])
                .inc();
            metrics
                .limit_rejections_total
                .with_label_values(&["listener"])
                .inc();
            continue;
        };
        let sh = Arc::clone(&shared);
        shared.tracker.spawn(async move {
            let _total = total;
            let _per_listener = per_listener;
            connection(sh, rt, stream, addr).await;
        });
    }
}

async fn connection(shared: Arc<Shared>, rt: ListenerRt, stream: TcpStream, tcp_peer: SocketAddr) {
    let name = rt.cfg.name.clone();
    let metrics = &shared.metrics;
    let state = shared.state();
    if let Err(e) = crate::sockopt::apply(&stream, &state.cfg.tcp.client) {
        tracing::debug!(error = %e, "cannot set client socket options");
    }

    // PROXY protocol: the header's source address stands for the client when the
    // peer is a trusted proxy.
    let mut peer = tcp_peer;
    let mode = rt.cfg.proxy_protocol;
    if mode != ProxyProtocolMode::Off {
        let trusted = rt.trusted.iter().any(|n| n.contains(&tcp_peer.ip()));
        if trusted {
            match proxy_protocol::read_header(&stream, state.cfg.timeouts.handshake).await {
                Ok(h) => {
                    if let Some(src) = h.src {
                        peer = src;
                    }
                }
                Err(ProxyProtocolError::NotProxyProtocol)
                    if mode == ProxyProtocolMode::Optional => {}
                Err(_) => {
                    metrics
                        .connections_total
                        .with_label_values(&[&name, "proxy_protocol_error"])
                        .inc();
                    return;
                }
            }
        } else if mode == ProxyProtocolMode::Required {
            metrics
                .connections_total
                .with_label_values(&[&name, "proxy_protocol_error"])
                .inc();
            return;
        }
    }

    let Some(_per_src) = shared
        .conns
        .per_src
        .acquire(peer.ip(), state.cfg.server.max_connections_per_src)
    else {
        metrics
            .connections_total
            .with_label_values(&[&name, "over_limit"])
            .inc();
        metrics
            .limit_rejections_total
            .with_label_values(&["per_src"])
            .inc();
        return;
    };

    metrics
        .connections_total
        .with_label_values(&[&name, "accepted"])
        .inc();
    let open = metrics.connections_open.with_label_values(&[&name]);
    open.inc();
    let local_ip = stream.local_addr().map_or(rt.cfg.listen.ip(), |a| a.ip());
    if crate::conn::check_stage(
        &shared,
        &state,
        &rt,
        peer,
        None,
        crate::config::RuleStage::PreNegotiation,
        crate::acl::Proto::Http,
    )
    .is_ok()
    {
        if let Some(acceptor) = &rt.tls {
            match timeout(state.cfg.timeouts.handshake, acceptor.accept(stream)).await {
                Ok(Ok(tls)) => {
                    let h2 = tls.get_ref().1.alpn_protocol() == Some(b"h2");
                    if h2 {
                        crate::h2_connect::serve(Arc::clone(&shared), rt, tls, peer).await;
                    } else {
                        dispatch(Arc::clone(&shared), rt, tls, local_ip, peer).await;
                    }
                }
                _ => {
                    metrics
                        .connections_total
                        .with_label_values(&[&name, "tls_error"])
                        .inc();
                }
            }
        } else {
            dispatch(Arc::clone(&shared), rt, stream, local_ip, peer).await;
        }
    }
    open.dec();
}

async fn dispatch<S: Transport>(
    shared: Arc<Shared>,
    rt: ListenerRt,
    stream: S,
    local_ip: std::net::IpAddr,
    peer: SocketAddr,
) {
    let mut stream = BufReader::new(stream);
    let handshake = shared.state().cfg.timeouts.handshake;
    let socks = match rt.cfg.protocol {
        ListenerProtocol::Http => false,
        ListenerProtocol::Socks => true,
        ListenerProtocol::Auto => match timeout(handshake, stream.fill_buf()).await {
            Ok(Ok(b)) if !b.is_empty() => matches!(b[0], 4 | 5),
            _ => return,
        },
    };
    if socks {
        socks::serve(shared, rt, stream, local_ip, peer).await;
    } else {
        http::serve(shared, rt, stream, peer, Vec::new()).await;
    }
}
