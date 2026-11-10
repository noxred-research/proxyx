//! `proxyx edge`: a self-hosted multi-IP forward proxy.
//!
//! One TOML file, no database. It serves HTTP proxy, HTTPS `CONNECT`, SOCKS4/4a
//! and SOCKS5 (TCP and UDP ASSOCIATE) on any number of listeners, connects to
//! targets from a pool of local addresses chosen per listener, user, rule or
//! login option, and applies ordered access rules, limits, header policy and
//! parent proxies on the way.
//!
//! Layout: [`config`] (the file), [`state`] (the compiled form, swapped on
//! reload), [`conn`] (the per-request pipeline), [`http`] / [`socks`] /
//! [`udp`] (wire protocols), [`connect`] and [`egress`] (outgoing
//! connections), [`acl`], [`auth`], [`limits`], [`parent`], [`dns`],
//! [`headers`], [`accesslog`], [`metrics`] and [`ops`].

pub mod accesslog;
pub mod acl;
pub mod auth;
pub mod breaker;
pub mod config;
pub mod conn;
pub mod connect;
pub mod dns;
pub mod egress;
pub mod headers;
pub mod health;
pub mod http;
pub mod limits;
pub mod metrics;
pub mod ops;
pub mod parent;
pub mod password;
pub mod proxy_protocol;
pub mod relay;
pub mod server;
pub mod sockopt;
pub mod socks;
pub mod state;
pub mod udp;
pub mod wire;

use std::path::Path;
use std::sync::Arc;

use anyhow::Context as _;
use tokio::signal::unix::{SignalKind, signal};

pub use config::Config;
pub use server::Server;

/// What `--check` found.
#[derive(Debug)]
pub struct CheckReport {
    pub listeners: usize,
    pub pools: Vec<(String, Vec<std::net::IpAddr>)>,
    pub parents: usize,
    pub users: usize,
    pub rules: usize,
}

/// Parse and compile the configuration without binding listeners: every
/// reference resolves, every local address is assigned and bindable, every
/// password hash is supported.
pub fn check(path: &Path) -> anyhow::Result<CheckReport> {
    let cfg = Config::load(path)?;
    let rules = cfg.rules.len();
    let state = state::State::build(cfg, None, &metrics::Metrics::new())
        .with_context(|| format!("config {}", path.display()))?;
    let mut pools: Vec<(String, Vec<std::net::IpAddr>)> = state
        .pools
        .iter()
        .map(|(n, p)| (n.clone(), p.addresses()))
        .collect();
    pools.sort();
    Ok(CheckReport {
        listeners: state.listeners.len(),
        pools,
        parents: state.parents.all().len(),
        users: state.users.names().len(),
        rules,
    })
}

fn init_logging(cfg: &Config) {
    use tracing_subscriber::EnvFilter;
    let filter =
        EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(&cfg.log.level));
    let b = tracing_subscriber::fmt().with_env_filter(filter);
    let _ = if cfg.log.json {
        b.json().try_init()
    } else {
        b.try_init()
    };
}

/// Run until SIGTERM or SIGINT. SIGHUP reloads the configuration and reopens the access log.
pub async fn run(path: &Path) -> anyhow::Result<()> {
    let cfg = Config::load(path)?;
    init_logging(&cfg);
    let server = Server::start(path).await?;
    let state = server.shared.state();
    if let Some(addr) = state.cfg.server.ops_listen {
        let bound = ops::serve(Arc::clone(&server), addr)
            .await
            .with_context(|| format!("ops listener {addr}"))?;
        tracing::info!(%bound, "ops listener (/metrics, /healthz, /readyz)");
    }
    let grace = state.cfg.server.shutdown_grace;
    drop(state);

    let mut hup = signal(SignalKind::hangup()).context("install SIGHUP handler")?;
    let mut term = signal(SignalKind::terminate()).context("install SIGTERM handler")?;
    let mut int = signal(SignalKind::interrupt()).context("install SIGINT handler")?;
    loop {
        tokio::select! {
            _ = hup.recv() => {
                tracing::info!("SIGHUP: reloading configuration");
                let _ = server.reload().await;
            }
            _ = term.recv() => break,
            _ = int.recv() => break,
        }
    }
    tracing::info!(?grace, "stopping: waiting for open connections");
    server.shutdown(grace).await;
    Ok(())
}
