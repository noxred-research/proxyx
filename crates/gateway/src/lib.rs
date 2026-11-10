//! CONNECT and SOCKS5 listeners, lease and relay.
//!
//! [`run`] serves three listeners from [`common::config::Settings`]:
//!
//! * `connect_listen`: HTTP CONNECT. the session proxy and the browser pool connect here.
//! * `socks_listen`: SOCKS5 with username/password (RFC 1929).
//! * `probe_listen`: HTTP CONNECT for the prober's browsers. Its password
//!   is a short-lived token the control API signs with the probe secret
//!   ([`common::probe_token`]), not an org key, and it opens only the hosts of
//!   `probe-targets.toml`. The two other listeners refuse the token and the
//!   probe org's keys.
//!
//! The password is the org key and the username carries the options
//! ([`policy::InboundOptions`]). A tunnel is authenticated, narrowed by the
//! policy, leased, dialed through the provider and relayed byte for byte.
//! Every refusal answers with its [`common::Cause`], never with a direct dial.
//! On cancel the listeners stop and open tunnels get `drain_timeout` to end
//! before they are closed. At most `max_connections` client connections run
//! at once across all listeners; a full pod closes the next one at once
//! (`over_limit` in `connections_total`). At most `max_pending_connections`
//! of them may be unauthenticated, and at most `max_pending_per_ip` per source
//! (an IPv4 address, an IPv6 /64): past either a new connection is closed at
//! once (`over_limit` too), so stalled clients cannot fill the pod. An
//! unauthenticated connection must send its first byte within 3 s and its
//! whole head within 10 s, or it is closed (`bad_request`). A tunnel
//! ends when it is silent for `tunnel_idle_timeout`, 60 s after one side
//! closed, or when TCP keepalive finds a dead peer.

mod acquire;
mod auth;
mod credentials;
mod gateway;
mod listener;
mod relay;
mod tunnels;
mod wire;

#[cfg(test)]
mod tests;

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Context as _;
use common::config::Settings;
use common::metrics::Metrics;
use store::loaded::Loaded;
use store::{Db, Hot};
use tokio::net::TcpListener;
use tokio::sync::watch;
use tokio::task::JoinSet;
use tokio::time::timeout;
use tokio_util::sync::CancellationToken;
use verify::{ExitIpChecker, LightProbe, Reputation};

pub use tunnels::Tunnels;

use crate::gateway::{Gateway, Listener, Pacing};
use crate::listener::accept_loop;

/// After the drain deadline, tunnels get this long to close before `run` returns.
const CLOSE_GRACE: Duration = Duration::from_secs(5);

/// Everything the data plane needs.
pub struct GatewayCtx {
    pub settings: Settings,
    pub db: Db,
    pub hot: Hot,
    pub loaded: watch::Receiver<Arc<Loaded>>,
    pub metrics: Arc<Metrics>,
    pub exit_ip: ExitIpChecker,
    /// Scorers of the reputation rule, the same as the warmer's: a session
    /// created on demand passes the checks of a warmed one.
    pub reputation: Reputation,
    pub probe: LightProbe,
    /// The registry of open tunnels. Give a clone to the control API, which
    /// closes tunnels with it when an operator blocks an org.
    pub tunnels: Tunnels,
}

/// The bound listeners.
pub(crate) struct Bound {
    connect: TcpListener,
    socks: TcpListener,
    probe: TcpListener,
}

impl Bound {
    pub(crate) async fn bind(settings: &Settings) -> anyhow::Result<Self> {
        let bind = |name: &'static str, addr: SocketAddr| async move {
            TcpListener::bind(addr)
                .await
                .with_context(|| format!("failed to bind the {name} listener on {addr}"))
        };
        Ok(Self {
            connect: bind("connect", settings.connect_listen).await?,
            socks: bind("socks", settings.socks_listen).await?,
            probe: bind("probe", settings.probe_listen).await?,
        })
    }

    pub(crate) fn addrs(&self) -> anyhow::Result<[SocketAddr; 3]> {
        let addr = |l: &TcpListener| l.local_addr().context("failed to read a listener address");
        Ok([addr(&self.connect)?, addr(&self.socks)?, addr(&self.probe)?])
    }
}

/// Serve the CONNECT, SOCKS5 and probe listeners until `cancel` fires, then
/// drain for `settings.drain_timeout` and close what is left.
///
/// Fails when a listener cannot bind or `probe_org` is not an org id.
pub async fn run(ctx: GatewayCtx, cancel: CancellationToken) -> anyhow::Result<()> {
    let bound = Bound::bind(&ctx.settings).await?;
    run_bound(ctx, bound, cancel, Pacing::default()).await
}

pub(crate) async fn run_bound(
    ctx: GatewayCtx,
    bound: Bound,
    cancel: CancellationToken,
    pacing: Pacing,
) -> anyhow::Result<()> {
    let drain = ctx.settings.drain_timeout;
    let [connect, socks, probe] = bound.addrs()?;
    let gw = Arc::new(Gateway::new(ctx, pacing)?);

    let mut accepts = JoinSet::new();
    for (listener, kind) in [
        (bound.connect, Listener::Connect),
        (bound.socks, Listener::Socks),
        (bound.probe, Listener::Probe),
    ] {
        accepts.spawn(accept_loop(Arc::clone(&gw), listener, kind, cancel.clone()));
    }
    accepts.spawn(credentials::forget_cooldowns_of_new_logins(
        Arc::clone(&gw),
        cancel.clone(),
    ));
    tracing::info!(%connect, %socks, %probe, "gateway listening");
    while accepts.join_next().await.is_some() {}

    gw.tracker.close();
    tracing::info!(
        open_tunnels = gw.tunnels.count(),
        drain_secs = drain.as_secs(),
        "draining tunnels"
    );
    if timeout(drain, gw.tracker.wait()).await.is_err() {
        tracing::warn!(
            open_tunnels = gw.tunnels.count(),
            "drain deadline reached, closing tunnels"
        );
        gw.tunnels.close_all();
        if timeout(CLOSE_GRACE, gw.tracker.wait()).await.is_err() {
            tracing::warn!("tunnels did not close in time");
        }
    }
    Ok(())
}
