//! The two serving roles. Each one starts the ops server first (so
//! `/healthz` answers while a dependency is still down), connects to
//! Postgres and Redis, loads the snapshot, builds its context, binds the
//! listeners it serves, and runs its tasks until the `CancellationToken`
//! fires. `/readyz` stays 503 `starting` until the listeners are bound, so
//! ready never precedes the sockets. The ops server outlives the rest: on the
//! stop request `/readyz` turns 503 and the drain stays scrapable, and the
//! server stops once every other task has ended.

use std::sync::Arc;
use std::time::Duration;

use anyhow::Context as _;
use common::config::Settings;
use common::metrics::Metrics;
use provider::MobileBoxClient;
use store::loaded::Loaded;
use store::{Db, Hot};
use tokio::net::TcpListener;
use tokio::sync::watch;
use tokio::task::JoinSet;
use tokio_util::sync::CancellationToken;
use verify::{ExitIpChecker, ExitIpConfig, LightProbe, ProbeConfig, Reputation, ReputationConfig};

use crate::{connect, scorers};

/// Name of the ops server task.
const OPS_TASK: &str = "ops";
/// Time to finish after `drain_timeout` (listener close, flush) before the
/// role gives up waiting for a task and aborts it.
const STOP_MARGIN: Duration = Duration::from_secs(15);
/// Descriptors the gateway needs besides the tunnels: listeners, Postgres and
/// Redis connections, the ops server, files.
const FD_MARGIN: u64 = 512;

/// What both roles hold once connected.
struct Started {
    metrics: Arc<Metrics>,
    db: Db,
    hot: Hot,
    loaded: watch::Receiver<Arc<Loaded>>,
}

impl Started {
    /// What `/readyz` checks. Publish it on the sender [`start`] returned only
    /// once everything the role must own to serve is up.
    fn ops_deps(&self) -> api::OpsDeps {
        api::OpsDeps {
            db: self.db.clone(),
            hot: self.hot.clone(),
            loaded: self.loaded.clone(),
        }
    }
}

/// The channel that makes the ops server report ready: `/readyz` answers 503
/// `starting` until a role sends `Some` on it, which it does once the
/// listeners it must own are bound.
type OpsReady = watch::Sender<Option<api::OpsDeps>>;

/// Start the ops server, connect, and load the first snapshot. `sync_git`
/// is the gateway's duty: it copies changed git data into Postgres. `None`
/// when `cancel` fired before startup finished.
async fn start(
    settings: &Settings,
    service: &str,
    sync_git: bool,
    cancel: &CancellationToken,
) -> anyhow::Result<Option<(Tasks, Started, OpsReady)>> {
    let metrics = Arc::new(Metrics::new(service));
    let mut tasks = Tasks::new(cancel, settings.drain_timeout + STOP_MARGIN);
    let (deps_tx, deps_rx) = watch::channel(None);
    tasks.spawn_ops(
        settings.ops_listen,
        api::OpsState::new(Arc::clone(&metrics), deps_rx).with_draining(cancel.clone()),
    );

    let started = tasks
        .until(async {
            let db = connect::db(&settings.database_url, cancel).await?;
            let hot = connect::hot(&settings.redis_url, cancel).await?;
            let loaded = connect::loaded(&db, settings, &metrics, sync_git, cancel).await?;
            tracing::info!("connected and configuration loaded");
            Ok(Started {
                metrics: Arc::clone(&metrics),
                db,
                hot,
                loaded,
            })
        })
        .await;
    let started = match started {
        Ok(started) => started,
        Err(err) => {
            // A stop during startup (a dependency never came up) is not a failure.
            let stopping = cancel.is_cancelled();
            let err = tasks.fail(err).await;
            return if stopping { Ok(None) } else { Err(err) };
        }
    };
    Ok(Some((tasks, started, deps_tx)))
}

/// Serve tunnels and the control API. `/readyz` turns 200 only once the
/// CONNECT, SOCKS5, probe and API listeners are bound by this process: a bind
/// failure (an address in use) ends the role with an error naming the
/// listener, and the ops server never reports ready.
pub async fn gateway(
    settings: Settings,
    service: &str,
    exit_ip: ExitIpConfig,
    cancel: CancellationToken,
) -> anyhow::Result<()> {
    let Some((mut tasks, started, deps)) = start(&settings, service, true, &cancel).await? else {
        return Ok(());
    };
    let ops_deps = started.ops_deps();
    let Started {
        metrics,
        db,
        hot,
        loaded,
    } = started;
    let tunnels = gateway::Tunnels::default();
    let built = (|| {
        let api_state = api::ApiState::new(
            &settings,
            db.clone(),
            hot.clone(),
            loaded.clone(),
            Arc::clone(&metrics),
            Arc::new(tunnels.clone()),
            ExitIpChecker::new(exit_ip.clone(), Arc::clone(&metrics)),
        )
        .context("failed to build the API state")?;
        Ok::<_, anyhow::Error>((Arc::new(api_state), quality(&settings, &metrics)?))
    })();
    let (api_state, (reputation, probe)) = match built {
        Ok(built) => built,
        Err(err) => return Err(tasks.fail(err).await),
    };
    let bound = match bind_listeners(&settings).await {
        Ok(bound) => bound,
        Err(err) => return Err(tasks.fail(err).await),
    };
    deps.send_replace(Some(ops_deps));
    tasks.spawn(
        "api",
        api::serve_listener(bound.api, api_state, cancel.clone()),
    );
    tasks.spawn(
        "gateway",
        gateway::run_on(
            gateway::GatewayCtx {
                settings,
                db,
                hot,
                loaded,
                exit_ip: ExitIpChecker::new(exit_ip, Arc::clone(&metrics)),
                reputation,
                probe,
                metrics,
                tunnels,
            },
            bound.tunnels,
            cancel,
        ),
    );
    tasks.finish().await
}

/// The listeners of the gateway role, owned before it reports ready.
struct GatewayListeners {
    api: TcpListener,
    tunnels: gateway::Bound,
}

/// Bind the control API and the tunnel listeners. The error names the
/// listener and its address.
async fn bind_listeners(settings: &Settings) -> anyhow::Result<GatewayListeners> {
    let api = TcpListener::bind(settings.api_listen)
        .await
        .with_context(|| format!("failed to bind the control API to {}", settings.api_listen))?;
    tracing::info!(addr = %settings.api_listen, "control API listening");
    let tunnels = gateway::Bound::bind(settings).await?;
    Ok(GatewayListeners { api, tunnels })
}

/// Keep the pools, the static inventory and the quality checks healthy. The
/// warmer binds no listener besides the ops server: it is ready once its
/// context is built.
pub async fn warmer(
    settings: Settings,
    service: &str,
    exit_ip: ExitIpConfig,
    cancel: CancellationToken,
) -> anyhow::Result<()> {
    let Some((mut tasks, started, deps)) = start(&settings, service, false, &cancel).await? else {
        return Ok(());
    };
    let ops_deps = started.ops_deps();
    let Started {
        metrics,
        db,
        hot,
        loaded,
    } = started;

    let built = (|| {
        let (reputation, probe) = quality(&settings, &metrics)?;
        Ok::<_, anyhow::Error>(warmer::WarmerCtx {
            reputation,
            probe,
            rotate: MobileBoxClient::new().context("failed to build the SIM box client")?,
            exit_ip: ExitIpChecker::new(exit_ip, Arc::clone(&metrics)),
            settings,
            db,
            hot,
            loaded,
            metrics,
        })
    })();
    let ctx = match built {
        Ok(ctx) => ctx,
        Err(err) => return Err(tasks.fail(err).await),
    };
    deps.send_replace(Some(ops_deps));
    tasks.spawn("warmer", warmer::run(ctx, cancel));
    tasks.finish().await
}

/// The reputation client and light probe of the quality checks.
fn quality(
    settings: &Settings,
    metrics: &Arc<Metrics>,
) -> anyhow::Result<(Reputation, LightProbe)> {
    let reputation = Reputation::new(
        ReputationConfig::default(),
        scorers::slots(settings)?,
        Arc::clone(metrics),
    )
    .context("failed to build the reputation client")?;
    Ok((reputation, LightProbe::new(ProbeConfig::default())))
}

/// The tasks of one role and what to do when one of them ends.
struct Tasks {
    set: JoinSet<(&'static str, anyhow::Result<()>)>,
    cancel: CancellationToken,
    /// How long tasks get to end after `cancel` fired.
    stop_within: Duration,
    /// Stops the ops server, which runs until every other task has ended.
    ops_stop: CancellationToken,
    /// Tasks other than the ops server that have not ended.
    running: usize,
}

impl Tasks {
    fn new(cancel: &CancellationToken, stop_within: Duration) -> Self {
        Self {
            set: JoinSet::new(),
            cancel: cancel.clone(),
            stop_within,
            ops_stop: CancellationToken::new(),
            running: 0,
        }
    }

    fn spawn(
        &mut self,
        name: &'static str,
        task: impl Future<Output = anyhow::Result<()>> + Send + 'static,
    ) {
        self.running += 1;
        self.set.spawn(async move { (name, task.await) });
    }

    /// Start the ops server. It does not stop with `cancel` but when the
    /// other tasks are done.
    fn spawn_ops(&mut self, addr: std::net::SocketAddr, state: api::OpsState) {
        let stop = self.ops_stop.clone();
        self.set
            .spawn(async move { (OPS_TASK, api::serve_ops(addr, Arc::new(state), stop).await) });
    }

    /// Run `startup` while watching the tasks: one that ends first is a
    /// startup failure (the ops server could not bind).
    async fn until<T>(
        &mut self,
        startup: impl Future<Output = anyhow::Result<T>>,
    ) -> anyhow::Result<T> {
        tokio::select! {
            result = startup => result,
            Some(joined) = self.set.join_next() => {
                Err(ended(joined).unwrap_or_else(|| anyhow::anyhow!("a task ended during startup")))
            }
        }
    }

    /// Stop the tasks after a startup failure and return `err`.
    async fn fail(self, err: anyhow::Error) -> anyhow::Error {
        self.cancel.cancel();
        let _ = self.finish().await;
        err
    }

    /// Wait for every task. The first to end, with or without an error,
    /// stops the others; the first error is returned. The ops server stops
    /// last, once no other task runs, so the drain can be scraped.
    async fn finish(mut self) -> anyhow::Result<()> {
        let deadline = {
            let cancel = self.cancel.clone();
            let within = self.stop_within;
            async move {
                cancel.cancelled().await;
                tokio::time::sleep(within).await;
            }
        };
        tokio::pin!(deadline);
        let mut first_err = None;
        loop {
            if self.running == 0 {
                self.ops_stop.cancel();
            }
            let joined = tokio::select! {
                joined = self.set.join_next() => joined,
                () = &mut deadline => {
                    self.set.abort_all();
                    first_err.get_or_insert_with(|| anyhow::anyhow!("tasks did not stop in time"));
                    break;
                }
            };
            let Some(joined) = joined else { break };
            if !matches!(joined, Ok((OPS_TASK, _))) {
                self.running = self.running.saturating_sub(1);
            }
            if !self.cancel.is_cancelled() {
                tracing::error!("a task ended before shutdown, stopping");
            }
            self.cancel.cancel();
            if let Some(err) = ended(joined) {
                first_err.get_or_insert(err);
            }
        }
        first_err.map_or(Ok(()), Err)
    }
}

/// The error of a finished task, with the task named. It is not logged here:
/// the role returns it and `main` logs it once.
fn ended(
    joined: Result<(&'static str, anyhow::Result<()>), tokio::task::JoinError>,
) -> Option<anyhow::Error> {
    match joined {
        Ok((_, Ok(()))) => None,
        Ok((name, Err(err))) => Some(err.context(format!("the {name} task failed"))),
        Err(err) => Some(anyhow::Error::new(err).context("a task panicked")),
    }
}

/// Refuse to start a gateway whose descriptor limit cannot hold
/// `max_connections` tunnels (two descriptors each, plus [`FD_MARGIN`]): once
/// full the pod would answer `provider_unavailable` (EMFILE) instead of
/// refusing at accept. Reads `/proc/self/limits`, so it is skipped where that
/// does not exist.
pub fn check_fd_limit(settings: &Settings) -> anyhow::Result<()> {
    let Ok(limits) = std::fs::read_to_string("/proc/self/limits") else {
        return Ok(());
    };
    ensure_fds(settings.max_connections, nofile_soft(&limits))
}

fn ensure_fds(max_connections: usize, soft: Option<u64>) -> anyhow::Result<()> {
    let needed = (max_connections as u64)
        .saturating_mul(2)
        .saturating_add(FD_MARGIN);
    match soft {
        Some(soft) if soft < needed => anyhow::bail!(
            "the open files limit is {soft} but max_connections = {max_connections} needs \
             {needed} (2 per tunnel and {FD_MARGIN} spare): raise `ulimit -n` or lower max_connections"
        ),
        _ => Ok(()),
    }
}

/// The soft "Max open files" limit in the text of `/proc/self/limits`; `None`
/// for `unlimited` or a line that cannot be read.
fn nofile_soft(limits: &str) -> Option<u64> {
    let line = limits
        .lines()
        .find(|line| line.starts_with("Max open files"))?;
    line.split_whitespace().nth(3)?.parse().ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    const LIMITS: &str = "Limit                     Soft Limit           Hard Limit           Units     \n\
                          Max processes             63000                63000                processes \n\
                          Max open files            1024                 1048576              files     \n";

    #[test]
    fn the_open_files_limit_must_hold_two_descriptors_per_tunnel() {
        let soft = nofile_soft(LIMITS);
        assert_eq!(soft, Some(1024));
        let err = ensure_fds(10_000, soft).expect_err("1024 cannot hold 10000 tunnels");
        assert!(
            format!("{err}").contains("max_connections = 10000"),
            "{err}"
        );
        ensure_fds(256, soft).expect("256 tunnels need 1024");
        let err = ensure_fds(257, soft).expect_err("one over");
        assert!(format!("{err}").contains("needs 1026"), "{err}");
        ensure_fds(10_000, None).expect("unlimited or unreadable passes");
        assert_eq!(
            nofile_soft("Max open files unlimited unlimited files"),
            None
        );
    }

    async fn free_addr() -> std::net::SocketAddr {
        let l = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        l.local_addr().expect("addr")
    }

    async fn status(addr: std::net::SocketAddr, path: &str) -> Option<(u16, String)> {
        let resp = reqwest::get(format!("http://{addr}{path}")).await.ok()?;
        let code = resp.status().as_u16();
        Some((code, resp.text().await.ok()?))
    }

    #[tokio::test]
    async fn the_ops_server_keeps_answering_through_the_drain_and_stops_after_it() {
        let cancel = CancellationToken::new();
        let addr = free_addr().await;
        let metrics = Arc::new(Metrics::new("roles-test"));
        metrics.tunnels_open.set(5);
        let (_deps, deps_rx) = watch::channel(None);
        let mut tasks = Tasks::new(&cancel, Duration::from_secs(30));
        tasks.spawn_ops(
            addr,
            api::OpsState::new(metrics, deps_rx).with_draining(cancel.clone()),
        );
        let (release, released) = tokio::sync::oneshot::channel::<()>();
        let stopping = cancel.clone();
        tasks.spawn("worker", async move {
            // a gateway draining its tunnels: ends some time after the stop request
            stopping.cancelled().await;
            let _ = released.await;
            Ok(())
        });
        let role = tokio::spawn(tasks.finish());
        for _ in 0..50 {
            if status(addr, "/healthz").await.is_some() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }

        cancel.cancel();
        tokio::time::sleep(Duration::from_millis(300)).await;
        assert_eq!(
            status(addr, "/readyz").await,
            Some((503, "draining".to_owned())),
            "not ready from the stop request on"
        );
        assert_eq!(status(addr, "/healthz").await.map(|s| s.0), Some(200));
        let (code, body) = status(addr, "/metrics")
            .await
            .expect("metrics during drain");
        assert_eq!(code, 200);
        assert!(
            body.contains("proxyx_pool_tunnels_open{service=\"roles-test\"} 5"),
            "{body}"
        );
        assert!(!role.is_finished(), "the worker still drains");

        release.send(()).expect("worker waits");
        tokio::time::timeout(Duration::from_secs(5), role)
            .await
            .expect("the role ends once the worker ended")
            .expect("join")
            .expect("clean stop");
        assert!(
            status(addr, "/healthz").await.is_none(),
            "the ops server stopped after the drain"
        );
    }
}
