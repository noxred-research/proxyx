//! Reconcile loops, keepalive, sweeper and cost meter
//!
//!
//! The warmer is its own Deployment. Every replica runs every loop; the
//! partition lock (`SET NX PX 15s`, renewed) decides which replica works on
//! which partition, so no leader election exists. Loops:
//!
//! 1. seed: rebuild Redis from Postgres after a loss
//! 2. locks: keep the partition locks
//! 3. reconcile: rotating partitions, every 5 s, creates sessions
//! 4. keepalive: sessions from the `due` set, neutral request only
//! 5. statics: every 30 s, re-checks, retests, replacement rule
//! 6. boxes: SIM box resets
//! 7. sweeper: stuck state, every 30 s
//! 8. gauges
//!
//! A failed canary pauses a route class (`Hot::warm_pause`): its partitions
//! start no new unit until the API lifts the pause. Static IPs (candidates,
//! cooled and quarantined ones) are still checked and promoted, or no canary
//! could ever pass again.

mod budget;
mod checks;
mod gauges;
mod job;
mod keepalive;
mod mobile_box;
mod plan;
mod reconcile;
mod report;
mod sample;
mod seed;
mod state;
mod statics;
mod sweeper;
#[cfg(test)]
mod tests;

use std::sync::Arc;
use std::time::Duration;

use common::config::Settings;
use common::metrics::Metrics;
use provider::MobileBoxClient;
use store::loaded::Loaded;
use store::{Db, Hot};
use tokio::sync::watch;
use tokio::task::JoinSet;
use tokio_util::sync::CancellationToken;
use verify::{ExitIpChecker, LightProbe, Reputation};

use crate::state::{Timing, Warmer};

/// What the warmer needs from the process.
pub struct WarmerCtx {
    pub settings: Settings,
    pub db: Db,
    pub hot: Hot,
    /// Policies, adapters and the Postgres snapshot, reloaded by the binary.
    pub loaded: watch::Receiver<Arc<Loaded>>,
    pub metrics: Arc<Metrics>,
    pub exit_ip: ExitIpChecker,
    pub reputation: Reputation,
    pub probe: LightProbe,
    pub rotate: MobileBoxClient,
}

/// Longest a tick of a quick loop may run.
const QUICK_TICK_LIMIT: Duration = Duration::from_secs(60);
/// Longest a tick of the static loop may run (many IPs, several calls each).
const SLOW_TICK_LIMIT: Duration = Duration::from_secs(300);
/// Creates and resets get this long to stop after shutdown.
const SHUTDOWN_WAIT: Duration = Duration::from_secs(10);

/// Run every loop until `cancel` fires, then give back the partition locks.
/// Fails when `settings.probe_org` is not an org id, and when a loop ended
/// before shutdown (a panic): the process then stops and restarts, instead of
/// running on with a loop missing and, if it was the locks loop, working
/// partitions another replica has taken.
pub async fn run(ctx: WarmerCtx, cancel: CancellationToken) -> anyhow::Result<()> {
    let warmer = Arc::new(Warmer::new(ctx, Timing::default(), cancel)?);
    let loops = run_loops(&warmer).await;
    warmer.tracker.close();
    if tokio::time::timeout(SHUTDOWN_WAIT, warmer.tracker.wait())
        .await
        .is_err()
    {
        tracing::warn!("creates or resets still running at shutdown");
    }
    warmer.release_locks().await;
    tracing::info!("warmer stopped");
    loops
}

/// Wait for the loops. The first one that ends while `cancel` has not fired
/// stops the others (it cancels, which also stops the role) and is the
/// error.
async fn supervise(cancel: &CancellationToken, mut loops: JoinSet<()>) -> anyhow::Result<()> {
    let mut dead = None;
    while let Some(joined) = loops.join_next().await {
        if !cancel.is_cancelled() {
            let why = match joined {
                Ok(()) => "a warmer loop returned before shutdown".to_owned(),
                Err(error) => format!("a warmer loop died: {error}"),
            };
            tracing::error!("{why}, stopping the warmer");
            dead.get_or_insert(why);
            cancel.cancel();
        }
    }
    dead.map_or(Ok(()), |why| Err(anyhow::anyhow!(why)))
}

async fn run_loops(w: &Arc<Warmer>) -> anyhow::Result<()> {
    // The first pass should not wait a full interval: reconcile needs the
    // locks, and a Redis that was lost must be rebuilt before anything else.
    w.seed_tick().await;
    w.locks_tick().await;
    let mut loops = JoinSet::new();
    macro_rules! spawn_loop {
        ($name:literal, $secs:expr, $limit:expr, $method:ident) => {{
            let w = w.clone();
            loops.spawn(async move {
                w.every($name, Duration::from_secs($secs), $limit, || {
                    let w = w.clone();
                    async move { w.$method().await }
                })
                .await;
            });
        }};
    }
    spawn_loop!("seed", 5, QUICK_TICK_LIMIT, seed_tick);
    spawn_loop!("locks", 5, QUICK_TICK_LIMIT, locks_tick);
    spawn_loop!("reconcile", 5, QUICK_TICK_LIMIT, reconcile_tick);
    spawn_loop!("keepalive", 1, QUICK_TICK_LIMIT, keepalive_tick);
    spawn_loop!("static", 30, SLOW_TICK_LIMIT, static_tick);
    spawn_loop!("boxes", 5, QUICK_TICK_LIMIT, box_tick);
    spawn_loop!("sweeper", 30, QUICK_TICK_LIMIT, sweep_tick);
    spawn_loop!("gauges", 15, QUICK_TICK_LIMIT, gauges_tick);
    tracing::info!("warmer started");
    supervise(&w.cancel, loops).await
}
