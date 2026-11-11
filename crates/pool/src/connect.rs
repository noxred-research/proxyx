//! Wait for the database, Redis and the first configuration without
//! crash-looping the pod.
//!
//! A dependency that is down at start is retried with capped, jittered
//! backoff until it answers or the process is told to stop. The ops server is
//! already up by then, so `/healthz` stays 200 and `/readyz` reports the
//! missing dependency instead of the kubelet restarting the pod. The same
//! holds for a first configuration load that fails: a warmer that starts
//! before the gateway has synced the git policies must wait for them.

use std::fmt::Display;
use std::sync::Arc;
use std::time::Duration;

use common::Secret;
use common::config::Settings;
use common::metrics::Metrics;
use common::retry::full_jitter;
use store::loaded::Loaded;
use store::{Db, Hot};
use tokio::sync::watch;
use tokio_util::sync::CancellationToken;

/// An attempt that takes longer counts as failed. The configuration load, the
/// slowest, has its own 30 s bound in `store::loaded`.
const ATTEMPT_TIMEOUT: Duration = Duration::from_secs(30);
/// First retry waits up to this long (full jitter).
const BACKOFF_BASE: Duration = Duration::from_millis(500);
/// No retry waits longer than this.
const BACKOFF_CAP: Duration = Duration::from_secs(15);

/// Connect to the database (`postgres://`, `mysql://` / `mariadb://` or
/// `sqlite://`), retrying until it answers or `cancel` fires.
pub(crate) async fn db(url: &Secret, cancel: &CancellationToken) -> anyhow::Result<Db> {
    retry("database", cancel, || Db::connect(url.expose())).await
}

/// Connect to Redis, retrying until it answers or `cancel` fires.
pub(crate) async fn hot(url: &Secret, cancel: &CancellationToken) -> anyhow::Result<Hot> {
    retry("redis", cancel, || Hot::connect(url.expose())).await
}

/// Load the first configuration snapshot and start its reload loop, retrying
/// until it loads or `cancel` fires. `sync_git` is the gateway's duty.
pub(crate) async fn loaded(
    db: &Db,
    settings: &Settings,
    metrics: &Arc<Metrics>,
    sync_git: bool,
    cancel: &CancellationToken,
) -> anyhow::Result<watch::Receiver<Arc<Loaded>>> {
    retry("configuration", cancel, || {
        store::loaded::sync_and_watch(
            db.clone(),
            settings,
            Arc::clone(metrics),
            cancel.clone(),
            sync_git,
        )
    })
    .await
}

async fn retry<T, E, F, Fut>(
    dependency: &'static str,
    cancel: &CancellationToken,
    mut attempt: F,
) -> anyhow::Result<T>
where
    F: FnMut() -> Fut,
    Fut: Future<Output = Result<T, E>>,
    E: Display,
{
    let mut failures = 0u32;
    loop {
        let attempted = tokio::select! {
            () = cancel.cancelled() => anyhow::bail!("stopped while waiting for {dependency}"),
            attempted = tokio::time::timeout(ATTEMPT_TIMEOUT, attempt()) => attempted,
        };
        let err = match attempted {
            Ok(Ok(value)) => return Ok(value),
            Ok(Err(err)) => format!("{err:#}"),
            Err(_) => "the attempt timed out".to_owned(),
        };
        let delay = full_jitter(BACKOFF_BASE, BACKOFF_CAP, failures);
        failures = failures.saturating_add(1);
        tracing::warn!(dependency, failures, retry_in = ?delay, error = %err, "dependency not ready");
        tokio::select! {
            () = cancel.cancelled() => {
                anyhow::bail!("stopped while waiting for {dependency}");
            }
            () = tokio::time::sleep(delay) => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicU32, Ordering};

    use super::*;

    #[tokio::test(start_paused = true)]
    async fn a_dependency_that_comes_up_late_is_reached() {
        let calls = AtomicU32::new(0);
        let got = retry("test", &CancellationToken::new(), || async {
            if calls.fetch_add(1, Ordering::Relaxed) < 3 {
                Err("refused")
            } else {
                Ok(7)
            }
        })
        .await
        .expect("fourth attempt succeeds");
        assert_eq!(got, 7);
        assert_eq!(calls.load(Ordering::Relaxed), 4);
    }

    #[tokio::test(start_paused = true)]
    async fn stopping_ends_the_wait_with_an_error() {
        let cancel = CancellationToken::new();
        let stopper = cancel.clone();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_secs(60)).await;
            stopper.cancel();
        });
        let err = retry::<(), _, _, _>("redis", &cancel, || async { Err("refused") })
            .await
            .expect_err("never connects");
        assert!(err.to_string().contains("redis"), "{err}");
    }

    #[tokio::test(start_paused = true)]
    async fn an_attempt_that_never_answers_is_retried_and_cut_short_by_a_stop() {
        let cancel = CancellationToken::new();
        let stopper = cancel.clone();
        tokio::spawn(async move {
            tokio::time::sleep(ATTEMPT_TIMEOUT * 3).await;
            stopper.cancel();
        });
        let calls = AtomicU32::new(0);
        let hung = || {
            calls.fetch_add(1, Ordering::Relaxed);
            std::future::pending::<Result<(), &str>>()
        };
        let result = tokio::time::timeout(ATTEMPT_TIMEOUT * 10, retry("redis", &cancel, hung))
            .await
            .expect("a stop ends a hung attempt");
        assert!(result.is_err(), "stopped, not connected");
        assert!(
            calls.load(Ordering::Relaxed) >= 2,
            "a hung attempt counts as failed and is tried again"
        );
    }
}
