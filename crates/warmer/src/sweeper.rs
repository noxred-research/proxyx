//! The sweeper: every 30 s, reclaim state that nothing owns any
//! more. A crashed replica leaves in-flight creates, reservations and lease
//! fields behind; they all carry a deadline, and this loop removes the ones
//! that passed and counts them in `sweeper_reclaimed_total{kind}`. Once an
//! hour (one replica, by a Redis claim) it also prunes the Postgres history
//! that grows with every check and signal ([`store::Db::prune_history`]).

use std::time::Duration;

use common::types::{Kind, Partition};
use store::ReleaseRule;

use crate::state::{Warmer, all_partitions, policy_for};

/// The history is pruned at most this often.
const PRUNE_EVERY: Duration = Duration::from_secs(3_600);

impl Warmer {
    /// One pass over every partition. No lock is needed: removing what has
    /// expired is safe for every replica.
    pub(crate) async fn sweep_tick(&self) {
        let loaded = self.loaded();
        for p in all_partitions(&loaded) {
            if let Err(error) = self.sweep_partition(&p).await {
                self.metrics.redis_down.set(1);
                tracing::warn!(partition = %p, %error, "failed to sweep the partition");
            }
        }
        self.prune_history().await;
    }

    /// Delete the history older than its retention, when no replica did in
    /// the last hour. A failed prune is logged and tried again after the
    /// next claim window.
    async fn prune_history(&self) {
        match self.hot.claim_once("prune-history", PRUNE_EVERY).await {
            Ok(true) => {}
            Ok(false) => return,
            Err(error) => {
                tracing::warn!(%error, "failed to claim the history prune");
                return;
            }
        }
        match self.db.prune_history().await {
            Ok(pruned) if pruned == store::Pruned::default() => {}
            Ok(pruned) => tracing::info!(
                scores = pruned.scores,
                blocks = pruned.blocks,
                audit = pruned.audit,
                "pruned old history from postgres"
            ),
            Err(error) => tracing::warn!(%error, "failed to prune the history in postgres"),
        }
    }

    /// Sweep one partition and count what it reclaimed. The reconcile loop
    /// calls it too, before it counts the partition, because counting also
    /// drops expired entries and would hide them from this metric. A rotating
    /// session that lost its last lease is drained or kept for its org here
    /// (`rotating.after_release`); the probe org's samples are left alone.
    pub(crate) async fn sweep_partition(&self, p: &Partition) -> store::Result<()> {
        let loaded = self.loaded();
        let after = loaded
            .adapters
            .get(&p.provider)
            .filter(|a| a.kind() == Kind::Rotating)
            .map(|_| ReleaseRule {
                after: policy_for(&loaded, &p.provider).rotating.after_release,
                probe_org: &self.probe_org,
            });
        let swept = self.hot.sweep(p, after).await?;
        for (kind, n) in [
            ("session", swept.sessions),
            ("reservation", swept.reservations),
            ("lease", swept.leases),
        ] {
            if n > 0 {
                self.metrics
                    .sweeper_reclaimed_total
                    .with_label_values(&[kind])
                    .inc_by(n);
                tracing::info!(partition = %p, kind, count = n, "sweeper reclaimed stuck state");
            }
        }
        Ok(())
    }
}
