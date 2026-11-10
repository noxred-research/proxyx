//! Redis seed check.
//!
//! `Hot::is_seeded` is false after a flush or a fresh Redis. The warmer then
//! runs [`store::rebuild_hot`]: static IPs that may be leased, cooldowns still
//! running and org blocks come back from Postgres, so no banned IP is leased.
//! Rotating sessions are not rebuilt; the reconcile loop refills them.

use crate::state::Warmer;

impl Warmer {
    pub(crate) async fn seed_tick(&self) {
        match self.hot.is_seeded().await {
            Ok(true) => self.metrics.redis_down.set(0),
            Ok(false) => {
                self.metrics.redis_down.set(0);
                match store::rebuild_hot(&self.db, &self.hot).await {
                    Ok(report) => tracing::info!(
                        units = report.units,
                        withdrawn = report.withdrawn,
                        target_cooldowns = report.target_cooldowns,
                        org_blocks = report.org_blocks,
                        "redis was empty, rebuilt it from postgres"
                    ),
                    Err(error) => {
                        tracing::warn!(%error, "failed to rebuild redis from postgres, retrying");
                    }
                }
            }
            Err(error) => {
                self.metrics.redis_down.set(1);
                tracing::warn!(%error, "failed to check the redis seed marker");
            }
        }
    }
}
