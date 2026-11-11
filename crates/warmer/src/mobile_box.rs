//! SIM box dynamics.
//!
//! A `mobile_box` that rests in *Cooldown* or *Quarantined* is reset: the
//! warmer waits up to `drain_wait` for its leases to end (a reset cuts open
//! tunnels), calls `rotate_ip` and polls the exit IP until it differs or
//! `rotate_timeout` passes. The box is *Rotating*, not leasable, meanwhile.
//! Only `changed` leads to *Candidate*; any other outcome counts as one failed
//! reset and sends the box back to *Quarantined*, and `rotate_attempts`
//! failures in a row make it *ReplaceRequested*. A box left in *Rotating* by a
//! crash is put back in *Quarantined* here; a silent box (*Offline*) is the
//! static loop's business.
//!
//! Resets are rate limited per box: `rotate_min_interval` apart and at most
//! `rotate_per_hour` an hour.

use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::Context as _;
use common::types::IpState;
use policy::MobileBoxRules;
use provider::ProviderError;
use store::InventoryRow;
use store::loaded::Loaded;
use time::OffsetDateTime;
use verify::ExitQuery;

use crate::checks::static_endpoint;
use crate::state::{Warmer, policy_for};
use crate::statics::{RowCtx, is_box, time_duration};

const HOUR: Duration = Duration::from_secs(3600);

/// How a reset ended; the label of `rotate_total`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Outcome {
    /// The exit IP differs from before the reset.
    Changed(IpAddr),
    /// The box answers from the same IP (carrier NAT can return it).
    Unchanged,
    /// No exit check answered before `rotate_timeout`, or the call timed out.
    Timeout,
    /// The reset call failed.
    Error,
}

impl Outcome {
    fn label(self) -> &'static str {
        match self {
            Outcome::Changed(_) => "changed",
            Outcome::Unchanged => "unchanged",
            Outcome::Timeout => "timeout",
            Outcome::Error => "error",
        }
    }
}

impl Warmer {
    /// Start resets for the boxes that rest and are allowed one, and recover
    /// boxes whose reset was interrupted.
    pub(crate) async fn box_tick(self: &Arc<Self>) {
        let loaded = self.loaded();
        let rows = match self.db.list_inventory(None, None).await {
            Ok(rows) => rows,
            Err(error) => {
                self.metrics.postgres_down.set(1);
                tracing::warn!(%error, "failed to read the inventory for box resets");
                return;
            }
        };
        let now = OffsetDateTime::now_utc();
        for row in rows {
            if !is_box(&row.entry)
                || !self.holds(&row.partition())
                || loaded.adapters.get(&row.entry.provider).is_none()
            {
                continue;
            }
            let rules = policy_for(&loaded, &row.entry.provider).mobile_box.clone();
            let result = match row.state {
                IpState::Cooldown | IpState::Quarantined => {
                    self.start_reset(&loaded, row, &rules);
                    Ok(())
                }
                IpState::Rotating => self.recover_reset(&loaded, row, &rules, now).await,
                _ => Ok(()),
            };
            if let Err(error) = result {
                tracing::warn!(error = ?error, "failed to handle a box");
            }
        }
    }

    /// May a box be reset now? Records the reset when it may.
    fn reset_allowed(&self, ip: IpAddr, rules: &MobileBoxRules) -> bool {
        let mut memory = self.memory.lock();
        let now = Instant::now();
        let resets = memory.rotations.entry(ip).or_default();
        resets.retain(|t| now.duration_since(*t) < HOUR);
        let too_soon = resets
            .last()
            .is_some_and(|t| now.duration_since(*t) < rules.rotate_min_interval);
        if too_soon || resets.len() >= rules.rotate_per_hour as usize {
            return false;
        }
        resets.push(now);
        true
    }

    fn start_reset(
        self: &Arc<Self>,
        loaded: &Arc<Loaded>,
        row: InventoryRow,
        rules: &MobileBoxRules,
    ) {
        let (ip, provider) = (row.entry.ip, row.entry.provider.clone());
        if self.resetting.lock().contains(&ip) || !self.reset_allowed(ip, rules) {
            return;
        }
        self.resetting.lock().insert(ip);
        let (w, loaded) = (self.clone(), loaded.clone());
        self.tracker.spawn(async move {
            if let Err(error) = w.reset_box(&loaded, row).await {
                tracing::warn!(%provider, error = ?error, "box reset failed");
            }
            w.resetting.lock().remove(&ip);
        });
    }

    /// A box that stays *Rotating* with no reset running lost its warmer:
    /// count the reset as failed.
    async fn recover_reset(
        &self,
        loaded: &Loaded,
        row: InventoryRow,
        rules: &MobileBoxRules,
        now: OffsetDateTime,
    ) -> anyhow::Result<()> {
        let ip = row.entry.ip;
        let patience = time_duration(rules.drain_wait + rules.rotate_timeout * 2);
        if self.resetting.lock().contains(&ip) || now - row.state_since < patience {
            return Ok(());
        }
        let rc = RowCtx::new(loaded, &row.entry.provider, now).context("no adapter for a box")?;
        self.reset_failed(&rc, row, "interrupted").await
    }

    async fn reset_box(&self, loaded: &Loaded, row: InventoryRow) -> anyhow::Result<()> {
        let entry = &row.entry;
        let rc = RowCtx::new(loaded, &entry.provider, OffsetDateTime::now_utc())
            .context("no adapter for a box")?;
        let rules = &rc.policy.mobile_box;
        if !self.wait_for_drain(&row, rules.drain_wait).await {
            // Shutdown while the box still serves tunnels: leave it as it is,
            // the next pod resets it after its own wait.
            return Ok(());
        }
        let old = row.unit_ip();
        let change = store::Transition::to(IpState::Rotating, "box reset");
        let Some(rotating) = self.transition(&row, change).await? else {
            return Ok(());
        };

        let outcome = self.reset_and_watch(&rc, &row, old).await;
        self.metrics
            .rotate_total
            .with_label_values(&[entry.provider.as_str(), outcome.label()])
            .inc();
        tracing::info!(provider = %entry.provider, outcome = outcome.label(), "box reset finished");
        match outcome {
            Outcome::Changed(new_ip) => {
                self.db
                    .record_check(entry.ip, Some(new_ip), OffsetDateTime::now_utc())
                    .await?;
                self.memory.lock().failed_resets.remove(&entry.ip);
                let change = store::Transition::to(IpState::Candidate, "new ip after reset");
                self.transition(&rotating, change).await?;
                Ok(())
            }
            failed => self.reset_failed(&rc, rotating, failed.label()).await,
        }
    }

    /// Count a failed reset, quarantine the box and apply the replacement rule.
    async fn reset_failed(
        &self,
        rc: &RowCtx<'_>,
        row: InventoryRow,
        why: &str,
    ) -> anyhow::Result<()> {
        self.memory
            .lock()
            .failed_resets
            .entry(row.entry.ip)
            .and_modify(|n| *n += 1)
            .or_insert(1);
        let quarantined = self
            .quarantine(rc, row, &format!("box reset {why}"))
            .await?;
        self.replacement_step(rc, quarantined).await
    }

    /// Wait until no lease and no tunnel uses the box, or `limit` passes.
    /// False when the warmer was told to stop meanwhile.
    async fn wait_for_drain(&self, row: &InventoryRow, limit: Duration) -> bool {
        let p = row.partition();
        let id = row.entry.ip.to_string();
        let deadline = Instant::now() + limit;
        loop {
            match self.hot.unit_load(&p, &id).await {
                Ok(load) if load.leases > 0 || load.tunnels > 0 => {}
                Ok(_) => return true,
                Err(error) => {
                    tracing::warn!(%error, "failed to read the load of a box, not waiting");
                    return true;
                }
            }
            if Instant::now() >= deadline {
                tracing::info!(provider = %row.entry.provider, "drain_wait passed, resetting a box that is in use");
                return true;
            }
            tokio::select! {
                () = tokio::time::sleep(self.timing.drain_poll) => {}
                () = self.cancel.cancelled() => return false,
            }
        }
    }

    /// Call `rotate_ip`, then poll the exit IP until it changes.
    async fn reset_and_watch(&self, rc: &RowCtx<'_>, row: &InventoryRow, old: IpAddr) -> Outcome {
        let entry = &row.entry;
        let Some(handle) = entry.box_handle.as_deref() else {
            tracing::warn!(provider = %entry.provider, "box has no handle to reset");
            return Outcome::Error;
        };
        match self.rotate.rotate(rc.adapter, handle).await {
            Ok(()) => {}
            Err(ProviderError::RotateTimeout) => return Outcome::Timeout,
            Err(error) => {
                tracing::warn!(provider = %entry.provider, %error, "box reset call failed");
                return Outcome::Error;
            }
        }
        let deadline = Instant::now() + rc.policy.mobile_box.rotate_timeout;
        let mut answered = false;
        loop {
            tokio::select! {
                () = tokio::time::sleep(self.timing.box_poll) => {}
                () = self.cancel.cancelled() => return Outcome::Timeout,
            }
            match static_endpoint(&self.settings, rc.adapter, entry) {
                Ok(endpoint) => {
                    let query = ExitQuery {
                        echo_url: rc.adapter.echo_url(),
                        ..ExitQuery::default()
                    };
                    if let Ok(exit) = self.exit_ip.check(&endpoint, &query).await {
                        let now_ip = IpAddr::V4(exit.ip);
                        if now_ip != old {
                            return Outcome::Changed(now_ip);
                        }
                        answered = true;
                    }
                }
                Err(error) => {
                    tracing::warn!(provider = %entry.provider, error = ?error, "failed to render a box endpoint");
                    return Outcome::Error;
                }
            }
            if Instant::now() >= deadline {
                return if answered {
                    Outcome::Unchanged
                } else {
                    Outcome::Timeout
                };
            }
        }
    }
}
