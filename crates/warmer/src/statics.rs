//! The static loop: every 30 s, per
//! partition under its lock, re-check IPs that are due, retest the ones that
//! rest in cooldown or quarantine, move states with `Db::transition_ip`, and
//! apply the replacement rule.
//!
//! Postgres is the source of truth for state and deadlines, Redis for
//! leasability: whenever an IP leaves `Available` or `Degraded` the unit is
//! taken out of the ready set, and whenever it returns it is put back.
//! A leasable row that Redis lost (the write after its move failed) is put
//! back by the next pass.
//!
//! The moves this loop makes (the gateway and the API make the rest):
//!
//! | From | To | When |
//! | -- | -- | -- |
//! | Candidate | Available | checks pass |
//! | Candidate, Cooldown | Degraded | checks pass but the light probe is slow |
//! | Available | Degraded | a recheck finds clean answers over `max_ttfb_ms` |
//! | Degraded | Available | a recheck passes at full speed |
//! | Degraded | Cooldown | like Available |
//! | Candidate | Quarantined | exit differs from the entry, or a check fails |
//! | Available | Candidate | exit IP changed |
//! | Available | Cooldown | reputation drain or a blocked probe |
//! | Available | Offline | SIM box silent for `offline_after` |
//! | Cooldown | Available | retest passes after `cooldown`, or at the breaker's probe spacing while the route class is down |
//! | Cooldown | Quarantined | `quarantine_after` IP-wide blocks in 1 h |
//! | Quarantined | Candidate, Available | retest passes after `retest_every` |
//! | Offline | Candidate | the box answers |
//! | any | ReplaceRequested | a replacement rule holds |

use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::Context as _;
use common::types::{
    InventoryEntry, IpState, OrgId, Partition, ProviderId, SignalSource, SignalType, Subtype, Tier,
};
use policy::EffectivePolicy;
use provider::Adapter;
use store::loaded::Loaded;
use store::{InventoryRow, ScoreRow, StoreError, Transition, UnitRecord};
use time::OffsetDateTime;
use tokio::task::JoinSet;
use verify::{
    Assessment, ExitIpError, ExitQuery, Flags, IpHistory, ReplaceRule, Score, ScorerKind, Verdict,
    quality,
};

use crate::checks::{owned_endpoint, static_endpoint};
use crate::job::Subject;
use crate::state::{PROBE_HISTORY, Warmer, policy_for};

/// Audit actor of this loop's state changes.
const ACTOR: &str = "warmer";

/// IPs checked at once.
const CONCURRENCY: usize = 8;

/// The window of the `quarantine_after` rule.
const BLOCK_WINDOW: time::Duration = time::Duration::hours(1);

/// IPs of a route class that must rest at once, with `block.max_cooldown_share`
/// of the class, for the class to be taken as down: the provider's outage, or a
/// block page every IP gets, not the IPs' fault (the gateway's
/// `PROVIDER_FAULT_UNITS`). A down class is retested at the breaker's probe
/// spacing, without waiting for the policy cooldown, so service returns soon
/// after the provider; a failed retest then does not count as a block, and its
/// probe does not count toward a replacement.
const PROVIDER_FAULT_IPS: usize = 2;

/// The checks whose failure an outage causes: the upstream refuses every
/// connection, or the exit-IP services disagree. A block page or a reputation
/// score is about the IP.
const OUTAGE_REASONS: [&str; 2] = ["upstream refused", "exit"];

/// Everything a step needs besides the row.
pub(crate) struct RowCtx<'a> {
    pub adapter: &'a Adapter,
    pub policy: &'a EffectivePolicy,
    pub now: OffsetDateTime,
    /// The route class of the row is down ([`down_partitions`]).
    pub down: bool,
}

impl<'a> RowCtx<'a> {
    /// `None` when `loaded` has no adapter for `provider`.
    pub(crate) fn new(
        loaded: &'a Loaded,
        provider: &ProviderId,
        now: OffsetDateTime,
    ) -> Option<Self> {
        Some(Self {
            adapter: loaded.adapters.get(provider)?,
            policy: policy_for(loaded, provider),
            now,
            down: false,
        })
    }
}

/// What one check of a static IP found.
pub(crate) enum Check {
    /// Everything holds, or the IP is only slow (`tier` is then `Degraded`).
    /// `verdict` is the reputation verdict (`Keep` or `Recheck`) for the
    /// "twice in the warn zone" rule.
    Pass {
        exit: IpAddr,
        verdict: Verdict,
        tier: Tier,
    },
    /// The exit IP is not the one the row stands for.
    ExitChanged { exit: IpAddr },
    /// The IP fails a rule: `reason` says which, `block` is the type of the
    /// block page when a target blocked it.
    Bad {
        reason: &'static str,
        block: Option<SignalType>,
    },
    /// No verdict: the check services or the upstream did not answer.
    Silent,
}

impl Check {
    /// A failed rule that no block page caused.
    fn bad(reason: &'static str) -> Self {
        Self::Bad {
            reason,
            block: None,
        }
    }
}

/// Log a static ip task that panicked or was cancelled.
fn log_died(joined: Option<Result<(), tokio::task::JoinError>>) {
    if let Some(Err(error)) = joined {
        tracing::error!(%error, "static ip task died");
    }
}

fn std_duration(d: time::Duration) -> Duration {
    Duration::try_from(d).unwrap_or_default()
}

/// The route classes whose shared IPs rest in cooldown or quarantine at
/// [`PROVIDER_FAULT_IPS`] or more, and at least `block.max_cooldown_share` of
/// them: the provider is down, not the IPs. Customer upstreams are not part of
/// the pool.
fn down_partitions(loaded: &Loaded, rows: &[InventoryRow]) -> HashSet<Partition> {
    let mut counts: HashMap<Partition, (usize, usize)> = HashMap::new();
    for row in rows.iter().filter(|r| r.owner.is_none()) {
        let resting = match row.state {
            IpState::Cooldown | IpState::Quarantined => 1,
            IpState::Available | IpState::Leased | IpState::Degraded => 0,
            _ => continue,
        };
        let (r, t) = counts.entry(row.partition()).or_default();
        *r += resting;
        *t += 1;
    }
    counts
        .into_iter()
        .filter(|(p, (resting, total))| {
            *resting >= PROVIDER_FAULT_IPS
                && *resting as f64 / *total as f64
                    >= policy_for(loaded, &p.provider).block.max_cooldown_share
        })
        .map(|(p, _)| p)
        .collect()
}

pub(crate) fn time_duration(d: Duration) -> time::Duration {
    time::Duration::try_from(d).unwrap_or(time::Duration::MAX)
}

pub(crate) fn is_box(entry: &InventoryEntry) -> bool {
    entry.subtype == Subtype::MobileBox
}

/// Turn the newest score rows (per service, newest first) into checks, oldest
/// first: check `k` holds the `k`-th newest score of every service that has
/// one.
pub(crate) fn checks_from(rows: &[ScoreRow], depth: usize) -> Vec<Vec<Score>> {
    let mut per_source: HashMap<&str, Vec<Score>> = HashMap::new();
    for row in rows {
        let Some(source) = ScorerKind::from_name(&row.source) else {
            continue;
        };
        per_source.entry(&row.source).or_default().push(Score {
            risk: row.risk,
            flags: Flags {
                tor: row.flags.iter().any(|f| f == "tor"),
                proxy: row.flags.iter().any(|f| f == "proxy"),
            },
            source,
        });
    }
    (0..depth)
        .rev()
        .map(|k| {
            per_source
                .values()
                .filter_map(|scores| scores.get(k).copied())
                .collect::<Vec<_>>()
        })
        .filter(|check| !check.is_empty())
        .collect()
}

impl Warmer {
    /// One pass over the static IPs of every partition this replica holds.
    pub(crate) async fn static_tick(self: &Arc<Self>) {
        let loaded = self.loaded();
        let rows = match self.db.list_inventory(None, None).await {
            Ok(rows) => {
                self.metrics.postgres_down.set(0);
                rows
            }
            Err(error) => {
                self.metrics.postgres_down.set(1);
                tracing::warn!(%error, "failed to read the inventory, keeping the last state");
                return;
            }
        };
        self.publish_rental_days(&rows);
        self.withdraw_moved(&rows).await;
        let down_classes = down_partitions(&loaded, &rows);

        let now = OffsetDateTime::now_utc();
        // At most CONCURRENCY rows are in flight: a task per row spawned up
        // front holds a future of several KB each, which is 70 MB of heap and
        // 300 MB of RSS at 10,000 inventory entries.
        let mut work = JoinSet::new();
        for row in rows {
            if !self.holds(&row.partition()) {
                continue;
            }
            while work.len() >= CONCURRENCY {
                log_died(work.join_next().await);
            }
            let (w, loaded) = (self.clone(), loaded.clone());
            let down = down_classes.contains(&row.partition());
            work.spawn(async move {
                let provider = row.entry.provider.clone();
                if let Err(error) = w.process_row(&loaded, row, now, down).await {
                    tracing::warn!(%provider, error = ?error, "failed to process a static ip");
                }
            });
        }
        while let joined @ Some(_) = work.join_next().await {
            log_died(joined);
        }
    }

    /// Take the unit of an IP out of the partition it was listed in before
    /// its provider or region changed. Repeated until Redis took it.
    async fn withdraw_moved(&self, rows: &[InventoryRow]) {
        let pending: Vec<(IpAddr, Partition)> = {
            let mut memory = self.memory.lock();
            for row in rows {
                let now = row.partition();
                if let Some(was) = memory.listed.insert(row.entry.ip, now.clone())
                    && was != now
                {
                    memory.moved.insert((row.entry.ip, was));
                }
            }
            memory.moved.iter().cloned().collect()
        };
        for (ip, from) in pending {
            match self.hot.unit_retire(&from, &ip.to_string()).await {
                Ok(retired) => {
                    if retired.was_ready {
                        self.count_eviction("moved");
                    }
                    if retired.forgotten {
                        self.memory.lock().moved.remove(&(ip, from));
                    }
                }
                Err(error) => {
                    tracing::warn!(%ip, %error, "failed to withdraw a moved ip from its old partition");
                }
            }
        }
    }

    async fn process_row(
        &self,
        loaded: &Loaded,
        row: InventoryRow,
        now: OffsetDateTime,
        down: bool,
    ) -> anyhow::Result<()> {
        let Some(mut rc) = RowCtx::new(loaded, &row.entry.provider, now) else {
            tracing::debug!(provider = %row.entry.provider, "no adapter for an inventory entry");
            return Ok(());
        };
        rc.down = down;
        let boxed = is_box(&row.entry);
        if !row.state.is_leasable() && row.state != IpState::Retired {
            self.unlist(&row).await?;
        }
        let row = match row.state {
            // Static IPs are checked, retested and promoted while the route
            // class is paused: the pause that a failed canary sets drained
            // them, and only a leasable IP lets the next canary pass and lift
            // it. A class whose IPs are all candidates (a new region, an
            // initial rollout) recovers the same way.
            IpState::Candidate => self.candidate_step(&rc, row).await?,
            IpState::Available | IpState::Leased | IpState::Degraded => {
                self.recheck_step(&rc, row).await?
            }
            IpState::Cooldown | IpState::Quarantined if !boxed => {
                self.retest_step(&rc, row).await?
            }
            IpState::Offline => self.offline_step(&rc, row).await?,
            IpState::ReplaceRequested => {
                let reasons = self.replacement_reasons(&rc, &row).await?;
                return self.emit_report(&row, &reasons, now).await;
            }
            IpState::Retired => return self.retire_step(&row).await,
            _ => row,
        };
        self.replacement_step(&rc, row).await
    }

    /// Move the row, tolerating a move that another actor already made. The
    /// move is made from the state `row` was read in: a row from a snapshot
    /// that a signal, the gateway or the API moved since is left alone (a
    /// stale recheck must not lift a fresh cooldown).
    pub(crate) async fn transition(
        &self,
        row: &InventoryRow,
        change: Transition,
    ) -> anyhow::Result<Option<InventoryRow>> {
        let change = change.expecting(row.state);
        match self.db.transition_ip(row.entry.ip, &change, ACTOR).await {
            Ok(moved) => {
                tracing::info!(
                    provider = %row.entry.provider,
                    from = row.state.as_str(),
                    to = change.to.as_str(),
                    reason = %change.reason,
                    "static ip moved"
                );
                Ok(Some(moved))
            }
            Err(StoreError::InvalidTransition { from, to }) => {
                tracing::debug!(
                    provider = %row.entry.provider,
                    from = from.as_str(),
                    to = to.as_str(),
                    "static ip move refused, another actor moved it first"
                );
                Ok(None)
            }
            Err(error) => Err(error).context("failed to move a static ip"),
        }
    }

    /// [`Self::transition`], keeping `row` when another actor moved it first.
    async fn move_row(
        &self,
        row: InventoryRow,
        change: Transition,
    ) -> anyhow::Result<InventoryRow> {
        Ok(self.transition(&row, change).await?.unwrap_or(row))
    }

    /// Take a unit out of the ready set when its row is not leasable. A
    /// `rebuild_hot` that read Postgres before a block or a cooldown and wrote
    /// Redis after it puts a banned IP back, and nothing else would remove it
    /// before its next state change. Postgres is read again, so a row that
    /// only just became leasable is not undone.
    async fn unlist(&self, row: &InventoryRow) -> anyhow::Result<()> {
        let (p, id) = (row.partition(), row.entry.ip.to_string());
        if !self.hot.is_ready(&p, &id).await? {
            return Ok(());
        }
        let Some(current) = self.db.inventory_row(row.entry.ip).await? else {
            return Ok(());
        };
        if current.state.is_leasable() {
            return Ok(());
        }
        tracing::warn!(provider = %row.entry.provider, ip = %row.entry.ip, state = current.state.as_str(), "static ip in the ready set is not leasable, taking it out");
        self.hot.ready_take(&p, &id).await?;
        self.count_eviction("not_leasable");
        Ok(())
    }

    async fn make_leasable(
        &self,
        row: &InventoryRow,
        exit: IpAddr,
        tier: Tier,
    ) -> anyhow::Result<()> {
        let unit = UnitRecord {
            id: row.entry.ip.to_string(),
            ip: exit,
            expires_at: None,
            ttl: None,
            owner: row.owner.clone(),
        };
        self.hot
            .ready_put_tier(&row.partition(), &unit, tier)
            .await
            .context("failed to make a static ip leasable")
    }

    /// Move a leasable row to the state of `tier` and tell Redis, when it is
    /// not there yet.
    pub(crate) async fn retier(
        &self,
        row: InventoryRow,
        tier: Tier,
    ) -> anyhow::Result<InventoryRow> {
        if row.state.tier() == tier {
            return Ok(row);
        }
        let change = match tier {
            Tier::Degraded => Transition::to(IpState::Degraded, "slow"),
            Tier::Normal => Transition::to(IpState::Available, "back to full speed"),
        };
        let Some(moved) = self.transition(&row, change).await? else {
            return Ok(row);
        };
        self.hot
            .set_tier(&moved.partition(), &moved.entry.ip.to_string(), tier)
            .await
            .context("failed to set the tier of a static ip")?;
        Ok(moved)
    }

    async fn withdraw(&self, row: &InventoryRow) -> anyhow::Result<()> {
        self.hot
            .ready_take(&row.partition(), &row.entry.ip.to_string())
            .await
            .context("failed to take a static ip out of leasing")?;
        Ok(())
    }

    /// Remember that the IP cooled, or failed a retest, like an outage.
    fn mark_outage(&self, row: &InventoryRow) {
        self.memory
            .lock()
            .outage_retests
            .insert(row.entry.ip, row.state_since);
    }

    /// Put the IP in quarantine until the next retest.
    pub(crate) async fn quarantine(
        &self,
        rc: &RowCtx<'_>,
        row: InventoryRow,
        why: &str,
    ) -> anyhow::Result<InventoryRow> {
        self.withdraw(&row).await?;
        let retest_at = rc.now + time_duration(rc.policy.static_ips.retest_every);
        let change = Transition::to(IpState::Quarantined, why).retest_at(retest_at);
        self.move_row(row, change).await
    }

    /// True when `row` may be retested now: not twice within `spacing`
    /// unless it entered its state again since the last attempt.
    fn note_attempt(&self, row: &InventoryRow, spacing: Duration) -> bool {
        let ip = row.entry.ip;
        let mut memory = self.memory.lock();
        let now = Instant::now();
        if memory
            .attempts
            .get(&ip)
            .is_some_and(|(t, since)| *since == row.state_since && now.duration_since(*t) < spacing)
        {
            return false;
        }
        memory.attempts.insert(ip, (now, row.state_since));
        true
    }

    /// Exit-IP quorum, reputation and light probe through the unit.
    pub(crate) async fn run_check(
        &self,
        rc: &RowCtx<'_>,
        row: &InventoryRow,
        previous: Option<Verdict>,
    ) -> Check {
        let entry = &row.entry;
        if let Some(owner) = &row.owner {
            return self.run_owned_check(rc, row, owner).await;
        }
        let endpoint = match static_endpoint(&self.settings, rc.adapter, entry) {
            Ok(endpoint) => endpoint,
            Err(error) => {
                tracing::warn!(provider = %entry.provider, error = ?error, "failed to render a static endpoint");
                return Check::Silent;
            }
        };
        let boxed = is_box(entry);
        let query = ExitQuery {
            // A SIM box exits from whatever IP it has now.
            ip: (!boxed).then_some(entry.ip),
            ..ExitQuery::in_region(&entry.region, rc.adapter.echo_url())
        };
        let exit = match self.exit_ip.check(&endpoint, &query).await {
            Ok(exit) => IpAddr::V4(exit.ip),
            Err(ExitIpError::IpMismatch { got, .. }) => {
                return Check::ExitChanged {
                    exit: IpAddr::V4(got),
                };
            }
            Err(ExitIpError::CountryMismatch { .. } | ExitIpError::Disagree) => {
                return Check::bad("exit");
            }
            // A SIM box is excluded: its silence is `Offline`, and it comes back
            // by itself.
            Err(ExitIpError::Unreachable) if !boxed => {
                tracing::debug!(provider = %entry.provider, "static ip refuses every check connection");
                return Check::bad("upstream refused");
            }
            Err(error) => {
                tracing::debug!(provider = %entry.provider, %error, "static exit check gave no verdict");
                return Check::Silent;
            }
        };
        if boxed && exit != row.unit_ip() {
            return Check::ExitChanged { exit };
        }

        let assessment = verify::assess(&self.reputation, exit, rc.policy).await;
        self.record_scores(entry.ip, &assessment, rc.now).await;
        if assessment.verdict.escalate(previous) == Verdict::Drain {
            return Check::bad("reputation");
        }

        let criteria = &rc.policy.criteria;
        let targets = self.loaded().probe_targets.for_region(&entry.region);
        if !targets.is_empty() {
            match self.probe.run(&endpoint, &targets).await {
                Ok(report) => {
                    let q = quality(&report, criteria.max_ttfb_ms);
                    // While the route class is down, every IP of it fails the
                    // same way: that is the target's or provider's doing, not
                    // the IPs', so a round with a block does not count toward
                    // replacement. A clean round always does.
                    if !rc.down || q.round.blocked == 0 {
                        let mut memory = self.memory.lock();
                        let rounds = memory.probes.entry(entry.ip).or_default();
                        rounds.push(q.round);
                        if rounds.len() > PROBE_HISTORY {
                            rounds.remove(0);
                        }
                    }
                    if !q.passes(criteria.min_success) {
                        if q.slow_only(criteria.min_success) {
                            return Check::Pass {
                                exit,
                                verdict: assessment.verdict,
                                tier: Tier::Degraded,
                            };
                        }
                        let reason = if q.block.is_some() {
                            "block"
                        } else {
                            "quality"
                        };
                        return Check::Bad {
                            reason,
                            block: q.block,
                        };
                    }
                }
                Err(error) => {
                    tracing::warn!(provider = %entry.provider, %error, "failed to probe a static ip");
                }
            }
        }
        Check::Pass {
            exit,
            verdict: assessment.verdict,
            tier: Tier::Normal,
        }
    }

    /// Check a customer upstream: the exit-IP quorum and the declared
    /// country, through the owner's stored login. Its exit IP is whatever the
    /// customer's proxy gives, so there is no address to match, and its
    /// reputation and block history are the customer's business, not a reason
    /// to replace it.
    async fn run_owned_check(&self, rc: &RowCtx<'_>, row: &InventoryRow, owner: &OrgId) -> Check {
        let entry = &row.entry;
        let login = match self.db.customer_login(owner).await {
            Ok(login) => login,
            Err(error) => {
                tracing::warn!(%error, "failed to read a customer login");
                return Check::Silent;
            }
        };
        let endpoint = match owned_endpoint(rc.adapter, entry, login.as_ref()) {
            Ok(endpoint) => endpoint,
            Err(error) => {
                tracing::warn!(provider = %entry.provider, error = ?error, "failed to render a customer endpoint");
                return Check::Silent;
            }
        };
        let query = ExitQuery::in_region(&entry.region, rc.adapter.echo_url());
        match self.exit_ip.check(&endpoint, &query).await {
            Ok(exit) => Check::Pass {
                exit: IpAddr::V4(exit.ip),
                verdict: Verdict::Keep,
                tier: Tier::Normal,
            },
            Err(ExitIpError::CountryMismatch { .. } | ExitIpError::Disagree) => Check::bad("exit"),
            Err(error) => {
                tracing::debug!(provider = %entry.provider, %error, "customer exit check gave no verdict");
                Check::Silent
            }
        }
    }

    async fn record_scores(&self, ip: IpAddr, a: &Assessment, now: OffsetDateTime) {
        for score in &a.scores {
            let mut flags = Vec::new();
            if score.flags.tor {
                flags.push("tor".to_owned());
            }
            if score.flags.proxy {
                flags.push("proxy".to_owned());
            }
            let row = ScoreRow {
                ip,
                source: score.source.name().to_owned(),
                risk: score.risk,
                flags,
                checked_at: now,
            };
            if let Err(error) = self.db.record_score(&row).await {
                tracing::warn!(%error, "failed to record a reputation score");
            }
        }
    }

    async fn candidate_step(
        &self,
        rc: &RowCtx<'_>,
        row: InventoryRow,
    ) -> anyhow::Result<InventoryRow> {
        let ip = row.entry.ip;
        match self.run_check(rc, &row, None).await {
            Check::Pass {
                exit,
                verdict,
                tier,
            } => {
                self.db.record_check(ip, Some(exit), rc.now).await?;
                self.memory.lock().verdicts.insert(ip, verdict);
                if row.owner.is_some() {
                    // A customer upstream becomes available only through the
                    // API's `validate`: the check is recorded, nothing else.
                    return Ok(row);
                }
                let to = match tier {
                    Tier::Normal => IpState::Available,
                    Tier::Degraded => IpState::Degraded,
                };
                if let Some(moved) = self
                    .transition(&row, Transition::to(to, "checks passed"))
                    .await?
                {
                    self.make_leasable(&moved, exit, tier).await?;
                    self.maybe_sample(
                        &moved.partition(),
                        Subject::Static,
                        &moved.entry.ip.to_string(),
                        rc.policy,
                    )
                    .await;
                    return Ok(moved);
                }
            }
            Check::ExitChanged { exit } => {
                self.db.record_check(ip, Some(exit), rc.now).await?;
                if !is_box(&row.entry) {
                    return self
                        .quarantine(rc, row, "exit ip differs from the inventory entry")
                        .await;
                }
                // A box has a new IP: the next pass checks it against the new address.
            }
            Check::Bad { reason, .. } => return self.quarantine(rc, row, reason).await,
            Check::Silent => {}
        }
        Ok(row)
    }

    /// Repair what Redis lost or never got for a leasable row: the write
    /// that followed its move to `Available` or `Degraded` failed, and
    /// nothing else would repeat it. A unit missing from the ready set is put
    /// back; one in the wrong tier (the move to the state of the other tier
    /// is in Postgres, the tier field is not) gets the tier of its row. Rows
    /// that are deliberately out (cooldown, quarantine, withdrawn customer
    /// units) are not leasable in Postgres, which is read again so a
    /// withdrawal that is only now reaching the row is not undone.
    async fn relist(&self, row: &InventoryRow) -> anyhow::Result<()> {
        let (p, id) = (row.partition(), row.entry.ip.to_string());
        let ready = self.hot.is_ready(&p, &id).await?;
        if ready && self.hot.tier(&p, &id).await? == row.state.tier() {
            return Ok(());
        }
        let Some(current) = self.db.inventory_row(row.entry.ip).await? else {
            return Ok(());
        };
        if !current.state.is_leasable() {
            return Ok(());
        }
        let tier = current.state.tier();
        if ready {
            if self.hot.tier(&p, &id).await? != tier {
                tracing::warn!(provider = %row.entry.provider, ip = %row.entry.ip, "static ip had another tier in Redis than in Postgres, correcting it");
                self.hot.set_tier(&p, &id, tier).await?;
            }
            return Ok(());
        }
        tracing::warn!(provider = %row.entry.provider, ip = %row.entry.ip, "leasable static ip was missing from the ready set, putting it back");
        // as `rebuild_hot`: the unit stands for the exit IP of the last check
        self.make_leasable(&current, current.unit_ip(), tier).await
    }

    async fn recheck_step(
        &self,
        rc: &RowCtx<'_>,
        row: InventoryRow,
    ) -> anyhow::Result<InventoryRow> {
        self.relist(&row).await?;
        let policy = &rc.policy.static_ips;
        let ip = row.entry.ip;
        let due = row
            .last_check_at
            .is_none_or(|t| rc.now - t >= time_duration(policy.recheck_every));
        if !due {
            return Ok(row);
        }
        let previous = self.memory.lock().verdicts.get(&ip).copied();
        match self.run_check(rc, &row, previous).await {
            Check::Pass {
                exit,
                verdict,
                tier,
            } => {
                if row.owner.is_some() && row.exit_ip != Some(exit) {
                    // a customer upstream moved to another exit IP: the unit
                    // record carries the exit IP the gateway reports
                    self.make_leasable(&row, exit, row.state.tier()).await?;
                }
                self.db.record_check(ip, Some(exit), rc.now).await?;
                self.memory.lock().verdicts.insert(ip, verdict);
                return self.retier(row, tier).await;
            }
            Check::ExitChanged { exit } => {
                self.withdraw(&row).await?;
                self.count_eviction("ip_changed");
                self.db.record_check(ip, Some(exit), rc.now).await?;
                let change = Transition::to(IpState::Candidate, "exit ip changed");
                return self.move_row(row, change).await;
            }
            Check::Bad { reason, block } => {
                self.withdraw(&row).await?;
                if let Some(kind) = block {
                    self.db
                        .record_block(ip, None, SignalSource::Probe, kind, None)
                        .await?;
                }
                self.memory.lock().verdicts.remove(&ip);
                let until = rc.now + time_duration(policy.cooldown);
                let change = Transition::to(IpState::Cooldown, reason).cooldown_until(until);
                let moved = self.move_row(row, change).await?;
                if moved.state == IpState::Cooldown && OUTAGE_REASONS.contains(&reason) {
                    self.mark_outage(&moved);
                }
                return Ok(moved);
            }
            Check::Silent => {
                let silent_for = rc.now - row.last_check_at.unwrap_or(row.state_since);
                let offline_after = time_duration(rc.policy.mobile_box.offline_after);
                if is_box(&row.entry) && silent_for >= offline_after {
                    self.withdraw(&row).await?;
                    let change = Transition::to(IpState::Offline, "the box does not answer");
                    return self.move_row(row, change).await;
                }
            }
        }
        Ok(row)
    }

    /// Retest an IP that rests in cooldown or quarantine, once its deadline
    /// passed and not more often than the state's spacing.
    async fn retest_step(
        &self,
        rc: &RowCtx<'_>,
        row: InventoryRow,
    ) -> anyhow::Result<InventoryRow> {
        let policy = &rc.policy.static_ips;
        let ip = row.entry.ip;
        // Cooled for an outage-like failure, in this cooldown: a down route
        // class retests it at once and then at the probe spacing.
        let marked = self.memory.lock().outage_retests.get(&ip) == Some(&row.state_since);
        let (due, spacing) = match row.state {
            IpState::Cooldown => (
                row.cooldown_until.is_some_and(|t| t <= rc.now) || (marked && rc.down),
                if marked {
                    self.timing.breaker.first_probe_after
                } else {
                    policy.cooldown
                },
            ),
            _ => (
                row.retest_at.is_some_and(|t| t <= rc.now),
                policy.retest_every,
            ),
        };
        let early = row.cooldown_until.is_some_and(|t| t > rc.now);
        if !due || !self.note_attempt(&row, spacing) {
            return Ok(row);
        }
        let previous = self.memory.lock().verdicts.get(&ip).copied();
        match self.run_check(rc, &row, previous).await {
            Check::Pass {
                exit,
                verdict,
                tier,
            } => {
                self.db.record_check(ip, Some(exit), rc.now).await?;
                {
                    let mut memory = self.memory.lock();
                    memory.verdicts.insert(ip, verdict);
                    memory.outage_retests.remove(&ip);
                }
                let mut current = row;
                if current.state == IpState::Quarantined {
                    let change = Transition::to(IpState::Candidate, "retest due");
                    let Some(moved) = self.transition(&current, change).await? else {
                        return Ok(current);
                    };
                    current = moved;
                }
                let to = match tier {
                    Tier::Normal => IpState::Available,
                    Tier::Degraded => IpState::Degraded,
                };
                if let Some(moved) = self
                    .transition(&current, Transition::to(to, "retest passed"))
                    .await?
                {
                    self.make_leasable(&moved, exit, tier).await?;
                    return Ok(moved);
                }
                Ok(current)
            }
            Check::ExitChanged { .. } => self.retest_failed(rc, row, false, early).await,
            Check::Bad { reason, .. } => {
                self.retest_failed(rc, row, OUTAGE_REASONS.contains(&reason), early)
                    .await
            }
            Check::Silent => Ok(row),
        }
    }

    /// A failed retest counts as an IP-wide block; enough of them in one
    /// hour quarantine a cooled IP. A failure that looks like an outage
    /// (`outage`) while the route class is down is the provider's, not the
    /// IP's: it does not count, and the IP is retested at the probe spacing
    /// until it passes, instead of resting 15 min or, after the provider is
    /// back, 6 h. A retest before the cooldown ended (`early`, a down class)
    /// does not count either.
    async fn retest_failed(
        &self,
        rc: &RowCtx<'_>,
        row: InventoryRow,
        outage: bool,
        early: bool,
    ) -> anyhow::Result<InventoryRow> {
        let ip = row.entry.ip;
        if row.state != IpState::Cooldown {
            return Ok(row);
        }
        if outage && rc.down {
            tracing::debug!(%ip, "retest failed like the rest of the route class, not counted");
            self.mark_outage(&row);
            return Ok(row);
        }
        self.memory.lock().outage_retests.remove(&ip);
        if early {
            return Ok(row);
        }
        self.db
            .record_block(ip, None, SignalSource::Probe, SignalType::Forbidden, None)
            .await?;
        let blocks = self
            .db
            .ip_wide_blocks_since(ip, rc.now - BLOCK_WINDOW)
            .await?;
        if blocks >= i64::from(rc.policy.static_ips.quarantine_after) {
            return self
                .quarantine(rc, row, "repeated blocks in one hour")
                .await;
        }
        Ok(row)
    }

    /// An offline box that answers is a candidate again.
    async fn offline_step(
        &self,
        rc: &RowCtx<'_>,
        row: InventoryRow,
    ) -> anyhow::Result<InventoryRow> {
        let ip = row.entry.ip;
        if !self.note_attempt(&row, rc.policy.mobile_box.offline_after) {
            return Ok(row);
        }
        match self.run_check(rc, &row, None).await {
            Check::Pass { exit, .. } | Check::ExitChanged { exit } => {
                self.db.record_check(ip, Some(exit), rc.now).await?;
                let change = Transition::to(IpState::Candidate, "the box answers");
                self.move_row(row, change).await
            }
            Check::Bad { .. } | Check::Silent => Ok(row),
        }
    }

    /// A retired IP leaves leasing; its unit is forgotten once its tunnels
    /// end, also when the API took it out of the ready set first. Once
    /// nothing is left the pass skips the IP (the rows stay in the inventory).
    async fn retire_step(&self, row: &InventoryRow) -> anyhow::Result<()> {
        let ip = row.entry.ip;
        if self.memory.lock().forgotten.get(&ip) == Some(&row.state_since) {
            return Ok(());
        }
        let retired = self
            .hot
            .unit_retire(&row.partition(), &ip.to_string())
            .await?;
        if retired.was_ready {
            self.count_eviction("retired");
        }
        if retired.forgotten {
            self.memory.lock().forgotten.insert(ip, row.state_since);
        }
        Ok(())
    }

    pub(crate) async fn replacement_reasons(
        &self,
        rc: &RowCtx<'_>,
        row: &InventoryRow,
    ) -> anyhow::Result<Vec<String>> {
        let rules = &rc.policy.static_ips;
        let ip = row.entry.ip;
        let rule = ReplaceRule {
            max_risk: rc.policy.criteria.max_risk,
            replace_after_checks: rules.replace_after_checks as usize,
            replace_min_sources: rules.replace_min_sources as usize,
            replace_blocked_share: rules.replace_blocked_share,
            replace_quarantine_for: rules.replace_quarantine_for,
            rotate_attempts: rc.policy.mobile_box.rotate_attempts,
        };
        let scores = self
            .db
            .recent_scores(ip, i64::from(rules.replace_after_checks))
            .await?;
        let checks = checks_from(&scores, rules.replace_after_checks as usize);
        let (probes, failed_resets) = {
            let memory = self.memory.lock();
            (
                memory.probes.get(&ip).cloned().unwrap_or_default(),
                memory.failed_resets.get(&ip).copied().unwrap_or(0),
            )
        };
        let quarantined_for = (row.state == IpState::Quarantined)
            .then_some(row.quarantined_at)
            .flatten()
            .map(|t| std_duration(rc.now - t));
        let mut reasons: Vec<String> = rule
            .reasons(&IpHistory {
                checks: &checks,
                probes: &probes,
                quarantined_for,
                failed_resets,
            })
            .into_iter()
            .map(|r| r.label().to_owned())
            .collect();
        // A box that stays offline as long as an IP may stay quarantined.
        if row.state == IpState::Offline
            && row
                .offline_since
                .is_some_and(|t| std_duration(rc.now - t) >= rules.replace_quarantine_for)
        {
            reasons.push("offline".to_owned());
        }
        Ok(reasons)
    }

    /// Apply the rule; on a hit take the IP out of leasing, move it to
    /// `ReplaceRequested` and emit the first report.
    pub(crate) async fn replacement_step(
        &self,
        rc: &RowCtx<'_>,
        row: InventoryRow,
    ) -> anyhow::Result<()> {
        if row.owner.is_some() {
            // the customer's own IP: nothing to replace
            return Ok(());
        }
        if !matches!(
            row.state,
            IpState::Candidate
                | IpState::Available
                | IpState::Leased
                | IpState::Degraded
                | IpState::Cooldown
                | IpState::Quarantined
                | IpState::Offline
        ) {
            return Ok(());
        }
        let reasons = self.replacement_reasons(rc, &row).await?;
        if reasons.is_empty() {
            return Ok(());
        }
        self.withdraw(&row).await?;
        let change = Transition::to(IpState::ReplaceRequested, reasons.join(","));
        let Some(moved) = self.transition(&row, change).await? else {
            return Ok(());
        };
        self.emit_report(&moved, &reasons, rc.now).await
    }
}
