//! Session registry, warm-pause flag, browser-sample jobs and verdicts
//!.
//!
//! * `sess:{id}`: which org, partition and unit a tunnel's
//!   `X-ProxyX-Pool-Session` belongs to. The gateway writes it before it replies
//!   200 and pushes the expiry out while the tunnel is open
//!   ([`Hot::session_touch`]); the control API reads it to check that a block
//!   signal reports a session of the org that sends it.
//! * `warm_pause:{provider:region}`: a failed canary stops the warmer from
//!   creating new rotating units of the partition until a passing canary (or
//!   the TTL) lifts it. Static IPs are still checked and promoted.
//! * `sample:{probe}:{job}` and the set `samples:{probe}`: browser-sample jobs
//!   the warmer queues for the prober. A job stays listed until the prober's
//!   result arrives ([`Hot::sample_done`]) or its TTL ends.
//! * `verdict:{probe}:{key}`: the API's judgement of a result (a sample job id,
//!   or `canary:provider:region`), which the warmer reads.

use std::net::IpAddr;
use std::time::Duration;

use common::types::{OrgId, Partition, ProviderId, Region};
use serde::{Deserialize, Serialize};

use super::{Hot, encode, ms, tag};
use crate::error::{Result, ensure};

const SAMPLES_SET: &str = "samples:{probe}";

/// A browser sample the prober should run: one candidate, a few targets.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SampleJob {
    pub job_id: String,
    pub route_class: String,
    pub provider: ProviderId,
    pub region: Region,
    /// The sticky key under which the warmer reserved the candidate.
    pub sid: Option<String>,
    pub targets: Vec<String>,
}

/// The API's judgement of a probe result against the policy criteria.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Verdict {
    pub ok: bool,
    /// Share of runs that were ok and within the time limits.
    pub success_ratio: f64,
    /// Unix seconds.
    pub checked_at: i64,
    /// Why it failed; empty when `ok`.
    pub detail: String,
    /// Not `ok`, but only for speed: no run was blocked and enough runs loaded
    /// (`min_success`) though over the time limits. The unit is slow, not bad.
    #[serde(default)]
    pub slow: bool,
}

/// Who a session id was issued to.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionRecord {
    pub org: OrgId,
    pub partition: Partition,
    /// Static: the IP as text. Rotating: the session id.
    pub unit: String,
    /// The exit IP the gateway reported.
    pub ip: IpAddr,
}

fn session_key(id: &str) -> String {
    format!("sess:{id}")
}

fn pause_key(p: &Partition) -> String {
    format!("warm_pause:{}", tag(p))
}

fn sample_key(job_id: &str) -> String {
    format!("sample:{{probe}}:{job_id}")
}

fn verdict_key(key: &str) -> String {
    format!("verdict:{{probe}}:{key}")
}

impl Hot {
    /// Remember that `id` was issued to `rec.org` for `ttl`.
    ///
    /// Fails with `StoreError::Invalid` for an empty id or a zero ttl.
    pub async fn session_put(&self, id: &str, rec: &SessionRecord, ttl: Duration) -> Result<()> {
        ensure(
            !id.is_empty() && !ttl.is_zero(),
            "a session needs an id and a ttl above zero",
        )?;
        self.set_px(session_key(id), encode(rec)?, ttl).await
    }

    /// Push the expiry of `id` to `ttl` from now. False when the session is
    /// unknown or already expired: it is not written again.
    ///
    /// Fails with `StoreError::Invalid` for an empty id or a zero ttl.
    pub async fn session_touch(&self, id: &str, ttl: Duration) -> Result<bool> {
        ensure(
            !id.is_empty() && !ttl.is_zero(),
            "a session needs an id and a ttl above zero",
        )?;
        self.cmd(redis::cmd("PEXPIRE").arg(session_key(id)).arg(ms(ttl)))
            .await
    }

    /// The record of a session id, or `None` when unknown or expired.
    pub async fn session_get(&self, id: &str) -> Result<Option<SessionRecord>> {
        self.get_json(session_key(id), "session record").await
    }

    /// Stop the warmer from starting work on a partition for `ttl`.
    ///
    /// Fails with `StoreError::Invalid` for a zero ttl.
    pub async fn warm_pause(&self, p: &Partition, ttl: Duration) -> Result<()> {
        ensure(!ttl.is_zero(), "pause ttl must be above zero")?;
        self.set_px(pause_key(p), 1, ttl).await
    }

    /// Lift the pause. Returns whether the partition was paused.
    pub async fn warm_resume(&self, p: &Partition) -> Result<bool> {
        self.cmd(redis::cmd("DEL").arg(pause_key(p))).await
    }

    pub async fn warm_paused(&self, p: &Partition) -> Result<bool> {
        self.cmd(redis::cmd("EXISTS").arg(pause_key(p))).await
    }

    /// Queue a browser sample for the prober; it is listed until
    /// [`Hot::sample_done`] or `ttl`. The id set expires with its longest job.
    ///
    /// Fails with `StoreError::Invalid` for an empty job id or a zero ttl.
    pub async fn sample_put(&self, job: &SampleJob, ttl: Duration) -> Result<()> {
        ensure(
            !job.job_id.is_empty() && !ttl.is_zero(),
            "a sample job needs an id and a ttl above zero",
        )?;
        self.pipe(
            redis::pipe()
                .cmd("SET")
                .arg(sample_key(&job.job_id))
                .arg(encode(job)?)
                .arg("PX")
                .arg(ms(ttl))
                .ignore()
                .cmd("SADD")
                .arg(SAMPLES_SET)
                .arg(&job.job_id)
                .ignore()
                // the set lives as long as its longest job: NX sets the first
                // expiry, GT only raises it (GT alone ignores a key without one)
                .cmd("PEXPIRE")
                .arg(SAMPLES_SET)
                .arg(ms(ttl))
                .arg("NX")
                .ignore()
                .cmd("PEXPIRE")
                .arg(SAMPLES_SET)
                .arg(ms(ttl))
                .arg("GT")
                .ignore(),
        )
        .await
    }

    /// Samples queued and not finished, by job id. Expired ones leave the set.
    pub async fn sample_pending(&self) -> Result<Vec<SampleJob>> {
        let mut ids: Vec<String> = self.cmd(redis::cmd("SMEMBERS").arg(SAMPLES_SET)).await?;
        ids.sort();
        let mut jobs = Vec::with_capacity(ids.len());
        for id in ids {
            match self.get_json(sample_key(&id), "sample job").await? {
                Some(job) => jobs.push(job),
                None => {
                    self.cmd::<()>(redis::cmd("SREM").arg(SAMPLES_SET).arg(&id))
                        .await?;
                }
            }
        }
        Ok(jobs)
    }

    /// The prober delivered a result: stop listing the job. Returns whether
    /// it was listed.
    pub async fn sample_done(&self, job_id: &str) -> Result<bool> {
        let (deleted, removed): (i64, i64) = self
            .pipe(
                redis::pipe()
                    .cmd("DEL")
                    .arg(sample_key(job_id))
                    .cmd("SREM")
                    .arg(SAMPLES_SET)
                    .arg(job_id),
            )
            .await?;
        Ok(deleted > 0 || removed > 0)
    }

    /// Keep the verdict of a result under `key` for `ttl`.
    ///
    /// Fails with `StoreError::Invalid` for a zero ttl.
    pub async fn verdict_put(&self, key: &str, verdict: &Verdict, ttl: Duration) -> Result<()> {
        ensure(!ttl.is_zero(), "verdict ttl must be above zero")?;
        self.set_px(verdict_key(key), encode(verdict)?, ttl).await
    }

    pub async fn verdict_get(&self, key: &str) -> Result<Option<Verdict>> {
        self.get_json(verdict_key(key), "verdict").await
    }
}
