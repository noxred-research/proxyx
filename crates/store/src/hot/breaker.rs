//! The shared circuit breaker of a route class.
//!
//! One hash per partition, `breaker:{provider:region}`, written by the
//! warmer's creates and the gateway's dials and read by both, so every replica
//! sees the same state. The rules: five
//! failures in 60 s open it; the first probe is allowed after 5 s (the
//! proposal said 30 s, see `BreakerConfig`), each failed probe doubles the
//! wait up to 5 min; three passes close it. One
//! Lua script applies each step, so two replicas cannot both take a probe.
//!
//! A probe is a lease of `first_probe_after`: when its holder never reports,
//! the next caller after that time may probe again. The hash expires after an
//! hour without writes, which closes a breaker nobody uses any more.

use std::time::Duration;

use common::retry::{BreakerConfig, BreakerState};
use common::types::Partition;
use serde_json::json;

use super::{Hot, ms, tag};
use crate::error::{Result, StoreError};

/// A breaker nobody wrote to for this long is forgotten (closed).
const IDLE_TTL: Duration = Duration::from_secs(3600);

/// What the breaker says about one more call to a route class.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Admit {
    /// Closed: go ahead.
    Go,
    /// Open or half-open and a probe is due. After a [`Hot::breaker_claim`]
    /// that returned this, the caller holds the probe and must report its
    /// result.
    Probe,
    /// Open, or half-open with a probe in flight: skip this route class.
    Blocked,
}

fn state_of(code: i64) -> Result<BreakerState> {
    match code {
        0 => Ok(BreakerState::Closed),
        1 => Ok(BreakerState::HalfOpen),
        2 => Ok(BreakerState::Open),
        other => Err(StoreError::decode("breaker state", other)),
    }
}

impl Hot {
    async fn breaker_step(
        &self,
        p: &Partition,
        cfg: &BreakerConfig,
        op: &str,
    ) -> Result<(BreakerState, Admit)> {
        let reply: Vec<i64> = self
            .run(
                &self.scripts.breaker,
                &format!("breaker:{}", tag(p)),
                &json!({
                    "op": op,
                    "open_after": cfg.failures_to_open,
                    "window": ms(cfg.window),
                    "first": ms(cfg.first_probe_after),
                    "max": ms(cfg.max_probe_after),
                    "close_after": cfg.passes_to_close,
                    "idle": ms(IDLE_TTL),
                }),
            )
            .await?;
        match reply[..] {
            [state, verdict] => Ok((
                state_of(state)?,
                match verdict {
                    0 => Admit::Go,
                    1 => Admit::Probe,
                    _ => Admit::Blocked,
                },
            )),
            _ => Err(StoreError::decode("breaker reply", format!("{reply:?}"))),
        }
    }

    /// The state of the route class and whether a call may go, without taking
    /// a probe.
    pub async fn breaker_peek(
        &self,
        p: &Partition,
        cfg: &BreakerConfig,
    ) -> Result<(BreakerState, Admit)> {
        self.breaker_step(p, cfg, "peek").await
    }

    /// Like [`Hot::breaker_peek`], and when a probe is due the caller takes it
    /// (open becomes half-open): the answer is [`Admit::Probe`] for exactly one
    /// caller at a time. A probe must be followed by
    /// [`Hot::breaker_success`] or [`Hot::breaker_failure`].
    pub async fn breaker_claim(
        &self,
        p: &Partition,
        cfg: &BreakerConfig,
    ) -> Result<(BreakerState, Admit)> {
        self.breaker_step(p, cfg, "claim").await
    }

    /// A probe passed. Only half-open counts passes: `passes_to_close` of them
    /// close the breaker. In any other state this does nothing.
    pub async fn breaker_success(
        &self,
        p: &Partition,
        cfg: &BreakerConfig,
    ) -> Result<BreakerState> {
        Ok(self.breaker_step(p, cfg, "success").await?.0)
    }

    /// A call failed because the provider is unreachable. Closed: counts in
    /// the failure window and opens at `failures_to_open`. Half-open: reopens
    /// with the wait doubled (up to `max_probe_after`). Open: nothing.
    pub async fn breaker_failure(
        &self,
        p: &Partition,
        cfg: &BreakerConfig,
    ) -> Result<BreakerState> {
        Ok(self.breaker_step(p, cfg, "failure").await?.0)
    }
}
