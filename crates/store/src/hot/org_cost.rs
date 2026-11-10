//! The per-org byte meter.
//!
//! * `ocost:{org}:bytes:{day}`: bytes the org used in one UTC day, across
//!   all providers. The gateway relay adds to it and refuses new tunnels
//!   when the policy budget is spent.

use common::types::OrgId;
use time::OffsetDateTime;

use super::{DAY_KEY_TTL, DAY_SECS, Hot, incr_px};
use crate::error::Result;

fn org_day_key(org: &OrgId, at: OffsetDateTime) -> String {
    format!(
        "ocost:{{{org}}}:bytes:{}",
        at.unix_timestamp().div_euclid(DAY_SECS)
    )
}

impl Hot {
    /// Count bytes against the org's budget of the UTC day that contains `at`.
    pub async fn org_cost_add(&self, org: &OrgId, bytes: u64, at: OffsetDateTime) -> Result<()> {
        if bytes == 0 {
            return Ok(());
        }
        let mut pipe = redis::pipe();
        incr_px(&mut pipe, &org_day_key(org, at), bytes, DAY_KEY_TTL);
        self.pipe(&pipe).await
    }

    /// Bytes the org used in the UTC day that contains `at`.
    pub async fn org_cost_used(&self, org: &OrgId, at: OffsetDateTime) -> Result<u64> {
        let used: Option<u64> = self
            .cmd(redis::cmd("GET").arg(org_day_key(org, at)))
            .await?;
        Ok(used.unwrap_or(0))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_org_meter_changes_at_midnight_utc() {
        let org: OrgId = "acme".parse().expect("org");
        let before = OffsetDateTime::from_unix_timestamp(2 * DAY_SECS - 1).expect("time");
        let after = OffsetDateTime::from_unix_timestamp(2 * DAY_SECS).expect("time");
        assert_ne!(org_day_key(&org, before), org_day_key(&org, after));
        assert_eq!(org_day_key(&org, after), "ocost:{acme}:bytes:2");
    }
}
