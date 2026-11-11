//! Per-organization live sticky leases, bounded LRU state and counters.
//!
//! The index and its counters share the organization's Redis hash slot. LRU
//! eviction is atomic there; releasing a partition lease follows separately,
//! with a unit comparison so an unrelated replacement is never released.

use std::net::IpAddr;
use std::time::Duration;

use common::types::{OrgId, Partition};
use serde::{Deserialize, Serialize};
use serde_json::json;

use super::{Hot, ms};
use crate::error::{Result, StoreError, ensure};

/// One live sticky lease. This record never contains client credentials.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AffinityRecord {
    /// Lease key, including its scope prefix, for example `sid:scan42`.
    pub sticky: String,
    /// Provider and region that currently own the lease.
    pub partition: Partition,
    /// Static IP or provider session identifier of the leased unit.
    pub unit: String,
    /// Last verified exit IP.
    pub ip: IpAddr,
    /// First acquisition time in Redis-clock Unix milliseconds.
    /// The store assigns this value; callers may pass zero.
    pub created_at_ms: i64,
    /// Last use in Redis-clock Unix milliseconds, assigned by the store.
    pub last_seen_ms: i64,
    /// Cumulative transferred bytes, preserved across lease renewals.
    /// Saturates at `u64::MAX` instead of overflowing.
    #[serde(deserialize_with = "byte_count")]
    pub bytes: u64,
}

/// Per-org affinity counters, retained for at least one day after last use.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct AffinityStats {
    /// Live entries after expired entries have been removed.
    pub entries: u64,
    /// Successful acquisitions that reused an existing lease.
    pub hits: u64,
    /// Successful acquisitions that created a lease.
    pub misses: u64,
    /// Live entries removed by the configured LRU cap.
    pub evictions: u64,
    /// Live entries explicitly force-rotated by an operator.
    pub rotations: u64,
}

fn byte_count<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> std::result::Result<u64, D::Error> {
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum Count {
        Number(u64),
        Decimal(String),
    }
    match Count::deserialize(deserializer)? {
        Count::Number(value) => Ok(value),
        Count::Decimal(value) => value.parse().map_err(serde::de::Error::custom),
    }
}

fn key(org: &OrgId) -> String {
    format!("affinity:{{{org}}}")
}

impl Hot {
    /// Register a successful sticky acquisition and enforce the org's LRU cap.
    ///
    /// `hit` describes the lease outcome, not index membership. `None` means
    /// no configured cap. Zero is invalid. Existing records preserve their
    /// birth time and byte count. Evicted leases are released before returning;
    /// already-open tunnels continue. Failed partition cleanup stays queued
    /// and is retried by the next touch or rotation for this org.
    ///
    /// # Errors
    /// Returns an invalid-input error for an empty sticky key, zero TTL or cap,
    /// or a Redis error when updating or releasing a lease fails.
    pub async fn affinity_touch(
        &self,
        org: &OrgId,
        record: &AffinityRecord,
        ttl: Duration,
        max_entries: Option<u32>,
        hit: bool,
    ) -> Result<()> {
        ensure(!record.sticky.is_empty(), "empty sticky key")?;
        ensure(!ttl.is_zero(), "affinity ttl must be above zero")?;
        ensure(max_entries != Some(0), "affinity cap must be above zero")?;
        let pending: Vec<String> = self
            .run(
                &self.scripts.affinity,
                &key(org),
                &json!({"op":"touch", "record":record, "ttl":ms(ttl),
                    "cap":max_entries, "hit":hit}),
            )
            .await?;
        self.affinity_release_pending(org, pending).await
    }

    /// Add transferred bytes without recreating a rotated or expired entry.
    /// Live traffic refreshes the entry's TTL but not acquisition-based LRU order.
    /// `ttl` must be bounded by the provider unit's remaining life. Zero drops
    /// the entry and returns false. This never changes hit/miss counters.
    ///
    /// # Errors
    /// Returns a Redis error when updating the entry fails.
    pub async fn affinity_add_bytes(
        &self,
        org: &OrgId,
        sticky: &str,
        bytes: u64,
        ttl: Duration,
    ) -> Result<bool> {
        self.run(
            &self.scripts.affinity,
            &key(org),
            &json!({"op":"bytes", "sticky":sticky, "bytes":bytes.to_string(), "ttl":ms(ttl)}),
        )
        .await
    }

    /// List this org's unexpired sticky leases, most recently used first.
    ///
    /// # Errors
    /// Returns a Redis or decoding error when the registry cannot be read.
    pub async fn affinity_sessions(&self, org: &OrgId) -> Result<Vec<AffinityRecord>> {
        let records: Vec<String> = self
            .run(&self.scripts.affinity, &key(org), &json!({"op":"list"}))
            .await?;
        records
            .iter()
            .map(|record| {
                serde_json::from_str(record).map_err(|e| StoreError::decode("affinity record", e))
            })
            .collect()
    }

    /// Read this org's affinity counters and current live-entry count.
    ///
    /// # Errors
    /// Returns a Redis or decoding error when the counters cannot be read.
    pub async fn affinity_stats(&self, org: &OrgId) -> Result<AffinityStats> {
        let stats: String = self
            .run(&self.scripts.affinity, &key(org), &json!({"op":"stats"}))
            .await?;
        serde_json::from_str(&stats).map_err(|e| StoreError::decode("affinity stats", e))
    }

    /// Forget and release a sticky lease without withdrawing a shared provider unit.
    ///
    /// Existing tunnels and other orgs' leases are untouched. Acquisition must
    /// honor [`Hot::affinity_rotation_skip`] to avoid the previous unit.
    /// Returns false for an unknown or expired key. Pending releases survive a
    /// failed Redis call so retrying the rotation finishes cleanup.
    ///
    /// # Errors
    /// Returns a Redis or decoding error when removal or release fails.
    pub async fn affinity_rotate(&self, org: &OrgId, sticky: &str) -> Result<bool> {
        let (found, pending): (bool, Vec<String>) = self
            .run(
                &self.scripts.affinity,
                &key(org),
                &json!({"op":"rotate", "sticky":sticky}),
            )
            .await?;
        self.affinity_release_pending(org, pending).await?;
        Ok(found)
    }

    /// Previous unit excluded after an explicit rotation, for at most one lease TTL.
    /// Append this unit to lease acquisition's skip list. A successful touch on
    /// another unit in this partition clears the exclusion. One-unit pools fail
    /// closed until expiry rather than silently undoing the operator's rotation.
    ///
    /// # Errors
    /// Returns a Redis error when reading the exclusion fails.
    pub async fn affinity_rotation_skip(
        &self,
        org: &OrgId,
        sticky: &str,
        partition: &Partition,
    ) -> Result<Option<String>> {
        self.run(
            &self.scripts.affinity,
            &key(org),
            &json!({"op":"skip", "sticky":sticky, "partition":partition}),
        )
        .await
    }

    async fn affinity_release_pending(&self, org: &OrgId, pending: Vec<String>) -> Result<()> {
        for value in pending {
            let record: AffinityRecord = serde_json::from_str(&value)
                .map_err(|e| StoreError::decode("evicted affinity record", e))?;
            let _: bool = self
                .run_ready(
                    &self.scripts.release,
                    &record.partition,
                    json!({"org":org.as_str(), "sticky":record.sticky, "unit":record.unit}),
                )
                .await?;
            let _: bool = self
                .run(
                    &self.scripts.affinity,
                    &key(org),
                    &json!({"op":"ack", "sticky":record.sticky, "value":value}),
                )
                .await?;
        }
        Ok(())
    }

    /// Consume one request of a shared per-org fixed-window control API limit.
    /// Returns remaining seconds when refused, zero when admitted.
    ///
    /// # Errors
    /// Returns invalid input for a zero limit or window, or a Redis error.
    pub async fn org_api_rate_limit(
        &self,
        org: &OrgId,
        limit: u32,
        window: Duration,
    ) -> Result<u64> {
        ensure(limit > 0 && !window.is_zero(), "invalid API rate limit")?;
        self.run(
            &self.scripts.affinity,
            &key(org),
            &json!({"op":"rate", "limit":limit, "window":ms(window)}),
        )
        .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn record_accepts_exact_decimal_redis_bytes_and_serializes_public_numeric_bytes() {
        let value = json!({
            "sticky":"sid:a", "partition":{"provider":"test","region":"fr"},
            "unit":"unit1", "ip":"198.51.100.1", "created_at_ms":123,
            "last_seen_ms":456, "bytes":"18446744073709551615", "ttl_ms":60000,
        });
        let record: AffinityRecord = serde_json::from_value(value).expect("Redis record");
        assert_eq!(record.bytes, u64::MAX);
        let value = serde_json::to_value(record).expect("API record");
        assert_eq!(value["bytes"].as_u64(), Some(u64::MAX));
        assert!(value.get("ttl_ms").is_none());
    }

    #[test]
    fn numeric_bytes_round_trip_and_invalid_counters_are_rejected() {
        let value = json!({
            "sticky":"sid:a", "partition":{"provider":"test","region":"fr"},
            "unit":"unit1", "ip":"198.51.100.1", "created_at_ms":0,
            "last_seen_ms":0, "bytes":42,
        });
        assert_eq!(
            serde_json::from_value::<AffinityRecord>(value.clone())
                .expect("record")
                .bytes,
            42
        );
        for invalid in [
            json!("-1"),
            json!("18446744073709551616"),
            json!("secret"),
            json!(-1),
        ] {
            let mut bad = value.clone();
            bad["bytes"] = invalid;
            assert!(serde_json::from_value::<AffinityRecord>(bad).is_err());
        }
    }
}
