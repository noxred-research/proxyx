//! The snapshot every role reloads and the rebuild of Redis from Postgres.
//!
//! The database is the source of truth; Redis is a cache that a loss may empty
//!.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

use common::types::{OrgId, Partition, Target};
use time::OffsetDateTime;

use crate::db::{CustomerLogin, Db, InventoryRow, PolicyRecord, merged_org_blocks};
use crate::error::Result;
use crate::hot::{Hot, UnitRecord};

/// The durable state the gateway and the warmer serve from. Postgres can go
/// Down and they keep the last snapshot.
#[derive(Debug, Clone)]
pub struct Snapshot {
    /// The current version of every policy. Shared with the snapshot it was
    /// reloaded from while no policy changed ([`Snapshot::reload`]).
    pub policies: Arc<[PolicyRecord]>,
    /// Every inventory row, retired ones included.
    pub inventory: Vec<InventoryRow>,
    /// The login of each customer upstream, by owner org. Secrets: they never
    /// leave this struct except into an upstream endpoint.
    pub customer_logins: HashMap<OrgId, CustomerLogin>,
    pub loaded_at: OffsetDateTime,
}

impl Snapshot {
    /// Read everything in one repeatable-read transaction, so the parts
    /// agree with each other.
    pub async fn load(db: &Db) -> Result<Self> {
        Self::read(db, None).await
    }

    /// [`Snapshot::load`] for a role that reloads on a timer: when no policy
    /// changed since `prev`, its policy records are reused instead of being
    /// read and decoded again, so a quiet reload leaves nothing for the
    /// caller to rebuild (`Arc::ptr_eq` on `policies` tells it).
    pub async fn reload(db: &Db, prev: &Self) -> Result<Self> {
        Self::read(db, Some(&prev.policies)).await
    }

    async fn read(db: &Db, prev: Option<&Arc<[PolicyRecord]>>) -> Result<Self> {
        let read = db.read_snapshot(prev).await?;
        Ok(Self {
            policies: read.policies,
            inventory: read.inventory,
            customer_logins: read.customer_logins,
            loaded_at: read.loaded_at,
        })
    }
}

/// What [`rebuild_hot`] wrote.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct RebuildReport {
    /// Static units made leasable.
    pub units: usize,
    /// Static units taken out of leasing (cooldown, quarantine, ...).
    pub withdrawn: usize,
    pub target_cooldowns: usize,
    pub org_blocks: usize,
}

/// Re-seed Redis from Postgres after a loss: static
/// units that may be leasable, per-target cooldowns still running, and org
/// blocks. Units in cooldown, quarantine and the other non-leasable states
/// leave the ready set, so no banned IP is leased. Leases, tunnels and
/// rotating sessions are not touched; the warmer refills those. Safe to run
/// on a live Redis. Marks Redis as seeded.
///
/// The org blocks are written under the org's block lock from the state
/// Postgres has then. The units and cooldowns come from one earlier read
/// with no fence against a live system: a cooldown that ran during the
/// rebuild can be overwritten, and the warmer's static loop corrects that
/// within a pass (it takes a unit whose row is not leasable out of the ready
/// set and puts a leasable one back).
///
/// Run it again when Postgres or Redis fails.
pub async fn rebuild_hot(db: &Db, hot: &Hot) -> Result<RebuildReport> {
    // The blocks are read here and not with the snapshot every role reloads:
    // signals add a target block each, and only a rebuild needs them.
    let crate::db::RebuildRead {
        inventory,
        target_blocks,
        org_blocks,
        now,
    } = db.read_rebuild().await?;
    let mut report = RebuildReport::default();
    let mut partition_of: HashMap<IpAddr, Partition> = HashMap::new();
    for row in &inventory {
        let partition = row.partition();
        partition_of.insert(row.entry.ip, partition.clone());
        if row.state.is_leasable() {
            // The unit stands for the exit IP the last check saw: a SIM box
            // has another address than its row key after a reset, and an
            // org-owned unit stands for an upstream that is not the row key.
            let unit = UnitRecord {
                owner: row.owner.clone(),
                ip: row.unit_ip(),
                ..UnitRecord::static_ip(row.entry.ip)
            };
            hot.ready_put_tier(&partition, &unit, row.state.tier())
                .await?;
            report.units += 1;
        } else if hot
            .ready_take(&partition, &row.entry.ip.to_string())
            .await?
        {
            report.withdrawn += 1;
        }
    }
    for block in &target_blocks {
        let (Some(target), Some(until), Some(partition)) = (
            block.target.as_ref(),
            block.expires_at,
            partition_of.get(&block.ip),
        ) else {
            continue;
        };
        let left = until - now;
        let Ok(ttl) = Duration::try_from(left) else {
            continue;
        };
        if ttl.is_zero() {
            continue;
        }
        let target = Target {
            host: target.clone(),
            port: 0,
        };
        hot.cool_target(partition, block.ip, &target, ttl).await?;
        report.target_cooldowns += 1;
    }
    // One field per org and scope, written from what Postgres holds when the
    // org's block lock is taken: `org_blocks` above may be older than a
    // revoke that ran since, and the last writer would bring that block back.
    for (org, scope, _) in merged_org_blocks(&org_blocks) {
        db.resync_org_block(hot, &org, &scope).await?;
        report.org_blocks += 1;
    }
    hot.mark_seeded().await?;
    Ok(report)
}
