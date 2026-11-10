//! Postgres (durable) and Redis (hot) state, lease scripts.
//!
//! * [`Db`]: policies, inventory with deadlines, scores, block history, org
//!   blocks, org keys, git sync hashes and the append-only audit trail.
//! * [`Hot`]: leases, ready sets, tunnel counters, reservations, cooldowns,
//!   locks and the `due` set. Every key of one partition shares the hash tag
//!   `{partition.tag()}`, and every decision of a lease is one Lua script.
//! * [`Snapshot::load`] and [`rebuild_hot`]: read the durable state, and
//!   Re-seed Redis from it after a loss.

mod db;
mod error;
mod hot;
mod session_job;
mod snapshot;

pub mod loaded;
#[doc(hidden)]
pub mod testing;

pub use db::{
    AUDIT_KEEP_DAYS, AuditRow, BLOCKS_KEEP_DAYS, BlockScope, BlockSummary, CustomerLogin,
    CustomerSet, CustomerUnit, Db, InventoryRow, InventorySync, IpBlock, KeyStatus, OrgBlock,
    PolicyPut, PolicyRecord, Pruned, SCORES_KEEP_DAYS, ScoreRow, Transition, UpsertOutcome,
    hash_org_key, merged_org_blocks, sha256_hex,
};
pub use error::{Result, StoreError};
pub use hot::{
    Admit, CostUsage, ExitIpClaim, FAILED_LEASE_MEMO_TTL, FairUse, Grant, Hot, LeaseLimits,
    LeaseOutcome, LeaseRequest, MAX_RANK, RESERVATION_TTL, ReleaseRule, Reservation, Retired,
    SampleJob, SessionRecord, Swept, TunnelRef, UNIT_PENALTY_BASE, UNIT_PENALTY_MAX, UnitCounts,
    UnitLoad, UnitRecord, Verdict, sid_sticky,
};
pub use session_job::{Phase, SessionJob};
pub use snapshot::{RebuildReport, Snapshot, rebuild_hot};
