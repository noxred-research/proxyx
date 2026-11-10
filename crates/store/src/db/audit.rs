//! Append-only audit rows: every write in the sibling modules adds one in
//! its own transaction, so an operator can tell who changed what and when.

use proxyx_db::Ts;
use serde_json::Value;
use sqlx::FromRow;
use sqlx::types::Json;
use time::OffsetDateTime;

use crate::error::Result;

instances!("impls/audit.rs");

/// Reputation scores are kept this long.
pub const SCORES_KEEP_DAYS: i32 = 30;
/// Block signal rows are kept this long.
pub const BLOCKS_KEEP_DAYS: i32 = 30;
/// The audit rows the system writes by itself (state changes, reset requests,
/// replacement reports) are kept this long. The migration
/// `audit_retention` lets the append-only trigger delete exactly these, at
/// exactly this age; every other row stays for good.
pub const AUDIT_KEEP_DAYS: i32 = 90;

/// Rows [`Db::prune_history`] deletes in one statement: the first prune of a
/// long-lived table must stay inside the statement timeout.
pub(super) const PRUNE_CHUNK: i64 = 5_000;

/// What [`Db::prune_history`] deleted.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Pruned {
    pub scores: u64,
    pub blocks: u64,
    pub audit: u64,
}

/// One append-only audit row. Holds actor, action and subject; never a secret.
#[derive(Debug, Clone)]
pub struct AuditRow {
    pub id: i64,
    pub at: OffsetDateTime,
    pub actor: String,
    pub action: String,
    pub subject: String,
    pub detail: Value,
}

#[derive(FromRow)]
pub(super) struct RawAudit {
    id: i64,
    at: Ts,
    actor: String,
    action: String,
    subject: String,
    detail: Json<Value>,
}

impl From<RawAudit> for AuditRow {
    fn from(r: RawAudit) -> Self {
        Self {
            id: r.id,
            at: r.at.0,
            actor: r.actor,
            action: r.action,
            subject: r.subject,
            detail: r.detail.0,
        }
    }
}

macro_rules! audit_columns {
    () => {
        "id, at, actor, action, subject, detail"
    };
}
pub(super) use audit_columns;

delegate! {
    /// Append an audit row for a change made outside this crate.
    pub async fn audit(&self, actor: &str, action: &str, subject: &str, detail: Value) -> Result<()>;

    /// Audit rows of one subject, newest first.
    pub async fn audit_for(&self, subject: &str, limit: i64) -> Result<Vec<AuditRow>>;

    /// The newest `inventory.transition` row of an IP: who moved it last, and
    /// to which state (`detail.to`). `None` for an IP that never moved.
    pub async fn last_transition(&self, ip: &str) -> Result<Option<AuditRow>>;

    /// Delete history nothing reads any more: reputation scores and block
    /// rows older than [`SCORES_KEEP_DAYS`] and [`BLOCKS_KEEP_DAYS`] days
    /// (the replacement rule looks at the last few checks, quarantine at an
    /// hour, the report at a day; target blocks still running stay), and the
    /// machine-written audit rows older than [`AUDIT_KEEP_DAYS`] days.
    pub async fn prune_history(&self) -> Result<Pruned>;
}
