//! The two multi-table reads: the snapshot every role reloads and the
//! read that rebuilds Redis. Each runs in one transaction with a single view
//! of the data, so the parts agree with each other.

use std::collections::HashMap;
use std::sync::Arc;

use common::types::OrgId;
use time::OffsetDateTime;

use super::{CustomerLogin, Db, InventoryRow, IpBlock, OrgBlock, PolicyRecord};
use crate::error::Result;

instances!("impls/reads.rs");

/// What [`Snapshot`](crate::Snapshot) is built from.
pub(crate) struct SnapshotRead {
    pub(crate) policies: Arc<[PolicyRecord]>,
    pub(crate) inventory: Vec<InventoryRow>,
    pub(crate) customer_logins: HashMap<OrgId, CustomerLogin>,
    pub(crate) loaded_at: OffsetDateTime,
}

/// What [`rebuild_hot`](crate::rebuild_hot) seeds Redis from.
pub(crate) struct RebuildRead {
    pub(crate) inventory: Vec<InventoryRow>,
    pub(crate) target_blocks: Vec<IpBlock>,
    pub(crate) org_blocks: Vec<OrgBlock>,
    pub(crate) now: OffsetDateTime,
}

impl Db {
    /// Read everything the gateway and warmer serve from in one snapshot
    /// transaction. With `prev`, the policy records are reused when no policy
    /// changed since.
    pub(crate) async fn read_snapshot(
        &self,
        prev: Option<&Arc<[PolicyRecord]>>,
    ) -> Result<SnapshotRead> {
        match self.pool() {
            proxyx_db::Pool::Postgres(pool) => postgres::read_snapshot(pool, prev).await,
            proxyx_db::Pool::MariaDb(pool) => mariadb::read_snapshot(pool, prev).await,
            proxyx_db::Pool::Sqlite(pool) => sqlite::read_snapshot(pool, prev).await,
        }
    }

    /// Read the state a rebuild of Redis seeds it from, in one snapshot.
    pub(crate) async fn read_rebuild(&self) -> Result<RebuildRead> {
        match self.pool() {
            proxyx_db::Pool::Postgres(pool) => postgres::read_rebuild(pool).await,
            proxyx_db::Pool::MariaDb(pool) => mariadb::read_rebuild(pool).await,
            proxyx_db::Pool::Sqlite(pool) => sqlite::read_rebuild(pool).await,
        }
    }
}
