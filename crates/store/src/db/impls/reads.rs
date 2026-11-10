// The snapshot reads of one backend. See `db/reads.rs`.

use std::sync::Arc;

use time::OffsetDateTime;

use crate::db::PolicyRecord;
use crate::db::reads::{RebuildRead, SnapshotRead};
use crate::error::Result;

pub(crate) async fn read_snapshot(
    pool: &d::Pool,
    prev: Option<&Arc<[PolicyRecord]>>,
) -> Result<SnapshotRead> {
    let mut tx = d::begin_snapshot(pool).await?;
    let loaded_at = OffsetDateTime::now_utc();
    let policies = match prev {
        Some(prev) => {
            let versions = d::policies::current_policy_versions_in(&mut tx).await?;
            let same = versions.len() == prev.len()
                && versions
                    .iter()
                    .zip(prev.iter())
                    .all(|((scope, name, version), p)| {
                        *scope == p.scope && *name == p.name && *version == p.version
                    });
            if same {
                Arc::clone(prev)
            } else {
                d::policies::current_policies_in(&mut tx).await?.into()
            }
        }
        None => d::policies::current_policies_in(&mut tx).await?.into(),
    };
    let inventory = d::inventory::list_inventory_in(&mut tx, None, None).await?;
    let customer_logins = d::customer::customer_logins_in(&mut tx).await?;
    tx.commit().await?;
    Ok(SnapshotRead {
        policies,
        inventory,
        customer_logins,
        loaded_at,
    })
}

pub(crate) async fn read_rebuild(pool: &d::Pool) -> Result<RebuildRead> {
    let mut tx = d::begin_snapshot(pool).await?;
    let now = OffsetDateTime::now_utc();
    let inventory = d::inventory::list_inventory_in(&mut tx, None, None).await?;
    let target_blocks = d::blocks::active_target_blocks_in(&mut tx, now).await?;
    let org_blocks = d::org_blocks::active_org_blocks_in(&mut tx, now).await?;
    tx.commit().await?;
    Ok(RebuildRead {
        inventory,
        target_blocks,
        org_blocks,
        now,
    })
}
