//! Org blocks (`org_blocks`): an org kept off an IP, provider, route class or pool.
//! Postgres holds them; the Redis cache is rebuilt from here after a loss.

use std::net::IpAddr;

use common::types::{OrgId, Partition, ProviderId};
use policy::Pool;
use proxyx_db::Ts;
use sqlx::FromRow;
use time::OffsetDateTime;
use uuid::Uuid;

use crate::error::{Result, StoreError};
use crate::hot::Hot;

instances!("impls/org_blocks.rs");

/// What an org block covers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BlockScope {
    /// One exit IP.
    Ip(IpAddr),
    /// Every partition of one provider.
    Provider(ProviderId),
    /// One route class: a provider and a region.
    RouteClass(Partition),
    /// The shared or the private pool.
    Pool(Pool),
}

impl BlockScope {
    /// Column `scope` and `scope_value`; also the field name in Redis.
    pub fn parts(&self) -> (&'static str, String) {
        match self {
            Self::Ip(ip) => ("ip", ip.to_string()),
            Self::Provider(p) => ("provider", p.to_string()),
            Self::RouteClass(p) => ("route_class", p.tag()),
            Self::Pool(Pool::Shared) => ("pool", "shared".into()),
            Self::Pool(Pool::Private) => ("pool", "private".into()),
        }
    }

    /// Redis hash field of this scope, `scope:value`.
    pub(crate) fn field(&self) -> String {
        let (scope, value) = self.parts();
        format!("{scope}:{value}")
    }

    fn parse(scope: &str, value: &str) -> Result<Self> {
        fn bad<E: ToString>(e: E) -> StoreError {
            StoreError::decode("org block scope", e)
        }
        Ok(match scope {
            "ip" => Self::Ip(value.parse().map_err(bad)?),
            "provider" => Self::Provider(value.parse().map_err(bad)?),
            "route_class" => {
                let (provider, region) = value
                    .split_once(':')
                    .ok_or_else(|| bad("route class needs provider:region"))?;
                Self::RouteClass(Partition {
                    provider: provider.parse().map_err(bad)?,
                    region: region.parse().map_err(bad)?,
                })
            }
            "pool" => match value {
                "shared" => Self::Pool(Pool::Shared),
                "private" => Self::Pool(Pool::Private),
                other => return Err(bad(other)),
            },
            other => return Err(bad(other)),
        })
    }
}

/// An operator block: the org may not use the scope until it expires or is
/// revoked.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OrgBlock {
    pub id: Uuid,
    pub org: OrgId,
    pub scope: BlockScope,
    pub reason: String,
    pub operator: String,
    pub created_at: OffsetDateTime,
    pub expires_at: Option<OffsetDateTime>,
    pub revoked_at: Option<OffsetDateTime>,
}

#[derive(FromRow)]
pub(super) struct RawOrgBlock {
    id: Uuid,
    org: String,
    scope: String,
    scope_value: String,
    reason: String,
    operator: String,
    created_at: Ts,
    expires_at: Option<Ts>,
    revoked_at: Option<Ts>,
}

impl RawOrgBlock {
    pub(super) fn id(&self) -> Uuid {
        self.id
    }

    pub(super) fn org(&self) -> &str {
        &self.org
    }
}

impl TryFrom<RawOrgBlock> for OrgBlock {
    type Error = StoreError;

    fn try_from(r: RawOrgBlock) -> Result<Self> {
        Ok(Self {
            id: r.id,
            org: OrgId::try_from(r.org).map_err(|e| StoreError::decode("org id", e))?,
            scope: BlockScope::parse(&r.scope, &r.scope_value)?,
            reason: r.reason,
            operator: r.operator,
            created_at: r.created_at.0,
            expires_at: r.expires_at.map(|t| t.0),
            revoked_at: r.revoked_at.map(|t| t.0),
        })
    }
}

macro_rules! org_block_columns {
    () => {
        "id, org, scope, scope_value, reason, operator, created_at, expires_at, revoked_at"
    };
}
pub(super) use org_block_columns;

/// One cache entry per org and scope from the **active** blocks `blocks`:
/// the scope stays blocked while any of its blocks does, so the expiry is the
/// latest one, and `None` (until cleared) when any of them has none. Writing
/// each block's own expiry would let the last write shorten the others.
pub fn merged_org_blocks(blocks: &[OrgBlock]) -> Vec<(OrgId, BlockScope, Option<OffsetDateTime>)> {
    let mut merged: Vec<(OrgId, BlockScope, Option<OffsetDateTime>)> = Vec::new();
    for b in blocks {
        match merged
            .iter_mut()
            .find(|(org, scope, _)| *org == b.org && *scope == b.scope)
        {
            Some((_, _, until)) => {
                *until = match (*until, b.expires_at) {
                    (Some(a), Some(c)) => Some(a.max(c)),
                    _ => None,
                };
            }
            None => merged.push((b.org.clone(), b.scope.clone(), b.expires_at)),
        }
    }
    merged
}

delegate! {
    /// Block an org from a scope, and cache it in Redis (`hot`) before the
    /// commit: when the cache write fails, nothing is stored. The caller
    /// drains the org's leases in that scope.
    ///
    /// Fails with [`StoreError::Invalid`] when `expires_at` is not in the
    /// future or the reason is empty.
    pub async fn create_org_block(
        &self,
        hot: &Hot,
        org: &OrgId,
        scope: &BlockScope,
        reason: &str,
        operator: &str,
        expires_at: Option<OffsetDateTime>,
    ) -> Result<OrgBlock>;

    /// Lift a block and update its cache field in Redis (`hot`) before the
    /// commit. `None` when it does not exist or was lifted already; a block
    /// that was lifted already still repeats the cache update, so a request
    /// that failed after the commit can be sent again.
    pub async fn revoke_org_block(&self, hot: &Hot, id: Uuid, operator: &str) -> Result<Option<OrgBlock>>;

    /// Blocks that are neither revoked nor expired at `now`.
    pub async fn active_org_blocks(&self, now: OffsetDateTime) -> Result<Vec<OrgBlock>>;

    /// Bring the cache field of `org` and `scope` in line with what the
    /// database holds now, under the org's block lock like every change of its
    /// blocks. A rebuild of Redis that read an older state would otherwise
    /// bring back a block that was lifted since.
    pub async fn resync_org_block(&self, hot: &Hot, org: &OrgId, scope: &BlockScope) -> Result<()>;
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;

    fn block(org: &str, scope: BlockScope, expires_at: Option<OffsetDateTime>) -> OrgBlock {
        OrgBlock {
            id: Uuid::new_v4(),
            org: org.parse().expect("org"),
            scope,
            reason: "r".into(),
            operator: "o".into(),
            created_at: OffsetDateTime::now_utc(),
            expires_at,
            revoked_at: None,
        }
    }

    #[test]
    fn one_cache_entry_per_org_and_scope_lasts_as_long_as_its_longest_block() {
        let now = OffsetDateTime::now_utc();
        let (soon, later) = (now + Duration::from_secs(3), now + Duration::from_secs(60));
        let pool = || BlockScope::Pool(Pool::Shared);
        let merged = merged_org_blocks(&[
            // permanent first, then a short one: the short one must not win
            block("ovw", pool(), None),
            block("ovw", pool(), Some(soon)),
            // the other order
            block("rev", pool(), Some(soon)),
            block("rev", pool(), None),
            // two expiring blocks: the later wins
            block("two", pool(), Some(later)),
            block("two", pool(), Some(soon)),
            // another scope of the same org stays its own entry
            block("two", BlockScope::Pool(Pool::Private), Some(soon)),
        ]);
        let of = |org: &str, scope: &BlockScope| {
            merged
                .iter()
                .find(|(o, s, _)| o.as_str() == org && s == scope)
                .map(|(_, _, until)| *until)
        };
        assert_eq!(merged.len(), 4);
        assert_eq!(of("ovw", &pool()), Some(None));
        assert_eq!(of("rev", &pool()), Some(None));
        assert_eq!(of("two", &pool()), Some(Some(later)));
        assert_eq!(
            of("two", &BlockScope::Pool(Pool::Private)),
            Some(Some(soon))
        );
    }
}
