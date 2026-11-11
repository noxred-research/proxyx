//! Customer upstreams (plan section 7): one org-owned static unit and its
//! login.
//!
//! The unit is an ordinary inventory row with `owner_org` set, so only that
//! org may lease it. The login lives in `customer_credentials`, in clear text
//! like the session proxy's `orgs.proxy_password` (the database is private to ProxyX).
//! No query here returns a login to an API route: only [`Snapshot`] (for the
//! gateway and warmer) and [`Db::customer_login`] (for the API's own dial)
//! read it, and both hand out [`Secret`]s.
//!
//! [`Snapshot`]: crate::Snapshot

use std::net::IpAddr;

use common::Secret;
use common::types::{InventoryEntry, OrgId};
use sqlx::FromRow;

use super::Db;
use super::inventory::{InventoryRow, RawRow};
use crate::error::{Result, StoreError};

instances!("impls/customer.rs");

/// Username and password of a customer upstream. Never in a log or a reply.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CustomerLogin {
    pub username: Secret,
    pub password: Secret,
}

/// What [`Db::set_customer_upstream`] wrote.
#[derive(Debug, Clone, PartialEq)]
pub struct CustomerSet {
    /// The org's unit, now `Candidate`.
    pub row: InventoryRow,
    /// The unit the org had before, when there was one. The caller takes it
    /// out of the ready set: it may sit in another partition than `row`.
    pub replaced: Option<InventoryRow>,
}

impl CustomerLogin {
    pub(super) fn new(username: String, password: String) -> Self {
        Self {
            username: Secret::new(username),
            password: Secret::new(password),
        }
    }
}

/// An org's live upstream and the version a write that depends on a check
/// through it must still see (`inventory.upstream_version`). Every set,
/// rotate and clear takes a new value from one sequence, so a version names
/// one state of one row.
#[derive(Debug, Clone, PartialEq)]
pub struct CustomerUnit {
    pub row: InventoryRow,
    pub version: i64,
}

#[derive(FromRow)]
pub(super) struct RawVersioned {
    #[sqlx(flatten)]
    row: RawRow,
    upstream_version: i64,
}

impl TryFrom<RawVersioned> for CustomerUnit {
    type Error = StoreError;

    fn try_from(raw: RawVersioned) -> Result<Self> {
        Ok(Self {
            row: raw.row.try_into()?,
            version: raw.upstream_version,
        })
    }
}

delegate! {
    /// Make `entry` the org's upstream, in state `Candidate`, and store its
    /// login (`None`: the upstream takes no login). An earlier upstream of the
    /// org is retired when it has another address, and reset to `Candidate`
    /// when it has the same one, so every change is validated again.
    ///
    /// The row key is `entry.ip`: only a key, chosen by the caller (the API
    /// derives one per org). It is neither the upstream's address nor its exit
    /// IP; the exit IP is learned by [`Db::customer_validated`].
    ///
    /// Fails with [`StoreError::Invalid`] when `entry` is not a static entry,
    /// [`StoreError::Conflict`] when its IP is a live row of another org or of
    /// the shared inventory.
    pub async fn set_customer_upstream(
        &self,
        org: &OrgId,
        entry: &InventoryEntry,
        login: Option<&CustomerLogin>,
        actor: &str,
    ) -> Result<CustomerSet>;

    /// The actor of the org's latest `customer.set` (the audit trail), or
    /// `None` when it never had an upstream.
    pub async fn last_customer_setter(&self, org: &OrgId) -> Result<Option<String>>;

    /// Retire the org's upstream and delete its login. Returns the retired
    /// unit so the caller can take it out of the ready set.
    ///
    /// Fails with [`StoreError::NotFound`] when the org has no upstream.
    pub async fn clear_customer_upstream(&self, org: &OrgId, actor: &str) -> Result<InventoryRow>;

    /// Replace the stored login of the org's upstream. The state does not
    /// change: the caller checked the new login against the upstream first.
    /// `version` is the one [`Db::customer_upstream`] returned before that
    /// check; the upstream changing since then writes nothing.
    ///
    /// Fails with [`StoreError::NotFound`] when the org has no upstream,
    /// [`StoreError::Stale`] when the upstream changed since `version`.
    pub async fn rotate_customer_login(
        &self,
        org: &OrgId,
        version: i64,
        login: &CustomerLogin,
        actor: &str,
    ) -> Result<()>;

    /// The org's live upstream with its version. Read it before a check
    /// through the upstream and hand it to the write that records the result
    /// ([`Db::customer_validated`], [`Db::rotate_customer_login`]).
    pub async fn customer_upstream(&self, org: &OrgId) -> Result<Option<CustomerUnit>>;

    /// The stored login of the org's upstream, for the API's own dial.
    pub async fn customer_login(&self, org: &OrgId) -> Result<Option<CustomerLogin>>;

    /// Record a passed validation: the unit becomes `Available` (a unit that
    /// is `Available` or `Leased` keeps its state), its deadlines clear, and
    /// the exit IP and check time are stored. Writes the `customer.validate`
    /// audit row. `version` is the one [`Db::customer_upstream`] returned
    /// before the check ran: a set, rotate or clear since then makes the
    /// result about another upstream, and nothing is written.
    ///
    /// Fails with [`StoreError::NotFound`] when the org has no upstream,
    /// [`StoreError::Stale`] when the upstream changed since `version`,
    /// [`StoreError::InvalidTransition`] when the unit waits for a replacement
    /// or rotates.
    pub async fn customer_validated(
        &self,
        org: &OrgId,
        version: i64,
        exit_ip: IpAddr,
        actor: &str,
    ) -> Result<InventoryRow>;
}

impl Db {
    /// The org's live (not retired) upstream.
    pub async fn customer_unit(&self, org: &OrgId) -> Result<Option<InventoryRow>> {
        Ok(self.customer_upstream(org).await?.map(|u| u.row))
    }
}
