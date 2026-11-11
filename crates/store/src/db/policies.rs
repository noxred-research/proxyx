//! Versioned policy documents (`policies`): one current row per scope and name,
//! and the newest [`MAX_POLICY_VERSIONS`] versions of each.
//! The documents stay JSON here; the `policy` crate owns their schema.

use std::collections::HashMap;

use policy::PolicyDoc;
use proxyx_db::Ts;
use serde::Deserialize as _;
use serde_json::Value;
use sqlx::FromRow;
use sqlx::types::Json;
use time::OffsetDateTime;

use crate::error::{Result, StoreError};

instances!("impls/policies.rs");

/// Versions kept per policy, the current one included.
pub(super) const MAX_POLICY_VERSIONS: i32 = 50;

/// One stored policy version. The document is JSON so the store does not
/// follow the policy schema; [`PolicyRecord::doc`] parses it.
#[derive(Debug, Clone)]
pub struct PolicyRecord {
    pub scope: String,
    pub name: String,
    pub target: Option<String>,
    pub version: i32,
    pub doc: Value,
    pub current: bool,
    pub actor: String,
    pub created_at: OffsetDateTime,
}

impl PolicyRecord {
    /// Fails with [`StoreError::Decode`] when the stored document no longer
    /// parses.
    pub fn doc(&self) -> Result<PolicyDoc> {
        PolicyDoc::deserialize(&self.doc).map_err(|e| StoreError::decode("policy", e))
    }
}

/// What [`Db::put_policies`] did.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PolicyPut {
    /// `scope/name` of each policy that got a new version.
    pub stored: Vec<String>,
    /// Policies whose document did not change.
    pub unchanged: usize,
}

macro_rules! policy_columns {
    () => {
        "scope, name, target, version, doc, current, actor, created_at"
    };
}
pub(super) use policy_columns;

#[derive(FromRow)]
pub(super) struct RawPolicy {
    scope: String,
    name: String,
    target: Option<String>,
    version: i32,
    doc: Json<Value>,
    current: bool,
    actor: String,
    created_at: Ts,
}

impl From<RawPolicy> for PolicyRecord {
    fn from(r: RawPolicy) -> Self {
        Self {
            scope: r.scope,
            name: r.name,
            target: r.target,
            version: r.version,
            doc: r.doc.0,
            current: r.current,
            actor: r.actor,
            created_at: r.created_at.0,
        }
    }
}

fn strip_unset(value: &mut Value) {
    match value {
        Value::Object(map) => {
            map.values_mut().for_each(strip_unset);
            map.retain(|_, v| !v.is_null() && !matches!(v, Value::Object(o) if o.is_empty()));
        }
        Value::Array(items) => items.iter_mut().for_each(strip_unset),
        _ => {}
    }
}

/// The document as `policies.doc` stores it. Two documents are the same
/// policy exactly when their canonical forms are equal.
pub fn canonical_policy_doc(doc: &PolicyDoc) -> Result<Value> {
    let mut value = serde_json::to_value(doc)
        .map_err(|e| StoreError::Invalid(format!("policy {}: {e}", doc.name)))?;
    strip_unset(&mut value);
    Ok(value)
}

delegate! {
    /// Store each document as a new version when it differs from the current
    /// one, or when it is the same document and `actor` is `gitops` taking
    /// over a version an operator wrote. A document in a new `(scope, name)`
    /// is version 1.
    ///
    /// Nothing is stored when a document does not serialise or Postgres fails.
    pub async fn put_policies(&self, docs: &[PolicyDoc], actor: &str) -> Result<PolicyPut>;

    /// `(scope, name, version)` of every current policy.
    pub async fn current_policy_versions(&self) -> Result<Vec<(String, String, i32)>>;

    /// The newest stored document of each policy that `actor` wrote, current
    /// or not, by `(scope, name)`. Git sync compares a file's policy with it
    /// to tell what git changed from what an operator changed since.
    pub async fn latest_policy_docs_by(&self, actor: &str) -> Result<HashMap<(String, String), Value>>;

    /// Stop using a policy (its versions stay). Returns false when it was
    /// not current.
    pub async fn deactivate_policy(&self, scope: &str, name: &str, actor: &str) -> Result<bool>;

    /// The current version of every policy.
    pub async fn current_policies(&self) -> Result<Vec<PolicyRecord>>;

    /// Every version of one policy, newest first.
    pub async fn policy_versions(&self, scope: &str, name: &str) -> Result<Vec<PolicyRecord>>;
}
