//! Content hashes of the git data sources, so a sync that changed nothing
//! writes nothing.

use std::time::Duration;

use sha2::{Digest, Sha256};

use crate::error::Result;

instances!("impls/sources.rs");

/// Lowercase hex sha256, the form `data_sources` stores.
pub fn sha256_hex(bytes: &[u8]) -> String {
    use std::fmt::Write;
    Sha256::digest(bytes)
        .iter()
        .fold(String::with_capacity(64), |mut s, b| {
            let _ = write!(s, "{b:02x}");
            s
        })
}

delegate! {
    /// Content hash of a git data source as last applied, if any.
    pub async fn source_hash(&self, name: &str) -> Result<Option<String>>;

    /// Record that the source with this content hash was applied. Call it
    /// after the sync that used the content; a crash in between only repeats
    /// an idempotent sync.
    pub async fn set_source_hash(&self, name: &str, sha256: &str, actor: &str) -> Result<()>;

    /// Say that the gateway `instance` runs the policy tree `hash`,
    /// and forget gateways that have not said so for a day.
    pub async fn beat_gateway_tree(&self, instance: &str, hash: &str) -> Result<()>;

    /// Drop the mark of a gateway that stops: nothing is left running its tree,
    /// so a restart does not have to wait for the mark to go stale.
    pub async fn forget_gateway_tree(&self, instance: &str) -> Result<()>;

    /// Whether a gateway other than `instance` said within `live_for` that it
    /// runs the policy tree `hash`.
    pub async fn gateway_tree_is_live(&self, instance: &str, hash: &str, live_for: Duration) -> Result<bool>;

    /// Whether the policy tree `hash` was applied to the stored policies
    /// before: a tree that never was is new, not a rollback.
    pub async fn policy_tree_was_applied(&self, hash: &str) -> Result<bool>;
}
