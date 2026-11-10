//! Org keys (`org_keys`): only the sha256 of a key is stored and compared, so a
//! database read never exposes a key.

use common::Secret;
use common::types::OrgId;
use sha2::{Digest, Sha256};

use crate::error::Result;

instances!("impls/org_keys.rs");

/// The sha256 of an org key: the only form in which a key is stored.
pub fn hash_org_key(key: &str) -> [u8; 32] {
    Sha256::digest(key.as_bytes()).into()
}

/// The answer of [`Db::verify_org_key`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KeyStatus {
    /// The key works for this org.
    Enabled(OrgId),
    /// The key is registered and disabled (`org_disabled`).
    Disabled,
    /// No such key.
    Unknown,
}

delegate! {
    /// Register an org key. Only its hash is stored.
    ///
    /// Fails with [`StoreError::Conflict`] when the key is already registered
    /// and with [`StoreError::Invalid`] when `key` is empty.
    pub async fn add_org_key(&self, org: &OrgId, key: &Secret, label: &str, actor: &str) -> Result<()>;

    /// What the key table says about `key`: an enabled key and its org, a
    /// key an operator disabled, or a key nobody registered.
    pub async fn verify_org_key(&self, key: &str) -> Result<KeyStatus>;

    /// Disable every key of an org. Returns how many were enabled.
    pub async fn disable_org_keys(&self, org: &OrgId, actor: &str) -> Result<u64>;
}
