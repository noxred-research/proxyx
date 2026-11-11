//! API keys (`api_keys`): only the SHA-256 of a key is stored.

use proxyx_db::Ts;
use sqlx::FromRow;
use time::OffsetDateTime;

use crate::db::DbResult;

instances!("impls/keys.rs");

/// One stored key, without the key.
#[derive(FromRow)]
pub struct KeyRow {
    pub key_hash: Vec<u8>,
    pub kind: String,
    pub org_id: Option<String>,
    pub name: String,
    pub disabled: bool,
    created_at: Ts,
}

impl KeyRow {
    pub fn created_at(&self) -> OffsetDateTime {
        self.created_at.0
    }
}

delegate! {
    /// Store a key by its hash.
    pub async fn insert_key(&self, key_hash: &[u8], kind: &str, org_id: Option<&str>, name: &str) -> DbResult<()>;

    /// Every key of `org_id` (or every key when `None`), newest first.
    pub async fn list_keys(&self, org_id: Option<&str>) -> DbResult<Vec<KeyRow>>;

    /// Disable the live key whose id (hex of the first 8 bytes of its hash)
    /// is `id`. Whether a key was disabled.
    pub async fn disable_key(&self, id: &str) -> DbResult<bool>;

    /// The kind, org and name of the enabled key with this hash.
    pub async fn enabled_key(&self, key_hash: &[u8]) -> DbResult<Option<(String, Option<String>, String)>>;
}
