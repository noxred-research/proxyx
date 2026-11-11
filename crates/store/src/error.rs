//! The one error type of the database and Redis layers.
//!
//! Callers branch on `NotFound`, `Conflict`, `Stale`, `Invalid` and
//! `InvalidTransition` (the control API maps them to statuses); everything else
//! is infrastructure failure.

use common::types::IpState;

/// Error of the database and Redis layers.
#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    #[error("database: {0}")]
    Database(#[from] sqlx::Error),
    #[error("migration: {0}")]
    Migrate(#[from] sqlx::migrate::MigrateError),
    #[error("redis: {0}")]
    Redis(#[from] redis::RedisError),
    /// A stored value does not parse into its domain type.
    #[error("stored {what} is invalid: {reason}")]
    Decode { what: &'static str, reason: String },
    #[error("{what} not found")]
    NotFound { what: &'static str },
    #[error("{what} already exists")]
    Conflict { what: &'static str },
    /// A write that depends on an earlier read found the row changed since.
    #[error("{what} changed since it was read")]
    Stale { what: &'static str },
    #[error("invalid state transition {} -> {}", .from.as_str(), .to.as_str())]
    InvalidTransition { from: IpState, to: IpState },
    /// The caller passed an argument the store refuses.
    #[error("invalid argument: {0}")]
    Invalid(String),
}

pub type Result<T, E = StoreError> = std::result::Result<T, E>;

impl StoreError {
    pub(crate) fn decode(what: &'static str, reason: impl ToString) -> Self {
        Self::Decode {
            what,
            reason: reason.to_string(),
        }
    }
}

/// `Ok` when `ok`, else [`StoreError::Invalid`] with `reason`.
pub(crate) fn ensure(ok: bool, reason: &str) -> Result<()> {
    if ok {
        Ok(())
    } else {
        Err(StoreError::Invalid(reason.to_owned()))
    }
}
