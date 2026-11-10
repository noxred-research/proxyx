//! Why a policy file or set is refused. The gateway and the warmer keep their
//! last good set on any of these, so the messages name the file, policy and
//! field to fix. `Toml` carries the cause in its message and exposes no
//! `source`, so `{:#}` of a wrapping `anyhow::Error` does not print it twice.

use crate::doc::Scope;

/// A policy file or set that cannot be used. The caller keeps the last good set.
#[derive(Debug, thiserror::Error)]
pub enum PolicyError {
    #[error("policy file: {0}")]
    Toml(toml::de::Error),
    #[error("duplicate {scope} policy for {key:?}")]
    Duplicate { scope: Scope, key: String },
    #[error("duplicate policy name {0:?}")]
    DuplicateName(String),
    /// `scope` and `match` disagree, or `match` is not a valid id.
    #[error("policy {name:?}: {reason}")]
    Scope { name: String, reason: String },
    /// `context` names the policies merged for the failing combination.
    #[error("{context}: {field}: {reason}")]
    Invalid {
        context: String,
        field: &'static str,
        reason: String,
    },
    #[error("{context}: {field} {value} is above the ceiling {ceiling}")]
    AboveCeiling {
        context: String,
        field: &'static str,
        value: String,
        ceiling: String,
    },
}
