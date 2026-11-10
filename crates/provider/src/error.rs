//! The one error type of the crate. `Io`, `Parse` and `Secret` hold their
//! cause in a field that is not a `source`, so a message printed with `{:#}`
//! does not repeat it.

use std::path::PathBuf;

use common::types::ProviderId;

/// Everything the provider crate refuses or fails at.
///
/// No variant carries a credential or an option value: messages name the
/// field and the rule, never the text that broke it.
#[derive(Debug, thiserror::Error)]
pub enum ProviderError {
    #[error("failed to read {path}: {error}")]
    Io {
        path: PathBuf,
        error: std::io::Error,
    },
    #[error("failed to parse {path}: {error}")]
    Parse {
        path: PathBuf,
        error: toml::de::Error,
    },
    #[error("duplicate adapter id {0}")]
    DuplicateId(ProviderId),
    /// An adapter file that cannot work, found when it is loaded.
    #[error("adapter {id}: {reason}")]
    Config { id: ProviderId, reason: String },
    #[error("adapter {id}: secret file {name:?}: {error:#}")]
    Secret {
        id: ProviderId,
        name: String,
        error: anyhow::Error,
    },
    /// A value outside the option's charset, length or maximum (refuse,
    /// never escape).
    #[error("option {option} refused: {reason}")]
    OptionRefused {
        option: &'static str,
        reason: String,
    },
    #[error("{field} is {len} bytes, the limit is {limit}", limit = crate::MAX_FIELD_BYTES)]
    FieldTooLong { field: &'static str, len: usize },
    /// A control character, or `:` in a username, which Basic auth cannot carry.
    #[error("{field} holds a character that cannot be sent")]
    BadChar { field: &'static str },
    /// A base username or password contains the text of an option fragment,
    /// so a rendered option could not be told from the base.
    #[error("{base} holds the provider separator {separator:?}")]
    SeparatorInBase {
        base: &'static str,
        separator: String,
    },
    #[error("adapter {id} needs a {field} credential and none is set")]
    MissingCredential { id: ProviderId, field: &'static str },
    /// The spec does not fit this adapter (wrong kind, provider or subtype,
    /// or a request the provider cannot express).
    #[error("adapter {id}: {reason}")]
    SpecMismatch { id: ProviderId, reason: String },
    /// A `customer` upstream address that is not public routable.
    #[error("upstream address is not public routable")]
    NotPublic,
    #[error("adapter {0} has no rotate call")]
    NoRotate(ProviderId),
    #[error("box handle must be 1 to 64 characters of [A-Za-z0-9_-]")]
    BadHandle,
    #[error("rotate answered 429")]
    RotateRateLimited,
    #[error("rotate timed out")]
    RotateTimeout,
    #[error("rotate answered {0}")]
    RotateStatus(u16),
    #[error("rotate failed: {0}")]
    RotateTransport(String),
    #[error("http client: {0}")]
    Client(String),
}
