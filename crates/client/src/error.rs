//! Error type shared by the control-plane and pool clients.

use std::time::Duration;

use crate::gateway::SelectorError;

/// Result alias for this crate.
pub type Result<T, E = Error> = std::result::Result<T, E>;

/// Why a client call failed.
///
/// HTTP failures are typed by status: 401 and 403 are [`Error::Auth`], 404 is
/// [`Error::NotFound`], 409 is [`Error::Conflict`], 5xx is [`Error::Unavailable`] and any
/// other 4xx is [`Error::Client`].
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// 401 or 403: the key is missing, unknown, disabled, or not allowed for the org.
    #[error("authentication failed (HTTP {status}): {message}")]
    Auth {
        /// HTTP status, 401 or 403.
        status: u16,
        /// Server message.
        message: String,
    },
    /// 404: the session, capture or route does not exist.
    #[error("not found: {message}")]
    NotFound {
        /// Server message.
        message: String,
    },
    /// 409: an `upstream_overrides` conflict on create, or a session that can no longer be
    /// extended (unknown, expired, closing or closed).
    #[error("conflict: {message}")]
    Conflict {
        /// Server message.
        message: String,
    },
    /// 5xx: the service failed or cannot reach its backend. Worth retrying.
    #[error("service unavailable (HTTP {status}): {message}")]
    Unavailable {
        /// HTTP status, 500 to 599.
        status: u16,
        /// Server message.
        message: String,
    },
    /// Any other 4xx: the request is wrong, or (429) the caller is rate limited.
    #[error("request rejected (HTTP {status}): {message}")]
    Client {
        /// HTTP status, 400 to 499.
        status: u16,
        /// Server message.
        message: String,
        /// Delay from a `Retry-After` header, when the server sent one.
        retry_after: Option<Duration>,
    },
    /// The request did not complete: connect failure, timeout, TLS or protocol error.
    #[error("transport error: {0}")]
    Transport(reqwest::Error),
    /// The response body is not the JSON the client expects.
    #[error("invalid response body: {0}")]
    Decode(#[from] serde_json::Error),
    /// A caller argument failed local validation; nothing was sent.
    #[error("invalid input: {0}")]
    InvalidInput(String),
    /// The create response cannot be used safely (`success` is not true, or a proxy URL is
    /// missing or malformed). Credentials are withheld: a client that treated the missing
    /// URL as "no proxy" would send traffic direct.
    #[error("create response refused: {0}")]
    InvalidCreateResponse(String),
    /// The server did not accept the requested `upstream_overrides` verbatim. The session
    /// was released and no proxy credentials are exposed.
    #[error(
        "upstream_overrides in the create response differ from the request; credentials withheld"
    )]
    UpstreamOverridesMismatch,
    /// A wait ran out of time.
    #[error("timed out after {waited:?} waiting for {what}")]
    Timeout {
        /// What was awaited.
        what: &'static str,
        /// How long the wait lasted.
        waited: Duration,
    },
    /// A pool selector (the proxy username) is not valid.
    #[error(transparent)]
    Selector(#[from] SelectorError),
    /// Reading or writing a CA bundle failed.
    #[error("ca bundle: {0}")]
    CaBundle(String),
    /// Local file I/O failed.
    #[error(transparent)]
    Io(#[from] std::io::Error),
}

impl From<reqwest::Error> for Error {
    /// Drops the URL from the error: control-plane paths carry session ids.
    fn from(err: reqwest::Error) -> Self {
        Self::Transport(err.without_url())
    }
}

impl Error {
    /// True when repeating the call can succeed: 5xx, a transport failure, or 408/429.
    pub fn is_retryable(&self) -> bool {
        match self {
            Self::Unavailable { .. } => true,
            Self::Transport(err) => !err.is_builder() && !err.is_decode(),
            Self::Client { status, .. } => matches!(status, 408 | 429),
            _ => false,
        }
    }

    /// True for [`Error::NotFound`].
    pub fn is_not_found(&self) -> bool {
        matches!(self, Self::NotFound { .. })
    }
}

#[cfg(test)]
mod tests {
    use super::Error;

    #[test]
    fn retryable_classification() {
        let unavailable = Error::Unavailable {
            status: 503,
            message: String::new(),
        };
        let limited = Error::Client {
            status: 429,
            message: String::new(),
            retry_after: None,
        };
        let bad = Error::Client {
            status: 400,
            message: String::new(),
            retry_after: None,
        };
        let auth = Error::Auth {
            status: 401,
            message: String::new(),
        };
        assert!(unavailable.is_retryable());
        assert!(limited.is_retryable());
        assert!(!bad.is_retryable());
        assert!(!auth.is_retryable());
        assert!(
            !Error::NotFound {
                message: String::new()
            }
            .is_retryable()
        );
        assert!(!Error::UpstreamOverridesMismatch.is_retryable());
    }
}
