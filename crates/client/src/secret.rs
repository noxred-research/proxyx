//! A string that never prints itself.

use serde::Deserialize;

/// Credential text: a service key, an org key, or a proxy URL that carries the session id.
///
/// `Debug` prints a placeholder and there is no `Display`, so a stray `{:?}` or `tracing`
/// field cannot leak the value. Read it with [`Secret::expose`] at the point of use.
#[derive(Clone, Deserialize)]
#[serde(transparent)]
pub struct Secret(String);

impl Secret {
    /// Wrap a credential.
    pub fn new(value: impl Into<String>) -> Self {
        Self(value.into())
    }

    /// The credential text. Do not log it.
    pub fn expose(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Debug for Secret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Secret([redacted])")
    }
}

impl From<String> for Secret {
    fn from(value: String) -> Self {
        Self(value)
    }
}

impl From<&str> for Secret {
    fn from(value: &str) -> Self {
        Self(value.to_owned())
    }
}

#[cfg(test)]
mod tests {
    use super::Secret;

    #[test]
    fn debug_hides_the_value() {
        let secret = Secret::new("pxk_topsecret");
        assert!(!format!("{secret:?}").contains("topsecret"));
        assert_eq!(secret.expose(), "pxk_topsecret");
    }
}
