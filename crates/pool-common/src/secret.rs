//! A credential that never prints.

use std::fmt;

use serde::{Deserialize, Deserializer};

/// A secret string. `Debug` and `Display` print `***`, so a secret cannot
/// reach a log, metric label, error message or API reply by formatting.
/// Read the value only with [`Secret::expose`], at the point of use.
#[derive(Clone, PartialEq, Eq, Default)]
pub struct Secret(String);

impl Secret {
    pub fn new(value: impl Into<String>) -> Self {
        Self(value.into())
    }

    /// The raw value. Call only where the value is sent to its consumer.
    pub fn expose(&self) -> &str {
        &self.0
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl fmt::Debug for Secret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("***")
    }
}

impl fmt::Display for Secret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("***")
    }
}

impl<'de> Deserialize<'de> for Secret {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        String::deserialize(d).map(Self)
    }
}

#[cfg(test)]
mod tests {
    use super::Secret;

    #[test]
    fn formatting_never_shows_the_value() {
        let s = Secret::new("hunter2");
        assert_eq!(format!("{s} {s:?} {:?}", Some(&s)), "*** *** Some(***)");
        assert_eq!(s.expose(), "hunter2");
    }
}
