//! The relational backends ProxyX runs on and the URL scheme that selects one.

use std::fmt;

/// A supported relational backend.
///
/// PostgreSQL is the default and the only backend the project's own
/// deployments are sized for. MariaDB (10.6 or newer, 11 tested) is the
/// second multi-node backend. SQLite is for one node: see `docs/databases.md`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Backend {
    Postgres,
    MariaDb,
    Sqlite,
}

/// The URL names no supported backend.
#[derive(Debug, thiserror::Error)]
#[error(
    "unsupported database url scheme {scheme:?}: use postgres://, mysql:// or mariadb://, or sqlite://PATH"
)]
pub struct UnsupportedScheme {
    scheme: String,
}

impl Backend {
    /// Every backend, in documentation order.
    pub const ALL: [Backend; 3] = [Backend::Postgres, Backend::MariaDb, Backend::Sqlite];

    /// The backend a `database_url` selects by its scheme: `postgres://` or
    /// `postgresql://`, `mysql://` or `mariadb://`, `sqlite://` or `sqlite:`.
    ///
    /// Fails for any other scheme (and for a string without one), so a typo
    /// never falls back to another database.
    pub fn from_url(url: &str) -> Result<Self, UnsupportedScheme> {
        let scheme = url.split_once(':').map_or("", |(scheme, _)| scheme);
        match scheme.to_ascii_lowercase().as_str() {
            "postgres" | "postgresql" => Ok(Self::Postgres),
            "mysql" | "mariadb" => Ok(Self::MariaDb),
            "sqlite" => Ok(Self::Sqlite),
            _ => Err(UnsupportedScheme {
                scheme: scheme.to_owned(),
            }),
        }
    }

    /// Stable lowercase name: `postgres`, `mariadb`, `sqlite`.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Postgres => "postgres",
            Self::MariaDb => "mariadb",
            Self::Sqlite => "sqlite",
        }
    }

    /// Whether several processes on several hosts can share this backend.
    /// SQLite is a file: every role that uses it must run on the same host,
    /// and a role that needs coordination across replicas refuses it.
    pub const fn is_multi_node(self) -> bool {
        !matches!(self, Self::Sqlite)
    }
}

impl fmt::Display for Backend {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl std::str::FromStr for Backend {
    type Err = UnsupportedScheme;

    /// A backend by name (`postgres`, `mariadb`, `mysql`, `sqlite`).
    fn from_str(name: &str) -> Result<Self, Self::Err> {
        match name.to_ascii_lowercase().as_str() {
            "postgres" | "postgresql" => Ok(Self::Postgres),
            "mariadb" | "mysql" => Ok(Self::MariaDb),
            "sqlite" => Ok(Self::Sqlite),
            _ => Err(UnsupportedScheme {
                scheme: name.to_owned(),
            }),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_scheme_selects_the_backend() {
        for (url, backend) in [
            ("postgres://u@h/d", Backend::Postgres),
            ("postgresql://u@h/d", Backend::Postgres),
            ("POSTGRES://u@h/d", Backend::Postgres),
            ("mysql://u@h/d", Backend::MariaDb),
            ("mariadb://u@h/d", Backend::MariaDb),
            ("sqlite:///var/lib/proxyx/pool.db?mode=rwc", Backend::Sqlite),
            ("sqlite:pool.db", Backend::Sqlite),
        ] {
            assert_eq!(Backend::from_url(url).expect(url), backend, "{url}");
        }
        for bad in ["", "redis://h", "pool.db", "http://h", "oracle://h/d"] {
            assert!(Backend::from_url(bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn only_sqlite_is_single_node() {
        assert!(Backend::Postgres.is_multi_node());
        assert!(Backend::MariaDb.is_multi_node());
        assert!(!Backend::Sqlite.is_multi_node());
    }
}
