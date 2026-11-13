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

/// `url` with every connection pinned to the PostgreSQL schema `schema`
/// (`search_path`), so several products can share one database, each with its
/// own tables and its own `_sqlx_migrations`. [`crate::Pool::migrate`] creates
/// the schema when it is missing. `public` stays on the search path behind it
/// only so that objects of extensions, which exist once per database, resolve.
///
/// # Errors
/// When the URL is not a PostgreSQL URL (MariaDB names its namespace in the
/// URL's database and SQLite is one file per product), or `schema` is not a
/// plain lowercase identifier.
pub fn url_with_schema(url: &str, schema: &str) -> Result<String, String> {
    match Backend::from_url(url) {
        Ok(Backend::Postgres) => {}
        Ok(other) => {
            return Err(format!(
                "database_schema applies to PostgreSQL only; {other} names its namespace in the \
                 URL (the MariaDB database, the SQLite file)"
            ));
        }
        Err(error) => return Err(error.to_string()),
    }
    let valid = (1..=63).contains(&schema.len())
        && schema.starts_with(|c: char| c.is_ascii_lowercase() || c == '_')
        && schema
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_');
    if !valid || schema.starts_with("pg_") || matches!(schema, "public" | "information_schema") {
        return Err(format!(
            "database_schema {schema:?} must be 1 to 63 lowercase letters, digits or underscores, \
             start with a letter or underscore, and not be public, information_schema or pg_*"
        ));
    }
    if url.contains("options=") {
        return Err(
            "database_schema cannot be combined with an `options` parameter in the URL".to_owned(),
        );
    }
    let joiner = if url.contains('?') { '&' } else { '?' };
    Ok(format!(
        "{url}{joiner}options=-c%20search_path%3D{schema}%2Cpublic"
    ))
}

/// The schema a PostgreSQL connection is pinned to by [`url_with_schema`].
pub(crate) fn pinned_schema(options: Option<&str>) -> Option<String> {
    options?
        .split_whitespace()
        .find_map(|part| part.strip_prefix("search_path="))
        .and_then(|path| path.split(',').next())
        .map(str::to_owned)
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
    fn a_schema_is_added_to_postgres_urls_only() {
        assert_eq!(
            url_with_schema("postgres://u@h/d", "proxyx").expect("pg"),
            "postgres://u@h/d?options=-c%20search_path%3Dproxyx%2Cpublic"
        );
        assert_eq!(
            url_with_schema("postgres://u@h/d?sslmode=require", "proxyx").expect("pg"),
            "postgres://u@h/d?sslmode=require&options=-c%20search_path%3Dproxyx%2Cpublic"
        );
        for (url, schema) in [
            ("mariadb://u@h/d", "proxyx"),
            ("sqlite:///x.db", "proxyx"),
            ("postgres://u@h/d", "Proxy X"),
            ("postgres://u@h/d", "public"),
            ("postgres://u@h/d", "pg_catalog"),
            ("postgres://u@h/d", ""),
            ("postgres://u@h/d?options=-c%20x%3Dy", "proxyx"),
            ("redis://h", "proxyx"),
        ] {
            assert!(url_with_schema(url, schema).is_err(), "{url} {schema}");
        }
        assert_eq!(
            pinned_schema(Some("-c statement_timeout=5 -c search_path=proxyx,public")).as_deref(),
            Some("proxyx")
        );
        assert_eq!(pinned_schema(None), None);
    }

    #[test]
    fn only_sqlite_is_single_node() {
        assert!(Backend::Postgres.is_multi_node());
        assert!(Backend::MariaDb.is_multi_node());
        assert!(!Backend::Sqlite.is_multi_node());
    }
}
