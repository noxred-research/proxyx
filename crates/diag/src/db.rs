//! The relational database (PostgreSQL, MariaDB or SQLite, by the URL scheme):
//! reachability, latency, version and the migration table.
//!
//! The check ids keep the `postgres.` prefix on every backend (they are part of
//! the documented JSON report); the messages name the backend.

use std::time::{Duration, Instant};

use proxyx_db::{Backend, Pool, PoolSettings};

use crate::report::Check;

/// A `SELECT 1` slower than this warns: every request path pays it.
pub const SLOW_QUERY: Duration = Duration::from_millis(250);
/// The oldest PostgreSQL major version the schema is tested on; older ones warn.
pub const MIN_MAJOR: u32 = 13;
/// The oldest MariaDB the migrations and queries need (`SKIP LOCKED`, `JSON_TABLE`).
pub const MIN_MARIADB: (u32, u32) = (10, 6);
/// The oldest SQLite the migrations need (`RETURNING`, window functions, `ALTER TABLE ... DROP COLUMN`).
pub const MIN_SQLITE: (u32, u32) = (3, 40);

/// What [`database`] reads.
struct Found {
    backend: Backend,
    connect: Duration,
    query: Duration,
    version: String,
    migrations: Option<(i64, Option<i64>)>,
}

/// `host:port/database` of a database URL, or the file of a SQLite URL, with no
/// credentials and no options.
fn target_of(url: &str) -> String {
    let rest = url.split_once("://").map_or(url, |(_, rest)| rest);
    let rest = rest.split(['?', '#']).next().unwrap_or(rest);
    let rest = rest.strip_prefix("sqlite:").unwrap_or(rest);
    match rest.split_once('/') {
        Some((authority, path)) if !authority.is_empty() || url.contains("://") => {
            let host = authority
                .rsplit_once('@')
                .map_or(authority, |(_, host)| host);
            if host.is_empty() {
                format!("/{path}")
            } else {
                format!("{host}/{path}")
            }
        }
        _ => rest.to_owned(),
    }
}

/// The `postgres.*` checks of one database URL, all inside `timeout`:
/// `postgres.reachable` (connect and `SELECT 1`, with latency),
/// `postgres.version` and `postgres.migrations` (the `_sqlx_migrations`
/// table: present and how many migrations it lists). A failure to reach the
/// server is one failing `postgres.reachable`; the others are not reported.
///
/// The URL's password never appears in a message.
pub async fn database(url: &str, timeout: Duration) -> Vec<Check> {
    if let Err(error) = Backend::from_url(url) {
        return vec![
            Check::fail("postgres.reachable", error.to_string())
                .hint("use `postgres://user:password@host:5432/database`, `mariadb://...` or `sqlite://PATH?mode=rwc`"),
        ];
    }
    let target = target_of(url);
    let start = Instant::now();
    let found = tokio::time::timeout(timeout, read(url, timeout)).await;
    let elapsed = start.elapsed();
    let found = match found {
        Ok(Ok(found)) => found,
        Ok(Err(error)) => {
            return vec![
                Check::fail(
                    "postgres.reachable",
                    format!("cannot use {target}: {}", scrub(&error.to_string(), url)),
                )
                .hint("check the URL, the credentials, the server's access rules and that the server runs")
                .elapsed(elapsed),
            ];
        }
        Err(_) => {
            return vec![
                Check::fail(
                    "postgres.reachable",
                    format!("{target}: no answer within {} ms", timeout.as_millis()),
                )
                .hint("the host is unreachable or filtered, or the server is overloaded")
                .elapsed(elapsed),
            ];
        }
    };
    let message = format!(
        "{} {target} answers: connect {} ms, SELECT 1 {} ms",
        found.backend,
        found.connect.as_millis(),
        found.query.as_millis()
    );
    let reachable = if found.query > SLOW_QUERY {
        Check::warn("postgres.reachable", format!("{message} (slow)"))
            .hint("a SELECT 1 over 250 ms points at a distant or overloaded server")
    } else {
        Check::pass("postgres.reachable", message)
    };
    vec![
        reachable.elapsed(found.connect + found.query),
        version_check(found.backend, &found.version),
        migrations_check(found.migrations),
    ]
}

/// `text` with the password of `url` (the part between the first `:` after the
/// scheme and the `@`) removed, in case a driver echoes the URL.
fn scrub(text: &str, url: &str) -> String {
    let password = url
        .split_once("://")
        .and_then(|(_, rest)| rest.split('/').next())
        .and_then(|authority| authority.rsplit_once('@'))
        .and_then(|(userinfo, _)| userinfo.split_once(':'))
        .map(|(_, password)| password)
        .filter(|password| !password.is_empty());
    match password {
        Some(password) => text.replace(password, "***"),
        None => text.to_owned(),
    }
}

async fn read(url: &str, timeout: Duration) -> Result<Found, sqlx::Error> {
    let settings = PoolSettings {
        max_connections: 1,
        acquire_timeout: timeout,
        ..PoolSettings::default()
    };
    let t = Instant::now();
    let pool = Pool::connect(url, &settings).await?;
    // A pool connects once, on creation: that is the connect latency.
    let connect = t.elapsed();
    let t = Instant::now();
    pool.ping().await?;
    let query = t.elapsed();
    let version = pool.server_version().await?;
    let migrations = pool
        .applied_migrations()
        .await?
        .map(|versions| (versions.len() as i64, versions.iter().copied().max()));
    let backend = pool.backend();
    pool.close().await;
    Ok(Found {
        backend,
        connect,
        query,
        version,
        migrations,
    })
}

/// The leading integers of a version text (`16.2 (Debian 16.2-1)`,
/// `11.8.9-MariaDB-ubu2404`, `3.46.0`), at most `n`.
fn version_numbers(text: &str, n: usize) -> Vec<u32> {
    text.split(|c: char| !c.is_ascii_digit())
        .filter(|part| !part.is_empty())
        .take(n)
        .filter_map(|part| part.parse().ok())
        .collect()
}

/// The major version of a `server_version` text (`16.2 (Debian 16.2-1)`).
pub fn major_version(text: &str) -> Option<u32> {
    text.split(|c: char| !c.is_ascii_digit())
        .next()?
        .parse()
        .ok()
}

fn version_check(backend: Backend, version: &str) -> Check {
    const ID: &str = "postgres.version";
    match backend {
        Backend::Postgres => match major_version(version) {
            Some(major) if major >= MIN_MAJOR => Check::pass(ID, format!("PostgreSQL {version}")),
            Some(_) => Check::warn(
                ID,
                format!("PostgreSQL {version} is older than {MIN_MAJOR}"),
            )
            .hint("upgrade: older majors are out of upstream support"),
            None => Check::warn(ID, format!("cannot read the version from {version:?}")),
        },
        Backend::MariaDb => {
            if !version.to_ascii_lowercase().contains("mariadb") {
                return Check::fail(ID, format!("{version} is not MariaDB"))
                    .hint("the mysql:// backend is MariaDB 10.6 or newer; MySQL lacks `IF NOT EXISTS` on indexes and columns");
            }
            match version_numbers(version, 2).as_slice() {
                [major, minor] if (*major, *minor) >= MIN_MARIADB => {
                    Check::pass(ID, format!("MariaDB {version}"))
                }
                [_, _] => Check::fail(
                    ID,
                    format!(
                        "MariaDB {version} is older than {}.{}",
                        MIN_MARIADB.0, MIN_MARIADB.1
                    ),
                )
                .hint("upgrade: the queries need `SKIP LOCKED` and `JSON_TABLE`"),
                _ => Check::warn(ID, format!("cannot read the version from {version:?}")),
            }
        }
        Backend::Sqlite => match version_numbers(version, 2).as_slice() {
            [major, minor] if (*major, *minor) >= MIN_SQLITE => {
                Check::pass(ID, format!("SQLite {version}"))
            }
            [_, _] => Check::warn(
                ID,
                format!(
                    "SQLite {version} is older than {}.{}",
                    MIN_SQLITE.0, MIN_SQLITE.1
                ),
            ),
            _ => Check::warn(ID, format!("cannot read the version from {version:?}")),
        },
    }
}

fn migrations_check(migrations: Option<(i64, Option<i64>)>) -> Check {
    match migrations {
        Some((count, Some(latest))) if count > 0 => Check::pass(
            "postgres.migrations",
            format!("_sqlx_migrations lists {count} applied migration(s), latest {latest}"),
        ),
        Some(_) => Check::fail(
            "postgres.migrations",
            "_sqlx_migrations exists but lists no applied migration",
        )
        .hint("run the role's `proxyx migrate` command"),
        None => Check::fail(
            "postgres.migrations",
            "the _sqlx_migrations table is missing: the schema was never applied",
        )
        .hint("run the role's `proxyx migrate` command against this database"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Status;

    #[test]
    fn major_versions_parse() {
        assert_eq!(major_version("16.2 (Debian 16.2-1.pgdg120+2)"), Some(16));
        assert_eq!(major_version("9.6.24"), Some(9));
        assert_eq!(major_version("x"), None);
    }

    #[test]
    fn old_versions_warn_and_a_foreign_server_fails() {
        assert_eq!(
            version_check(Backend::Postgres, "16.2").status,
            Status::Pass
        );
        assert_eq!(
            version_check(Backend::Postgres, "12.9").status,
            Status::Warn
        );
        assert_eq!(
            version_check(Backend::MariaDb, "11.8.9-MariaDB-ubu2404").status,
            Status::Pass
        );
        assert_eq!(
            version_check(Backend::MariaDb, "10.11.6-MariaDB").status,
            Status::Pass
        );
        assert_eq!(
            version_check(Backend::MariaDb, "10.5.22-MariaDB").status,
            Status::Fail
        );
        assert_eq!(
            version_check(Backend::MariaDb, "8.4.0").status,
            Status::Fail
        );
        assert_eq!(
            version_check(Backend::Sqlite, "3.46.0").status,
            Status::Pass
        );
        assert_eq!(
            version_check(Backend::Sqlite, "3.39.4").status,
            Status::Warn
        );
    }

    #[test]
    fn the_target_has_no_credentials() {
        assert_eq!(
            target_of("postgres://u:secret@db.example:5432/proxyx?sslmode=require"),
            "db.example:5432/proxyx"
        );
        assert_eq!(
            target_of("mariadb://root:pw@127.0.0.1:3306/proxyx"),
            "127.0.0.1:3306/proxyx"
        );
        assert_eq!(
            target_of("sqlite:///var/lib/proxyx/pool.db?mode=rwc"),
            "/var/lib/proxyx/pool.db"
        );
        assert_eq!(target_of("sqlite://pool.db"), "pool.db");
        assert_eq!(
            scrub("failed for pw at h", "mysql://u:pw@h/d"),
            "failed for *** at h"
        );
    }

    #[test]
    fn a_missing_migration_table_fails() {
        assert_eq!(migrations_check(None).status, Status::Fail);
        assert_eq!(migrations_check(Some((0, None))).status, Status::Fail);
        assert_eq!(
            migrations_check(Some((6, Some(20261019000002)))).status,
            Status::Pass
        );
    }

    #[tokio::test]
    async fn a_bad_url_fails_without_echoing_the_password() {
        let checks = database("not a url with secret-pass", Duration::from_secs(1)).await;
        assert_eq!(checks.len(), 1);
        assert_eq!(checks[0].status, Status::Fail);
        assert!(!checks[0].message.contains("secret-pass"));
    }
}
