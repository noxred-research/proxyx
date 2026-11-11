//! One connection pool over any supported backend.

use std::str::FromStr;
use std::time::Duration;

use sqlx::mysql::{MySqlConnectOptions, MySqlPoolOptions};
use sqlx::postgres::{PgConnectOptions, PgPoolOptions};
use sqlx::sqlite::{SqliteConnectOptions, SqliteJournalMode, SqlitePoolOptions, SqliteSynchronous};
use sqlx::{Connection as _, Executor as _, MySqlPool, PgPool, SqlitePool};

use crate::Backend;

/// Limits of a pool and of every connection in it.
#[derive(Debug, Clone)]
pub struct PoolSettings {
    /// Connections the pool opens at most.
    pub max_connections: u32,
    /// How long a caller waits for a free connection, and for the first
    /// connect.
    pub acquire_timeout: Duration,
    /// A statement running longer fails. PostgreSQL `statement_timeout`,
    /// MariaDB `max_statement_time`; SQLite has no per-statement limit and
    /// uses it as the busy timeout (how long a writer waits for the file lock).
    pub statement_timeout: Duration,
    /// A wait for a row or table lock longer than this fails. PostgreSQL
    /// `lock_timeout`, MariaDB `innodb_lock_wait_timeout` (whole seconds,
    /// rounded up); not used by SQLite.
    pub lock_timeout: Duration,
    /// Accept an in-memory SQLite database (`sqlite::memory:`). It lives inside
    /// one connection and no other process can open it, so a role that serves
    /// from it loses everything at restart and shares nothing: refused unless a
    /// test asks for it.
    pub allow_in_memory: bool,
}

impl Default for PoolSettings {
    fn default() -> Self {
        Self {
            max_connections: 10,
            acquire_timeout: Duration::from_secs(5),
            statement_timeout: Duration::from_secs(5),
            lock_timeout: Duration::from_secs(2),
            allow_in_memory: false,
        }
    }
}

/// A connection pool of the backend its URL names.
///
/// Clone is cheap (the pools are reference counted).
#[derive(Clone)]
pub enum Pool {
    Postgres(PgPool),
    MariaDb(MySqlPool),
    Sqlite(SqlitePool),
}

fn config(message: impl Into<String>) -> sqlx::Error {
    sqlx::Error::Configuration(message.into().into())
}

/// Whole seconds, rounded up, at least one: `innodb_lock_wait_timeout`.
fn whole_secs(d: Duration) -> u64 {
    d.as_secs() + u64::from(d.subsec_nanos() > 0).max(u64::from(d.is_zero()))
}

impl Pool {
    /// Connect to the database `url` names (scheme `postgres://`,
    /// `mysql://` / `mariadb://` or `sqlite://`), with the limits of
    /// `settings` on every connection. Does not migrate.
    ///
    /// Fails when the URL is invalid, names no supported backend, or the server
    /// does not answer within `acquire_timeout`.
    pub async fn connect(url: &str, settings: &PoolSettings) -> Result<Self, sqlx::Error> {
        match Backend::from_url(url).map_err(|e| config(e.to_string()))? {
            Backend::Postgres => {
                let options = pg_options(url, settings)?;
                let pool = PgPoolOptions::new()
                    .max_connections(settings.max_connections)
                    .acquire_timeout(settings.acquire_timeout)
                    .connect_with(options)
                    .await?;
                Ok(Self::Postgres(pool))
            }
            Backend::MariaDb => {
                let (options, session) = mysql_options(url, settings)?;
                let pool = mysql_pool(settings, session).connect_with(options).await?;
                Ok(Self::MariaDb(pool))
            }
            Backend::Sqlite => {
                let (options, max) = sqlite_options(url, settings)?;
                // Switching a new file to WAL needs a lock no other connection
                // may hold: do it once, here, with retries, so processes that
                // start together on a new database do not fail on each other.
                sqlite_prepare(&options, settings.acquire_timeout).await?;
                let pool = SqlitePoolOptions::new()
                    .max_connections(max)
                    .acquire_timeout(settings.acquire_timeout)
                    .connect_with(options)
                    .await?;
                Ok(Self::Sqlite(pool))
            }
        }
    }

    /// A pool that connects on first use, so a test can point it at a server
    /// that never answers. Same limits as [`Pool::connect`].
    pub fn connect_lazy(url: &str, settings: &PoolSettings) -> Result<Self, sqlx::Error> {
        match Backend::from_url(url).map_err(|e| config(e.to_string()))? {
            Backend::Postgres => Ok(Self::Postgres(
                PgPoolOptions::new()
                    .max_connections(settings.max_connections)
                    .acquire_timeout(settings.acquire_timeout)
                    .connect_lazy_with(pg_options(url, settings)?),
            )),
            Backend::MariaDb => {
                let (options, session) = mysql_options(url, settings)?;
                Ok(Self::MariaDb(
                    mysql_pool(settings, session).connect_lazy_with(options),
                ))
            }
            Backend::Sqlite => {
                let (options, max) = sqlite_options(url, settings)?;
                Ok(Self::Sqlite(
                    SqlitePoolOptions::new()
                        .max_connections(max)
                        .acquire_timeout(settings.acquire_timeout)
                        .connect_lazy_with(options),
                ))
            }
        }
    }

    /// The backend of this pool.
    pub fn backend(&self) -> Backend {
        match self {
            Self::Postgres(_) => Backend::Postgres,
            Self::MariaDb(_) => Backend::MariaDb,
            Self::Sqlite(_) => Backend::Sqlite,
        }
    }

    /// Whether a pooled connection can be had within `limit`. The pool keeps
    /// retrying a refused or hung connect until its own acquire timeout; a
    /// caller that only asks "is the database there" must not wait that long.
    /// An answer that is late counts as unreachable
    /// ([`sqlx::Error::PoolTimedOut`]).
    pub async fn check_reachable(&self, limit: Duration) -> Result<(), sqlx::Error> {
        let acquired = async {
            match self {
                Self::Postgres(p) => p.acquire().await.map(drop),
                Self::MariaDb(p) => p.acquire().await.map(drop),
                Self::Sqlite(p) => p.acquire().await.map(drop),
            }
        };
        match tokio::time::timeout(limit, acquired).await {
            Ok(result) => result,
            Err(_) => Err(sqlx::Error::PoolTimedOut),
        }
    }

    /// Cheap liveness check: one `SELECT 1`.
    pub async fn ping(&self) -> Result<(), sqlx::Error> {
        match self {
            Self::Postgres(p) => sqlx::query("SELECT 1").execute(p).await.map(drop),
            Self::MariaDb(p) => sqlx::query("SELECT 1").execute(p).await.map(drop),
            Self::Sqlite(p) => sqlx::query("SELECT 1").execute(p).await.map(drop),
        }
    }

    /// The server's version text (`18.1`, `11.8.2-MariaDB-...`, `3.46.0`).
    pub async fn server_version(&self) -> Result<String, sqlx::Error> {
        match self {
            Self::Postgres(p) => sqlx::query_scalar("SHOW server_version").fetch_one(p).await,
            Self::MariaDb(p) => sqlx::query_scalar("SELECT VERSION()").fetch_one(p).await,
            Self::Sqlite(p) => {
                sqlx::query_scalar("SELECT sqlite_version()")
                    .fetch_one(p)
                    .await
            }
        }
    }

    /// Close every connection.
    pub async fn close(&self) {
        match self {
            Self::Postgres(p) => p.close().await,
            Self::MariaDb(p) => p.close().await,
            Self::Sqlite(p) => p.close().await,
        }
    }

    /// Whether the table `name` exists in the connected database.
    pub async fn table_exists(&self, name: &str) -> Result<bool, sqlx::Error> {
        let n: i64 = match self {
            Self::Postgres(p) => {
                sqlx::query_scalar(
                    "SELECT count(*) FROM information_schema.tables
                     WHERE table_schema = current_schema() AND table_name = $1",
                )
                .bind(name)
                .fetch_one(p)
                .await?
            }
            Self::MariaDb(p) => {
                sqlx::query_scalar(
                    "SELECT count(*) FROM information_schema.tables
                     WHERE table_schema = DATABASE() AND table_name = ?",
                )
                .bind(name)
                .fetch_one(p)
                .await?
            }
            Self::Sqlite(p) => {
                sqlx::query_scalar(
                    "SELECT count(*) FROM sqlite_master WHERE type = 'table' AND name = ?",
                )
                .bind(name)
                .fetch_one(p)
                .await?
            }
        };
        Ok(n > 0)
    }
}

fn pg_options(url: &str, settings: &PoolSettings) -> Result<PgConnectOptions, sqlx::Error> {
    // Startup parameters, so a pooler in statement mode would drop them.
    Ok(PgConnectOptions::from_str(url)?.options([
        (
            "statement_timeout",
            settings.statement_timeout.as_millis().to_string(),
        ),
        (
            "lock_timeout",
            settings.lock_timeout.as_millis().to_string(),
        ),
    ]))
}

/// The statements every MariaDB connection runs once after it connects.
#[derive(Clone)]
struct MySqlSession {
    statements: Vec<String>,
}

fn mysql_options(
    url: &str,
    settings: &PoolSettings,
) -> Result<(MySqlConnectOptions, MySqlSession), sqlx::Error> {
    let options = MySqlConnectOptions::from_str(url)?
        .charset("utf8mb4")
        .collation("utf8mb4_general_ci");
    // READ COMMITTED: a locking read and the plain reads after it see the
    // latest committed rows, as PostgreSQL does by default. The default of
    // InnoDB, REPEATABLE READ, would pin the snapshot at the first read.
    let statements = vec![
        "SET SESSION TRANSACTION ISOLATION LEVEL READ COMMITTED".to_owned(),
        format!(
            "SET SESSION max_statement_time = {:.3}, innodb_lock_wait_timeout = {}",
            settings.statement_timeout.as_secs_f64(),
            whole_secs(settings.lock_timeout)
        ),
    ];
    Ok((options, MySqlSession { statements }))
}

fn mysql_pool(settings: &PoolSettings, session: MySqlSession) -> MySqlPoolOptions {
    MySqlPoolOptions::new()
        .max_connections(settings.max_connections)
        .acquire_timeout(settings.acquire_timeout)
        .after_connect(move |conn, _| {
            let statements = session.statements.clone();
            Box::pin(async move {
                // Statements contain only fixed SQL and numeric timeout settings.
                for statement in statements {
                    conn.execute(sqlx::AssertSqlSafe(statement)).await?;
                }
                Ok(())
            })
        })
}

/// What the limits of SQLite mean for whoever runs it, said once per process.
fn warn_sqlite_is_single_node() {
    static ONCE: std::sync::Once = std::sync::Once::new();
    ONCE.call_once(|| {
        tracing::warn!(
            "using SQLite: one node only. Every ProxyX role that uses this database must run on \
             this host and on a local disk; gateways, warmers and control APIs on several hosts \
             need PostgreSQL or MariaDB (docs/databases.md)"
        );
    });
}

/// SQLite options and the pool size: an in-memory database lives in one
/// connection, so it gets exactly one.
fn sqlite_options(
    url: &str,
    settings: &PoolSettings,
) -> Result<(SqliteConnectOptions, u32), sqlx::Error> {
    let in_memory = url.contains(":memory:") || url.contains("mode=memory");
    if in_memory && !settings.allow_in_memory {
        return Err(config(
            "an in-memory SQLite database is private to one connection and is lost at exit: \
             use `sqlite://PATH?mode=rwc` (docs/databases.md)",
        ));
    }
    warn_sqlite_is_single_node();
    let options = SqliteConnectOptions::from_str(url)?
        // Readers do not block the writer and the writer does not block readers.
        .journal_mode(SqliteJournalMode::Wal)
        .synchronous(SqliteSynchronous::Normal)
        .busy_timeout(settings.statement_timeout);
    let max = if in_memory {
        1
    } else {
        settings.max_connections
    };
    Ok((options, max))
}

/// Open one connection (which sets the journal mode) and close it again,
/// retrying while another process holds the file (`SQLITE_BUSY`, 5, and
/// `SQLITE_LOCKED`, 6) for up to `limit`.
async fn sqlite_prepare(
    options: &SqliteConnectOptions,
    limit: Duration,
) -> Result<(), sqlx::Error> {
    let deadline = tokio::time::Instant::now() + limit;
    loop {
        match sqlx::SqliteConnection::connect_with(options).await {
            Ok(conn) => return conn.close().await,
            Err(sqlx::Error::Database(e))
                if matches!(e.code().as_deref(), Some("5" | "6"))
                    && tokio::time::Instant::now() < deadline =>
            {
                tokio::time::sleep(Duration::from_millis(25)).await;
            }
            Err(e) => return Err(e),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lock_timeout_rounds_up_to_whole_seconds() {
        assert_eq!(whole_secs(Duration::from_millis(2_000)), 2);
        assert_eq!(whole_secs(Duration::from_millis(2_001)), 3);
        assert_eq!(whole_secs(Duration::from_millis(100)), 1);
        assert_eq!(whole_secs(Duration::ZERO), 1);
    }

    #[tokio::test]
    async fn an_in_memory_sqlite_is_refused_unless_a_test_allows_it() {
        let err = Pool::connect("sqlite::memory:", &PoolSettings::default())
            .await
            .err()
            .expect("refused");
        assert!(err.to_string().contains("in-memory"), "{err}");
        let settings = PoolSettings {
            allow_in_memory: true,
            ..PoolSettings::default()
        };
        let pool = Pool::connect("sqlite::memory:", &settings)
            .await
            .expect("allowed");
        pool.ping().await.expect("ping");
        assert!(!pool.server_version().await.expect("version").is_empty());
    }

    #[tokio::test]
    async fn an_unsupported_scheme_is_a_configuration_error() {
        let err = Pool::connect("redis://h/0", &PoolSettings::default())
            .await
            .err()
            .expect("must fail");
        assert!(matches!(err, sqlx::Error::Configuration(_)), "{err}");
    }
}
