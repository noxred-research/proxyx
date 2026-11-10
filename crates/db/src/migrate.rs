//! Embedded migrations, one directory per backend with the same versions.

use sqlx::Executor as _;
use sqlx::migrate::{MigrateError, Migrator};

use crate::{Backend, Pool};

/// The migrations of one schema for every backend. Each directory holds the
/// same versions (`migrations/postgres`, `migrations/mariadb`,
/// `migrations/sqlite`): the same logical schema in each dialect.
pub struct Migrators {
    pub postgres: Migrator,
    pub mariadb: Migrator,
    pub sqlite: Migrator,
}

impl Migrators {
    /// The migrations of `backend`.
    pub fn of(&self, backend: Backend) -> &Migrator {
        match backend {
            Backend::Postgres => &self.postgres,
            Backend::MariaDb => &self.mariadb,
            Backend::Sqlite => &self.sqlite,
        }
    }
}

/// Embed the three migration directories of a crate: `migrations/postgres`,
/// `migrations/mariadb` and `migrations/sqlite`, relative to the crate root.
/// The crate's `build.rs` must print `cargo:rerun-if-changed=migrations`.
#[macro_export]
macro_rules! migrators {
    () => {
        $crate::Migrators {
            postgres: ::sqlx::migrate!("./migrations/postgres"),
            mariadb: ::sqlx::migrate!("./migrations/mariadb"),
            sqlite: ::sqlx::migrate!("./migrations/sqlite"),
        }
    };
}

impl Pool {
    /// Apply the embedded migrations of this pool's backend. Safe to run again
    /// and from several processes at once: PostgreSQL takes an advisory lock
    /// (and a process waiting on it must not hit `lock_timeout`), MariaDB
    /// takes `GET_LOCK`, SQLite takes a file lock next to the database.
    ///
    /// A migration may run longer than the per-statement limits of the pool,
    /// so they are off for the one connection that migrates and restored
    /// before it returns to the pool.
    pub async fn migrate(&self, migrators: &Migrators) -> Result<(), MigrateError> {
        let migrator = migrators.of(self.backend());
        match self {
            Self::Postgres(pool) => {
                let mut conn = pool.acquire().await?;
                conn.execute("SET statement_timeout = 0; SET lock_timeout = 0")
                    .await?;
                let applied = migrator.run(&mut *conn).await;
                let restored = conn
                    .execute("RESET statement_timeout; RESET lock_timeout")
                    .await;
                applied?;
                restored?;
                Ok(())
            }
            Self::MariaDb(pool) => {
                let mut conn = pool.acquire().await?;
                let (statement, lock): (f64, u64) = sqlx::query_as(
                    "SELECT CAST(@@SESSION.max_statement_time AS DOUBLE),
                            @@SESSION.innodb_lock_wait_timeout",
                )
                .fetch_one(&mut *conn)
                .await?;
                conn.execute(
                    "SET SESSION max_statement_time = 0, innodb_lock_wait_timeout = 86400",
                )
                .await?;
                // sqlx takes `GET_LOCK(name, -1)` and ignores the answer; MariaDB
                // does not wait on a negative timeout, so two processes would
                // both apply a migration. Wait for the lock here, an hour at most.
                let (database,): (String,) = sqlx::query_as("SELECT DATABASE()")
                    .fetch_one(&mut *conn)
                    .await?;
                let lock_name = format!("proxyx-migrate:{database}");
                let (got,): (Option<i64>,) = sqlx::query_as("SELECT GET_LOCK(?, 3600)")
                    .bind(&lock_name)
                    .fetch_one(&mut *conn)
                    .await?;
                if got != Some(1) {
                    return Err(MigrateError::Execute(sqlx::Error::Protocol(format!(
                        "could not take the migration lock {lock_name:?} within an hour"
                    ))));
                }
                let applied = migrator.run(&mut *conn).await;
                let _ = sqlx::query("SELECT RELEASE_LOCK(?)")
                    .bind(&lock_name)
                    .execute(&mut *conn)
                    .await;
                let restored = conn
                    .execute(
                        format!(
                            "SET SESSION max_statement_time = {statement}, \
                             innodb_lock_wait_timeout = {lock}"
                        )
                        .as_str(),
                    )
                    .await;
                applied?;
                restored?;
                Ok(())
            }
            Self::Sqlite(pool) => {
                // sqlx runs each migration in its own transaction and takes no
                // lock on SQLite, so two processes would race on the same
                // version. An exclusive lock on a file next to the database
                // makes them take turns; the later one finds nothing to apply.
                let _lock = sqlite_migration_lock(pool).await?;
                let mut conn = pool.acquire().await?;
                migrator.run(&mut *conn).await
            }
        }
    }

    /// The versions the migrations table lists as applied, or `None` when
    /// the table does not exist (the schema was never applied). Read-only.
    pub async fn applied_migrations(&self) -> Result<Option<Vec<i64>>, sqlx::Error> {
        if !self.table_exists("_sqlx_migrations").await? {
            return Ok(None);
        }
        let versions = match self {
            Self::Postgres(p) => {
                sqlx::query_scalar("SELECT version FROM _sqlx_migrations WHERE success")
                    .fetch_all(p)
                    .await?
            }
            Self::MariaDb(p) => {
                sqlx::query_scalar("SELECT version FROM _sqlx_migrations WHERE success")
                    .fetch_all(p)
                    .await?
            }
            Self::Sqlite(p) => {
                sqlx::query_scalar("SELECT version FROM _sqlx_migrations WHERE success")
                    .fetch_all(p)
                    .await?
            }
        };
        Ok(Some(versions))
    }

    /// Names (`version_description`) of the embedded migrations that are not
    /// applied yet; empty when the schema is up to date. Read-only: it
    /// applies nothing and does not create `_sqlx_migrations`.
    pub async fn pending_migrations(
        &self,
        migrators: &Migrators,
    ) -> Result<Vec<String>, sqlx::Error> {
        let applied = self.applied_migrations().await?.unwrap_or_default();
        Ok(migrators
            .of(self.backend())
            .iter()
            .filter(|m| !m.migration_type.is_down_migration() && !applied.contains(&m.version))
            .map(|m| format!("{}_{}", m.version, m.description))
            .collect())
    }
}

/// An exclusive lock on `<database file>.migrate-lock`, held until the
/// returned file is dropped. `None` for an in-memory database, which only one
/// connection can see.
async fn sqlite_migration_lock(
    pool: &sqlx::SqlitePool,
) -> Result<Option<std::fs::File>, MigrateError> {
    let path = pool.connect_options().get_filename().to_path_buf();
    if path.as_os_str() == ":memory:" || path.as_os_str().is_empty() {
        return Ok(None);
    }
    let mut lock_path = path.into_os_string();
    lock_path.push(".migrate-lock");
    let file = tokio::task::spawn_blocking(move || -> std::io::Result<std::fs::File> {
        let file = std::fs::OpenOptions::new()
            .create(true)
            .truncate(false)
            .write(true)
            .open(lock_path)?;
        file.lock()?;
        Ok(file)
    })
    .await
    .map_err(|e| MigrateError::Execute(sqlx::Error::Io(std::io::Error::other(e))))?
    .map_err(|e| MigrateError::Execute(sqlx::Error::Io(e)))?;
    Ok(Some(file))
}
