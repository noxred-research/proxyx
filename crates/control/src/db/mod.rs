//! The relational store of the control plane (orgs, session lifecycle,
//! traffic view jobs, API keys) on PostgreSQL, MariaDB or SQLite, by the scheme
//! of `database_url`.
//!
//! Each domain module declares its row types and its [`Db`] methods once. The
//! queries behind a method are one template in `impls/` that the module compiles
//! three times, against the typed sqlx pool of each backend, with the text that
//! differs taken from `dialect/`. No statement is chosen or rewritten at run
//! time, and no query goes through `sqlx::Any`.

/// Declare [`Db`] methods. Each calls the function of the same name in the
/// module of the backend of the pool: `postgres`, `mariadb` or `sqlite`, the
/// three instances of the domain's template. The first argument of an instance is
/// the typed pool.
macro_rules! delegate {
    ($(
        $(#[$meta:meta])*
        $vis:vis async fn $name:ident(&self $(, $arg:ident : $ty:ty)* $(,)?) -> $ret:ty;
    )*) => {
        impl $crate::db::Db {
            $(
                $(#[$meta])*
                $vis async fn $name(&self $(, $arg: $ty)*) -> $ret {
                    match self.pool() {
                        ::proxyx_db::Pool::Postgres(pool) => postgres::$name(pool $(, $arg)*).await,
                        ::proxyx_db::Pool::MariaDb(pool) => mariadb::$name(pool $(, $arg)*).await,
                        ::proxyx_db::Pool::Sqlite(pool) => sqlite::$name(pool $(, $arg)*).await,
                    }
                }
            )*
        }
    };
}

/// The three instances of a template: `$template` is the path of
/// `db/impls/<domain>.rs`, relative to the module that calls this. The file is
/// included once in each of `postgres`, `mariadb` and `sqlite`, where `d` is the
/// dialect of the instance.
macro_rules! instances {
    ($template:literal) => {
        pub(in crate::db) mod postgres {
            use crate::db::dialect::postgres as d;
            include!($template);
        }
        pub(in crate::db) mod mariadb {
            use crate::db::dialect::mariadb as d;
            include!($template);
        }
        pub(in crate::db) mod sqlite {
            use crate::db::dialect::sqlite as d;
            include!($template);
        }
    };
}

mod dialect;
mod keys;
mod orgs;
mod sessions;
mod views;

use std::time::Duration;

use proxyx_db::{Backend, Migrators, Pool, PoolSettings};

/// The error of every [`Db`] method.
pub type DbResult<T> = Result<T, sqlx::Error>;

pub use keys::KeyRow;
pub use orgs::{OrgSettingsRow, OrgSettingsWrite, ProxyColumns};
pub use sessions::{SessionClaim, SessionInsert, SessionStatusRow, SourceWindow};
pub use views::{ViewJobRow, ViewJobUpsert};

/// The embedded migrations: `migrations/postgres`, `migrations/mariadb` and
/// `migrations/sqlite`, the same versions in each.
fn migrators() -> Migrators {
    proxyx_db::migrators!(extensions = ["pg_trgm"])
}

/// Pool of database connections: PostgreSQL, MariaDB or SQLite, by the scheme
/// of the URL.
#[derive(Clone)]
pub struct Db {
    pool: Pool,
}

impl Db {
    /// Connect to the database `url` names: `postgres://`, `mysql://` or
    /// `mariadb://`, `sqlite://PATH?mode=rwc`. Does not migrate; call
    /// [`Db::migrate`].
    ///
    /// Fails when the URL is invalid, names no supported backend, or the
    /// server does not answer within 30 seconds.
    pub async fn connect(url: &str, max_connections: u32) -> DbResult<Self> {
        let settings = PoolSettings {
            max_connections,
            acquire_timeout: Duration::from_secs(30),
            statement_timeout: Duration::from_secs(30),
            lock_timeout: Duration::from_secs(10),
            ..PoolSettings::default()
        };
        Ok(Self {
            pool: Pool::connect(url, &settings).await?,
        })
    }

    /// The backend this pool talks to.
    pub fn backend(&self) -> Backend {
        self.pool.backend()
    }

    /// Cheap liveness check for the readiness probe: one `SELECT 1`.
    pub async fn ping(&self) -> Result<(), sqlx::Error> {
        self.pool.ping().await
    }

    /// Apply the embedded migrations. Safe to run again and from several
    /// processes at once.
    pub async fn migrate(&self) -> Result<(), sqlx::migrate::MigrateError> {
        self.pool.migrate(&migrators()).await
    }

    /// Names (`version_description`) of the embedded migrations that are not
    /// applied yet; empty when the schema is up to date. Read-only.
    pub async fn pending_migrations(&self) -> Result<Vec<String>, sqlx::Error> {
        self.pool.pending_migrations(&migrators()).await
    }

    /// The server version, for logs.
    pub async fn server_version(&self) -> Result<String, sqlx::Error> {
        self.pool.server_version().await
    }

    pub(crate) fn pool(&self) -> &Pool {
        &self.pool
    }

    /// The pool, for tests that need raw SQL.
    #[doc(hidden)]
    pub fn raw_pool(&self) -> &Pool {
        &self.pool
    }
}
