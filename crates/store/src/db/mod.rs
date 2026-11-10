//! Repository over PostgreSQL, MariaDB or SQLite: every write runs in one
//! transaction with its audit row.
//!
//! The URL scheme selects the backend ([`Db::connect`]). Each domain module
//! (`inventory`, `policies`, ...) declares its public types and its [`Db`]
//! methods once; the queries behind a method are one template in `impls/`
//! that the module compiles three times, against the typed sqlx pool of each
//! backend, with the text that differs taken from `dialect/`. No statement is
//! chosen or rewritten at run time, and no query goes through `sqlx::Any`.

/// Declare the [`Db`] methods of a domain module. Each one calls the function
/// of the same name in the module of the backend of the pool: `postgres`,
/// `mariadb` or `sqlite`, the three instances of the module's `impls/`
/// template. The first argument of an instance is the typed pool.
macro_rules! delegate {
    ($(
        $(#[$meta:meta])*
        pub async fn $name:ident(&self $(, $arg:ident : $ty:ty)* $(,)?) -> $ret:ty;
    )*) => {
        impl $crate::db::Db {
            $(
                $(#[$meta])*
                pub async fn $name(&self $(, $arg: $ty)*) -> $ret {
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
/// included once in each of `postgres`, `mariadb` and `sqlite`, where `d` is
/// the dialect of the instance.
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

mod assess;
mod audit;
mod blocks;
mod customer;
mod inventory;
mod org_blocks;
mod org_keys;
mod policies;
mod reads;
mod scores;
mod sources;

use std::time::Duration;

use proxyx_db::{Backend, Migrators, Pool, PoolSettings};
use serde::Serialize;
use serde::de::DeserializeOwned;

use crate::error::{Result, StoreError};

pub use assess::BlockSummary;
pub use audit::{AUDIT_KEEP_DAYS, AuditRow, BLOCKS_KEEP_DAYS, Pruned, SCORES_KEEP_DAYS};
pub use blocks::IpBlock;
pub use customer::{CustomerLogin, CustomerSet, CustomerUnit};
pub use inventory::{InventoryRow, InventorySync, Transition, UpsertOutcome};
pub use org_blocks::{BlockScope, OrgBlock, merged_org_blocks};
pub use org_keys::{KeyStatus, hash_org_key};
pub use policies::{PolicyPut, PolicyRecord};
pub use scores::ScoreRow;
pub use sources::sha256_hex;

pub(crate) use dialect::org_lock_name;
pub(crate) use inventory::check_rental_end;
pub(crate) use policies::canonical_policy_doc;
pub(crate) use reads::RebuildRead;

/// The embedded migrations: `migrations/postgres`, `migrations/mariadb` and
/// `migrations/sqlite`, the same versions in each.
fn migrators() -> Migrators {
    proxyx_db::migrators!()
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
    /// Every connection gets a 5 s statement limit and a 2 s lock wait
    /// (PostgreSQL startup parameters, so a pooler in statement mode would
    /// drop them; MariaDB session variables; the SQLite busy timeout), so a
    /// stuck lock or a runaway query fails instead of holding a gateway or API
    /// request forever.
    ///
    /// Fails when the URL is invalid, names no supported backend, or the server
    /// does not answer within 5 seconds.
    pub async fn connect(url: &str) -> Result<Self> {
        let pool = Pool::connect(url, &PoolSettings::default()).await?;
        Ok(Self { pool })
    }

    /// A pool that connects on first use, so a test can point it at a server
    /// that never answers. Same limits as [`Db::connect`].
    #[cfg(test)]
    pub(crate) fn connect_lazy(url: &str) -> Result<Self> {
        let pool = Pool::connect_lazy(url, &PoolSettings::default())?;
        Ok(Self { pool })
    }

    /// The backend this pool talks to.
    pub fn backend(&self) -> Backend {
        self.pool.backend()
    }

    /// Whether a pooled connection can be had within `limit`. The pool keeps
    /// retrying a refused or hung connect until its own 5 s acquire timeout;
    /// a caller that only asks "is the database there" must not wait that long.
    /// An answer that is late counts as unreachable ([`sqlx::Error::PoolTimedOut`]).
    pub async fn check_reachable(&self, limit: Duration) -> Result<()> {
        Ok(self.pool.check_reachable(limit).await?)
    }

    /// Apply the embedded migrations. Safe to run again and from several
    /// replicas at once (PostgreSQL: an advisory lock, and a replica waiting
    /// on it must not hit `lock_timeout`; MariaDB: `GET_LOCK`; SQLite: one
    /// write transaction). A migration may run longer than the statement
    /// limit, so the limits are off for the connection that migrates and
    /// restored before it returns to the pool.
    pub async fn migrate(&self) -> Result<()> {
        Ok(self.pool.migrate(&migrators()).await?)
    }

    /// Names (`version_description`) of the embedded migrations that are not
    /// applied yet; empty when the schema is up to date. Read-only: it
    /// applies nothing and does not create `_sqlx_migrations`.
    pub async fn pending_migrations(&self) -> Result<Vec<String>> {
        Ok(self.pool.pending_migrations(&migrators()).await?)
    }

    /// Cheap liveness check for `/readyz`.
    pub async fn ping(&self) -> Result<()> {
        Ok(self.pool.ping().await?)
    }

    pub(crate) fn pool(&self) -> &Pool {
        &self.pool
    }
}

pub(crate) fn to_json<T: Serialize>(value: &T) -> Result<serde_json::Value> {
    serde_json::to_value(value).map_err(|e| StoreError::Invalid(e.to_string()))
}

/// Snake-case name of a serde enum, as stored in a text column.
pub(crate) fn enum_text<T: Serialize>(value: &T) -> Result<String> {
    match to_json(value)? {
        serde_json::Value::String(s) => Ok(s),
        other => Err(StoreError::Invalid(format!("not a plain enum: {other}"))),
    }
}

pub(crate) fn parse_enum<T: DeserializeOwned>(what: &'static str, text: &str) -> Result<T> {
    serde_json::from_value(serde_json::Value::String(text.to_owned()))
        .map_err(|e| StoreError::decode(what, e))
}
