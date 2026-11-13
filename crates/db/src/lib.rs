//! Relational backends: PostgreSQL, MariaDB and SQLite behind one pool type.
//!
//! The `database_url` scheme selects the backend ([`Backend::from_url`]);
//! [`Pool`] holds the typed sqlx pool of that backend and the crates that own
//! a schema (`proxyx-store`, `proxyx-control`) keep one typed query module per
//! backend. There is no `sqlx::Any`: every statement is compiled against the
//! backend that runs it, with that backend's native column types. The parts
//! that differ per backend and are shared by all schemas live here:
//!
//! * [`Backend`]: the URL scheme and what each backend can promise.
//! * [`Pool`] and [`PoolSettings`]: connect with per-connection timeouts,
//!   health checks, server version.
//! * [`Migrators`] and [`Pool::migrate`]: per-backend embedded migrations with
//!   the same versions in every directory.
//! * [`Ts`]: one timestamp type for all three.
//! * [`pg_sql!`]: statements are written once with `?` placeholders and
//!   numbered for PostgreSQL at compile time.
//! * [`testing`]: scratch databases for the integration tests.

mod backend;
mod migrate;
mod pool;
pub mod sql;
#[doc(hidden)]
pub mod testing;
mod types;

pub use backend::{Backend, UnsupportedScheme, url_with_schema};
pub use migrate::Migrators;
pub use pool::{Pool, PoolSettings};
pub use types::Ts;
