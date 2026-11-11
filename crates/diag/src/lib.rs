//! Self-check framework shared by `proxyx doctor` and `proxyx-intercept doctor`.
//!
//! A run is a [`Report`] of [`Check`]s, each `pass`, `warn`, `fail` or `skip`.
//! [`Report::render_table`] prints it for people, [`Report::to_json`] for
//! machines, and [`Report::exit_code`] turns it into a process status.
//!
//! The generic checks live here: The relational database ([`db::database`]), Redis
//! ([`redis_checks::redis_server`]), ClickHouse ([`net::clickhouse_ping`]), brokers
//! ([`net::brokers_check`], [`redis_checks::redis_stream`]), CA material
//! ([`ca::ca_checks`]), secret files and the open-files limit ([`files`]),
//! listener ports and DNS ([`net`]). Role-specific checks are built from them
//! by the binaries.
//!
//! This crate links neither OpenSSL nor BoringSSL, so the session proxy (which
//! links BoringSSL) and the control plane (which links OpenSSL) can both use it.

pub mod ca;
pub mod db;
pub mod files;
pub mod net;
pub mod redis_checks;
mod report;

pub use report::{
    Check, EXIT_FAIL, EXIT_OK, EXIT_WARN, Report, SCHEMA_VERSION, Status, Summary, timed,
};
