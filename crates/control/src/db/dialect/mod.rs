//! What differs between the backends, one module each. A dialect gives a
//! template the sqlx types of its backend (`Conn`, `Tx`, `Pool`), macros for the
//! SQL text that differs (usable inside `concat!`), `sql!`, which numbers the
//! `?` placeholders for PostgreSQL at compile time, and how a write
//! transaction begins.

pub(super) mod mariadb;
pub(super) mod postgres;
pub(super) mod sqlite;
