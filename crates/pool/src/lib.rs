//! Process wiring of the pool roles: connect to Postgres and Redis, load the
//! snapshot, build the role's context, run its tasks and the ops server on one
//! `CancellationToken`, and drain on stop.
//!
//! [`cli`] initialises telemetry and picks the role; everything else is here so
//! the end-to-end tests can start the real roles in-process.

pub mod cli;
mod connect;
pub mod exit_ip;
pub mod migrate;
pub mod roles;
mod scorers;
