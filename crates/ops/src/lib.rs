//! Operator commands of the `proxyx` binary.
//!
//! * [`DoctorArgs`] / [`run_doctor`]: `proxyx doctor`, a self-check of one or
//!   more roles (configuration, dependencies, files, ports) that starts nothing.
//! * [`AssessArgs`] / [`run_assess`]: `proxyx assess pool`, a health assessment
//!   of a running pool from its Postgres, Redis and gateway.
//!
//! The session proxy is a separate binary and has its own `doctor` subcommand
//! (it links BoringSSL, which cannot share a process with the control plane's
//! OpenSSL). `proxyx doctor --role intercept` runs that binary and merges its
//! report.

pub mod assess;
pub mod doctor;

pub use assess::{AssessArgs, AssessTarget, PoolAssessArgs, run_assess};
pub use doctor::{DoctorArgs, RoleArg, run_doctor};
