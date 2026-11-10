//! Load tool behind the `proxyx-bench` binary.
//!
//! The criterion microbenchmarks live in `benches/`; this library holds the
//! end-to-end part: stub servers, the load driver, the `/proc` sampler of the
//! process under test and the two scenarios (pool gateway and session proxy).
//!
//! It depends on neither `proxyx-intercept` nor `proxyx-control`, so the binary
//! links no BoringSSL and no OpenSSL. The target process is a separate binary
//! that the tool spawns, or any process it is pointed at.

pub mod cli;
pub mod gateway;
pub mod http1;
pub mod load;
pub mod procstat;
pub mod report;
pub mod session;
pub mod stats;
pub mod stubs;
pub mod target;
pub mod tls;
