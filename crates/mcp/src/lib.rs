//! A Model Context Protocol server that lets AI agents monitor, manage and dynamically
//! configure ProxyX.
//!
//! * **Monitor**: health and readiness of every role, a summary of the documented Prometheus
//!   families, pool capacity, breakers, block-signal rates, refusals by cause, sessions, and a
//!   search over captured traffic with the control plane's query language.
//! * **Manage**: sessions, org keys, rate limits, egress, org blocks, block signals, policies
//!   and inventory, each behind a capability the operator enables, with dry runs, optional
//!   human approval and a hash-chained audit log.
//! * **Configure**: `propose_config_change` returns a validated diff, `apply_config_change`
//!   applies it, and policy documents are validated with the gateway's own `proxyx-policy`.
//! * **Assist**: optional LLM-backed tools (traffic narrative, block page classification, policy
//!   drafts) through any OpenAI-compatible endpoint; a model advises and never authorizes.
//!
//! Two transports share one protocol engine: newline-delimited JSON-RPC on stdio, and
//! streamable HTTP with a bearer token. Both speak revision 2026-07-28 (stateless, per-request
//! metadata, `server/discover`) and the earlier `initialize`-based revisions.
//!
//! The entry point for a binary is [`run`] with [`McpArgs`] (`proxyx mcp ...`).

pub mod audit;
pub mod backend;
pub mod cli;
pub mod config;
pub mod explain;
pub mod http;
pub mod llm;
pub mod metrics;
mod prompts;
pub mod protocol;
pub mod redact;
mod resources;
pub mod safety;
pub mod schema;
pub mod server;
pub mod stdio;
pub mod store;
pub mod tools;

pub use cli::{McpArgs, McpCommand, TransportKind, init_logging, run};
pub use config::Config;
pub use server::Server;
pub use tools::Ctx;
