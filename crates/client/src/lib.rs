//! Integrator client for ProxyX.
//!
//! ProxyX has two proxy products and this crate speaks to both:
//!
//! * **Capture sessions** ([`sessions`], [`traffic`]). The control plane hands out a session
//!   per unit of work; traffic sent through its proxy URL is intercepted and stored, and can
//!   be searched afterwards. [`sessions::SessionsClient::open_session`] creates one and keeps
//!   it alive; [`env`] turns it into proxy environment variables and a CA bundle.
//! * **The pool gateway** ([`gateway`], [`signals`]). Rented and rotating exit IPs. The caller
//!   picks an exit through the proxy username ([`gateway::PoolSelector`]), authenticates with
//!   the org key, learns the exit IP from the tunnel head ([`gateway::ConnectInfo`]), and
//!   reports blocks back ([`signals::PoolControlClient`]).
//!
//! [`provider`] wraps both behind one trait, with a passthrough that uses no proxy.
//!
//! Credentials never print: [`Secret`] and the `Debug` impls redact keys and proxy URLs. A
//! session's proxy URL carries the session id, which is the whole proxy credential; do not log it.

pub mod env;
pub mod error;
pub mod gateway;
mod http;
pub mod provider;
pub mod secret;
pub mod sessions;
pub mod signals;
pub mod traffic;

pub use error::{Error, Result};
pub use secret::Secret;
