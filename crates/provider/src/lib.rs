//! Provider adapters and credential templates.
//!
//! A provider is a TOML file, not code: the host, the credential templates
//! and, for each option (country, city, session id, duration, strict mode,
//! pinned IP), the field it is written into. [`Adapter::recipe`] renders a
//! lease spec into an upstream endpoint, purely. Values outside an option's
//! charset or length are refused, never escaped.

mod adapter;
mod config;
mod error;
mod rotate;
mod set;

pub use adapter::{Adapter, SessionRecipe, UnitSpec, ensure_public_address};
pub use config::{AdapterConfig, AdapterFile, SessionMode};
pub use error::ProviderError;
pub use rotate::MobileBoxClient;
pub use set::AdapterSet;

/// Longest username, password or host, in bytes: the SOCKS5 field limit.
pub(crate) const MAX_FIELD_BYTES: usize = 255;
