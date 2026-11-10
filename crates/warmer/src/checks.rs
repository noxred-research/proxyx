//! Rendering the endpoint of a unit and the session parameters the gateway
//! must render the same way.

use anyhow::Context as _;
use common::Secret;
use common::config::Settings;
use common::types::{InventoryEntry, Region, UpstreamEndpoint};
use provider::{Adapter, ProviderError, UnitSpec};
use rand::Rng as _;
use store::CustomerLogin;

/// Session id length when an adapter does not fix one.
const DEFAULT_SESSION_ID_LEN: usize = 16;

/// A new session id of `[A-Za-z0-9]`, the length the adapter accepts.
pub(crate) fn new_session_id(adapter: &Adapter) -> String {
    const ALPHABET: &[u8] = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    let len = adapter.session_id_len().unwrap_or(DEFAULT_SESSION_ID_LEN);
    let mut rng = rand::thread_rng();
    (0..len)
        .map(|_| char::from(ALPHABET[rng.gen_range(0..ALPHABET.len())]))
        .collect()
}

/// Render the endpoint of a rotating session. The gateway renders the same
/// spec for the same session, so the arguments must not diverge.
pub(crate) fn rotating_endpoint(
    adapter: &Adapter,
    session: &str,
    region: &Region,
) -> Result<UpstreamEndpoint, ProviderError> {
    adapter.recipe(&UnitSpec::Rotating {
        session_id: session,
        ttl_minutes: adapter.session_minutes(),
        region,
        strict: false,
    })
}

/// Render the endpoint of a rented IP or SIM box, reading its
/// `username:password` file from the secrets directory.
pub(crate) fn static_endpoint(
    settings: &Settings,
    adapter: &Adapter,
    entry: &InventoryEntry,
) -> anyhow::Result<UpstreamEndpoint> {
    let credentials = entry
        .credentials
        .as_deref()
        .map(|name| -> anyhow::Result<(Secret, Secret)> {
            let secret = settings.read_secret(name)?;
            let (user, pass) = secret
                .expose()
                .split_once(':')
                .context("credentials file is not username:password")?;
            Ok((Secret::new(user), Secret::new(pass)))
        })
        .transpose()?;
    adapter
        .recipe(&UnitSpec::Static { entry, credentials })
        .context("failed to render the static endpoint")
}

/// Render the endpoint of a customer upstream with the owner's stored login
/// (`None`: the upstream takes no login).
pub(crate) fn owned_endpoint(
    adapter: &Adapter,
    entry: &InventoryEntry,
    login: Option<&CustomerLogin>,
) -> anyhow::Result<UpstreamEndpoint> {
    let credentials = login.map(|l| (l.username.clone(), l.password.clone()));
    adapter
        .recipe(&UnitSpec::Static { entry, credentials })
        .context("failed to render the customer endpoint")
}
