use figment::{
    Figment,
    providers::{Env, Format, Toml},
};
use serde::Serialize;
use serde::de::DeserializeOwned;
use std::path::Path;

/// Load configuration from multiple sources (lowest → highest priority):
///
/// 1. Config file from default locations (`./{name}.toml` or `/etc/proxyx/{name}.toml`)
/// 2. Environment variables (`PROXYX_{NAME}_{FIELD}`, double-underscore for nesting)
/// 3. Explicit `--config` path (highest priority — overrides both file and env)
pub fn load<T: DeserializeOwned + Serialize>(
    name: &str,
    config_path: Option<&str>,
) -> anyhow::Result<T> {
    let mut figment = Figment::new();

    // Try local config file first, then /etc/proxyx/
    let local_path = format!("{}.toml", name);
    let etc_path = format!("/etc/proxyx/{}.toml", name);

    if Path::new(&local_path).exists() {
        figment = figment.merge(Toml::file(&local_path));
    } else if Path::new(&etc_path).exists() {
        figment = figment.merge(Toml::file(&etc_path));
    }

    // Environment variables
    let env_prefix = format!("PROXYX_{}", name.to_uppercase());
    figment = figment.merge(Env::prefixed(&format!("{}_", env_prefix)).split("__"));

    // Explicit path has highest priority
    if let Some(path) = config_path {
        figment = figment.merge(Toml::file(path));
    }

    Ok(figment.extract()?)
}
