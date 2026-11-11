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
    if let Some(path) = config_path {
        anyhow::ensure!(
            Path::new(path).is_file(),
            "configuration file {path} does not exist"
        );
    }
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

    // Explicit path has highest priority.
    if let Some(path) = config_path {
        figment = figment.merge(Toml::file(path));
    }

    Ok(figment.extract()?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    #[test]
    fn explicit_missing_config_is_rejected() {
        let path =
            std::env::temp_dir().join(format!("proxyx-missing-{}.toml", uuid::Uuid::new_v4()));
        let path = path.to_str().unwrap();
        let error = load::<BTreeMap<String, String>>("config_test", Some(path)).unwrap_err();
        assert_eq!(
            error.to_string(),
            format!("configuration file {path} does not exist")
        );
    }

    #[test]
    fn explicit_config_directory_is_rejected() {
        let dir = std::env::temp_dir();
        let path = dir.to_str().unwrap();
        let error = load::<BTreeMap<String, String>>("config_test", Some(path)).unwrap_err();
        assert_eq!(
            error.to_string(),
            format!("configuration file {path} does not exist")
        );
    }
}
