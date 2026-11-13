use figment::{
    Figment,
    providers::{Env, Format, Toml},
};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Deserializer, Serialize};
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

/// A backend's configuration table (`[clickhouse]`, `[rabbitmq]`, ...) that
/// has required keys (the URL, the brokers) and keys that an environment file
/// may set on their own: credentials, and switches that only mean something
/// when the backend is used.
///
/// One environment file often serves several deployments, so it may hold
/// settings of a backend that a deployment does not select
/// (`PROXYX_CONTROL_CLICKHOUSE__PASSWORD` next to `capture_store.backend =
/// "opensearch"`). Environment variables become table entries, and a table
/// without its required keys would fail the whole load. [`optional_section`]
/// reads a table that has only [`STANDALONE`](PartialSection::STANDALONE) keys
/// as absent. Every other table is read as before, so an unknown or misspelled
/// key is still an error, and a backend that is selected still reports its
/// missing URL.
pub trait PartialSection: DeserializeOwned {
    /// The keys that may stand alone in a table that is not used.
    const STANDALONE: &'static [&'static str];
}

/// `deserialize_with` of an optional [`PartialSection`] field: `None` when
/// the table holds only standalone keys, the parsed table otherwise.
pub fn optional_section<'de, D, T>(deserializer: D) -> Result<Option<T>, D::Error>
where
    D: Deserializer<'de>,
    T: PartialSection,
{
    let Some(value) = Option::<figment::value::Value>::deserialize(deserializer)? else {
        return Ok(None);
    };
    if let Some(table) = value.as_dict()
        && !table.is_empty()
        && table
            .keys()
            .all(|key| T::STANDALONE.contains(&key.as_str()))
    {
        return Ok(None);
    }
    value
        .deserialize::<T>()
        .map(Some)
        .map_err(serde::de::Error::custom)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    #[derive(Debug, Deserialize)]
    struct Backend {
        url: String,
        #[serde(default)]
        password: Option<String>,
    }

    impl PartialSection for Backend {
        const STANDALONE: &'static [&'static str] = &["password"];
    }

    #[derive(Debug, Deserialize)]
    struct Holder {
        #[serde(default, deserialize_with = "optional_section")]
        backend: Option<Backend>,
    }

    fn holder(toml: &str) -> Result<Holder, Box<figment::Error>> {
        Figment::new()
            .merge(Toml::string(toml))
            .extract()
            .map_err(Box::new)
    }

    #[test]
    fn a_table_with_only_credentials_is_absent() {
        assert!(
            holder("[backend]\npassword = \"x\"\n")
                .unwrap()
                .backend
                .is_none()
        );
        assert!(holder("").unwrap().backend.is_none());
    }

    #[test]
    fn a_complete_table_is_read() {
        let backend = holder("[backend]\nurl = \"u\"\npassword = \"x\"\n")
            .unwrap()
            .backend
            .unwrap();
        assert_eq!(
            (backend.url.as_str(), backend.password.as_deref()),
            ("u", Some("x"))
        );
    }

    #[test]
    fn any_other_key_without_the_required_ones_is_still_an_error() {
        let error = holder("[backend]\npassword = \"x\"\ntypo = 1\n").unwrap_err();
        assert!(error.to_string().contains("url"), "{error}");
        assert!(holder("[backend]\ntypo = 1\n").is_err());
        assert!(holder("[backend]\n").is_err());
    }

    #[test]
    fn environment_credentials_for_an_unselected_backend_are_ignored() {
        let figment = Figment::new().merge(Env::prefixed("PXTEST_SECTION_").split("__"));
        // SAFETY: the variable is private to this test.
        unsafe { std::env::set_var("PXTEST_SECTION_BACKEND__PASSWORD", "x") };
        let holder: Holder = figment.extract().unwrap();
        unsafe { std::env::remove_var("PXTEST_SECTION_BACKEND__PASSWORD") };
        assert!(holder.backend.is_none());
    }

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
