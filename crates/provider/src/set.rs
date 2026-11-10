//! The adapters of a data directory, checked together, by id.

use std::collections::BTreeMap;
use std::path::Path;

use common::Secret;
use common::types::ProviderId;

use crate::adapter::Adapter;
use crate::config::{AdapterConfig, AdapterFile};
use crate::error::ProviderError;

/// Every adapter loaded from a directory, by id.
#[derive(Debug, Clone)]
pub struct AdapterSet {
    adapters: BTreeMap<ProviderId, Adapter>,
}

impl AdapterSet {
    /// Load every `*.toml` file in `dir` (files in name order, no recursion).
    /// `secrets` reads a file of the secrets directory by name. The first
    /// unreadable directory or file, TOML error, adapter that cannot work,
    /// unreadable secret or duplicate id fails the whole load: a provider
    /// that silently disappears would be worse.
    pub fn load(
        dir: &Path,
        secrets: impl Fn(&str) -> anyhow::Result<Secret>,
    ) -> Result<Self, ProviderError> {
        let io = |path: &Path| {
            let path = path.to_path_buf();
            move |error| ProviderError::Io { path, error }
        };
        let mut files = Vec::new();
        for entry in std::fs::read_dir(dir).map_err(io(dir))? {
            let path = entry.map_err(io(dir))?.path();
            if path.extension().is_some_and(|e| e == "toml") {
                files.push(path);
            }
        }
        files.sort();

        let mut configs = Vec::new();
        for path in files {
            let text = std::fs::read_to_string(&path).map_err(io(&path))?;
            let file: AdapterFile =
                toml::from_str(&text).map_err(|error| ProviderError::Parse { path, error })?;
            configs.extend(file.adapter);
        }
        Self::from_configs(configs, &secrets)
    }

    /// Build a set from parsed configs, checking them as [`AdapterSet::load`]
    /// does after it has read the files.
    pub fn from_configs(
        configs: Vec<AdapterConfig>,
        secrets: &impl Fn(&str) -> anyhow::Result<Secret>,
    ) -> Result<Self, ProviderError> {
        let mut adapters = BTreeMap::new();
        for cfg in configs {
            let adapter = Adapter::from_config(cfg, secrets)?;
            let id = adapter.id().clone();
            tracing::debug!(provider = %id, kind = %adapter.kind(), "adapter loaded");
            if adapters.insert(id.clone(), adapter).is_some() {
                return Err(ProviderError::DuplicateId(id));
            }
        }
        Ok(Self { adapters })
    }

    pub fn get(&self, id: &ProviderId) -> Option<&Adapter> {
        self.adapters.get(id)
    }

    /// Adapters in id order.
    pub fn iter(&self) -> impl Iterator<Item = &Adapter> {
        self.adapters.values()
    }
}
