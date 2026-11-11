//! The configuration the gateway and the warmer serve from: policies,
//! provider adapters and the Postgres snapshot, reloaded on a timer
//!
//!
//! Git data lives under `settings.data_dir`:
//!
//! * `adapters/*.toml`: read straight from the files (they hold no state), with
//!   secrets from `settings.secrets_dir`.
//! * `policies/*.toml`: `[[policy]]` tables ([`policy::PolicyFile`]).
//! * `inventory/*.toml`: `[[entry]]` tables with the fields of
//!   [`common::types::InventoryEntry`]. An entry names its provider; the
//!   file `<provider>.toml` also owns that provider when it lists no entry,
//!   so an emptied file retires the provider's IPs.
//!
//! The gateway (`sync_git = true`) copies git policy and inventory files into
//! Postgres as actor `gitops`.
//!
//! * **Inventory:** the content hash of the source is kept in `data_sources`,
//!   so an unchanged tree costs one query.
//! * **Policies**: a policy is written only when its
//!   document differs from the last one `gitops` stored for it, so an edit of
//!   one file (or a comment) leaves every other policy, and an operator's API
//!   change to it, alone. Git wins for the policies it did change: the
//!   operator's version is replaced, and the audit row of that write names
//!   who was replaced (`replaced.actor`) and the sync logs a warning. A git
//!   document equal to the operator's current one still becomes git's own
//!   version, so that a later change of the operator's is not
//!   mistaken for git's. Whether a tree was already applied is remembered in
//!   the process, not in Postgres, so gateways whose trees differ (a rolling
//!   update, a drifted ConfigMap) write once each when they start and never
//!   fight over the stored policy. Each gateway also records the tree it runs
//!   in `gateway_trees`: a gateway whose tree differs from the stored one
//!   (it restarted with a tree an earlier one replaced, or it applied its own
//!   earlier in this process) does not overwrite the stored policies while a
//!   gateway that runs the stored tree is alive; once none is, it
//!   applies (a rollback).
//!
//! Postgres stays the source of truth: operator changes made through the API
//! are kept until git changes the same policy or provider. A policy that a git
//! file no longer defines is deactivated, but only when the gitops actor
//! wrote its current version.
//!
//! A failed reload never replaces the served state: the last good [`Loaded`]
//! stays, `config_reload_failed{source}` is set, and Postgres trouble sets
//! `postgres_down`.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::Context as _;
use common::config::Settings;
use common::metrics::Metrics;
use common::types::{InventoryEntry, ProviderId, Region};
use policy::{PolicyDoc, PolicyFile, PolicySet};
use provider::AdapterSet;
use serde::Deserialize;
use tokio::sync::watch;
use tokio_util::sync::CancellationToken;
use verify::Url;

use crate::db::{Db, PolicyRecord, sha256_hex};
use crate::snapshot::Snapshot;

/// Audit actor of every write that comes from the git data directory.
pub const GITOPS_ACTOR: &str = "gitops";

/// One reload, git sync included, must finish inside this bound.
const RELOAD_TIMEOUT: Duration = Duration::from_secs(30);
/// How long a reload waits for a pooled connection before it calls Postgres
/// unreachable. Short, so `postgres_down` flips one tick after the outage
/// starts (the pool's own 5 s acquire timeout would double that).
const PROBE_TIMEOUT: Duration = Duration::from_secs(1);

const POLICIES_SOURCE: &str = "policies";
const INVENTORY_SOURCE: &str = "inventory";

/// Everything the data plane needs, loaded together.
pub struct Loaded {
    pub policies: PolicySet,
    pub adapters: AdapterSet,
    pub probe_targets: ProbeTargets,
    pub snapshot: Snapshot,
    pub loaded_at: Instant,
}

/// Load once, with no reload loop behind it, for a caller that only reads
/// the current state (`proxyx assess`): nothing keeps running or holds a
/// connection after this returns. With `sync_git` it first syncs changed git
/// files into Postgres. Bound by the same time limit as one reload.
pub async fn load(
    db: &Db,
    settings: &Settings,
    metrics: &Metrics,
    sync_git: bool,
) -> anyhow::Result<Loaded> {
    first_load(
        db,
        settings,
        metrics,
        sync_git,
        &Applied::new(settings.reload_every),
    )
    .await
}

async fn first_load(
    db: &Db,
    settings: &Settings,
    metrics: &Metrics,
    sync_git: bool,
    applied: &Applied,
) -> anyhow::Result<Loaded> {
    tokio::time::timeout(
        RELOAD_TIMEOUT,
        load_once(db, settings, metrics, sync_git, None, applied),
    )
    .await
    .context("failed to load the initial configuration in time")?
    .context("failed to load the initial configuration")
}

/// Load once (blocking until it works), then reload every
/// `settings.reload_every` until `cancel` fires. With `sync_git` the first
/// and every later load first syncs changed git files into Postgres.
///
/// Fails when the first load does (Postgres is down, an adapter does not load
/// or the stored policies are not valid); the caller retries.
pub async fn sync_and_watch(
    db: Db,
    settings: &Settings,
    metrics: Arc<Metrics>,
    cancel: CancellationToken,
    sync_git: bool,
) -> anyhow::Result<watch::Receiver<Arc<Loaded>>> {
    let settings = settings.clone();
    let applied = Arc::new(Applied::new(settings.reload_every));
    let first = first_load(&db, &settings, &metrics, sync_git, &applied).await?;
    tracing::info!(
        sync_git,
        inventory_rows = first.snapshot.inventory.len(),
        "configuration loaded"
    );
    let (tx, rx) = watch::channel(Arc::new(first));
    tokio::spawn(reload_loop(
        db, settings, metrics, cancel, sync_git, applied, tx,
    ));
    Ok(rx)
}

async fn reload_loop(
    db: Db,
    settings: Settings,
    metrics: Arc<Metrics>,
    cancel: CancellationToken,
    sync_git: bool,
    applied: Arc<Applied>,
    tx: watch::Sender<Arc<Loaded>>,
) {
    let mut tick = tokio::time::interval(settings.reload_every.max(Duration::from_secs(1)));
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    tick.tick().await;
    loop {
        tokio::select! {
            _ = tick.tick() => {}
            () = cancel.cancelled() => break,
        }
        let prev = tx.borrow().clone();
        let load = load_once(&db, &settings, &metrics, sync_git, Some(&prev), &applied);
        if let Some(loaded) = bounded_load(RELOAD_TIMEOUT, load, &metrics).await {
            tx.send_replace(Arc::new(loaded));
        }
        metrics
            .snapshot_age_seconds
            .set(tx.borrow().loaded_at.elapsed().as_secs_f64());
    }
    // a graceful stop: tell the others that this gateway's tree is gone now
    // (a crashed one is still covered by `live_for`)
    if sync_git && let Err(error) = db.forget_gateway_tree(&applied.instance).await {
        tracing::warn!(?error, "failed to forget this gateway's policy tree");
    }
}

/// Run one reload inside `limit`. `None` keeps the last good state: the
/// reload failed or hung. A hung reload is nearly always a Postgres call
/// that never answers, so it raises `postgres_down` like a failed query;
/// the next reload that reads the snapshot clears it.
async fn bounded_load(
    limit: Duration,
    load: impl Future<Output = anyhow::Result<Loaded>>,
    metrics: &Metrics,
) -> Option<Loaded> {
    match tokio::time::timeout(limit, load).await {
        Ok(Ok(loaded)) => Some(loaded),
        Ok(Err(error)) => {
            tracing::warn!(
                ?error,
                "configuration reload failed, keeping the last good one"
            );
            None
        }
        Err(_) => {
            metrics.postgres_down.set(1);
            tracing::warn!("configuration reload timed out, keeping the last good one");
            None
        }
    }
}

/// Which sources failed in this reload.
#[derive(Default)]
struct Health {
    adapters: bool,
    probe_targets: bool,
    policies: bool,
    inventory: bool,
}

impl Health {
    fn publish(&self, metrics: &Metrics) {
        for (source, failed) in [
            ("adapters", self.adapters),
            ("probe_targets", self.probe_targets),
            (POLICIES_SOURCE, self.policies),
            (INVENTORY_SOURCE, self.inventory),
        ] {
            metrics
                .config_reload_failed
                .with_label_values(&[source])
                .set(i64::from(failed));
        }
    }
}

#[derive(Default)]
struct AppliedPolicies {
    hash: Option<String>,
    drift_warned: bool,
}

/// What this process has already applied from git. Kept in memory on purpose
///: a hash in Postgres is shared by gateways whose trees differ, and
/// each of them would rewrite the stored policies whenever the hash is not
/// its own.
struct Applied {
    policies: std::sync::Mutex<AppliedPolicies>,
    /// Names this process in `gateway_trees`.
    instance: String,
    /// How long another gateway's mark counts as alive: three reload periods,
    /// so one slow or missed reload does not make it look gone.
    live_for: Duration,
}

impl Applied {
    fn new(reload_every: Duration) -> Self {
        Self {
            policies: std::sync::Mutex::default(),
            instance: uuid::Uuid::new_v4().to_string(),
            live_for: reload_every.max(Duration::from_secs(1)) * 3,
        }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, AppliedPolicies> {
        self.policies
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    fn policies_is(&self, hash: &str) -> bool {
        self.lock().hash.as_deref() == Some(hash)
    }

    fn set_policies(&self, hash: &str) {
        let mut held = self.lock();
        held.hash = Some(hash.to_owned());
        held.drift_warned = false;
    }

    /// Run `warn` the first time since the last [`Self::set_policies`].
    fn warn_drift_once(&self, warn: impl FnOnce()) {
        let mut held = self.lock();
        if !held.drift_warned {
            held.drift_warned = true;
            warn();
        }
    }
}

async fn load_once(
    db: &Db,
    settings: &Settings,
    metrics: &Metrics,
    sync_git: bool,
    prev: Option<&Loaded>,
    applied: &Applied,
) -> anyhow::Result<Loaded> {
    let mut health = Health::default();
    let result = build(db, settings, metrics, sync_git, prev, applied, &mut health).await;
    health.publish(metrics);
    result
}

/// A source that fails to load keeps the last good one; without one the load fails.
fn or_previous<T: Clone>(
    loaded: anyhow::Result<T>,
    prev: Option<&T>,
    failed: &mut bool,
    what: &str,
) -> anyhow::Result<T> {
    match (loaded, prev) {
        (Ok(value), _) => Ok(value),
        (Err(error), Some(prev)) => {
            *failed = true;
            tracing::warn!(?error, "{what} failed to load, keeping the last good ones");
            Ok(prev.clone())
        }
        (Err(error), None) => {
            *failed = true;
            Err(error.context(format!("failed to load {what}")))
        }
    }
}

/// Whether `error` says Postgres cannot be reached (pool timeout or closed
/// pool, I/O or TLS failure, connection-class or shutdown SQLSTATE) rather
/// than a query or data failure.
fn database_unreachable(error: &anyhow::Error) -> bool {
    error
        .chain()
        .filter_map(|cause| cause.downcast_ref::<sqlx::Error>())
        .any(|cause| match cause {
            sqlx::Error::Io(_)
            | sqlx::Error::Tls(_)
            | sqlx::Error::PoolTimedOut
            | sqlx::Error::PoolClosed
            | sqlx::Error::WorkerCrashed => true,
            sqlx::Error::Database(db) => db
                .code()
                .is_some_and(|code| code.starts_with("08") || code.starts_with("57P")),
            _ => false,
        })
}

async fn build(
    db: &Db,
    settings: &Settings,
    metrics: &Metrics,
    sync_git: bool,
    prev: Option<&Loaded>,
    applied: &Applied,
    health: &mut Health,
) -> anyhow::Result<Loaded> {
    let owned = settings.clone();
    let disk = tokio::task::spawn_blocking(move || read_disk(&owned, sync_git))
        .await
        .context("failed to read the configuration: the reader panicked")?;

    let adapters = or_previous(
        disk.adapters,
        prev.map(|p| &p.adapters),
        &mut health.adapters,
        "adapters",
    )?;
    let probe_targets = or_previous(
        disk.probe_targets,
        prev.map(|p| &p.probe_targets),
        &mut health.probe_targets,
        "probe targets",
    )?;

    // Postgres that cannot be reached is found by one short probe, before any
    // query waits out the pool's acquire timeout. It raises `postgres_down`
    // and not `config_reload_failed`: nothing was rejected, so the config
    // alert must not fire for a database outage. A database that dies in the
    // middle of the reload still fails its first call after one acquire
    // timeout, and that failure ends the reload the same way.
    if let Err(error) = db.check_reachable(PROBE_TIMEOUT).await {
        metrics.postgres_down.set(1);
        return Err(anyhow::Error::new(error).context("postgres is unreachable"));
    }
    let mut unreachable: Option<anyhow::Error> = None;
    if sync_git {
        match disk.policies {
            Ok(Some(source)) => {
                if let Err(error) = sync_policies(db, &source, applied).await {
                    tracing::warn!(?error, "policy sync failed");
                    if database_unreachable(&error) {
                        unreachable = Some(error);
                    } else {
                        health.policies = true;
                    }
                }
            }
            Ok(None) => {}
            Err(error) => {
                health.policies = true;
                tracing::warn!(?error, "policy files are invalid, not syncing them");
            }
        }
        match disk.inventory {
            Ok(Some(_)) if unreachable.is_some() => {}
            Ok(Some(source)) => {
                if let Err(error) = sync_inventory(db, &source, &adapters).await {
                    tracing::warn!(?error, "inventory sync failed");
                    if database_unreachable(&error) {
                        unreachable = Some(error);
                    } else {
                        health.inventory = true;
                    }
                }
            }
            Ok(None) => {}
            Err(error) => {
                health.inventory = true;
                tracing::warn!(?error, "inventory files are invalid, not syncing them");
            }
        }
    }
    if let Some(error) = unreachable {
        metrics.postgres_down.set(1);
        return Err(error.context("postgres is unreachable, skipping the rest of the reload"));
    }

    let loading = match prev {
        Some(prev) => Snapshot::reload(db, &prev.snapshot).await,
        None => Snapshot::load(db).await,
    };
    let snapshot = match loading {
        Ok(snapshot) => {
            metrics.postgres_down.set(0);
            snapshot
        }
        Err(error) => {
            metrics.postgres_down.set(1);
            return Err(anyhow::Error::new(error).context("failed to load the snapshot"));
        }
    };
    // The merged set is expensive with many org policies (memory and CPU
    // grow with them), so a reload that finds the same policy versions keeps
    // the set it has and only re-checks it against the adapters; a changed
    // one is built on a blocking thread, off the tunnel path.
    let policies = match prev {
        Some(prev) if Arc::ptr_eq(&prev.snapshot.policies, &snapshot.policies) => {
            check_session_life(&prev.policies, &adapters)
                .context("the stored policies do not fit the provider's session life")
                .map(|()| prev.policies.clone())
        }
        _ => {
            let records = Arc::clone(&snapshot.policies);
            let adapters = adapters.clone();
            tokio::task::spawn_blocking(move || policy_set(&records, &adapters))
                .await
                .context("failed to build the policies: the builder panicked")
                .and_then(|built| built)
        }
    }
    .inspect_err(|_| health.policies = true)?;
    Ok(Loaded {
        policies,
        adapters,
        probe_targets,
        snapshot,
        // A source that fell back to the last good one is not freshly loaded:
        // `snapshot_age_seconds` keeps growing until it loads again.
        loaded_at: match prev {
            Some(prev) if health.adapters || health.probe_targets => prev.loaded_at,
            _ => Instant::now(),
        },
    })
}

/// The stored policies as one set that also fits the adapters
/// ([`check_session_life`]).
pub(crate) fn policy_set(
    records: &[PolicyRecord],
    adapters: &AdapterSet,
) -> anyhow::Result<PolicySet> {
    let docs = records
        .iter()
        .map(PolicyRecord::doc)
        .collect::<Result<Vec<_>, _>>()
        .context("failed to decode stored policies")?;
    let set = PolicySet::from_docs(docs).context("failed to validate the stored policies")?;
    check_session_life(&set, adapters)
        .context("the stored policies do not fit the provider's session life")?;
    Ok(set)
}

/// A rotating provider's sessions must outlive the policies' `min_remaining`,
/// or every session of it would be skipped at lease time. The gateway applies
/// this to the set it loads; the API applies it before it stores a write.
pub fn check_session_life(
    policies: &PolicySet,
    adapters: &AdapterSet,
) -> Result<(), policy::PolicyError> {
    for adapter in adapters
        .iter()
        .filter(|a| a.kind() == common::types::Kind::Rotating)
    {
        policies.check_session_life(adapter.id(), adapter.session_life())?;
    }
    Ok(())
}

// --- Probe targets ---

/// The light-probe and prober pages: global (`*`) and per region
/// (`search.example.fr` for `fr`). Loaded from `<data_dir>/probe-targets.toml` when
/// it exists, else one default page. The prober's browsers reach the
/// internet through the probe listener, which opens only these pages' hosts
/// and `extra_hosts` (the hosts of their subresources, subdomains included),
/// on ports 80 and 443 ([`ProbeTargets::allows`]).
///
/// ```toml
/// global = ["https://www.example.com/"]
/// extra_hosts = ["static.example.com"]
/// [region]
/// fr = ["https://www.example.fr/"]
/// "fr/paris" = ["https://www.example.fr/maps"]
/// ```
#[derive(Debug, Clone)]
pub struct ProbeTargets {
    global: Vec<Url>,
    by_region: HashMap<String, Vec<Url>>,
    /// Hosts of the pages' subresources: allowed on the probe listener (and
    /// their subdomains) besides the pages' own hosts.
    extra_hosts: Vec<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ProbeTargetsFile {
    #[serde(default)]
    global: Vec<String>,
    #[serde(default)]
    region: HashMap<String, Vec<String>>,
    #[serde(default)]
    extra_hosts: Vec<String>,
}

fn urls(list: &[String], what: &str) -> anyhow::Result<Vec<Url>> {
    list.iter()
        .map(|s| {
            let url = Url::parse(s).with_context(|| format!("failed to parse {what} url"))?;
            anyhow::ensure!(
                matches!(url.scheme(), "http" | "https") && url.host_str().is_some(),
                "{what} url must be http or https with a host"
            );
            Ok(url)
        })
        .collect()
}

impl Default for ProbeTargets {
    fn default() -> Self {
        Self {
            // detection-data: the default page, a search-engine front page
            global: vec![Url::parse("https://www.google.com/").expect("static url is valid")],
            by_region: HashMap::new(),
            extra_hosts: Vec::new(),
        }
    }
}

impl ProbeTargets {
    pub fn new(global: Vec<Url>, by_region: HashMap<String, Vec<Url>>) -> Self {
        Self {
            global,
            by_region,
            extra_hosts: Vec::new(),
        }
    }

    /// Read the optional file; defaults when it does not exist.
    ///
    /// Fails when the file is unreadable, does not parse, names an invalid
    /// region, or lists a URL that is not http(s) with a host.
    pub(crate) fn load(data_dir: &Path) -> anyhow::Result<Self> {
        let path = data_dir.join("probe-targets.toml");
        let text = match std::fs::read_to_string(&path) {
            Ok(text) => text,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Self::default()),
            Err(e) => return Err(anyhow::Error::new(e).context("failed to read probe targets")),
        };
        let file: ProbeTargetsFile =
            toml::from_str(&text).context("failed to parse probe targets")?;
        let by_region = file
            .region
            .iter()
            .map(|(region, list)| {
                region
                    .parse::<Region>()
                    .with_context(|| format!("invalid probe target region {region:?}"))?;
                Ok((region.clone(), urls(list, "region")?))
            })
            .collect::<anyhow::Result<_>>()?;
        Self::new(urls(&file.global, "global")?, by_region).with_extra_hosts(&file.extra_hosts)
    }

    /// The same targets, with `hosts` (and their subdomains) allowed on the
    /// probe listener besides the pages' own hosts. Fails on a name that is
    /// not a plain host name.
    pub fn with_extra_hosts(mut self, hosts: &[String]) -> anyhow::Result<Self> {
        for host in hosts {
            anyhow::ensure!(
                !host.is_empty()
                    && host
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'-'),
                "extra host {host:?} is not a plain host name"
            );
        }
        self.extra_hosts = hosts.iter().map(|h| h.to_ascii_lowercase()).collect();
        Ok(self)
    }

    /// True when the probe listener may open a tunnel to `host:port`: the host
    /// is one of the pages' hosts (or an `extra_hosts` entry, or a subdomain
    /// of one) and the port is 80, 443 or the explicit port of a page. A
    /// probe credential that leaks therefore opens nothing but the pages
    /// being measured.
    pub fn allows(&self, host: &str, port: u16) -> bool {
        let host = host.trim_end_matches('.').to_ascii_lowercase();
        let page_hosts = |url: &Url| {
            url.host_str()
                .is_some_and(|h| h.eq_ignore_ascii_case(&host))
        };
        let pages = || self.global.iter().chain(self.by_region.values().flatten());
        let host_ok = pages().any(page_hosts)
            || self.extra_hosts.iter().any(|extra| {
                host == *extra
                    || host
                        .strip_suffix(extra.as_str())
                        .is_some_and(|p| p.ends_with('.'))
            });
        host_ok
            && (matches!(port, 80 | 443)
                || pages().any(|url| page_hosts(url) && url.port() == Some(port)))
    }

    /// Global targets, then those of the region's country, then of the city,
    /// each URL once: a country page that repeats a global one (`us` and
    /// `example.com`) is not probed twice.
    pub fn for_region(&self, region: &Region) -> Vec<Url> {
        let country = self.by_region.get(region.country());
        let city = region
            .city()
            .and_then(|_| self.by_region.get(&region.to_string()));
        let mut out: Vec<Url> = Vec::new();
        for url in self
            .global
            .iter()
            .chain(country.into_iter().flatten())
            .chain(city.into_iter().flatten())
        {
            if !out.contains(url) {
                out.push(url.clone());
            }
        }
        out
    }
}

// --- Git files ---

#[derive(Debug)]
struct PolicySource {
    hash: String,
    docs: Vec<PolicyDoc>,
}

#[derive(Debug)]
struct InventorySource {
    hash: String,
    /// Every provider the files own, with its entries (maybe none).
    providers: BTreeMap<ProviderId, Vec<InventoryEntry>>,
}

/// One pass over the data directory.
struct Disk {
    adapters: anyhow::Result<AdapterSet>,
    probe_targets: anyhow::Result<ProbeTargets>,
    policies: anyhow::Result<Option<PolicySource>>,
    inventory: anyhow::Result<Option<InventorySource>>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct InventoryFile {
    #[serde(default)]
    entry: Vec<InventoryEntry>,
}

fn read_disk(settings: &Settings, sync_git: bool) -> Disk {
    let data = &settings.data_dir;
    Disk {
        adapters: AdapterSet::load(&data.join("adapters"), |name| settings.read_secret(name))
            .context("failed to read adapters"),
        probe_targets: ProbeTargets::load(data),
        policies: if sync_git {
            read_policies(&data.join("policies"))
        } else {
            Ok(None)
        },
        inventory: if sync_git {
            read_inventory(&data.join("inventory"))
        } else {
            Ok(None)
        },
    }
}

/// `*.toml` files of a directory in name order as `(file name, text)`.
/// `None` when the directory does not exist.
fn read_toml_dir(dir: &Path) -> anyhow::Result<Option<Vec<(String, String)>>> {
    let entries = match std::fs::read_dir(dir) {
        Ok(entries) => entries,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e).with_context(|| format!("failed to list {}", dir.display())),
    };
    let mut paths = Vec::new();
    for entry in entries {
        let path = entry
            .with_context(|| format!("failed to list {}", dir.display()))?
            .path();
        if path.extension().is_some_and(|e| e == "toml") {
            paths.push(path);
        }
    }
    paths.sort();
    paths
        .into_iter()
        .map(|path| {
            let text = std::fs::read_to_string(&path)
                .with_context(|| format!("failed to read {}", path.display()))?;
            let name = path
                .file_name()
                .map_or_else(String::new, |n| n.to_string_lossy().into_owned());
            Ok((name, text))
        })
        .collect::<anyhow::Result<Vec<_>>>()
        .map(Some)
}

/// Content hash of a file set: names and bytes, so a rename or an edit
/// changes it.
fn content_hash(files: &[(String, String)]) -> String {
    let mut bytes = Vec::new();
    for (name, text) in files {
        bytes.extend_from_slice(name.as_bytes());
        bytes.push(0);
        bytes.extend_from_slice(text.as_bytes());
        bytes.push(0);
    }
    sha256_hex(&bytes)
}

/// The policy documents the git files under `data_dir/policies` define now,
/// none when the directory does not exist.
pub fn git_policy_docs(data_dir: &Path) -> anyhow::Result<Vec<PolicyDoc>> {
    Ok(read_policies(&data_dir.join("policies"))?.map_or_else(Vec::new, |source| source.docs))
}

fn read_policies(dir: &Path) -> anyhow::Result<Option<PolicySource>> {
    let Some(files) = read_toml_dir(dir)? else {
        return Ok(None);
    };
    let mut docs = Vec::new();
    for (name, text) in &files {
        let file = PolicyFile::parse(text)
            .with_context(|| format!("failed to parse policy file {name}"))?;
        docs.extend(file.policies);
    }
    Ok(Some(PolicySource {
        hash: content_hash(&files),
        docs,
    }))
}

fn read_inventory(dir: &Path) -> anyhow::Result<Option<InventorySource>> {
    let Some(files) = read_toml_dir(dir)? else {
        return Ok(None);
    };
    let mut providers: BTreeMap<ProviderId, Vec<InventoryEntry>> = BTreeMap::new();
    let mut seen = HashSet::new();
    for (name, text) in &files {
        let file: InventoryFile = toml::from_str(text)
            .with_context(|| format!("failed to parse inventory file {name}"))?;
        if let Some(owner) = name
            .strip_suffix(".toml")
            .and_then(|stem| stem.parse::<ProviderId>().ok())
        {
            providers.entry(owner).or_default();
        }
        for entry in file.entry {
            anyhow::ensure!(
                entry.subtype.kind() == common::types::Kind::Static,
                "{name}: {} is a rotating subtype, not an inventory entry",
                entry.ip
            );
            anyhow::ensure!(seen.insert(entry.ip), "{name}: duplicate ip {}", entry.ip);
            crate::db::check_rental_end(&entry).with_context(|| format!("in {name}"))?;
            providers
                .entry(entry.provider.clone())
                .or_default()
                .push(entry);
        }
    }
    Ok(Some(InventorySource {
        hash: content_hash(&files),
        providers,
    }))
}

// --- Sync into Postgres ---

async fn is_synced(db: &Db, source: &str, hash: &str) -> anyhow::Result<bool> {
    let stored = db
        .source_hash(source)
        .await
        .with_context(|| format!("failed to read the {source} source hash"))?;
    Ok(stored.as_deref() == Some(hash))
}

async fn mark_synced(db: &Db, source: &str, hash: &str) -> anyhow::Result<()> {
    db.set_source_hash(source, hash, GITOPS_ACTOR)
        .await
        .with_context(|| format!("failed to record the {source} source hash"))
}

async fn sync_policies(db: &Db, source: &PolicySource, applied: &Applied) -> anyhow::Result<()> {
    db.beat_gateway_tree(&applied.instance, &source.hash)
        .await
        .context("failed to record the policy tree this gateway runs")?;
    let stored = db
        .source_hash(POLICIES_SOURCE)
        .await
        .context("failed to read the policies source hash")?;
    // The names alone answer whether git's policies are current, so the
    // steady state does not read every org's document.
    let present = db
        .current_policy_versions()
        .await
        .context("failed to read the current policy versions")?;
    let all_present = source.docs.iter().all(|d| {
        let scope = d.scope.to_string();
        present.iter().any(|(s, n, _)| *s == scope && *n == d.name)
    });
    let ours = stored.as_deref() == Some(source.hash.as_str());
    if ours && all_present {
        applied.set_policies(&source.hash);
        return Ok(());
    }
    // Another gateway stored a tree that is not this one, and still runs it.
    // While it does, this one leaves the stored policies alone: after it
    // applied its own tree (the files differ, writing ours again would
    // only start a fight, one new policy version per reload on each side), or
    // when its tree is an older one than the stored (a pod of the old
    // ReplicaSet restarted). Once no gateway runs the stored tree, this one
    // applies, whether it did before in this process or not (a rollback).
    let stored_is_running = match &stored {
        Some(stored) if !ours => db
            .gateway_tree_is_live(&applied.instance, stored, applied.live_for)
            .await
            .context("failed to look for a gateway that runs the stored policy tree")?,
        _ => false,
    };
    if stored_is_running && all_present && applied.policies_is(&source.hash) {
        applied.warn_drift_once(|| {
            tracing::warn!(
                "another gateway applied different policy files: this one leaves the stored \
                 policies alone until its files match (a rolling update does)"
            );
        });
        return Ok(());
    }
    if stored_is_running
        && db
            .policy_tree_was_applied(&source.hash)
            .await
            .context("failed to look for an earlier application of the policy tree")?
    {
        applied.warn_drift_once(|| {
            tracing::warn!(
                "the stored policies come from newer policy files, and a gateway that runs them \
                 is alive: this gateway leaves them alone until its files match"
            );
        });
        return Ok(());
    }
    let current = db
        .current_policies()
        .await
        .context("failed to read current policies")?;
    let last_git = db
        .latest_policy_docs_by(GITOPS_ACTOR)
        .await
        .context("failed to read the policies git wrote")?;
    // Rows are keyed by (scope, name), so that pair says what git replaces.
    let in_git: HashSet<(String, &str)> = source
        .docs
        .iter()
        .map(|d| (d.scope.to_string(), d.name.as_str()))
        .collect();
    let in_git_row = |r: &PolicyRecord| in_git.contains(&(r.scope.clone(), r.name.as_str()));
    let removed: Vec<&PolicyRecord> = current
        .iter()
        .filter(|r| r.actor == GITOPS_ACTOR && !in_git_row(r))
        .collect();

    // Git writes a policy only when its document is not the one git wrote
    // last: an unrelated file, a comment, or a restart rewrites
    // nothing, and an operator's change to an unchanged git policy stays. A
    // policy that is not current (an operator removed it) is written again.
    let mut to_write: Vec<PolicyDoc> = Vec::new();
    // The policies git defines as they will be after this sync.
    let mut combined: Vec<PolicyDoc> = Vec::new();
    for doc in &source.docs {
        let (scope, name) = (doc.scope.to_string(), &doc.name);
        let row = current.iter().find(|r| r.scope == scope && r.name == *name);
        let canonical =
            crate::db::canonical_policy_doc(doc).context("failed to encode a git policy")?;
        if let Some(record) = row
            && last_git.get(&(scope.clone(), name.clone())) == Some(&canonical)
        {
            combined.push(record.doc().context("failed to decode a stored policy")?);
            continue;
        }
        if let Some(record) = row.filter(|r| r.actor != GITOPS_ACTOR && r.doc != canonical) {
            tracing::warn!(
                policy = %name,
                %scope,
                replaced_actor = %record.actor,
                "git changed a policy that was written through the API: git wins, the API version is replaced"
            );
        }
        combined.push(doc.clone());
        to_write.push(doc.clone());
    }
    // Validate what the set will be before anything is written: the policies
    // above plus every one that stays (operator-written, not in git).
    for record in &current {
        if record.actor != GITOPS_ACTOR && !in_git_row(record) {
            combined.push(record.doc().context("failed to decode a stored policy")?);
        }
    }
    PolicySet::from_docs(combined).context(
        "git policies do not form a valid set (a policy written through the API can conflict: \
         GET /v1/policies lists them, DELETE /v1/policies/{scope}/{name} removes one)",
    )?;

    let put = db
        .put_policies(&to_write, GITOPS_ACTOR)
        .await
        .context("failed to store git policies")?;
    for record in removed {
        db.deactivate_policy(&record.scope, &record.name, GITOPS_ACTOR)
            .await
            .context("failed to deactivate a removed policy")?;
        tracing::info!(policy = %record.name, "policy removed from git, deactivated");
    }
    mark_synced(db, POLICIES_SOURCE, &source.hash).await?;
    applied.set_policies(&source.hash);
    tracing::info!(
        stored = put.stored.len(),
        unchanged = put.unchanged,
        "policies synced from git"
    );
    Ok(())
}

async fn sync_inventory(
    db: &Db,
    source: &InventorySource,
    adapters: &AdapterSet,
) -> anyhow::Result<()> {
    if is_synced(db, INVENTORY_SOURCE, &source.hash).await? {
        return Ok(());
    }
    // Nothing is written for a provider that has no adapter: the warmer and
    // the gateway could never lease or check its IPs, they would sit as
    // candidates until someone found them.
    let ghosts: Vec<String> = source
        .providers
        .iter()
        .filter(|(provider, entries)| !entries.is_empty() && adapters.get(provider).is_none())
        .map(|(provider, _)| provider.to_string())
        .collect();
    anyhow::ensure!(
        ghosts.is_empty(),
        "inventory names providers without an adapter: {}",
        ghosts.join(", ")
    );
    for (provider, entries) in &source.providers {
        let sync = db
            .replace_inventory(provider, entries, GITOPS_ACTOR)
            .await
            .with_context(|| format!("failed to sync the inventory of {provider}"))?;
        tracing::info!(
            %provider,
            added = sync.added.len(),
            updated = sync.updated.len(),
            revived = sync.revived.len(),
            retired = sync.retired.len(),
            unchanged = sync.unchanged,
            "inventory synced from git"
        );
    }
    // A provider whose file was deleted has no entry in `source`: retire what
    // git wrote for it, as an emptied file does.
    for provider in db
        .providers_written_by(GITOPS_ACTOR)
        .await
        .context("failed to list the providers git manages")?
    {
        if source.providers.contains_key(&provider) {
            continue;
        }
        let sync = db
            .replace_inventory(&provider, &[], GITOPS_ACTOR)
            .await
            .with_context(|| format!("failed to retire the inventory of {provider}"))?;
        tracing::info!(
            %provider,
            retired = sync.retired.len(),
            "inventory file removed from git, its ips are retired"
        );
    }
    mark_synced(db, INVENTORY_SOURCE, &source.hash).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn targets_are_global_then_country_then_city() {
        let u = |s: &str| Url::parse(s).expect("url");
        let t = ProbeTargets::new(
            vec![u("https://g.example/")],
            HashMap::from([
                ("fr".to_owned(), vec![u("https://fr.example/")]),
                ("fr/paris".to_owned(), vec![u("https://paris.example/")]),
                ("us".to_owned(), vec![u("https://g.example/")]),
                (
                    "gb".to_owned(),
                    vec![u("https://gb.example/"), u("https://gb.example/")],
                ),
            ]),
        );
        let hosts = |r: &str| -> Vec<String> {
            t.for_region(&r.parse().expect("region"))
                .iter()
                .map(|u| u.host_str().unwrap_or_default().to_owned())
                .collect()
        };
        assert_eq!(
            hosts("fr/paris"),
            ["g.example", "fr.example", "paris.example"]
        );
        assert_eq!(hosts("fr"), ["g.example", "fr.example"]);
        assert_eq!(hosts("de"), ["g.example"]);
        assert_eq!(hosts("us"), ["g.example"], "a repeat of a global page");
        assert_eq!(
            hosts("gb"),
            ["g.example", "gb.example"],
            "a repeat in a list"
        );
    }

    #[test]
    fn the_shipped_targets_give_each_country_its_own_site_once() {
        let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../data");
        let t = ProbeTargets::load(&dir).expect("data/probe-targets.toml loads");
        let hosts = |r: &str| -> Vec<String> {
            t.for_region(&r.parse().expect("region"))
                .iter()
                .map(|u| u.host_str().unwrap_or_default().to_owned())
                .collect()
        };
        assert_eq!(hosts("us"), ["www.google.com"], "us is the baseline site"); // detection-data
        assert_eq!(hosts("gb"), ["www.google.com", "www.google.co.uk"]); // detection-data
        assert_eq!(hosts("jp"), ["www.google.com", "www.google.co.jp"]); // detection-data
        assert_eq!(hosts("de"), ["www.google.com", "www.google.de"]); // detection-data
        for cc in ["fr", "nl", "es", "it", "ca", "au", "br", "in"] {
            assert_eq!(hosts(cc).len(), 2, "{cc}: baseline and its own site");
        }
        assert_eq!(
            hosts("pt"),
            ["www.google.com"], // detection-data
            "an unlisted country: baseline only"
        );
    }

    /// The probe listener opens the pages and `extra_hosts`
    /// only, on 80 and 443 (or a page's own port).
    #[test]
    fn the_probe_listener_allows_the_pages_and_extra_hosts_only() {
        let u = |s: &str| Url::parse(s).expect("url");
        let targets = ProbeTargets::new(
            vec![u("https://g.example/")],
            HashMap::from([("fr".to_owned(), vec![u("http://fr.example:8080/x")])]),
        )
        .with_extra_hosts(&["Static.Example".to_owned()])
        .expect("plain host names");
        for (host, port) in [
            ("g.example", 443),
            ("G.EXAMPLE.", 80),
            ("fr.example", 443),
            ("fr.example", 8080),
            ("static.example", 443),
            ("cdn.static.example", 443),
        ] {
            assert!(targets.allows(host, port), "{host}:{port}");
        }
        for (host, port) in [
            ("evil.example", 443),
            ("notstatic.example", 443),
            ("static.example.evil", 443),
            ("g.example", 22),
            ("g.example", 8080),
            ("127.0.0.1", 443),
            ("169.254.169.254", 80),
            ("", 443),
        ] {
            assert!(!targets.allows(host, port), "{host}:{port}");
        }
        assert!(
            ProbeTargets::default()
                .with_extra_hosts(&["a b".to_owned()])
                .is_err()
        );
    }

    #[test]
    fn the_shipped_targets_allow_the_consent_and_static_hosts() {
        let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../data");
        let t = ProbeTargets::load(&dir).expect("data/probe-targets.toml loads");
        for host in [
            "www.google.com",     // detection-data
            "www.google.co.uk",   // detection-data
            "consent.google.com", // detection-data
            "www.gstatic.com",    // detection-data
        ] {
            assert!(t.allows(host, 443), "{host}");
        }
        assert!(!t.allows("example.com", 443));
    }

    #[test]
    fn a_target_file_is_parsed_and_checked() {
        let dir = temp_dir();
        assert_eq!(
            ProbeTargets::load(&dir).expect("defaults").global.len(),
            1,
            "a missing file gives the defaults"
        );
        let file = "probe-targets.toml";
        write(
            &dir,
            file,
            "global = [\"https://a.example/\"]\n[region]\nfr = [\"https://b.example/\"]\n",
        );
        let loaded = ProbeTargets::load(&dir).expect("valid file");
        assert_eq!(loaded.for_region(&"fr".parse().expect("region")).len(), 2);
        write(&dir, file, "global = [\"ftp://a.example/\"]\n");
        assert!(ProbeTargets::load(&dir).is_err(), "only http and https");
        write(&dir, file, "[region]\nFRA = [\"https://b.example/\"]\n");
        assert!(ProbeTargets::load(&dir).is_err(), "region must parse");
        write(&dir, file, "surprise = 1\n");
        assert!(ProbeTargets::load(&dir).is_err(), "unknown field");
        std::fs::remove_dir_all(&dir).ok();
    }

    fn temp_dir() -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("proxyx-loaded-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).expect("create temp dir");
        dir
    }

    fn write(dir: &Path, name: &str, text: impl AsRef<[u8]>) {
        std::fs::write(dir.join(name), text).expect("write");
    }

    fn inventory_hash(dir: &Path) -> String {
        read_inventory(dir).expect("read").expect("source").hash
    }

    fn entry(ip: &str) -> String {
        format!(
            "[[entry]]\nprovider = \"isp_static_port\"\nsubtype = \"isp\"\nip = \"{ip}\"\n\
             host = \"rotating.isp.example.net\"\nport = 8001\nregion = \"fr\"\n"
        )
    }

    #[test]
    fn missing_directory_is_no_source_and_hash_follows_names_and_content() {
        let dir = temp_dir();
        assert!(read_inventory(&dir.join("absent")).expect("read").is_none());

        write(&dir, "a.toml", entry("203.0.113.1"));
        let first = inventory_hash(&dir);
        assert_eq!(first, inventory_hash(&dir));

        write(&dir, "a.toml", entry("203.0.113.2"));
        let edited = inventory_hash(&dir);
        assert_ne!(first, edited);

        std::fs::rename(dir.join("a.toml"), dir.join("b.toml")).expect("rename");
        assert_ne!(edited, inventory_hash(&dir));
    }

    #[test]
    fn inventory_files_group_by_provider_and_an_empty_file_still_owns_its_provider() {
        let dir = temp_dir();
        write(
            &dir,
            "isp_static_port.toml",
            format!("{}{}", entry("203.0.113.1"), entry("203.0.113.2")),
        );
        write(&dir, "emptied_provider.toml", "entry = []\n");
        write(&dir, "notes.txt", "ignored");

        let source = read_inventory(&dir).expect("read").expect("source");
        let ox: ProviderId = "isp_static_port".parse().expect("id");
        let emptied: ProviderId = "emptied_provider".parse().expect("id");
        assert_eq!(source.providers[&ox].len(), 2);
        assert!(source.providers[&emptied].is_empty());
    }

    #[test]
    fn inventory_refuses_duplicate_ips_rotating_subtypes_and_unknown_fields() {
        let dir = temp_dir();
        write(
            &dir,
            "a.toml",
            format!("{}{}", entry("203.0.113.1"), entry("203.0.113.1")),
        );
        let err = read_inventory(&dir).expect_err("duplicate");
        assert!(
            format!("{err:#}").contains("duplicate ip 203.0.113.1"),
            "{err:#}"
        );

        write(
            &dir,
            "a.toml",
            entry("203.0.113.1").replace("\"isp\"", "\"residential\""),
        );
        let err = read_inventory(&dir).expect_err("rotating");
        assert!(format!("{err:#}").contains("rotating subtype"), "{err:#}");

        write(
            &dir,
            "a.toml",
            format!("colour = \"red\"\n{}", entry("203.0.113.1")),
        );
        assert!(read_inventory(&dir).is_err());
    }

    #[test]
    fn a_bad_policy_file_is_an_error_not_an_empty_source() {
        let dir = temp_dir();
        write(&dir, "p.toml", "[[policy]]\nname = \"x\"\nbogus = 1\n");
        let err = read_policies(&dir).expect_err("unknown field");
        assert!(format!("{err:#}").contains("p.toml"), "{err:#}");
    }

    #[tokio::test(start_paused = true)]
    async fn a_reload_that_never_returns_is_cut_off_and_marks_postgres_down() {
        let metrics = Metrics::new("test");
        metrics.postgres_down.set(0);
        let loaded = bounded_load(
            RELOAD_TIMEOUT,
            std::future::pending::<anyhow::Result<Loaded>>(),
            &metrics,
        )
        .await;
        assert!(loaded.is_none());
        assert_eq!(metrics.postgres_down.get(), 1);
    }

    #[test]
    fn only_connectivity_failures_mean_postgres_is_unreachable() {
        let store = |e: sqlx::Error| {
            anyhow::Error::new(crate::error::StoreError::Database(e))
                .context("failed to read the policies source hash")
        };
        assert!(database_unreachable(&store(sqlx::Error::PoolTimedOut)));
        assert!(database_unreachable(&store(sqlx::Error::PoolClosed)));
        assert!(database_unreachable(&store(sqlx::Error::Io(
            std::io::ErrorKind::ConnectionRefused.into()
        ))));
        assert!(!database_unreachable(&store(sqlx::Error::RowNotFound)));
        assert!(!database_unreachable(&anyhow::anyhow!(
            "git policies do not form a valid set"
        )));
    }

    /// Postgres that accepts connections and never answers: the pool would
    /// wait out its 5 s acquire timeout on every call. A reload must find out
    /// within the short probe bound, flag `postgres_down` (not a rejected
    /// source), and skip the rest.
    #[tokio::test(start_paused = true)]
    async fn an_unreachable_postgres_ends_the_reload_within_the_probe_bound() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
        let port = listener.local_addr().expect("addr").port();
        let db = Db::connect_lazy(&format!("postgres://u:p@127.0.0.1:{port}/d")).expect("url");

        let dir = temp_dir();
        for sub in ["adapters", "policies", "inventory"] {
            std::fs::create_dir_all(dir.join(sub)).expect("create dir");
        }
        std::fs::write(
            dir.join("policies/p.toml"),
            "[[policy]]\nname = \"global\"\nregions = [\"fr\"]\nmin_ready = 1\nmax_ready = 40\n",
        )
        .expect("write");
        std::fs::write(dir.join("inventory/i.toml"), entry("203.0.113.1")).expect("write");
        let settings = Settings {
            data_dir: dir.clone(),
            ..Settings::default()
        };
        let metrics = Metrics::new("test");
        let mut health = Health::default();

        let start = tokio::time::Instant::now();
        let result = build(
            &db,
            &settings,
            &metrics,
            true,
            None,
            &Applied::new(settings.reload_every),
            &mut health,
        )
        .await;
        let took = start.elapsed();

        assert!(result.is_err());
        assert_eq!(metrics.postgres_down.get(), 1);
        assert!(
            !health.policies && !health.inventory,
            "an unreachable database is postgres_down, not a rejected configuration"
        );
        assert!(
            took <= PROBE_TIMEOUT + Duration::from_millis(100),
            "the reload waited {took:?} for an unreachable postgres"
        );
        drop(listener);
        std::fs::remove_dir_all(&dir).ok();
    }
}
