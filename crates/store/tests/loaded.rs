//! `proxyx_store::loaded` against real Postgres: git sync, reload with last-good
//! fallback, and the warmer role that never syncs.

mod support;

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

use common::config::Settings;
use common::metrics::Metrics;
use common::types::{IpState, OrgId};
use proxyx_store::loaded::{Loaded, sync_and_watch};
use tokio::sync::watch;
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

use support::{TestResult, fresh_db};

const ADAPTER: &str = r#"
[[adapter]]
id = "oxylabs_isp"
kind = "static"
subtype = "isp"
scheme = "http"
host = "disp.oxylabs.io"
user_file = "oxylabs_isp_user"
pass_file = "oxylabs_isp_pass"
user = "user-{base_user}"
pass = "{base_pass}"
"#;

fn policy(min_ready: u32) -> String {
    format!(
        "[[policy]]\nname = \"global\"\nregions = [\"fr\"]\nmin_ready = {min_ready}\nmax_ready = 40\n"
    )
}

fn entry(ip: &str, port: u16) -> String {
    format!(
        "[[entry]]\nprovider = \"oxylabs_isp\"\nsubtype = \"isp\"\nip = \"{ip}\"\n\
         host = \"disp.oxylabs.io\"\nport = {port}\nregion = \"fr\"\n"
    )
}

const BROKEN_ADAPTER: &str = "[[adapter]]\nid = ";

fn adapter_on_other_host() -> String {
    ADAPTER.replace("disp.oxylabs.io", "other.example")
}

/// A git policy file of the `route_class` scope for the oxylabs provider.
fn route_class(name: &str, min_ready: u32) -> String {
    format!(
        "[[policy]]\nname = \"{name}\"\nscope = \"route_class\"\nmatch = \"oxylabs_isp\"\nmin_ready = {min_ready}\n"
    )
}

fn two_entries() -> String {
    format!(
        "{}{}",
        entry("203.0.113.1", 8001),
        entry("203.0.113.2", 8002)
    )
}

fn doc(text: &str) -> policy::PolicyDoc {
    toml::from_str(text).expect("policy document")
}

/// Store `global` with `min_ready` the way the API does for `actor`.
async fn put_global(
    db: &proxyx_store::Db,
    min_ready: u32,
    actor: &str,
) -> Result<proxyx_store::PolicyPut, proxyx_store::StoreError> {
    let text =
        format!("name = \"global\"\nregions = [\"fr\"]\nmin_ready = {min_ready}\nmax_ready = 40\n");
    db.put_policies(&[doc(&text)], actor).await
}

async fn global_versions(db: &proxyx_store::Db) -> Result<usize, proxyx_store::StoreError> {
    Ok(db.policy_versions("global", "global").await?.len())
}

async fn policy_names(db: &proxyx_store::Db) -> Result<Vec<String>, proxyx_store::StoreError> {
    let mut names: Vec<String> = db
        .current_policies()
        .await?
        .into_iter()
        .map(|p| p.name)
        .collect();
    names.sort();
    Ok(names)
}

fn has_policy(r: &Running, name: &str) -> bool {
    r.rx.borrow()
        .snapshot
        .policies
        .iter()
        .any(|p| p.name == name)
}

struct Fixture {
    dir: PathBuf,
    settings: Settings,
}

impl Fixture {
    fn new() -> std::io::Result<Self> {
        let dir = std::env::temp_dir().join(format!("proxyx-loaded-it-{}", Uuid::new_v4()));
        for sub in [
            "data/adapters",
            "data/policies",
            "data/inventory",
            "secrets",
        ] {
            std::fs::create_dir_all(dir.join(sub))?;
        }
        std::fs::write(dir.join("secrets/oxylabs_isp_user"), "u")?;
        std::fs::write(dir.join("secrets/oxylabs_isp_pass"), "p")?;
        std::fs::write(dir.join("data/adapters/oxylabs_isp.toml"), ADAPTER)?;
        let settings = Settings {
            data_dir: dir.join("data"),
            secrets_dir: dir.join("secrets"),
            reload_every: Duration::from_secs(1),
            ..Settings::default()
        };
        Ok(Self { dir, settings })
    }

    /// A fixture whose data dir holds only the `global` policy.
    fn with_policy(min_ready: u32) -> std::io::Result<Self> {
        let f = Self::new()?;
        f.write("policies/global.toml", &policy(min_ready));
        Ok(f)
    }

    fn write(&self, rel: &str, text: &str) {
        std::fs::write(self.dir.join("data").join(rel), text).expect("write data file");
    }

    fn remove(&self, rel: &str) {
        std::fs::remove_file(self.dir.join("data").join(rel)).expect("remove data file");
    }

    fn data(&self) -> &Path {
        &self.settings.data_dir
    }
}

struct Running {
    rx: watch::Receiver<Arc<Loaded>>,
    metrics: Arc<Metrics>,
    cancel: CancellationToken,
}

impl Drop for Running {
    fn drop(&mut self) {
        self.cancel.cancel();
    }
}

async fn start(db: &proxyx_store::Db, f: &Fixture, sync_git: bool) -> anyhow::Result<Running> {
    let metrics = Arc::new(Metrics::new("test"));
    let cancel = CancellationToken::new();
    let rx = sync_and_watch(
        db.clone(),
        &f.settings,
        metrics.clone(),
        cancel.clone(),
        sync_git,
    )
    .await?;
    Ok(Running {
        rx,
        metrics,
        cancel,
    })
}

impl Running {
    fn min_ready(&self) -> u32 {
        self.rx
            .borrow()
            .policies
            .effective(&"any".parse::<OrgId>().expect("org"), None)
            .capacity
            .min_ready
    }

    fn failed(&self, source: &str) -> i64 {
        self.metrics
            .config_reload_failed
            .with_label_values(&[source])
            .get()
    }

    fn age(&self) -> f64 {
        self.metrics.snapshot_age_seconds.get()
    }

    fn state_of(&self, ip: &str) -> Option<IpState> {
        self.rx
            .borrow()
            .snapshot
            .inventory
            .iter()
            .find(|row| row.entry.ip.to_string() == ip)
            .map(|row| row.state)
    }

    async fn until(&self, what: &str, mut ok: impl FnMut(&Self) -> bool) {
        let deadline = Instant::now() + Duration::from_secs(15);
        while !ok(self) {
            assert!(Instant::now() < deadline, "timed out waiting for {what}");
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    }
}

#[tokio::test]
async fn the_first_load_syncs_git_into_postgres_as_gitops() -> TestResult {
    let Some((db, _)) = fresh_db("loaded_first").await? else {
        return Ok(());
    };
    let f = Fixture::with_policy(10)?;
    f.write("inventory/oxylabs_isp.toml", &two_entries());

    let run = start(&db, &f, true).await?;
    assert_eq!(run.min_ready(), 10);
    let loaded = run.rx.borrow().clone();
    assert_eq!(loaded.snapshot.inventory.len(), 2);
    assert!(loaded.adapters.get(&"oxylabs_isp".parse()?).is_some());
    let audit = db.audit_for("203.0.113.1", 5).await?;
    assert!(
        audit
            .iter()
            .any(|a| a.actor == "gitops" && a.action == "inventory.add"),
        "{audit:?}"
    );
    assert!(
        db.source_hash("policies").await?.is_some() && db.source_hash("inventory").await?.is_some()
    );
    assert_eq!(
        (
            run.failed("policies"),
            run.failed("inventory"),
            run.failed("adapters")
        ),
        (0, 0, 0)
    );
    assert_eq!(run.metrics.postgres_down.get(), 0);
    Ok(())
}

#[tokio::test]
async fn a_bad_policy_file_keeps_the_last_good_and_a_good_change_applies() -> TestResult {
    let Some((db, _)) = fresh_db("loaded_reload").await? else {
        return Ok(());
    };
    let f = Fixture::with_policy(10)?;
    let run = start(&db, &f, true).await?;
    assert_eq!(run.min_ready(), 10);

    // syntax error: the failure is reported, the served policies are unchanged
    f.write("policies/global.toml", "[[policy]\nname = ");
    run.until("the policy failure", |r| r.failed("policies") == 1)
        .await;
    assert_eq!(run.min_ready(), 10);
    // a set that parses but is invalid (min_ready above max_ready) is no better
    f.write("policies/global.toml", &policy(90));
    run.until("the invalid set to be refused", |r| {
        r.failed("policies") == 1
    })
    .await;
    tokio::time::sleep(Duration::from_millis(1_500)).await;
    assert_eq!(
        run.min_ready(),
        10,
        "a refused change never reaches Postgres or the served set"
    );
    assert_eq!(global_versions(&db).await?, 1);

    f.write("policies/global.toml", &policy(7));
    run.until("the good change", |r| r.min_ready() == 7).await;
    run.until("the failure to clear", |r| r.failed("policies") == 0)
        .await;
    assert_eq!(global_versions(&db).await?, 2);
    Ok(())
}

#[tokio::test]
async fn a_reload_that_finds_the_same_policies_keeps_their_records_and_a_change_replaces_them()
-> TestResult {
    let Some((db, _)) = fresh_db("loaded_reuse").await? else {
        return Ok(());
    };
    let f = Fixture::with_policy(10)?;
    let run = start(&db, &f, true).await?;
    let first = run.rx.borrow().clone();

    run.until("a quiet reload", |r| {
        r.rx.borrow().loaded_at > first.loaded_at
    })
    .await;
    let quiet = run.rx.borrow().clone();
    assert!(
        Arc::ptr_eq(&first.snapshot.policies, &quiet.snapshot.policies),
        "no policy changed: the records are not read and decoded again"
    );
    assert_eq!(run.min_ready(), 10);

    f.write("policies/global.toml", &policy(7));
    run.until("the change", |r| r.min_ready() == 7).await;
    let changed = run.rx.borrow().clone();
    assert!(!Arc::ptr_eq(
        &quiet.snapshot.policies,
        &changed.snapshot.policies
    ));
    Ok(())
}

#[tokio::test]
async fn a_broken_adapter_keeps_the_last_adapters_until_it_is_fixed() -> TestResult {
    let Some((db, _)) = fresh_db("loaded_adapters").await? else {
        return Ok(());
    };
    let f = Fixture::with_policy(10)?;
    let run = start(&db, &f, true).await?;
    let id = "oxylabs_isp".parse()?;

    f.write("adapters/oxylabs_isp.toml", BROKEN_ADAPTER);
    run.until("the adapter failure", |r| r.failed("adapters") == 1)
        .await;
    assert!(
        run.rx.borrow().adapters.get(&id).is_some(),
        "the last good adapters still serve"
    );

    f.write("adapters/oxylabs_isp.toml", &adapter_on_other_host());
    run.until("the fix to clear the failure", |r| {
        r.failed("adapters") == 0
    })
    .await;
    let host = run.rx.borrow().adapters.get(&id).map(|a| format!("{a:?}"));
    assert!(
        host.is_some_and(|d| d.contains("other.example")),
        "the fixed adapter replaced it"
    );
    Ok(())
}

#[tokio::test]
async fn first_load_fails_when_an_adapter_does_not_load() -> TestResult {
    let Some((db, _)) = fresh_db("loaded_firstfail").await? else {
        return Ok(());
    };
    let f = Fixture::with_policy(10)?;
    f.write("adapters/oxylabs_isp.toml", BROKEN_ADAPTER);
    let Err(err) = start(&db, &f, true).await else {
        panic!("there are no good adapters to fall back to");
    };
    assert!(format!("{err:#}").contains("adapters"), "{err:#}");
    Ok(())
}

#[tokio::test]
async fn removing_a_policy_from_git_deactivates_it_and_operator_policies_stay() -> TestResult {
    let Some((db, _)) = fresh_db("loaded_removed").await? else {
        return Ok(());
    };
    let f = Fixture::with_policy(10)?;
    f.write("policies/fr-web.toml", &route_class("fr-web", 5));
    let op = doc("name = \"org-acme\"\nscope = \"org\"\nmatch = \"acme\"\nmin_ready = 3\n");
    db.put_policies(&[op], "operator").await?;
    let run = start(&db, &f, true).await?;
    assert_eq!(policy_names(&db).await?, ["fr-web", "global", "org-acme"]);

    f.remove("policies/fr-web.toml");
    run.until("fr-web to be deactivated", |r| {
        r.rx.borrow()
            .snapshot
            .policies
            .iter()
            .all(|p| p.name != "fr-web")
    })
    .await;
    assert_eq!(
        policy_names(&db).await?,
        ["global", "org-acme"],
        "the operator's org policy is not git's to remove"
    );
    assert_eq!(
        db.policy_versions("route_class", "fr-web").await?.len(),
        1,
        "history stays"
    );
    Ok(())
}

/// api D3, git side: rows are keyed by (scope, name), so a git policy that
/// shares a name with an operator policy of another scope is refused before
/// anything is written (two rows of one name make the set unloadable).
#[tokio::test]
async fn a_git_policy_named_like_an_operator_policy_of_another_scope_is_refused() -> TestResult {
    let Some((db, _)) = fresh_db("loaded_samename").await? else {
        return Ok(());
    };
    let f = Fixture::with_policy(10)?;
    let op = doc("name = \"global\"\nscope = \"org\"\nmatch = \"acme\"\nmin_ready = 3\n");
    db.put_policies(&[op], "operator").await?;

    assert!(start(&db, &f, true).await.is_err(), "the set is invalid");
    let rows = db.current_policies().await?;
    assert!(
        rows.iter().all(|r| r.actor != "gitops"),
        "nothing of git was stored: {rows:?}"
    );
    Ok(())
}

#[tokio::test]
async fn inventory_files_retire_removed_ips_and_an_emptied_file_retires_its_provider() -> TestResult
{
    let Some((db, _)) = fresh_db("loaded_inventory").await? else {
        return Ok(());
    };
    let f = Fixture::with_policy(10)?;
    f.write("inventory/oxylabs_isp.toml", &two_entries());
    let run = start(&db, &f, true).await?;
    assert_eq!(run.state_of("203.0.113.2"), Some(IpState::Candidate));

    f.write("inventory/oxylabs_isp.toml", &entry("203.0.113.1", 8001));
    run.until(".2 to be retired", |r| {
        r.state_of("203.0.113.2") == Some(IpState::Retired)
    })
    .await;
    assert_eq!(run.state_of("203.0.113.1"), Some(IpState::Candidate));

    // no entries left: the file named after the provider still owns it
    f.write("inventory/oxylabs_isp.toml", "entry = []\n");
    run.until(".1 to be retired", |r| {
        r.state_of("203.0.113.1") == Some(IpState::Retired)
    })
    .await;

    // a duplicate IP across files is refused as a whole: nothing changes
    f.write("inventory/oxylabs_isp.toml", &entry("203.0.113.1", 8001));
    f.write("inventory/second.toml", &entry("203.0.113.1", 8009));
    run.until("the duplicate to be refused", |r| {
        r.failed("inventory") == 1
    })
    .await;
    assert_eq!(run.state_of("203.0.113.1"), Some(IpState::Retired));
    f.remove("inventory/second.toml");
    run.until("the revive", |r| {
        r.state_of("203.0.113.1") == Some(IpState::Candidate)
    })
    .await;
    assert_eq!(run.failed("inventory"), 0);
    Ok(())
}

/// Deleting a provider's file retires its IPs like emptying it,
/// and a provider without an adapter is refused as a whole. So is
/// a `rental_end` that is not a date.
#[tokio::test]
async fn a_deleted_inventory_file_retires_its_ips_and_bad_inventory_is_refused() -> TestResult {
    let Some((db, _)) = fresh_db("loaded_inv_removed").await? else {
        return Ok(());
    };
    let f = Fixture::with_policy(10)?;
    f.write("inventory/oxylabs_isp.toml", &entry("203.0.113.1", 8001));
    let run = start(&db, &f, true).await?;
    assert_eq!(run.state_of("203.0.113.1"), Some(IpState::Candidate));

    // a provider without an adapter: nothing of the file is stored
    f.write(
        "inventory/ghost.toml",
        &entry("203.0.113.9", 8009).replace("oxylabs_isp", "ghost"),
    );
    run.until("the ghost provider to be refused", |r| {
        r.failed("inventory") == 1
    })
    .await;
    assert_eq!(run.state_of("203.0.113.9"), None);
    f.remove("inventory/ghost.toml");

    // a rental_end that is not a date: refused, nothing changes
    let dated = |end: &str| format!("{}rental_end = \"{end}\"\n", entry("203.0.113.1", 8001));
    f.write("inventory/oxylabs_isp.toml", &dated("2026-02-30"));
    run.until("the bad date to be refused", |r| r.failed("inventory") == 1)
        .await;
    f.write("inventory/oxylabs_isp.toml", &dated("2030-02-28"));
    run.until("the good date to apply", |r| r.failed("inventory") == 0)
        .await;

    // the file is deleted: the IP is retired
    f.remove("inventory/oxylabs_isp.toml");
    run.until(".1 to be retired", |r| {
        r.state_of("203.0.113.1") == Some(IpState::Retired)
    })
    .await;
    Ok(())
}

#[tokio::test]
async fn the_warmer_role_reads_postgres_and_never_applies_git() -> TestResult {
    let Some((db, _)) = fresh_db("loaded_warmer").await? else {
        return Ok(());
    };
    let f = Fixture::with_policy(10)?;
    // the gateway seeds Postgres, then the warmer starts on the same data dir
    drop(start(&db, &f, true).await?);
    f.write("policies/global.toml", &policy(7));
    f.write("inventory/oxylabs_isp.toml", &entry("203.0.113.1", 8001));

    let warmer = start(&db, &f, false).await?;
    tokio::time::sleep(Duration::from_millis(2_500)).await;
    assert_eq!(
        warmer.min_ready(),
        10,
        "git changes are the gateway's to apply"
    );
    assert!(warmer.rx.borrow().snapshot.inventory.is_empty());
    assert!(
        warmer
            .rx
            .borrow()
            .adapters
            .get(&"oxylabs_isp".parse()?)
            .is_some(),
        "adapters still come from the files"
    );
    assert_eq!(f.data().join("policies").read_dir()?.count(), 1);

    // once the gateway applies it, the warmer sees it on its next reload
    let gateway = start(&db, &f, true).await?;
    assert_eq!(gateway.min_ready(), 7);
    warmer
        .until("the warmer to follow Postgres", |r| {
            r.min_ready() == 7 && r.rx.borrow().snapshot.inventory.len() == 1
        })
        .await;
    Ok(())
}

#[tokio::test]
async fn a_bad_probe_targets_file_keeps_the_last_good_and_a_good_one_applies() -> TestResult {
    let Some((db, _)) = fresh_db("loaded_probe_targets").await? else {
        return Ok(());
    };
    let f = Fixture::with_policy(10)?;
    f.write("probe-targets.toml", "global = [\"https://a.example/\"]\n");
    let run = start(&db, &f, true).await?;
    let hosts = |r: &Running| -> Vec<String> {
        r.rx.borrow()
            .probe_targets
            .for_region(&"fr".parse().expect("region"))
            .iter()
            .map(|u| u.host_str().unwrap_or_default().to_owned())
            .collect()
    };
    assert_eq!(hosts(&run), ["a.example"]);

    f.write("probe-targets.toml", "global = [\"ftp://a.example/\"]\n");
    run.until("the probe targets failure", |r| {
        r.failed("probe_targets") == 1
    })
    .await;
    assert_eq!(
        hosts(&run),
        ["a.example"],
        "the last good pages still serve"
    );

    f.write("probe-targets.toml", "global = [\"https://b.example/\"]\n");
    run.until("the fix", |r| hosts(r) == ["b.example"]).await;
    run.until("the failure to clear", |r| r.failed("probe_targets") == 0)
        .await;
    Ok(())
}

/// warmer D-W14: a reload that falls back to the last good adapters or probe
/// targets is not a fresh load, so `snapshot_age_seconds` keeps growing while
/// the file is broken and drops back once it loads again. Runs with a broken
/// and a fixed form of `rel`, already holding a good form.
async fn age_keeps_growing_while_a_source_is_rejected(
    name: &str,
    rel: &str,
    source: &str,
    broken: &str,
    fixed: &str,
) -> TestResult {
    let Some((db, _)) = fresh_db(name).await? else {
        return Ok(());
    };
    let f = Fixture::with_policy(10)?;
    f.write("probe-targets.toml", "global = [\"https://a.example/\"]\n");
    let run = start(&db, &f, true).await?;
    let loaded = Instant::now();

    f.write(rel, broken);
    run.until("the failure with a measured age", |r| {
        r.failed(source) == 1 && r.age() > 0.0
    })
    .await;
    let first = run.age();

    // Ticks are a second apart: a fresh load per tick would reset the age.
    let mut floor = first;
    run.until("the age to keep growing", |r| {
        let age = r.age();
        assert!(age >= floor, "the age went back from {floor} to {age}");
        floor = age;
        age >= first + 1.5
    })
    .await;
    // The age is set once per tick, so it lags the clock by about one tick.
    assert!(
        run.age() + 2.0 >= loaded.elapsed().as_secs_f64(),
        "the age {} is below the time since the last good load",
        run.age()
    );
    assert_eq!(run.failed(source), 1, "the failure stays raised");

    f.write(rel, fixed);
    run.until("the fix to clear the failure and reset the age", |r| {
        r.failed(source) == 0 && r.age() < 1.0
    })
    .await;
    Ok(())
}

#[tokio::test]
async fn the_snapshot_age_keeps_growing_while_the_adapters_are_rejected() -> TestResult {
    age_keeps_growing_while_a_source_is_rejected(
        "loaded_age_adapters",
        "adapters/oxylabs_isp.toml",
        "adapters",
        BROKEN_ADAPTER,
        &adapter_on_other_host(),
    )
    .await
}

#[tokio::test]
async fn the_snapshot_age_keeps_growing_while_the_probe_targets_are_rejected() -> TestResult {
    age_keeps_growing_while_a_source_is_rejected(
        "loaded_age_probe_targets",
        "probe-targets.toml",
        "probe_targets",
        "global = [\"ftp://a.example/\"]\n",
        "global = [\"https://b.example/\"]\n",
    )
    .await
}

/// Any git policy file change rewrote every git policy and overwrote an
/// operator's API change to `global`.
#[tokio::test]
async fn a_git_change_to_another_policy_keeps_an_operators_api_change() -> TestResult {
    let Some((db, _)) = fresh_db("loaded_bo1").await? else {
        return Ok(());
    };
    let f = Fixture::with_policy(5)?;
    let run = start(&db, &f, true).await?;
    assert_eq!(run.min_ready(), 5);

    put_global(&db, 9, "ops@example.com").await?;
    run.until("the operator change", |r| r.min_ready() == 9)
        .await;
    assert_eq!(global_versions(&db).await?, 2);

    // an unrelated file, then a comment-only edit of global.toml
    f.write("policies/route-other.toml", &route_class("route-other", 4));
    run.until("the new policy", |r| has_policy(r, "route-other"))
        .await;
    f.write(
        "policies/global.toml",
        &format!("# a comment\n{}", policy(5)),
    );
    tokio::time::sleep(Duration::from_millis(2_500)).await;
    assert_eq!(run.min_ready(), 9, "the operator's change is kept");
    assert_eq!(global_versions(&db).await?, 2, "nothing was rewritten");

    // git changing the same policy wins, and the audit row names who lost
    f.write("policies/global.toml", &policy(6));
    run.until("git to win", |r| r.min_ready() == 6).await;
    let audit = db.audit_for("global/global", 10).await?;
    let put = audit
        .iter()
        .find(|a| a.action == "policy.put" && a.actor == "gitops" && a.detail["version"] == 3)
        .ok_or("no git write")?;
    assert_eq!(put.detail["replaced"]["actor"], "ops@example.com");
    Ok(())
}

/// Git side: with the API route_class gone, the git one applies.
#[tokio::test]
async fn a_git_route_class_applies_once_the_api_one_for_the_provider_is_deleted() -> TestResult {
    let Some((db, _)) = fresh_db("loaded_bo6").await? else {
        return Ok(());
    };
    let f = Fixture::with_policy(5)?;
    f.write("policies/fr-web.toml", &route_class("fr-web", 3));
    put_global(&db, 5, "gitops").await?;
    db.put_policies(
        &[doc(
            "name = \"api-rc\"\nscope = \"route_class\"\nmatch = \"oxylabs_isp\"\nmin_ready = 2\n",
        )],
        "ops@example.com",
    )
    .await?;
    let run = start(&db, &f, true).await?;
    run.until("the duplicate to be refused", |r| r.failed("policies") == 1)
        .await;
    assert!(!has_policy(&run, "fr-web"));

    assert!(
        db.deactivate_policy("route_class", "api-rc", "ops@example.com")
            .await?
    );
    run.until("git's route_class", |r| has_policy(r, "fr-web"))
        .await;
    run.until("the failure to clear", |r| r.failed("policies") == 0)
        .await;
    Ok(())
}

/// An operator who deletes their override of a git
/// policy gets git's version back at the next reload.
#[tokio::test]
async fn deleting_an_api_override_of_a_git_policy_restores_git_s_version() -> TestResult {
    let Some((db, _)) = fresh_db("loaded_restore").await? else {
        return Ok(());
    };
    let f = Fixture::with_policy(5)?;
    let run = start(&db, &f, true).await?;
    put_global(&db, 9, "ops@example.com").await?;
    run.until("the override", |r| r.min_ready() == 9).await;

    db.deactivate_policy("global", "global", "ops@example.com")
        .await?;
    run.until("git's version back", |r| {
        has_policy(r, "global") && r.min_ready() == 5
    })
    .await;
    Ok(())
}

/// Two gateways with different trees rewrote the stored policy at every
/// reload (+16 versions in 40 s).
#[tokio::test]
async fn gateways_with_different_policy_trees_do_not_fight_over_the_stored_policy() -> TestResult {
    let Some((db, _)) = fresh_db("loaded_bo3").await? else {
        return Ok(());
    };
    let (one, two) = (Fixture::with_policy(5)?, Fixture::with_policy(6)?);
    let first = start(&db, &one, true).await?;
    assert_eq!(first.min_ready(), 5);
    let second = start(&db, &two, true).await?;
    tokio::time::sleep(Duration::from_millis(4_500)).await;

    assert_eq!(
        global_versions(&db).await?,
        2,
        "each tree was written once, at most"
    );
    first
        .until("both to serve the same policy", |r| r.min_ready() == 6)
        .await;
    assert_eq!(second.min_ready(), 6);
    Ok(())
}

/// A gateway that restarted with an older tree overwrote the newer
/// policy (min_ready 7 to 6) while the gateway that runs the newer tree only
/// logged a warning.
#[tokio::test]
async fn a_restarted_gateway_with_an_older_tree_does_not_overwrite_a_newer_one() -> TestResult {
    let Some((db, _)) = fresh_db("loaded_bo9").await? else {
        return Ok(());
    };
    let (old, new) = (Fixture::with_policy(6)?, Fixture::with_policy(7)?);
    // the old tree was applied, then replaced by the new one
    let first = start(&db, &old, true).await?;
    assert_eq!(first.min_ready(), 6);
    drop(first);
    let newer = start(&db, &new, true).await?;
    assert_eq!(newer.min_ready(), 7);
    let versions = global_versions(&db).await?;

    // an old-tree gateway starts while the new-tree one is alive
    let restarted = start(&db, &old, true).await?;
    tokio::time::sleep(Duration::from_millis(2_500)).await;
    assert_eq!(
        global_versions(&db).await?,
        versions,
        "the stale gateway wrote nothing"
    );
    assert_eq!(restarted.min_ready(), 7, "it serves what is stored");
    assert_eq!(newer.min_ready(), 7);

    // with no gateway left that runs the new tree, the old one is the only
    // truth (a rollback)
    drop(newer);
    restarted
        .until("the rollback to apply", |r| r.min_ready() == 6)
        .await;
    Ok(())
}

/// D4-2: a gateway that applied its tree earlier in the same process did not
/// roll back when the gateway that replaced it stopped, so the cluster stayed
/// on a tree that no gateway ran.
#[tokio::test]
async fn a_gateway_that_applied_its_tree_earlier_rolls_back_when_the_newer_one_stops() -> TestResult
{
    let Some((db, _)) = fresh_db("loaded_d42").await? else {
        return Ok(());
    };
    let (older, newer) = (Fixture::with_policy(6)?, Fixture::with_policy(7)?);
    let first = start(&db, &older, true).await?;
    assert_eq!(first.min_ready(), 6);
    let second = start(&db, &newer, true).await?;
    first
        .until("the newer tree to be stored", |r| r.min_ready() == 7)
        .await;

    drop(second);
    first
        .until("the rollback to apply", |r| r.min_ready() == 6)
        .await;
    Ok(())
}

/// A gateway that stops gracefully removes its mark at once, so a
/// restart with the older tree does not wait for the mark to go stale.
#[tokio::test]
async fn a_gateway_that_stops_removes_its_policy_tree_mark() -> TestResult {
    let Some((db, raw)) = fresh_db("loaded_n33").await? else {
        return Ok(());
    };
    let (old, new) = (Fixture::with_policy(6)?, Fixture::with_policy(7)?);
    let first = start(&db, &old, true).await?;
    let newer = start(&db, &new, true).await?;
    let marks = || async { raw.int("SELECT count(*) FROM gateway_trees", &[]).await };
    assert_eq!(marks().await?, 2);

    drop(newer);
    let deadline = Instant::now() + Duration::from_secs(5);
    while marks().await? != 1 {
        assert!(Instant::now() < deadline, "the mark outlived its gateway");
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    drop(first);
    Ok(())
}

/// Git's later edit to the value an operator had already applied was
/// not recorded as git's, so the operator's next change was replaced by an
/// unrelated git change.
#[tokio::test]
async fn a_git_edit_to_the_operators_value_is_recorded_as_git_s() -> TestResult {
    let Some((db, _)) = fresh_db("loaded_bo10").await? else {
        return Ok(());
    };
    let f = Fixture::with_policy(6)?;
    let run = start(&db, &f, true).await?;
    assert_eq!(run.min_ready(), 6);
    put_global(&db, 5, "ops@example.com").await?;
    run.until("the operator change", |r| r.min_ready() == 5)
        .await;

    // git catches up with the operator's value
    f.write("policies/global.toml", &policy(5));
    run.until("git's write", |r| {
        r.rx.borrow()
            .snapshot
            .policies
            .iter()
            .any(|p| p.name == "global" && p.actor == "gitops" && p.version == 3)
    })
    .await;

    // the operator changes it again; an unrelated git file must leave that alone
    put_global(&db, 9, "ops@example.com").await?;
    run.until("the second operator change", |r| r.min_ready() == 9)
        .await;
    f.write("policies/route-other.toml", &route_class("route-other", 4));
    run.until("the new policy", |r| has_policy(r, "route-other"))
        .await;
    assert_eq!(run.min_ready(), 9, "the operator's change is kept");
    Ok(())
}
