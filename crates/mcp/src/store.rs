//! The on-disk state of the MCP server: pending changes and their approvals, secrets written
//! for out-of-band use, and the registry of sessions it created.
//!
//! Everything lives under one state directory (`0700`), every file is `0600`. Decisions and
//! consumption lock the change file before checking its state, then create their marker with
//! `create_new`, so transitions are atomic even across the approving CLI and server processes.

use std::fs::{self, File, OpenOptions};
use std::io::{self, Write as _};
use std::path::{Path, PathBuf};

use anyhow::{Context as _, bail};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::audit::{canonical_json, sha256_hex};

/// A change waiting for approval, or applied.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Change {
    pub id: String,
    /// The mutating tool the change calls.
    pub action: String,
    /// Normalized arguments. Session UUIDs stay private; other credentials are references.
    pub arguments: Value,
    /// SHA-256 of the action and arguments. An approval is bound to it.
    pub digest: String,
    pub summary: String,
    pub diff: Value,
    pub warnings: Vec<String>,
    pub created_at: i64,
    pub expires_at: i64,
    pub requested_by: Value,
    pub engagement: Option<String>,
}

/// Where a change stands.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum Status {
    /// Waiting for `apply_config_change` (and, when required, approval).
    Proposed,
    Approved {
        by: String,
        at: i64,
    },
    Rejected {
        by: String,
        at: i64,
    },
    Applied {
        at: i64,
    },
    Expired,
}

impl Status {
    pub const fn name(&self) -> &'static str {
        match self {
            Status::Proposed => "proposed",
            Status::Approved { .. } => "approved",
            Status::Rejected { .. } => "rejected",
            Status::Applied { .. } => "applied",
            Status::Expired => "expired",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Decision {
    by: String,
    at: i64,
    digest: String,
    note: Option<String>,
}

/// The state directory.
#[derive(Debug, Clone)]
pub struct Store {
    root: PathBuf,
}

/// Unix seconds.
pub fn now_secs() -> i64 {
    time::OffsetDateTime::now_utc().unix_timestamp()
}

/// The digest an approval binds to.
pub fn change_digest(action: &str, arguments: &Value) -> String {
    sha256_hex(&format!("{action}\u{1f}{}", canonical_json(arguments)))
}

/// `chg_` and 20 lowercase hex characters.
pub fn is_change_id(text: &str) -> bool {
    text.strip_prefix("chg_").is_some_and(|rest| {
        rest.len() == 20 && rest.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
    })
}

pub fn new_change_id() -> String {
    let uuid = uuid::Uuid::new_v4().simple().to_string();
    format!("chg_{}", &uuid[..20])
}

fn private_dir(path: &Path) -> io::Result<()> {
    fs::create_dir_all(path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    }
    Ok(())
}

fn private_file(path: &Path, create_new: bool) -> io::Result<File> {
    let mut options = OpenOptions::new();
    options.write(true);
    if create_new {
        options.create_new(true);
    } else {
        options.create(true).truncate(true);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(0o600);
    }
    options.open(path)
}

impl Store {
    /// # Errors
    /// When the directory cannot be created.
    pub fn open(root: PathBuf) -> io::Result<Self> {
        private_dir(&root)?;
        private_dir(&root.join("changes"))?;
        Ok(Self { root })
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    fn changes(&self) -> PathBuf {
        self.root.join("changes")
    }

    fn path(&self, id: &str, suffix: &str) -> PathBuf {
        self.changes().join(format!("{id}.{suffix}"))
    }

    /// Store a new change.
    ///
    /// # Errors
    /// When the file cannot be written.
    pub fn create(&self, change: &Change) -> io::Result<()> {
        let mut file = private_file(&self.path(&change.id, "json"), true)?;
        file.write_all(&serde_json::to_vec_pretty(change).map_err(io::Error::other)?)?;
        file.flush()
    }

    /// Load a change.
    ///
    /// # Errors
    /// When the id is malformed, the change is unknown or its file is damaged.
    pub fn load(&self, id: &str) -> anyhow::Result<Change> {
        if !is_change_id(id) {
            bail!("{id:?} is not a change id (chg_ and 20 hex characters)");
        }
        let text = fs::read_to_string(self.path(id, "json"))
            .map_err(|_| anyhow::anyhow!("no change {id}"))?;
        let change: Change =
            serde_json::from_str(&text).with_context(|| format!("change {id} is damaged"))?;
        if change.id != id || change.digest != change_digest(&change.action, &change.arguments) {
            bail!("change {id} was edited after it was written");
        }
        Ok(change)
    }

    fn decision(&self, id: &str, suffix: &str) -> Option<Decision> {
        let text = fs::read_to_string(self.path(id, suffix)).ok()?;
        serde_json::from_str(&text).ok()
    }

    fn lock_change(&self, id: &str) -> anyhow::Result<File> {
        if !is_change_id(id) {
            bail!("{id:?} is not a change id (chg_ and 20 hex characters)");
        }
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .open(self.path(id, "json"))
            .with_context(|| format!("cannot lock change {id}"))?;
        file.lock()?;
        Ok(file)
    }

    /// The status of `change` now.
    pub fn status(&self, change: &Change) -> Status {
        if self.path(&change.id, "applied").exists() {
            let at = self
                .decision(&change.id, "applied")
                .map_or(0, |decision| decision.at);
            return Status::Applied { at };
        }
        if let Some(decision) = self.decision(&change.id, "rejected") {
            return Status::Rejected {
                by: decision.by,
                at: decision.at,
            };
        }
        if now_secs() >= change.expires_at {
            return Status::Expired;
        }
        if let Some(decision) = self.decision(&change.id, "approved")
            && decision.digest == change.digest
        {
            return Status::Approved {
                by: decision.by,
                at: decision.at,
            };
        }
        Status::Proposed
    }

    fn decide(
        &self,
        id: &str,
        suffix: &str,
        by: &str,
        note: Option<&str>,
    ) -> anyhow::Result<Change> {
        let _lock = self.lock_change(id)?;
        let change = self.load(id)?;
        match self.status(&change) {
            Status::Applied { .. } => bail!("change {id} was already applied"),
            Status::Rejected { .. } => bail!("change {id} was already rejected"),
            Status::Approved { .. } if suffix == "approved" => {
                bail!("change {id} is already approved")
            }
            Status::Expired => bail!("change {id} expired; propose it again"),
            Status::Proposed | Status::Approved { .. } => {}
        }
        let decision = Decision {
            by: by.to_owned(),
            at: now_secs(),
            digest: change.digest.clone(),
            note: note.map(str::to_owned),
        };
        let mut file = private_file(&self.path(id, suffix), true)
            .map_err(|_| anyhow::anyhow!("change {id} already has a {suffix} decision"))?;
        file.write_all(&serde_json::to_vec_pretty(&decision)?)?;
        file.flush()?;
        Ok(change)
    }

    /// Approve a change as `by`.
    ///
    /// # Errors
    /// When the change is unknown, expired, applied, rejected or already approved.
    pub fn approve(&self, id: &str, by: &str, note: Option<&str>) -> anyhow::Result<Change> {
        self.decide(id, "approved", by, note)
    }

    /// Reject a change as `by`.
    ///
    /// # Errors
    /// When the change is unknown, expired, applied or already rejected.
    pub fn reject(&self, id: &str, by: &str, note: Option<&str>) -> anyhow::Result<Change> {
        self.decide(id, "rejected", by, note)
    }

    /// Mark an unexpired, unrejected change applied. Atomic: only one caller ever succeeds.
    ///
    /// # Errors
    /// When the change is unknown, edited, expired, rejected or already applied.
    pub fn consume(&self, change: &Change) -> anyhow::Result<()> {
        let _lock = self.lock_change(&change.id)?;
        let stored = self.load(&change.id)?;
        if stored.digest != change.digest {
            bail!("change {} was edited after it was loaded", change.id);
        }
        match self.status(&stored) {
            Status::Applied { .. } => bail!("change {} was already applied", change.id),
            Status::Rejected { .. } => bail!("change {} was already rejected", change.id),
            Status::Expired => bail!("change {} expired; propose it again", change.id),
            Status::Proposed | Status::Approved { .. } => {}
        }
        let decision = Decision {
            by: "apply".to_owned(),
            at: now_secs(),
            digest: change.digest.clone(),
            note: None,
        };
        let mut file = private_file(&self.path(&change.id, "applied"), true)
            .map_err(|_| anyhow::anyhow!("change {} was already applied", change.id))?;
        file.write_all(&serde_json::to_vec(&decision)?)?;
        file.flush()?;
        Ok(())
    }

    /// Every stored change with its status, newest first.
    pub fn list(&self) -> Vec<(Change, Status)> {
        let Ok(entries) = fs::read_dir(self.changes()) else {
            return Vec::new();
        };
        let mut out: Vec<(Change, Status)> = entries
            .filter_map(Result::ok)
            .filter_map(|entry| {
                let name = entry.file_name().into_string().ok()?;
                let id = name.strip_suffix(".json")?;
                let change = self.load(id).ok()?;
                let status = self.status(&change);
                Some((change, status))
            })
            .collect();
        out.sort_by_key(|row| std::cmp::Reverse(row.0.created_at));
        out
    }

    /// Write `content` to a new `0600` file under `secrets/` and return its path. Used when a
    /// secret must not travel through the model's context.
    ///
    /// # Errors
    /// When the file cannot be created.
    pub fn write_secret(&self, label: &str, content: &str) -> io::Result<PathBuf> {
        let dir = self.root.join("secrets");
        private_dir(&dir)?;
        let safe: String = label
            .chars()
            .map(|c| {
                if c.is_ascii_alphanumeric() || c == '-' || c == '_' {
                    c
                } else {
                    '_'
                }
            })
            .take(64)
            .collect();
        let path = dir.join(format!(
            "{safe}-{}.secret",
            &uuid::Uuid::new_v4().simple().to_string()[..8]
        ));
        let mut file = private_file(&path, true)?;
        file.write_all(content.as_bytes())?;
        file.flush()?;
        Ok(path)
    }

    fn registry(&self) -> PathBuf {
        self.root.join("sessions.jsonl")
    }

    /// Remember a session this server created.
    ///
    /// # Errors
    /// When the registry cannot be written.
    pub fn register_session(&self, record: &Value) -> io::Result<()> {
        let mut options = OpenOptions::new();
        options.create(true).append(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt as _;
            options.mode(0o600);
        }
        let mut file = options.open(self.registry())?;
        let mut line = serde_json::to_vec(record).map_err(io::Error::other)?;
        line.push(b'\n');
        file.write_all(&line)
    }

    /// The most recent `count` registered sessions, newest first.
    pub fn recent_sessions(&self, count: usize) -> Vec<Value> {
        let Ok(text) = fs::read_to_string(self.registry()) else {
            return Vec::new();
        };
        let mut records: Vec<Value> = text
            .lines()
            .filter_map(|line| serde_json::from_str(line).ok())
            .collect();
        records.reverse();
        records.truncate(count);
        records
    }
}

/// A change as a tool result (no arguments: they are in the audit log and the file).
pub fn change_view(change: &Change, status: &Status) -> Value {
    json!({
        "change_id": change.id,
        "action": change.action,
        "status": status.name(),
        "decided_by": match status {
            Status::Approved { by, .. } | Status::Rejected { by, .. } => json!(by),
            _ => Value::Null,
        },
        "summary": change.summary,
        "created_at": change.created_at,
        "expires_at": change.expires_at,
        "requested_by": change.requested_by,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn store() -> Store {
        let dir = std::env::temp_dir().join(format!("proxyx-mcp-store-{}", uuid::Uuid::new_v4()));
        Store::open(dir).expect("open store")
    }

    fn change(store: &Store, ttl: i64) -> Change {
        let arguments = json!({"org": "acme", "requests_per_minute": 600});
        let change = Change {
            id: new_change_id(),
            action: "set_org_rate_limit".into(),
            digest: change_digest("set_org_rate_limit", &arguments),
            arguments,
            summary: "set limits".into(),
            diff: json!({}),
            warnings: vec![],
            created_at: now_secs(),
            expires_at: now_secs() + ttl,
            requested_by: json!({}),
            engagement: None,
        };
        store.create(&change).expect("create");
        change
    }

    #[test]
    fn approval_is_single_use_and_bound_to_the_digest() {
        let store = store();
        let change = change(&store, 3600);
        assert_eq!(store.status(&change), Status::Proposed);
        store
            .approve(&change.id, "alice", Some("ok"))
            .expect("approve");
        assert!(matches!(store.status(&change), Status::Approved { ref by, .. } if by == "alice"));
        assert!(store.approve(&change.id, "bob", None).is_err());
        store.consume(&change).expect("first apply");
        assert!(store.consume(&change).is_err(), "a change applies once");
        assert!(matches!(store.status(&change), Status::Applied { .. }));
    }

    #[test]
    fn edited_changes_and_bad_ids_are_refused() {
        let store = store();
        let change = change(&store, 3600);
        let path = store
            .root()
            .join("changes")
            .join(format!("{}.json", change.id));
        let text = fs::read_to_string(&path)
            .expect("read")
            .replace("600", "6000000");
        fs::write(&path, text).expect("edit");
        assert!(store.load(&change.id).is_err());
        assert!(store.load("../../etc/passwd").is_err());
        assert!(store.load("chg_zzzz").is_err());
    }

    #[test]
    fn expiry_and_rejection() {
        let store = store();
        let expired = change(&store, -5);
        assert_eq!(store.status(&expired), Status::Expired);
        assert!(store.approve(&expired.id, "alice", None).is_err());
        let other = change(&store, 3600);
        store.reject(&other.id, "alice", None).expect("reject");
        assert!(matches!(store.status(&other), Status::Rejected { .. }));
        assert_eq!(store.list().len(), 2);
    }

    #[test]
    fn approved_changes_expire_at_the_deadline() {
        let store = store();
        let mut change = change(&store, 3600);
        store.approve(&change.id, "alice", None).expect("approve");
        assert!(matches!(store.status(&change), Status::Approved { .. }));

        change.expires_at = now_secs();
        fs::write(
            store.path(&change.id, "json"),
            serde_json::to_vec(&change).expect("serialize expired change"),
        )
        .expect("expire change");

        assert_eq!(store.status(&change), Status::Expired);
        assert_eq!(store.list()[0].1, Status::Expired);
        assert!(store.approve(&change.id, "bob", None).is_err());
    }

    #[test]
    fn consumption_rechecks_expiry_after_approval() {
        let store = store();
        let change = change(&store, 3600);
        store.approve(&change.id, "alice", None).expect("approve");
        assert!(matches!(store.status(&change), Status::Approved { .. }));

        let mut expired = change.clone();
        expired.expires_at = now_secs();
        fs::write(
            store.path(&change.id, "json"),
            serde_json::to_vec(&expired).expect("serialize expired change"),
        )
        .expect("expire change");

        let error = store.consume(&change).expect_err("expiry prevents apply");
        assert!(error.to_string().contains("expired"));
        assert!(!store.path(&change.id, "applied").exists());
        assert_eq!(store.status(&expired), Status::Expired);
    }

    #[test]
    fn approved_changes_can_be_rejected_before_consumption() {
        let store = store();
        let mut change = change(&store, 3600);
        store.approve(&change.id, "alice", None).expect("approve");
        store
            .reject(&change.id, "bob", Some("cancel approval"))
            .expect("reject approved change");
        let rejected = store.status(&change);
        assert!(matches!(&rejected, Status::Rejected { by, .. } if by == "bob"));
        assert!(store.consume(&change).is_err());
        assert!(!store.path(&change.id, "applied").exists());
        assert!(store.approve(&change.id, "alice", None).is_err());
        assert!(store.reject(&change.id, "alice", None).is_err());

        change.expires_at = now_secs() - 1;
        assert_eq!(store.status(&change), rejected);
    }

    #[test]
    fn applied_changes_stay_applied_after_expiry() {
        let store = store();
        let mut change = change(&store, 3600);
        store.approve(&change.id, "alice", None).expect("approve");
        store.consume(&change).expect("apply");
        let applied = store.status(&change);
        assert!(matches!(applied, Status::Applied { .. }));

        change.expires_at = now_secs() - 1;
        assert_eq!(store.status(&change), applied);
        assert!(store.approve(&change.id, "bob", None).is_err());
        assert!(store.reject(&change.id, "bob", None).is_err());
        assert!(store.consume(&change).is_err());
    }

    #[test]
    fn concurrent_consumption_remains_single_use() {
        let store = store();
        let change = change(&store, 3600);
        store.approve(&change.id, "alice", None).expect("approve");
        let barrier = std::sync::Arc::new(std::sync::Barrier::new(2));
        let results = std::thread::scope(|scope| {
            let handles: Vec<_> = (0..2)
                .map(|_| {
                    let barrier = std::sync::Arc::clone(&barrier);
                    let store = &store;
                    let change = &change;
                    scope.spawn(move || {
                        barrier.wait();
                        store.consume(change)
                    })
                })
                .collect();
            handles
                .into_iter()
                .map(|handle| handle.join().expect("consumer"))
                .collect::<Vec<_>>()
        });
        assert_eq!(results.iter().filter(|result| result.is_ok()).count(), 1);
        assert!(matches!(store.status(&change), Status::Applied { .. }));
    }

    #[test]
    fn secrets_and_registry_are_private() {
        let store = store();
        let path = store
            .write_secret("org key/acme", "ak_secretvalue")
            .expect("secret");
        assert_eq!(fs::read_to_string(&path).expect("read"), "ak_secretvalue");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            let mode = fs::metadata(&path).expect("meta").permissions().mode();
            assert_eq!(mode & 0o777, 0o600);
        }
        store
            .register_session(&json!({"session_id": "a"}))
            .expect("register");
        store
            .register_session(&json!({"session_id": "b"}))
            .expect("register");
        assert_eq!(store.recent_sessions(1)[0]["session_id"], "b");
    }
}
