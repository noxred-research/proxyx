//! The append-only audit log: one JSON object per line for every tool call.
//!
//! Each entry carries the caller, the arguments (secrets redacted), the outcome and the hash of
//! the previous entry, so a deleted or edited line breaks the chain and `verify` finds it. A
//! mutating call is recorded twice: an `intent` entry before the backend is touched (the call
//! is refused when that write fails) and a `result` entry after. The file is created `0600` and
//! opened in append mode. Each record locks the file while reading the tail and appending, so
//! independent processes share one chain. For stronger guarantees set the append-only attribute
//! (`chattr +a`).

use std::fs::{File, OpenOptions};
use std::io::{self, BufRead as _, Read as _, Seek as _, SeekFrom, Write as _};
use std::path::{Path, PathBuf};

use serde::Serialize;
use serde_json::{Value, json};
use sha2::{Digest as _, Sha256};

use crate::redact::redacted;

/// The hash of the entry before the first one.
pub const GENESIS: &str = "0000000000000000000000000000000000000000000000000000000000000000";

/// Who made a call.
#[derive(Debug, Clone, Serialize, Default, PartialEq, Eq)]
pub struct Caller {
    /// `stdio` or `http`.
    pub transport: &'static str,
    pub client_name: Option<String>,
    pub client_version: Option<String>,
    /// The peer address of an HTTP call.
    pub remote: Option<String>,
}

/// The kind of audit record.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Phase {
    /// Written before a mutation touches a backend.
    Intent,
    /// The final outcome of a call.
    Result,
}

impl Phase {
    const fn as_str(self) -> &'static str {
        match self {
            Phase::Intent => "intent",
            Phase::Result => "result",
        }
    }
}

/// One audit record to write.
pub struct Entry<'a> {
    pub phase: Phase,
    pub caller: &'a Caller,
    pub tool: &'a str,
    pub arguments: &'a Value,
    /// `ok`, `error`, `refused`, `dry_run`, `pending_approval`, `intent`.
    pub outcome: &'a str,
    pub detail: Option<&'a str>,
    pub change_id: Option<&'a str>,
    pub duration_ms: Option<u64>,
}

/// The audit log writer.
pub struct Audit {
    path: PathBuf,
    engagement: Option<String>,
}

impl std::fmt::Debug for Audit {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Audit").field("path", &self.path).finish()
    }
}

/// `value` as JSON text with object keys sorted at every level.
pub fn canonical_json(value: &Value) -> String {
    // Map order is an implementation detail of serde_json's features: render keys explicitly.
    fn render(value: &Value, out: &mut String) {
        match value {
            Value::Object(map) => {
                let mut keys: Vec<&String> = map.keys().collect();
                keys.sort();
                out.push('{');
                for (index, key) in keys.into_iter().enumerate() {
                    if index > 0 {
                        out.push(',');
                    }
                    out.push_str(&Value::String(key.clone()).to_string());
                    out.push(':');
                    render(&map[key], out);
                }
                out.push('}');
            }
            Value::Array(items) => {
                out.push('[');
                for (index, item) in items.iter().enumerate() {
                    if index > 0 {
                        out.push(',');
                    }
                    render(item, out);
                }
                out.push(']');
            }
            other => out.push_str(&other.to_string()),
        }
    }
    let mut out = String::new();
    render(value, &mut out);
    out
}

/// Hex SHA-256 of `text`.
pub fn sha256_hex(text: &str) -> String {
    hex(&Sha256::digest(text.as_bytes()))
}

pub fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    bytes
        .iter()
        .fold(String::with_capacity(bytes.len() * 2), |mut out, byte| {
            let _ = write!(out, "{byte:02x}");
            out
        })
}

/// The hash of an entry given its fields. Fixed field order, so it does not depend on how a
/// JSON library orders object keys.
#[allow(clippy::too_many_arguments)]
fn entry_hash(
    seq: u64,
    ts: &str,
    prev: &str,
    phase: &str,
    tool: &str,
    outcome: &str,
    detail: &str,
    change_id: &str,
    duration_ms: u64,
    arguments: &Value,
    caller: &Value,
    engagement: &str,
) -> String {
    let material = [
        seq.to_string(),
        ts.to_owned(),
        prev.to_owned(),
        phase.to_owned(),
        tool.to_owned(),
        outcome.to_owned(),
        detail.to_owned(),
        change_id.to_owned(),
        duration_ms.to_string(),
        sha256_hex(&canonical_json(arguments)),
        sha256_hex(&canonical_json(caller)),
        engagement.to_owned(),
    ]
    .join("\u{1f}");
    sha256_hex(&material)
}

fn now_rfc3339() -> String {
    time::OffsetDateTime::now_utc()
        .format(&time::format_description::well_known::Rfc3339)
        .unwrap_or_default()
}

impl Audit {
    /// Open (creating it) the log at `path` and continue its hash chain.
    ///
    /// # Errors
    /// When the file or its directory cannot be created, the file cannot be locked, or the
    /// existing tail cannot be read.
    pub fn open(path: &Path, engagement: Option<String>) -> io::Result<Self> {
        if let Some(dir) = path.parent()
            && !dir.as_os_str().is_empty()
        {
            std::fs::create_dir_all(dir)?;
        }
        let mut file = Self::locked_file(path)?;
        Self::tail_state(&mut file)?;
        Ok(Self {
            path: path.to_path_buf(),
            engagement,
        })
    }

    /// Open an independent handle; dropping it releases the exclusive lock on every exit path.
    fn locked_file(path: &Path) -> io::Result<File> {
        let mut options = OpenOptions::new();
        options.create(true).read(true).append(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt as _;
            options.mode(0o600);
        }
        let file = options.open(path)?;
        file.lock()?;
        Ok(file)
    }

    /// The sequence number and hash of the last entry, read while holding the file lock.
    fn tail_state(file: &mut File) -> io::Result<(u64, String)> {
        let length = file.metadata()?.len();
        let window = length.min(1024 * 1024);
        file.seek(SeekFrom::Start(length - window))?;
        let mut tail = Vec::new();
        file.take(window).read_to_end(&mut tail)?;
        let text = String::from_utf8_lossy(&tail);
        let last = text.lines().rev().find(|line| !line.trim().is_empty());
        let Some(last) = last else {
            return Ok((0, GENESIS.to_owned()));
        };
        let value: Value = serde_json::from_str(last)
            .map_err(|_| io::Error::other("the audit log's last line is not valid JSON"))?;
        let seq = value["seq"]
            .as_u64()
            .ok_or_else(|| io::Error::other("the audit log's last line has no sequence number"))?;
        let hash = value["hash"]
            .as_str()
            .ok_or_else(|| io::Error::other("the audit log's last line has no hash"))?
            .to_owned();
        Ok((seq, hash))
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Append one entry and return its sequence number.
    ///
    /// # Errors
    /// When opening, locking, reading the tail or writing fails. A broken tail is not reset.
    pub fn record(&self, entry: &Entry<'_>) -> io::Result<u64> {
        let arguments = redacted(entry.arguments);
        let caller = serde_json::to_value(entry.caller).unwrap_or(Value::Null);
        let detail = crate::redact::redact_text(entry.detail.unwrap_or(""));
        let mut file = Self::locked_file(&self.path)?;
        let (last_seq, prev) = Self::tail_state(&mut file)?;
        let seq = last_seq
            .checked_add(1)
            .ok_or_else(|| io::Error::other("the audit log's sequence number is exhausted"))?;
        let ts = now_rfc3339();
        let engagement = self.engagement.as_deref().unwrap_or_default();
        let hash = entry_hash(
            seq,
            &ts,
            &prev,
            entry.phase.as_str(),
            entry.tool,
            entry.outcome,
            &detail,
            entry.change_id.unwrap_or(""),
            entry.duration_ms.unwrap_or(0),
            &arguments,
            &caller,
            engagement,
        );
        let line = json!({
            "seq": seq,
            "ts": ts,
            "prev": prev,
            "hash": hash,
            "phase": entry.phase.as_str(),
            "caller": caller,
            "tool": entry.tool,
            "arguments": arguments,
            "outcome": entry.outcome,
            "detail": detail,
            "change_id": entry.change_id,
            "duration_ms": entry.duration_ms,
            "engagement": self.engagement,
        });
        let mut bytes = serde_json::to_vec(&line).map_err(io::Error::other)?;
        bytes.push(b'\n');
        file.write_all(&bytes)?;
        file.flush()?;
        Ok(seq)
    }

    /// The last `count` entries, oldest first.
    pub fn tail(&self, count: usize) -> Vec<Value> {
        let Ok(file) = File::open(&self.path) else {
            return Vec::new();
        };
        let mut lines: std::collections::VecDeque<Value> = std::collections::VecDeque::new();
        for line in io::BufReader::new(file).lines().map_while(Result::ok) {
            if let Ok(value) = serde_json::from_str::<Value>(&line) {
                lines.push_back(value);
                if lines.len() > count {
                    lines.pop_front();
                }
            }
        }
        lines.into()
    }
}

/// The result of checking a log's hash chain.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Verification {
    pub entries: u64,
    /// The first line that breaks the chain, with the reason.
    pub broken: Option<(u64, String)>,
}

/// Recompute every hash of the log at `path` and check the links.
///
/// # Errors
/// When the file cannot be read.
pub fn verify(path: &Path) -> io::Result<Verification> {
    let file = File::open(path)?;
    let mut prev = GENESIS.to_owned();
    let mut expected_seq = 0_u64;
    let mut entries = 0_u64;
    for (index, line) in io::BufReader::new(file).lines().enumerate() {
        let line_no = index as u64 + 1;
        let line = line?;
        if line.trim().is_empty() {
            continue;
        }
        let broken = |reason: &str| {
            Ok(Verification {
                entries,
                broken: Some((line_no, reason.to_owned())),
            })
        };
        let Ok(value) = serde_json::from_str::<Value>(&line) else {
            return broken("not valid JSON");
        };
        expected_seq += 1;
        if value["seq"].as_u64() != Some(expected_seq) {
            return broken("sequence number out of order (a line is missing or moved)");
        }
        if value["prev"].as_str() != Some(prev.as_str()) {
            return broken("does not link to the previous entry");
        }
        let text = |key: &str| value[key].as_str().unwrap_or("").to_owned();
        let recomputed = entry_hash(
            expected_seq,
            &text("ts"),
            &prev,
            &text("phase"),
            &text("tool"),
            &text("outcome"),
            &text("detail"),
            value["change_id"].as_str().unwrap_or(""),
            value["duration_ms"].as_u64().unwrap_or(0),
            &value["arguments"],
            &value["caller"],
            value["engagement"].as_str().unwrap_or(""),
        );
        if value["hash"].as_str() != Some(recomputed.as_str()) {
            return broken("the entry's hash does not match its content (edited)");
        }
        prev = recomputed;
        entries += 1;
    }
    Ok(Verification {
        entries,
        broken: None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp(name: &str) -> PathBuf {
        let dir =
            std::env::temp_dir().join(format!("proxyx-mcp-audit-{name}-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).expect("temp dir");
        dir.join("audit.jsonl")
    }

    fn caller() -> Caller {
        Caller {
            transport: "stdio",
            client_name: Some("tester".into()),
            ..Caller::default()
        }
    }

    #[test]
    fn chain_verifies_survives_reopen_and_detects_edits() {
        let path = temp("chain");
        let caller = caller();
        let args = json!({"org": "acme", "password": "hunter2", "note": "ak_AAAAAAAAAAAAAAAAAAAAAAAAAAAA"});
        {
            let audit = Audit::open(&path, Some("ENG-1".into())).expect("open");
            for outcome in ["ok", "error"] {
                audit
                    .record(&Entry {
                        phase: Phase::Result,
                        caller: &caller,
                        tool: "health",
                        arguments: &args,
                        outcome,
                        detail: Some("backend answered 503"),
                        change_id: None,
                        duration_ms: Some(3),
                    })
                    .expect("record");
            }
        }
        {
            let audit = Audit::open(&path, Some("ENG-1".into())).expect("reopen");
            let seq = audit
                .record(&Entry {
                    phase: Phase::Intent,
                    caller: &caller,
                    tool: "put_policy",
                    arguments: &json!({}),
                    outcome: "intent",
                    detail: None,
                    change_id: Some("chg_00000000000000000000"),
                    duration_ms: None,
                })
                .expect("record after reopen");
            assert_eq!(seq, 3);
            assert_eq!(audit.tail(2).len(), 2);
        }
        let text = std::fs::read_to_string(&path).expect("read log");
        assert!(!text.contains("hunter2"), "password leaked into the log");
        assert!(!text.contains("ak_AAAA"), "org key leaked into the log");
        let report = verify(&path).expect("verify");
        assert_eq!((report.entries, report.broken.clone()), (3, None));
        let edited = text.replacen("\"outcome\":\"error\"", "\"outcome\":\"ok\"", 1);
        std::fs::write(&path, edited).expect("edit log");
        let report = verify(&path).expect("verify edited");
        assert_eq!(report.broken.map(|(line, _)| line), Some(2));
    }

    #[test]
    fn independent_writers_share_the_latest_chain_tail() {
        let path = temp("independent");
        let stdio = Audit::open(&path, None).expect("open stdio");
        let http = Audit::open(&path, None).expect("open http");
        let stdio_caller = caller();
        let http_caller = Caller {
            transport: "http",
            ..caller()
        };
        for (index, (audit, caller)) in [
            (&stdio, &stdio_caller),
            (&http, &http_caller),
            (&stdio, &stdio_caller),
            (&http, &http_caller),
        ]
        .into_iter()
        .enumerate()
        {
            let seq = audit
                .record(&Entry {
                    phase: Phase::Result,
                    caller,
                    tool: "health",
                    arguments: &json!({}),
                    outcome: "ok",
                    detail: None,
                    change_id: None,
                    duration_ms: Some(1),
                })
                .expect("record");
            assert_eq!(seq, index as u64 + 1);
        }
        let report = verify(&path).expect("verify");
        assert_eq!((report.entries, report.broken), (4, None));
    }

    #[test]
    fn concurrent_independent_writers_preserve_the_chain() {
        let path = temp("concurrent");
        let first = Audit::open(&path, None).expect("open first");
        let second = Audit::open(&path, None).expect("open second");
        let barrier = std::sync::Barrier::new(2);
        std::thread::scope(|scope| {
            for audit in [&first, &second] {
                let barrier = &barrier;
                scope.spawn(move || {
                    let caller = caller();
                    barrier.wait();
                    for _ in 0..20 {
                        audit
                            .record(&Entry {
                                phase: Phase::Result,
                                caller: &caller,
                                tool: "health",
                                arguments: &json!({}),
                                outcome: "ok",
                                detail: None,
                                change_id: None,
                                duration_ms: Some(1),
                            })
                            .expect("record");
                    }
                });
            }
        });
        let report = verify(&path).expect("verify");
        assert_eq!((report.entries, report.broken), (40, None));
    }

    #[test]
    fn broken_tail_refuses_append_and_releases_the_file_lock() {
        let path = temp("broken-tail");
        let first = Audit::open(&path, None).expect("open first");
        let second = Audit::open(&path, None).expect("open second");
        let caller = caller();
        let arguments = json!({});
        let entry = Entry {
            phase: Phase::Intent,
            caller: &caller,
            tool: "put_policy",
            arguments: &arguments,
            outcome: "intent",
            detail: None,
            change_id: None,
            duration_ms: None,
        };
        for broken in ["not-json\n", "{}\n", "{\"seq\":1}\n"] {
            std::fs::write(&path, broken).expect("break tail");
            assert!(first.record(&entry).is_err());
            assert!(second.record(&entry).is_err());
            assert_eq!(std::fs::read_to_string(&path).expect("read log"), broken);
        }
    }

    #[test]
    fn deleted_line_breaks_the_chain() {
        let path = temp("delete");
        let caller = caller();
        let audit = Audit::open(&path, None).expect("open");
        for _ in 0..3 {
            audit
                .record(&Entry {
                    phase: Phase::Result,
                    caller: &caller,
                    tool: "health",
                    arguments: &json!({}),
                    outcome: "ok",
                    detail: None,
                    change_id: None,
                    duration_ms: Some(1),
                })
                .expect("record");
        }
        let text = std::fs::read_to_string(&path).expect("read log");
        let without_second: String = text
            .lines()
            .enumerate()
            .filter(|(index, _)| *index != 1)
            .map(|(_, line)| format!("{line}\n"))
            .collect();
        std::fs::write(&path, without_second).expect("rewrite");
        assert!(verify(&path).expect("verify").broken.is_some());
    }

    #[test]
    fn canonical_json_ignores_key_order() {
        assert_eq!(
            canonical_json(&json!({"b": 1, "a": {"d": [2, {"y": 1, "x": 2}], "c": null}})),
            canonical_json(&json!({"a": {"c": null, "d": [2, {"x": 2, "y": 1}]}, "b": 1}))
        );
    }
}
