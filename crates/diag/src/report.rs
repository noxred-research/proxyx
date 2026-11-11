//! The report model: one [`Check`] per question, a [`Report`] per run, a table
//! for people and a stable JSON document for machines.

use std::fmt::Write as _;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

/// Version of the JSON document written by [`Report::to_json`]. It changes only
/// when a field is removed or changes meaning; adding a field does not.
pub const SCHEMA_VERSION: u32 = 1;

/// Exit code when every check passed or was skipped.
pub const EXIT_OK: i32 = 0;
/// Exit code when at least one check failed (or warned, under `--strict`).
pub const EXIT_FAIL: i32 = 1;
/// Exit code when nothing failed but at least one check warned.
pub const EXIT_WARN: i32 = 2;

/// Outcome of one check.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Status {
    /// The thing works as configured.
    Pass,
    /// Not applicable here, or not worth checking with this configuration.
    Skip,
    /// Works, but an operator should look at it.
    Warn,
    /// The role would not start or would not work.
    Fail,
}

impl Status {
    /// Fixed-width label of the table.
    pub const fn label(self) -> &'static str {
        match self {
            Self::Pass => "PASS",
            Self::Skip => "SKIP",
            Self::Warn => "WARN",
            Self::Fail => "FAIL",
        }
    }

    /// Lowercase name, as in the JSON document.
    pub const fn name(self) -> &'static str {
        match self {
            Self::Pass => "pass",
            Self::Skip => "skip",
            Self::Warn => "warn",
            Self::Fail => "fail",
        }
    }
}

/// One answered question.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Check {
    /// Stable dotted id, `<area>.<question>`, for example `postgres.reachable`.
    pub id: String,
    pub status: Status,
    /// One line: what was found.
    pub message: String,
    /// What to do about a `warn` or `fail`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hint: Option<String>,
    /// How long the check took, for the checks that talk to the network.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub elapsed_ms: Option<u64>,
}

impl Check {
    fn new(id: impl Into<String>, status: Status, message: impl Into<String>) -> Self {
        Self {
            id: id.into(),
            status,
            message: message.into(),
            hint: None,
            elapsed_ms: None,
        }
    }

    pub fn pass(id: impl Into<String>, message: impl Into<String>) -> Self {
        Self::new(id, Status::Pass, message)
    }

    pub fn warn(id: impl Into<String>, message: impl Into<String>) -> Self {
        Self::new(id, Status::Warn, message)
    }

    pub fn fail(id: impl Into<String>, message: impl Into<String>) -> Self {
        Self::new(id, Status::Fail, message)
    }

    pub fn skip(id: impl Into<String>, message: impl Into<String>) -> Self {
        Self::new(id, Status::Skip, message)
    }

    /// Attach what to do about it.
    #[must_use]
    pub fn hint(mut self, hint: impl Into<String>) -> Self {
        self.hint = Some(hint.into());
        self
    }

    /// Attach the time the check took.
    #[must_use]
    pub fn elapsed(mut self, elapsed: Duration) -> Self {
        self.elapsed_ms = Some(u64::try_from(elapsed.as_millis()).unwrap_or(u64::MAX));
        self
    }

    /// Put `prefix.` in front of the id: how a report that merges several roles
    /// keeps `postgres.reachable` of one apart from the other's.
    #[must_use]
    pub fn prefixed(mut self, prefix: &str) -> Self {
        self.id = format!("{prefix}.{}", self.id);
        self
    }

    /// The part of the id before the first dot: the area of the check.
    pub fn area(&self) -> &str {
        self.id.split_once('.').map_or(&self.id, |(area, _)| area)
    }
}

/// How many checks ended in each status.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Summary {
    pub pass: usize,
    pub warn: usize,
    pub fail: usize,
    pub skip: usize,
}

/// The checks of one run.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Report {
    /// What was checked: a role name, or `all`.
    pub subject: String,
    pub checks: Vec<Check>,
}

impl Report {
    pub fn new(subject: impl Into<String>) -> Self {
        Self {
            subject: subject.into(),
            checks: Vec::new(),
        }
    }

    pub fn push(&mut self, check: Check) {
        self.checks.push(check);
    }

    pub fn extend(&mut self, checks: impl IntoIterator<Item = Check>) {
        self.checks.extend(checks);
    }

    pub fn summary(&self) -> Summary {
        let mut s = Summary::default();
        for check in &self.checks {
            match check.status {
                Status::Pass => s.pass += 1,
                Status::Warn => s.warn += 1,
                Status::Fail => s.fail += 1,
                Status::Skip => s.skip += 1,
            }
        }
        s
    }

    /// The worst status: `fail`, else `warn`, else `pass`. A run of only skips
    /// is `pass`. With `strict`, a warning counts as a failure.
    pub fn overall(&self, strict: bool) -> Status {
        let s = self.summary();
        if s.fail > 0 || (strict && s.warn > 0) {
            Status::Fail
        } else if s.warn > 0 {
            Status::Warn
        } else {
            Status::Pass
        }
    }

    /// Process exit code: [`EXIT_OK`] when nothing failed or warned,
    /// [`EXIT_FAIL`] on any failure (a warning too when `strict`), and
    /// [`EXIT_WARN`] when there are only warnings.
    pub fn exit_code(&self, strict: bool) -> i32 {
        match self.overall(strict) {
            Status::Fail => EXIT_FAIL,
            Status::Warn => EXIT_WARN,
            Status::Pass | Status::Skip => EXIT_OK,
        }
    }

    /// The JSON document (schema [`SCHEMA_VERSION`]):
    ///
    /// ```json
    /// {"schema":1,"subject":"pool","strict":false,"overall":"warn","exit_code":2,
    ///  "summary":{"pass":3,"warn":1,"fail":0,"skip":0},
    ///  "checks":[{"id":"redis.reachable","status":"pass","message":"...","elapsed_ms":3}]}
    /// ```
    pub fn to_json(&self, strict: bool) -> Value {
        json!({
            "schema": SCHEMA_VERSION,
            "subject": self.subject,
            "strict": strict,
            "overall": self.overall(strict).name(),
            "exit_code": self.exit_code(strict),
            "summary": self.summary(),
            "checks": self.checks,
        })
    }

    /// Read a document written by [`Report::to_json`] (the `checks` and
    /// `subject` fields; the rest is derived again).
    pub fn from_json(text: &str) -> Result<Self, String> {
        #[derive(Deserialize)]
        struct Doc {
            schema: u32,
            subject: String,
            checks: Vec<Check>,
        }
        let doc: Doc = serde_json::from_str(text).map_err(|e| e.to_string())?;
        if doc.schema != SCHEMA_VERSION {
            return Err(format!(
                "report schema {} is not the supported {SCHEMA_VERSION}",
                doc.schema
            ));
        }
        Ok(Self {
            subject: doc.subject,
            checks: doc.checks,
        })
    }

    /// The table for a terminal: one line per check, the hint under a warning
    /// or failure, then the totals and the exit code.
    pub fn render_table(&self, strict: bool) -> String {
        let width = self
            .checks
            .iter()
            .map(|c| c.id.len())
            .max()
            .unwrap_or(0)
            .max("CHECK".len());
        let mut out = String::new();
        let _ = writeln!(out, "proxyx doctor: {}", self.subject);
        let _ = writeln!(out, "{:<6} {:<width$} RESULT", "STATUS", "CHECK");
        for c in &self.checks {
            let took = c
                .elapsed_ms
                .map_or_else(String::new, |ms| format!(" ({ms} ms)"));
            let _ = writeln!(
                out,
                "{:<6} {:<width$} {}{took}",
                c.status.label(),
                c.id,
                c.message
            );
            if let (Some(hint), Status::Warn | Status::Fail) = (&c.hint, c.status) {
                let _ = writeln!(out, "{:<6} {:<width$} -> {hint}", "", "");
            }
        }
        let s = self.summary();
        let _ = writeln!(
            out,
            "\n{} pass, {} warn, {} fail, {} skip: {} (exit {})",
            s.pass,
            s.warn,
            s.fail,
            s.skip,
            self.overall(strict).label(),
            self.exit_code(strict)
        );
        out
    }
}

/// Run `fut` and return its output with how long it took.
pub async fn timed<T>(fut: impl Future<Output = T>) -> (T, Duration) {
    let start = std::time::Instant::now();
    let out = fut.await;
    (out, start.elapsed())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> Report {
        let mut r = Report::new("pool");
        r.push(
            Check::pass("redis.reachable", "PONG from 127.0.0.1:6379")
                .elapsed(Duration::from_millis(3)),
        );
        r.push(Check::warn("redis.clock_skew", "Redis is 2 s ahead").hint("run NTP"));
        r.push(Check::skip("clickhouse.ping", "no ClickHouse configured"));
        r
    }

    #[test]
    fn exit_codes_follow_the_worst_status() {
        let mut r = Report::new("x");
        assert_eq!(r.exit_code(false), EXIT_OK);
        r.push(Check::pass("a.b", "ok"));
        r.push(Check::skip("a.c", "n/a"));
        assert_eq!(r.exit_code(false), EXIT_OK);
        r.push(Check::warn("a.d", "meh"));
        assert_eq!(r.exit_code(false), EXIT_WARN);
        assert_eq!(r.exit_code(true), EXIT_FAIL);
        r.push(Check::fail("a.e", "bad"));
        assert_eq!(r.exit_code(false), EXIT_FAIL);
        assert_eq!(r.exit_code(true), EXIT_FAIL);
    }

    #[test]
    fn json_schema_is_stable() {
        let expected = json!({
            "schema": 1,
            "subject": "pool",
            "strict": false,
            "overall": "warn",
            "exit_code": 2,
            "summary": {"pass": 1, "warn": 1, "fail": 0, "skip": 1},
            "checks": [
                {"id": "redis.reachable", "status": "pass", "message": "PONG from 127.0.0.1:6379", "elapsed_ms": 3},
                {"id": "redis.clock_skew", "status": "warn", "message": "Redis is 2 s ahead", "hint": "run NTP"},
                {"id": "clickhouse.ping", "status": "skip", "message": "no ClickHouse configured"},
            ],
        });
        assert_eq!(sample().to_json(false), expected);
    }

    #[test]
    fn json_round_trips() {
        let r = sample();
        let text = r.to_json(false).to_string();
        assert_eq!(Report::from_json(&text), Ok(r));
        assert!(Report::from_json(&text.replace("\"schema\":1", "\"schema\":9")).is_err());
    }

    #[test]
    fn table_snapshot() {
        let expected = "\
proxyx doctor: pool
STATUS CHECK            RESULT
PASS   redis.reachable  PONG from 127.0.0.1:6379 (3 ms)
WARN   redis.clock_skew Redis is 2 s ahead
                        -> run NTP
SKIP   clickhouse.ping  no ClickHouse configured

1 pass, 1 warn, 0 fail, 1 skip: WARN (exit 2)
";
        assert_eq!(sample().render_table(false), expected);
        assert!(sample().render_table(true).ends_with("FAIL (exit 1)\n"));
    }

    #[test]
    fn the_area_is_the_id_prefix() {
        assert_eq!(Check::pass("redis.reachable", "").area(), "redis");
        assert_eq!(Check::pass("config", "").area(), "config");
    }
}
