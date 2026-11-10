//! Redis / Valkey: reachability, version, clock skew, memory policy,
//! persistence, and the length of a stream.

use std::collections::HashMap;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use crate::report::Check;

/// When the clocks of Redis and this host differ by this much or more, warn / fail.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SkewThresholds {
    pub warn: Duration,
    pub fail: Duration,
}

impl Default for SkewThresholds {
    /// Lease and session TTLs are seconds: 1 s warns, 5 s fails.
    fn default() -> Self {
        Self {
            warn: Duration::from_secs(1),
            fail: Duration::from_secs(5),
        }
    }
}

/// What to check on a Redis server.
#[derive(Debug, Clone, Copy)]
pub struct RedisOptions {
    pub timeout: Duration,
    pub skew: SkewThresholds,
    /// Warn when the server persists nothing (no AOF, no RDB save points).
    /// Off for a cache that is rebuilt from Postgres.
    pub require_persistence: bool,
}

impl RedisOptions {
    pub fn new(timeout: Duration) -> Self {
        Self {
            timeout,
            skew: SkewThresholds::default(),
            require_persistence: false,
        }
    }
}

/// Microseconds since the Unix epoch.
pub fn now_micros() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| i64::try_from(d.as_micros()).unwrap_or(i64::MAX))
}

/// The `redis.clock_skew` check from three readings, in microseconds: the local
/// clock before and after the `TIME` call, and the server's answer. Half the
/// round trip is forgiven, since the server read its clock somewhere inside it.
pub fn clock_skew(local_before: i64, local_after: i64, remote: i64, th: SkewThresholds) -> Check {
    let id = "redis.clock_skew";
    let rtt = (local_after - local_before).max(0);
    let mid = local_before + rtt / 2;
    let diff = remote - mid;
    let effective =
        Duration::from_micros(diff.unsigned_abs().saturating_sub(rtt.unsigned_abs() / 2));
    let (ahead, shown) = (diff >= 0, Duration::from_micros(diff.unsigned_abs()));
    let message = format!(
        "Redis clock is {} ms {} this host (round trip {} ms)",
        shown.as_millis(),
        if ahead { "ahead of" } else { "behind" },
        rtt / 1000
    );
    if effective >= th.fail {
        Check::fail(id, message).hint(
            "fix NTP on the Redis host and on this one: TTLs and token windows depend on agreeing clocks",
        )
    } else if effective >= th.warn {
        Check::warn(id, message).hint("check NTP/chrony on the Redis host and on this one")
    } else {
        Check::pass(id, message)
    }
}

/// `INFO` text as `key -> value`.
pub fn parse_info(text: &str) -> HashMap<&str, &str> {
    text.lines()
        .filter(|l| !l.starts_with('#'))
        .filter_map(|l| l.trim_end().split_once(':'))
        .collect()
}

fn memory_check(info: &HashMap<&str, &str>) -> Check {
    let id = "redis.memory_policy";
    let policy = info.get("maxmemory_policy").copied().unwrap_or("unknown");
    let max: u64 = info
        .get("maxmemory")
        .and_then(|v| v.parse().ok())
        .unwrap_or(0);
    if max == 0 {
        Check::pass(id, format!("no maxmemory limit (policy {policy})"))
    } else if policy == "noeviction" {
        Check::pass(
            id,
            format!("maxmemory {} MiB, policy noeviction", max >> 20),
        )
    } else {
        Check::warn(
            id,
            format!("maxmemory {} MiB with policy {policy}: keys are evicted at the limit", max >> 20),
        )
        .hint("leases, sessions and streams must not be evicted: set `maxmemory-policy noeviction` and size the memory")
    }
}

fn persistence_check(info: &HashMap<&str, &str>, save: Option<&str>, require: bool) -> Check {
    let id = "redis.persistence";
    let aof = info.get("aof_enabled").is_some_and(|v| *v == "1");
    let rdb = save.is_some_and(|s| !s.trim().is_empty());
    let mut modes = Vec::new();
    if aof {
        modes.push("AOF");
    }
    if rdb {
        modes.push("RDB snapshots");
    }
    if !modes.is_empty() {
        Check::pass(id, format!("persistence: {}", modes.join(" + ")))
    } else if save.is_none() && !aof {
        // CONFIG is often disabled on managed servers, so "no save points" is not known.
        Check::pass(
            id,
            "persistence: AOF is off; RDB settings cannot be read (CONFIG GET refused)",
        )
    } else if require {
        Check::warn(id, "persistence is off: a restart loses the data")
            .hint("enable AOF (`appendonly yes`) or RDB save points; the capture stream and sessions live here")
    } else {
        Check::pass(
            id,
            "persistence is off (the state is rebuilt from Postgres after a loss)",
        )
    }
}

/// The `redis.*` checks of one server: `redis.reachable` (PING and version),
/// `redis.clock_skew` (server `TIME` against this host), `redis.memory_policy`
/// and `redis.persistence`. A server that cannot be reached is one failing
/// `redis.reachable`. The password never appears in a message.
pub async fn redis_server(url: &str, opts: RedisOptions) -> Vec<Check> {
    let target = redis_target(url);
    let start = Instant::now();
    let run = tokio::time::timeout(opts.timeout, read(url));
    let found = match run.await {
        Ok(Ok(found)) => found,
        Ok(Err(error)) => {
            return vec![
                Check::fail("redis.reachable", format!("cannot use {target}: {error}"))
                    .hint("check the URL, the password and that the server runs")
                    .elapsed(start.elapsed()),
            ];
        }
        Err(_) => {
            return vec![
                Check::fail(
                    "redis.reachable",
                    format!("{target}: no answer within {} ms", opts.timeout.as_millis()),
                )
                .hint("the host is unreachable or filtered, or the server is overloaded")
                .elapsed(start.elapsed()),
            ];
        }
    };
    let info = parse_info(&found.info);
    let server = info.get("server_name").copied().unwrap_or("redis");
    let version = info
        .get("valkey_version")
        .or_else(|| info.get("redis_version"))
        .copied()
        .unwrap_or("unknown");
    vec![
        Check::pass(
            "redis.reachable",
            format!("{target} answers PING ({server} {version})"),
        )
        .elapsed(found.ping),
        clock_skew(found.before, found.after, found.remote_micros, opts.skew),
        memory_check(&info),
        persistence_check(&info, found.save.as_deref(), opts.require_persistence),
    ]
}

/// `host:port/db` of a Redis URL, without credentials.
pub fn redis_target(url: &str) -> String {
    let rest = url.split_once("://").map_or(url, |(_, r)| r);
    let rest = rest.rsplit_once('@').map_or(rest, |(_, r)| r);
    rest.split('?').next().unwrap_or(rest).to_owned()
}

struct Found {
    ping: Duration,
    info: String,
    save: Option<String>,
    before: i64,
    after: i64,
    remote_micros: i64,
}

async fn read(url: &str) -> redis::RedisResult<Found> {
    let client = redis::Client::open(url)?;
    let mut conn = client.get_multiplexed_async_connection().await?;
    let t = Instant::now();
    let pong: String = redis::cmd("PING").query_async(&mut conn).await?;
    let ping = t.elapsed();
    if pong != "PONG" {
        return Err((redis::ErrorKind::ResponseError, "PING did not answer PONG").into());
    }
    let info: String = redis::cmd("INFO").query_async(&mut conn).await?;
    let before = now_micros();
    let (secs, micros): (i64, i64) = redis::cmd("TIME").query_async(&mut conn).await?;
    let after = now_micros();
    // Managed servers often refuse CONFIG.
    let save: Option<String> = redis::cmd("CONFIG")
        .arg("GET")
        .arg("save")
        .query_async::<Vec<String>>(&mut conn)
        .await
        .ok()
        .and_then(|v| v.get(1).cloned());
    Ok(Found {
        ping,
        info,
        save,
        before,
        after,
        remote_micros: secs.saturating_mul(1_000_000).saturating_add(micros),
    })
}

/// `redis.stream`: whether the stream `key` exists and how full it is against
/// `max_len` (0: untrimmed). A stream that does not exist yet passes: the
/// first writer creates it.
pub async fn redis_stream(url: &str, key: &str, max_len: u64, timeout: Duration) -> Check {
    let id = "redis.stream";
    let start = Instant::now();
    let run = async {
        let client = redis::Client::open(url)?;
        let mut conn = client.get_multiplexed_async_connection().await?;
        let exists: bool = redis::cmd("EXISTS").arg(key).query_async(&mut conn).await?;
        if !exists {
            return Ok::<Option<u64>, redis::RedisError>(None);
        }
        let len: u64 = redis::cmd("XLEN").arg(key).query_async(&mut conn).await?;
        Ok(Some(len))
    };
    let result = tokio::time::timeout(timeout, run).await;
    let check = match result {
        Ok(Ok(None)) => Check::pass(
            id,
            format!("stream {key} does not exist yet (the first writer creates it)"),
        ),
        Ok(Ok(Some(len))) => stream_check(key, len, max_len),
        Ok(Err(error)) => Check::fail(id, format!("cannot read stream {key}: {error}"))
            .hint("the key exists with another type, or Redis refused the command"),
        Err(_) => Check::fail(id, format!("no answer within {} ms", timeout.as_millis())),
    };
    check.elapsed(start.elapsed())
}

fn stream_check(key: &str, len: u64, max_len: u64) -> Check {
    let id = "redis.stream";
    if max_len > 0 && len >= max_len / 10 * 9 {
        Check::warn(
            id,
            format!(
                "stream {key} holds {len} entries, {}% of its cap {max_len}",
                len * 100 / max_len
            ),
        )
        .hint("the consumer is behind: entries past the cap are trimmed before they are read")
    } else {
        Check::pass(id, format!("stream {key} holds {len} entries"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Status;

    const TH: SkewThresholds = SkewThresholds {
        warn: Duration::from_secs(1),
        fail: Duration::from_secs(5),
    };

    #[test]
    fn skew_uses_the_injected_local_clock() {
        let base = 1_800_000_000_000_000_i64;
        // Remote read inside a 2 ms round trip, clocks agree.
        let ok = clock_skew(base, base + 2_000, base + 1_000, TH);
        assert_eq!(ok.status, Status::Pass, "{ok:?}");
        // 2 s ahead.
        let warn = clock_skew(base, base + 2_000, base + 2_001_000, TH);
        assert_eq!(warn.status, Status::Warn, "{warn:?}");
        assert!(warn.message.contains("ahead of"), "{warn:?}");
        // 10 s behind.
        let fail = clock_skew(base, base + 2_000, base - 9_999_000, TH);
        assert_eq!(fail.status, Status::Fail, "{fail:?}");
        assert!(fail.message.contains("behind"), "{fail:?}");
        // Just under the warn line once half the round trip is forgiven.
        let edge = clock_skew(base, base + 400_000, base + 200_000 + 1_100_000, TH);
        assert_eq!(edge.status, Status::Pass, "{edge:?}");
    }

    #[test]
    fn info_parses_and_judges_memory_and_persistence() {
        let text = "# Memory\r\nmaxmemory:1073741824\r\nmaxmemory_policy:allkeys-lru\r\n# Persistence\r\naof_enabled:0\r\n";
        let info = parse_info(text);
        assert_eq!(memory_check(&info).status, Status::Warn);
        let ok = parse_info("maxmemory:0\r\nmaxmemory_policy:noeviction\r\n");
        assert_eq!(memory_check(&ok).status, Status::Pass);
        let ne = parse_info("maxmemory:1048576\r\nmaxmemory_policy:noeviction\r\n");
        assert_eq!(memory_check(&ne).status, Status::Pass);

        let none = parse_info("aof_enabled:0\r\n");
        assert_eq!(
            persistence_check(&none, Some(""), true).status,
            Status::Warn
        );
        assert_eq!(
            persistence_check(&none, Some(""), false).status,
            Status::Pass
        );
        assert_eq!(
            persistence_check(&none, Some("3600 1 300 100"), true).status,
            Status::Pass
        );
        assert_eq!(
            persistence_check(&parse_info("aof_enabled:1\r\n"), None, true).status,
            Status::Pass
        );
        // CONFIG refused and no AOF: unknown, not a warning.
        assert_eq!(persistence_check(&none, None, true).status, Status::Pass);
    }

    #[test]
    fn streams_warn_near_their_cap() {
        assert_eq!(stream_check("s", 10, 0).status, Status::Pass);
        assert_eq!(stream_check("s", 89, 100).status, Status::Pass);
        assert_eq!(stream_check("s", 90, 100).status, Status::Warn);
    }

    #[test]
    fn the_target_hides_credentials() {
        assert_eq!(
            redis_target("redis://user:secret@cache.example:6379/2"),
            "cache.example:6379/2"
        );
        assert_eq!(redis_target("redis://localhost:6379"), "localhost:6379");
    }
}
