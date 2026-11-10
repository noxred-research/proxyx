//! Redis Streams implementation of the captures-log abstraction.
//!
//! - Producer: `XADD <stream> * data <payload>`. The producer key is
//!   recorded but unused for routing; Redis Streams is a single-partition
//!   log so all messages are globally ordered. Future broker impls
//!   (Redpanda) use the same key as a partition assignment.
//! - Consumer: dedicated non-multiplexed `Connection` for blocking
//!   `XREADGROUP` (a `MultiplexedConnection`/`ConnectionManager` cannot
//!   issue `BLOCK` without starving other ops). `XAUTOCLAIM` runs on the
//!   shared connection manager.
//! - `session_offset`: the `<ms>-<seq>` stream id packed into a single
//!   monotonically increasing `u64` (see `parse_offset`), used as the
//!   sub-millisecond tiebreaker in ClickHouse sort keys.

#![allow(deprecated)] // redis::aio::Connection is the only API that supports BLOCK.

use std::time::Duration;

use anyhow::{Result, anyhow};
use async_trait::async_trait;
use bytes::Bytes;
use redis::aio::ConnectionManager;

use super::{AckHandle, AckInner, CaptureLogConsumer, CaptureLogProducer, LogMessage};

/// `XADD`-based producer over a Redis Stream.
///
/// `max_stream_len` caps the stream's tail with `MAXLEN ~ N` on every
/// `XADD`. The `~` form trims at radix-tree boundaries (cheap, slightly
/// fuzzy upper bound) and prevents Redis from accumulating acked entries
/// indefinitely — Redis Streams retain XACK'd messages until trimmed.
/// Set to 0 to disable trimming (not recommended in production).
pub struct RedisStreamProducer {
    conn: ConnectionManager,
    stream_name: String,
    max_stream_len: u64,
}

impl RedisStreamProducer {
    pub fn new(conn: ConnectionManager, stream_name: String, max_stream_len: u64) -> Self {
        Self {
            conn,
            stream_name,
            max_stream_len,
        }
    }
}

#[async_trait]
impl CaptureLogProducer for RedisStreamProducer {
    async fn publish(&self, _key: &[u8], payload: Bytes) -> Result<()> {
        let mut conn = self.conn.clone();
        let mut cmd = redis::cmd("XADD");
        cmd.arg(&self.stream_name);
        if self.max_stream_len > 0 {
            cmd.arg("MAXLEN").arg("~").arg(self.max_stream_len);
        }
        cmd.arg("*")
            .arg("data")
            .arg(payload.as_ref())
            .query_async::<String>(&mut conn)
            .await?;
        Ok(())
    }

    async fn flush_and_close(&self, _timeout: Duration) {
        // XADD is synchronous on the Redis side; nothing to flush.
    }
}

/// `XREADGROUP`/`XAUTOCLAIM`/`XACK` consumer for one Redis Stream.
///
/// `poll` is intentionally `&mut self`: the dedicated blocking connection
/// is single-owned and is recreated on I/O failure.
pub struct RedisStreamConsumer {
    redis: ConnectionManager,
    blocking_conn: Option<redis::aio::Connection>,
    client: redis::Client,
    stream_name: String,
    consumer_group: String,
    consumer_id: String,
}

impl RedisStreamConsumer {
    /// Construct a consumer and ensure the consumer group exists.
    pub async fn new(
        client: redis::Client,
        redis: ConnectionManager,
        stream_name: String,
        consumer_group: String,
        consumer_id: String,
    ) -> Result<Self> {
        let consumer = Self {
            redis,
            blocking_conn: None,
            client,
            stream_name,
            consumer_group,
            consumer_id,
        };
        consumer.ensure_consumer_group().await?;
        Ok(consumer)
    }

    async fn ensure_consumer_group(&self) -> Result<()> {
        let result: redis::RedisResult<()> = redis::cmd("XGROUP")
            .arg("CREATE")
            .arg(&self.stream_name)
            .arg(&self.consumer_group)
            .arg("0")
            .arg("MKSTREAM")
            .query_async(&mut self.redis.clone())
            .await;

        match result {
            Ok(()) => Ok(()),
            Err(e) if e.to_string().contains("BUSYGROUP") => Ok(()),
            Err(e) => Err(e.into()),
        }
    }

    /// Reclaim entries idle past the threshold. Returns parsed messages
    /// (possibly empty).
    async fn autoclaim(&self, max: usize) -> Result<Vec<LogMessage>> {
        let result: redis::RedisResult<redis::Value> = redis::cmd("XAUTOCLAIM")
            .arg(&self.stream_name)
            .arg(&self.consumer_group)
            .arg(&self.consumer_id)
            .arg(30_000_i64) // min idle ms
            .arg("0-0")
            .arg("COUNT")
            .arg(max)
            .query_async(&mut self.redis.clone())
            .await;

        let entries = match result {
            Ok(redis::Value::Array(arr)) if arr.len() >= 2 => match arr.into_iter().nth(1) {
                Some(redis::Value::Array(entries)) => entries,
                _ => return Ok(Vec::new()),
            },
            Ok(_) => return Ok(Vec::new()),
            Err(e) => return Err(e.into()),
        };

        Ok(self.parse_entries(entries).await)
    }

    /// Block on `XREADGROUP > BLOCK 5000` for at most `max` new messages.
    async fn xreadgroup(&mut self, max: usize) -> Result<Vec<LogMessage>> {
        let conn = match self.blocking_conn.as_mut() {
            Some(c) => c,
            None => {
                let c = self.client.get_async_connection().await?;
                self.blocking_conn = Some(c);
                self.blocking_conn.as_mut().unwrap()
            }
        };

        let response: redis::RedisResult<redis::Value> = redis::cmd("XREADGROUP")
            .arg("GROUP")
            .arg(&self.consumer_group)
            .arg(&self.consumer_id)
            .arg("COUNT")
            .arg(max)
            .arg("BLOCK")
            .arg(5000)
            .arg("STREAMS")
            .arg(&self.stream_name)
            .arg(">")
            .query_async(conn)
            .await;

        // Drop a broken connection so the next call reconnects.
        if matches!(&response, Err(e) if e.is_io_error()) {
            self.blocking_conn = None;
        }

        let streams = match response {
            Ok(redis::Value::Nil) => return Ok(Vec::new()),
            Ok(redis::Value::Array(arr)) if arr.is_empty() => return Ok(Vec::new()),
            Ok(redis::Value::Array(arr)) => arr,
            Ok(other) => return Err(anyhow!("unexpected XREADGROUP response: {:?}", other)),
            Err(e) => return Err(e.into()),
        };

        // Response: [[stream_name, [[entry_id, [field, value, ...]], ...]]]
        let Some(redis::Value::Array(stream_data)) = streams.into_iter().next() else {
            return Ok(Vec::new());
        };
        if stream_data.len() < 2 {
            return Ok(Vec::new());
        }
        let entries = match stream_data.into_iter().nth(1) {
            Some(redis::Value::Array(entries)) => entries,
            _ => return Ok(Vec::new()),
        };

        Ok(self.parse_entries(entries).await)
    }

    /// Convert raw stream entries to `LogMessage`s. Any entry that cannot
    /// be turned into a message is acked-and-dropped so it leaves the
    /// pending-entries list instead of being reclaimed by every
    /// `XAUTOCLAIM` cycle forever. Entries so malformed that no stream id
    /// can be extracted cannot be acked (XACK needs the id) and are only
    /// logged — these are not producible by a well-behaved Redis and
    /// indicate protocol corruption.
    async fn parse_entries(&self, entries: Vec<redis::Value>) -> Vec<LogMessage> {
        let mut out = Vec::with_capacity(entries.len());
        for entry in entries {
            match self.parse_entry(entry) {
                Ok(msg) => out.push(msg),
                Err((Some(stream_id), reason)) => {
                    tracing::warn!(
                        stream_id,
                        reason,
                        "malformed stream entry, acking to drain PEL"
                    );
                    self.xack(&stream_id).await;
                }
                Err((None, reason)) => {
                    tracing::error!(reason, "unidentifiable stream entry, cannot ack");
                }
            }
        }
        out
    }

    /// Parse one raw stream entry. On failure returns the entry's stream
    /// id (when extractable) plus a reason, so the caller can ack-drop it.
    fn parse_entry(
        &self,
        entry: redis::Value,
    ) -> Result<LogMessage, (Option<String>, &'static str)> {
        let redis::Value::Array(entry_parts) = entry else {
            return Err((None, "entry not an array"));
        };
        let mut iter = entry_parts.into_iter();
        let Some(id_value) = iter.next() else {
            return Err((None, "missing stream id"));
        };
        let Some(stream_id) = value_to_string(&id_value) else {
            return Err((None, "stream id not a string"));
        };
        let fields = match iter.next() {
            Some(redis::Value::Array(f)) => f,
            _ => return Err((Some(stream_id), "fields not an array")),
        };

        let data = match find_field_bytes(fields, "data") {
            Some(b) => b,
            None => return Err((Some(stream_id), "no data field")),
        };

        let session_offset = parse_offset(&stream_id);
        let ack = AckHandle::new(RedisAck {
            redis: self.redis.clone(),
            stream_name: self.stream_name.clone(),
            consumer_group: self.consumer_group.clone(),
            stream_id: stream_id.clone(),
        });

        Ok(LogMessage {
            key: Bytes::new(),
            payload: data,
            session_offset,
            ack,
        })
    }

    async fn xack(&self, stream_id: &str) {
        let _: redis::RedisResult<()> = redis::cmd("XACK")
            .arg(&self.stream_name)
            .arg(&self.consumer_group)
            .arg(stream_id)
            .query_async(&mut self.redis.clone())
            .await;
    }
}

#[async_trait]
impl CaptureLogConsumer for RedisStreamConsumer {
    async fn poll(&mut self, max: usize) -> Result<Vec<LogMessage>> {
        // Reclaim orphaned entries before blocking on new work.
        let reclaimed = self.autoclaim(max).await?;
        if !reclaimed.is_empty() {
            return Ok(reclaimed);
        }
        self.xreadgroup(max).await
    }
}

struct RedisAck {
    redis: ConnectionManager,
    stream_name: String,
    consumer_group: String,
    stream_id: String,
}

#[async_trait]
impl AckInner for RedisAck {
    async fn ack_boxed(self: Box<Self>) -> Result<()> {
        let mut conn = self.redis.clone();
        redis::cmd("XACK")
            .arg(&self.stream_name)
            .arg(&self.consumer_group)
            .arg(&self.stream_id)
            .query_async::<i64>(&mut conn)
            .await?;
        Ok(())
    }
}

/// Pack a Redis Streams id `"<ms>-<seq>"` into a single monotonically
/// increasing `u64` for use as the ClickHouse sort-key tiebreaker.
///
/// Layout: high bits = milliseconds, low [`OFFSET_SEQ_BITS`] = intra-ms
/// sequence. This preserves stream order *across* milliseconds; the
/// previous seq-only parse reset every millisecond, so two captures with
/// the same wall-clock `timestamp` but different stream-ms could sort in
/// the wrong order. `ms` has room until well past year 2500; `seq`
/// saturates at `2^OFFSET_SEQ_BITS - 1` (~1M entries within one ms),
/// beyond which same-ms rows may share an offset and fall back to the
/// `id` tiebreaker — cross-ms order is still preserved. Unparseable ids
/// return 0 (lowest tiebreaker).
const OFFSET_SEQ_BITS: u32 = 20;

fn parse_offset(stream_id: &str) -> u64 {
    let Some((ms, seq)) = stream_id.split_once('-') else {
        return 0;
    };
    let (Ok(ms), Ok(seq)) = (ms.parse::<u64>(), seq.parse::<u64>()) else {
        return 0;
    };
    (ms << OFFSET_SEQ_BITS) | (seq & ((1 << OFFSET_SEQ_BITS) - 1))
}

fn find_field_bytes(fields: Vec<redis::Value>, name: &str) -> Option<Bytes> {
    let mut iter = fields.into_iter();
    while let Some(key) = iter.next() {
        let value = iter.next()?;
        if let Some(key_str) = value_to_string(&key)
            && key_str == name
        {
            return value_to_bytes(value);
        }
    }
    None
}

fn value_to_string(val: &redis::Value) -> Option<String> {
    match val {
        redis::Value::BulkString(bytes) => String::from_utf8(bytes.clone()).ok(),
        redis::Value::SimpleString(s) => Some(s.clone()),
        _ => None,
    }
}

fn value_to_bytes(val: redis::Value) -> Option<Bytes> {
    match val {
        redis::Value::BulkString(bytes) => Some(Bytes::from(bytes)),
        redis::Value::SimpleString(s) => Some(Bytes::from(s.into_bytes())),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::{OFFSET_SEQ_BITS, parse_offset};

    #[test]
    fn parse_offset_packs_ms_and_seq() {
        assert_eq!(
            parse_offset("1700000000000-0"),
            1700000000000u64 << OFFSET_SEQ_BITS
        );
        assert_eq!(
            parse_offset("1700000000000-7"),
            (1700000000000u64 << OFFSET_SEQ_BITS) | 7
        );
    }

    #[test]
    fn parse_offset_is_monotonic_across_milliseconds() {
        // The bug this fixes: a later stream-ms with seq 0 must outrank an
        // earlier stream-ms with a high seq.
        let earlier = parse_offset("1700000000000-999");
        let later = parse_offset("1700000000001-0");
        assert!(later > earlier, "later ms must produce a larger offset");
    }

    #[test]
    fn parse_offset_seq_saturates_without_corrupting_ms() {
        // A seq beyond the field width must not bleed into the ms bits.
        let huge_seq = parse_offset("1700000000000-99999999");
        let next_ms = parse_offset("1700000000001-0");
        assert!(next_ms > huge_seq);
    }

    #[test]
    fn parse_offset_handles_malformed_ids() {
        assert_eq!(parse_offset(""), 0);
        assert_eq!(parse_offset("nope"), 0);
        assert_eq!(parse_offset("1700000000000-"), 0);
        assert_eq!(parse_offset("1700000000000-abc"), 0);
    }
}
