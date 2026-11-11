//! Cursor encoding for `(timestamp, session_offset, id)` pagination.
//!
//! 40-byte composite: 16 bytes big-endian `unix_timestamp_nanos` + 8 bytes
//! big-endian `session_offset` + 16 bytes raw UUID. Lex byte order matches
//! the ClickHouse sort key `(timestamp, session_offset, id)` so cursor
//! comparison and pagination agree exactly with the on-disk order.
//!
//! Searches ordered by another column prefix that tuple with the row's sort
//! value; their cursor appends the value's UTF-8 bytes after the 40 bytes.

use anyhow::{Context, Result};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use time::OffsetDateTime;
use uuid::Uuid;

fn cursor_bytes(ts: OffsetDateTime, session_offset: u64, id: Uuid) -> [u8; 40] {
    let mut buf = [0u8; 40];
    let nanos = ts.unix_timestamp_nanos();
    buf[..16].copy_from_slice(&nanos.to_be_bytes());
    buf[16..24].copy_from_slice(&session_offset.to_be_bytes());
    buf[24..].copy_from_slice(id.as_bytes());
    buf
}

fn parse_cursor_bytes(arr: &[u8; 40]) -> Result<(OffsetDateTime, u64, Uuid)> {
    let mut ts_buf = [0u8; 16];
    ts_buf.copy_from_slice(&arr[..16]);
    let nanos = i128::from_be_bytes(ts_buf);
    let ts =
        OffsetDateTime::from_unix_timestamp_nanos(nanos).context("invalid cursor timestamp")?;
    let mut off_buf = [0u8; 8];
    off_buf.copy_from_slice(&arr[16..24]);
    let session_offset = u64::from_be_bytes(off_buf);
    let mut id_buf = [0u8; 16];
    id_buf.copy_from_slice(&arr[24..]);
    let id = Uuid::from_bytes(id_buf);
    Ok((ts, session_offset, id))
}

pub(crate) fn encode_cursor(ts: OffsetDateTime, session_offset: u64, id: Uuid) -> String {
    URL_SAFE_NO_PAD.encode(cursor_bytes(ts, session_offset, id))
}

pub(crate) fn decode_cursor(cursor: &str) -> Result<(OffsetDateTime, u64, Uuid)> {
    let bytes = URL_SAFE_NO_PAD
        .decode(cursor)
        .context("invalid cursor encoding")?;
    let arr: [u8; 40] = bytes
        .try_into()
        .map_err(|_| anyhow::anyhow!("invalid cursor length"))?;
    parse_cursor_bytes(&arr)
}

/// Cursor for a search ordered by a non-timestamp column: the 40-byte
/// timestamp cursor, one `tag` byte naming the sort field and direction,
/// then the row's sort value as ClickHouse rendered it with `toString`.
pub(crate) fn encode_sorted_cursor(
    tag: u8,
    sort_key: &str,
    ts: OffsetDateTime,
    session_offset: u64,
    id: Uuid,
) -> String {
    let mut buf = Vec::with_capacity(41 + sort_key.len());
    buf.extend_from_slice(&cursor_bytes(ts, session_offset, id));
    buf.push(tag);
    buf.extend_from_slice(sort_key.as_bytes());
    URL_SAFE_NO_PAD.encode(buf)
}

/// Decode a cursor minted by [`encode_sorted_cursor`] for the same `tag`.
/// A timestamp cursor or one from another sort field or direction is
/// rejected: its value would resume the scan at the wrong place.
pub(crate) fn decode_sorted_cursor(
    cursor: &str,
    tag: u8,
) -> Result<(String, OffsetDateTime, u64, Uuid)> {
    let mut bytes = URL_SAFE_NO_PAD
        .decode(cursor)
        .context("invalid cursor encoding")?;
    if bytes.len() <= 40 || bytes[40] != tag {
        anyhow::bail!("cursor does not match orderBy");
    }
    let key = String::from_utf8(bytes.split_off(41)).context("invalid cursor sort key")?;
    bytes.truncate(40);
    let arr: [u8; 40] = bytes.try_into().expect("truncated to 40 bytes");
    let (ts, session_offset, id) = parse_cursor_bytes(&arr)?;
    Ok((key, ts, session_offset, id))
}

/// Format `OffsetDateTime` as ClickHouse `DateTime64(3)` literal.
pub(crate) fn ts_literal(ts: OffsetDateTime) -> String {
    format!(
        "{:04}-{:02}-{:02} {:02}:{:02}:{:02}.{:03}",
        ts.year(),
        ts.month() as u8,
        ts.day(),
        ts.hour(),
        ts.minute(),
        ts.second(),
        ts.millisecond(),
    )
}
