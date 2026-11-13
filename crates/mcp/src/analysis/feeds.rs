//! Cursor-based capture feeds: a registered query, a position, and nothing else.
//!
//! A feed stores the scope-constrained query, the scope's digest and two cursors: where it began
//! and the newest position handed out. It never stores a capture, a body or a credential. Each
//! poll re-checks the scope, reads stored captures after the cursor in ascending order through the
//! control plane, and returns stable ids so a reader can drop duplicates. A feed is polled, not
//! pushed, and what it reads is what was stored: an empty page says nothing about live traffic.

use std::collections::VecDeque;
use std::time::Instant;

use base64::Engine as _;
use serde_json::Value;

/// Capture ids remembered per feed for duplicate detection.
const RECENT_IDS: usize = 2000;

/// One registered feed.
#[derive(Debug)]
pub struct Feed {
    pub id: String,
    pub org: String,
    pub scope_id: String,
    pub scope_digest: String,
    /// The branches with the scope already intersected in.
    pub branches: Value,
    pub include_bodies: bool,
    /// The newest stored position when the feed opened.
    pub start: Option<String>,
    /// The newest position any read returned.
    pub acked: Option<String>,
    pub opened_at: i64,
    /// Unix seconds.
    pub expires_at: i64,
    pub last_poll: Option<Instant>,
    pub polls: u64,
    recent: VecDeque<String>,
}

impl Feed {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        id: String,
        org: String,
        scope_id: String,
        scope_digest: String,
        branches: Value,
        include_bodies: bool,
        start: Option<String>,
        opened_at: i64,
        expires_at: i64,
    ) -> Self {
        Self {
            id,
            org,
            scope_id,
            scope_digest,
            branches,
            include_bodies,
            acked: start.clone(),
            start,
            opened_at,
            expires_at,
            last_poll: None,
            polls: 0,
            recent: VecDeque::new(),
        }
    }

    /// Set the position the feed began at, once it is known.
    pub fn set_start(&mut self, start: Option<String>) {
        self.acked.clone_from(&start);
        self.start = start;
    }

    /// Whether `id` was returned recently. Records it either way.
    pub fn seen(&mut self, id: &str) -> bool {
        if self.recent.iter().any(|known| known == id) {
            return true;
        }
        if self.recent.len() >= RECENT_IDS {
            self.recent.pop_front();
        }
        self.recent.push_back(id.to_owned());
        false
    }
}

/// The 40 bytes behind a cursor, or `None` when it is not one.
pub fn cursor_key(cursor: &str) -> Option<Vec<u8>> {
    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(cursor)
        .ok()?;
    (bytes.len() == 40).then_some(bytes)
}

/// Whether cursor `a` is strictly later than `b`. Cursors sort by their decoded bytes.
pub fn later(a: &str, b: &str) -> bool {
    match (cursor_key(a), cursor_key(b)) {
        (Some(a), Some(b)) => a > b,
        _ => false,
    }
}

/// The later of two optional cursors.
pub fn newest(a: Option<String>, b: Option<&str>) -> Option<String> {
    match (a, b) {
        (Some(a), Some(b)) => Some(if later(b, &a) { b.to_owned() } else { a }),
        (Some(a), None) => Some(a),
        (None, Some(b)) => Some(b.to_owned()),
        (None, None) => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cursor(nanos: u128) -> String {
        let mut bytes = nanos.to_be_bytes().to_vec();
        bytes.extend([0_u8; 24]);
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
    }

    #[test]
    fn cursors_order_by_time_not_by_text() {
        let (early, late) = (cursor(1), cursor(63));
        assert!(later(&late, &early) && !later(&early, &late) && !later(&early, &early));
        assert!(!later("garbage", &early));
        assert_eq!(
            newest(Some(early.clone()), Some(&late)).as_deref(),
            Some(late.as_str())
        );
        assert_eq!(
            newest(Some(late.clone()), Some(&early)).as_deref(),
            Some(late.as_str())
        );
    }

    #[test]
    fn duplicates_are_remembered_within_a_bound() {
        let mut feed = Feed::new(
            "feed_1".into(),
            "acme".into(),
            "scope".into(),
            "d".into(),
            Value::Null,
            false,
            None,
            0,
            10,
        );
        assert!(!feed.seen("a"));
        assert!(feed.seen("a"));
        for n in 0..RECENT_IDS {
            feed.seen(&format!("id{n}"));
        }
        assert!(!feed.seen("a"), "the oldest id was forgotten");
    }
}
