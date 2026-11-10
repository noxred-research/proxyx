//! Pick the source table/MV for a WS query.
//!
//! Three tables are available:
//!   - `ws_messages` — base, ordered by `(org_id, source_id, timestamp,
//!     session_offset, id)`. All filterable columns and the payload
//!     live here.
//!   - `ws_messages_by_parent` — MV ordered by `(parent_event_id,
//!     timestamp, session_offset, id)`. Direct sort-key seek for
//!     per-conversation playback. Carries the same column set as the
//!     base.
//!   - `ws_messages_by_id` — MV ordered by `(id)`. Used only by
//!     `crate::ws_traffic::get_ws_by_id`.
//!
//! Routing rule: pick `ws_messages_by_parent` only when every branch
//! pins a `parent_event_id` and carries no other filter. The bloom
//! skip-index on `parent_event_id` in the base table still requires a
//! granule scan, so the MV's sort-key seek dominates for parent-pinned
//! workloads. Any other filter shape must use the base.

use super::ws::{WsQueryBranch, WsTrafficQuery};

pub(crate) fn select_table(query: &WsTrafficQuery) -> &'static str {
    let parent_pinned_only = query.branches.0.iter().all(is_parent_only_branch);
    if parent_pinned_only {
        "ws_messages_by_parent"
    } else {
        "ws_messages"
    }
}

fn is_parent_only_branch(b: &WsQueryBranch) -> bool {
    b.parent_event_id.is_some()
        && b.session_id.is_none()
        && b.source_id.is_none()
        && b.source.is_none()
        && b.host.is_none()
        && b.payload.is_none()
        && b.direction.is_none()
        && b.opcode.is_none()
        && b.close_reason.is_none()
        && b.close_code.is_none()
        && b.payload_size.is_none()
        && b.was_compressed.is_none()
        && b.payload_is_text.is_none()
        && b.payload_truncated.is_none()
}
