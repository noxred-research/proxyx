//! Pick the source table/MV per query.
//!
//! `http_captures_timeline` materializes a `(org_id, timestamp, session_offset, id)`
//! ordering optimal for org-scoped pagination.
//!
//! `http_captures_by_agent_hierarchy` materializes
//! `(org_id, parent_correlation_id, correlation_id, tool_call_id, timestamp,
//! session_offset, id)` for the agent hierarchy lookup shapes.
//!
//! Body/header predicates force the base table because those columns only live
//! there. Body fetching and header-derived sort fields also force the base table.

use super::TrafficQuery;

pub(crate) fn select_table(query: &TrafficQuery, want_bodies: bool) -> &'static str {
    if want_bodies || query.order_by.needs_headers() {
        "http_captures"
    } else if query.org_id.is_some()
        && query
            .branches
            .0
            .iter()
            .all(|b| b.matches_agent_hierarchy_prefix())
    {
        "http_captures_by_agent_hierarchy"
    } else if query.branches.0.iter().any(|b| b.needs_full_table()) {
        "http_captures"
    } else {
        "http_captures_timeline"
    }
}
