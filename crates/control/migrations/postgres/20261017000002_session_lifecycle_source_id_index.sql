-- Traffic queries look up a source's session window by source_id alone
-- (query::bound_to_sessions). The existing (source, source_id) index needs
-- `source`, which a query branch does not always carry.
CREATE INDEX IF NOT EXISTS session_lifecycle_source_id_idx
    ON session_lifecycle (source_id);
