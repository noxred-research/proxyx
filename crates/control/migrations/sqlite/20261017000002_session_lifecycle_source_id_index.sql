-- Traffic queries look up a source's session window by source_id alone
-- (query::bound_to_sessions).
CREATE INDEX IF NOT EXISTS session_lifecycle_source_id_idx ON session_lifecycle (source_id);
