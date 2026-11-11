-- source_id is required at session creation (see the Postgres migration).
DELETE FROM session_lifecycle WHERE source_id IS NULL;
ALTER TABLE session_lifecycle MODIFY source_id VARCHAR(255) NOT NULL;
