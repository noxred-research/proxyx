-- source_id is required at session creation. The original migration left
-- the column nullable for legacy callers; the wire/API contract now
-- rejects empty/missing source_id at /sessions ingress, so no new rows
-- arrive with NULL. Enforce that invariant in the schema.
--
-- Any pre-existing NULL rows represent abandoned legacy sessions and
-- are removed; they would otherwise break the new (org_id, source_id)
-- primary lookup invariants in the API.

DELETE FROM session_lifecycle WHERE source_id IS NULL;

ALTER TABLE session_lifecycle ALTER COLUMN source_id SET NOT NULL;
