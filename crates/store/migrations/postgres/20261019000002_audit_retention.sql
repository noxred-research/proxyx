-- Retention of the audit rows the system writes by itself: a
-- state change, a reset request and a replacement report are written on every
-- check or signal and nothing reads them after a few weeks, so the warmer
-- deletes them after 90 days (`Db::prune_history`). Everything an operator or
-- a git sync did stays, and no row can be changed or deleted before that age.
CREATE OR REPLACE FUNCTION audit_append_only() RETURNS trigger AS $$
BEGIN
    IF TG_OP = 'DELETE' THEN
        IF OLD.at < now() - interval '90 days'
           AND OLD.action IN ('inventory.transition', 'ip.rotate_requested', 'inventory.replacement_report') THEN
            RETURN OLD;
        END IF;
    END IF;
    RAISE EXCEPTION 'audit rows are append-only';
END;
$$ LANGUAGE plpgsql;

-- Deleting by age walks the table by time.
CREATE INDEX IF NOT EXISTS audit_at ON audit (at);
CREATE INDEX IF NOT EXISTS ip_scores_checked_at ON ip_scores (checked_at);
