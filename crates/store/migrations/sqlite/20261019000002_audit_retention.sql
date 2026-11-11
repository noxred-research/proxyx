-- Retention of the audit rows the system writes by itself: a
-- state change, a reset request and a replacement report are written on every
-- check or signal and nothing reads them after a few weeks, so the warmer
-- deletes them after 90 days (`Db::prune_history`). Everything an operator or
-- a git sync did stays, and no row can be changed or deleted before that age.
DROP TRIGGER IF EXISTS audit_no_delete;
CREATE TRIGGER audit_no_delete BEFORE DELETE ON audit
FOR EACH ROW
WHEN NOT (OLD.at < CAST(strftime('%s', 'now') AS INTEGER) * 1000000 + (CAST(ROUND(strftime('%f', 'now') * 1000) AS INTEGER) % 1000) * 1000 - 90 * 86400000000
          AND OLD.action IN ('inventory.transition', 'ip.rotate_requested',
                             'inventory.replacement_report'))
BEGIN
    SELECT RAISE(ABORT, 'audit rows are append-only');
END;

-- Deleting by age walks the table by time.
CREATE INDEX IF NOT EXISTS audit_at ON audit (at);
CREATE INDEX IF NOT EXISTS ip_scores_checked_at ON ip_scores (checked_at);
