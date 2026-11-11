-- A degraded IP is leasable but slow: clean answers over the TTFB or load limit.
-- The gateway leases it only when no normal IP is left.
ALTER TABLE inventory DROP CONSTRAINT IF EXISTS inventory_state_check;
ALTER TABLE inventory ADD CONSTRAINT inventory_state_check CHECK (state IN (
    'candidate', 'available', 'leased', 'degraded', 'cooldown', 'quarantined',
    'rotating', 'offline', 'replace_requested', 'retired'));
