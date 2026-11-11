-- Extend a counted tunnel, and count it again when the zset forgot it (Redis
-- lost its data, or was out for longer than the tunnel TTL). A tunnel that
-- org_tunnel_close ended is not counted again: its marker blocks a touch that
-- was already in flight when the tunnel closed. The zset expires with its
-- latest deadline, as in org_tunnel_open.
-- KEYS[1] zset, KEYS[2] closed marker (same hash tag). ARGV: tunnel id, ttl (ms).
-- Returns 1 when the tunnel is counted, 0 when it was closed.
local ttl = tonumber(ARGV[2])
if redis.call('ZSCORE', KEYS[1], ARGV[1]) == false and redis.call('EXISTS', KEYS[2]) == 1 then
  return 0
end
redis.call('ZADD', KEYS[1], now_ms() + ttl, ARGV[1])
extend(KEYS[1], ttl)
return 1
