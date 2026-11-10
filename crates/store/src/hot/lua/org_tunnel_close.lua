-- Stop counting a tunnel of an org, and remember that it ended so a late
-- org_tunnel_touch does not count it again.
-- KEYS[1] zset, KEYS[2] closed marker (same hash tag). ARGV: tunnel id,
-- marker ttl (ms). Returns 1 when the tunnel was counted.
redis.call('SET', KEYS[2], 1, 'PX', ARGV[2])
return redis.call('ZREM', KEYS[1], ARGV[1])
