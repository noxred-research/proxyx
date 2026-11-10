-- KEYS[1] zset. Returns the number of live tunnels.
redis.call('ZREMRANGEBYSCORE', KEYS[1], '-inf', now_ms())
return redis.call('ZCARD', KEYS[1])
