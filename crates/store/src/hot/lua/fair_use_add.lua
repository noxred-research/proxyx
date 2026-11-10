-- ARGV[1] JSON: tag, ip, month ("202610"), bytes, limit (bytes, 0 = none),
-- warn_at (bytes), stop_ms (ms until the month ends), counter_ttl (ms).
-- Returns {used, warned, stopped}: `warned` and `stopped` are 1 only for the
-- call that crossed the threshold.
local p = cjson.decode(ARGV[1])
local key = 'fair:' .. p.tag .. ':' .. p.ip .. ':' .. p.month
local after = redis.call('INCRBY', key, p.bytes)
redis.call('PEXPIRE', key, p.counter_ttl)
local before = after - p.bytes
local warned, stopped = 0, 0
if p.limit > 0 then
  if before < p.warn_at and after >= p.warn_at then
    warned = 1
  end
  if after >= p.limit then
    redis.call('SET', 'fairstop:' .. p.tag .. ':' .. p.ip, 1, 'PX', math.max(p.stop_ms, 1))
    if before < p.limit then
      stopped = 1
    end
  end
end
return { after, warned, stopped }
