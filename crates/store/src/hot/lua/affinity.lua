-- All keys have the same organization hash tag. KEYS[1] is affinity:{org}.
-- The partition lease cleanup is performed by Rust after updating this index.
local p = cjson.decode(ARGV[1])
local base = KEYS[1]
local records, expiry, lru = base .. ':records', base .. ':expiry', base .. ':lru'
local stats, pending = base .. ':stats', base .. ':pending'
local now = now_ms()
local rotations = base .. ':rotations'
local rotation_expiry = base .. ':rotation_expiry'

local function rotation_field(sticky, partition)
  return sticky .. '|' .. partition.provider .. '|' .. partition.region
end

if p.op == 'rate' then
  local k = base .. ':rate'
  if redis.call('EXISTS', k) == 0 then
    redis.call('SET', k, 1, 'PX', p.window)
    return 0
  end
  if tonumber(redis.call('GET', k)) >= p.limit then
    return math.max(1, math.ceil(redis.call('PTTL', k) / 1000))
  end
  redis.call('INCR', k)
  return 0
end

if p.op == 'ack' then
  if redis.call('HGET', pending, p.sticky) == p.value then
    return redis.call('HDEL', pending, p.sticky)
  end
  return 0
end
for _, field in ipairs(redis.call('ZRANGEBYSCORE', rotation_expiry, '-inf', now)) do
  redis.call('HDEL', rotations, field)
end
redis.call('ZREMRANGEBYSCORE', rotation_expiry, '-inf', now)


if p.op == 'skip' then
  local field = rotation_field(p.sticky, p.partition)
  local value = redis.call('HGET', rotations, field)
  if not value then return false end
  local previous = cjson.decode(value)
  if previous.until_ms <= now then
    redis.call('HDEL', rotations, field)
    redis.call('ZREM', rotation_expiry, field)
    return false
  end
  return previous.unit
end

-- Expired entries cannot be hits, appear in listings, or trigger LRU eviction.
for _, sticky in ipairs(redis.call('ZRANGEBYSCORE', expiry, '-inf', now)) do
  redis.call('HDEL', records, sticky)
  redis.call('ZREM', lru, sticky)
end
redis.call('ZREMRANGEBYSCORE', expiry, '-inf', now)

local function forget(sticky, rotate)
  local value = redis.call('HGET', records, sticky)
  if not value then return false end
  redis.call('HSET', pending, sticky, value)
  redis.call('HDEL', records, sticky)
  redis.call('ZREM', expiry, sticky)
  redis.call('ZREM', lru, sticky)
  extend(pending, 86400000)
  if rotate then
    local record = cjson.decode(value)
    local ttl = record.ttl_ms
    redis.call('HSET', rotations, rotation_field(sticky, record.partition),
      cjson.encode({unit=record.unit, until_ms=now + ttl}))
    redis.call('ZADD', rotation_expiry, now + ttl, rotation_field(sticky, record.partition))
    extend(rotations, ttl)
    extend(rotation_expiry, ttl)
  end
  return true
end

local function touch_lru(sticky, ttl)
  local seq = redis.call('HINCRBY', stats, 'sequence', 1)
  redis.call('ZADD', lru, seq, sticky)
  redis.call('ZADD', expiry, now + ttl, sticky)
  for _, k in ipairs({records, expiry, lru, stats}) do
    extend(k, math.max(ttl, 86400000))
  end
end

-- Keep byte counts as decimal strings: Lua doubles lose precision above 2^53.
local function add_bytes(a, b)
  local i, j, carry, out = #a, #b, 0, ''
  while i > 0 or j > 0 or carry > 0 do
    local n = (i > 0 and tonumber(string.sub(a, i, i)) or 0)
      + (j > 0 and tonumber(string.sub(b, j, j)) or 0) + carry
    out = tostring(n % 10) .. out
    carry, i, j = math.floor(n / 10), i - 1, j - 1
  end
  local max = '18446744073709551615'
  if #out > #max or (#out == #max and out > max) then return max end
  return out
end

if p.op == 'touch' then
  local record = p.record
  local old = redis.call('HGET', records, record.sticky)
  record.created_at_ms, record.last_seen_ms, record.bytes = now, now, '0'
  if old then
    old = cjson.decode(old)
    if old.partition.provider ~= record.partition.provider
        or old.partition.region ~= record.partition.region or old.unit ~= record.unit then
      redis.call('HSET', pending, record.sticky, cjson.encode(old))
      extend(pending, 86400000)
    end
    record.created_at_ms, record.bytes = old.created_at_ms, old.bytes
  end
  record.ttl_ms = p.ttl
  redis.call('HSET', records, record.sticky, cjson.encode(record))
  touch_lru(record.sticky, p.ttl)
  redis.call('HINCRBY', stats, p.hit and 'hits' or 'misses', 1)
  if type(p.cap) == 'number' then
    local overflow = redis.call('ZCARD', lru) - p.cap
    if overflow > 0 then
      for _, sticky in ipairs(redis.call('ZRANGE', lru, 0, overflow - 1)) do
        if forget(sticky, false) then redis.call('HINCRBY', stats, 'evictions', 1) end
      end
    end
  end
  local field = rotation_field(record.sticky, record.partition)
  local previous = redis.call('HGET', rotations, field)
  if previous and cjson.decode(previous).unit ~= record.unit then
    redis.call('HDEL', rotations, field)
    redis.call('ZREM', rotation_expiry, field)
  end
  return redis.call('HVALS', pending)
elseif p.op == 'bytes' then
  if p.ttl == 0 then
    redis.call('HDEL', records, p.sticky)
    redis.call('ZREM', expiry, p.sticky)
    redis.call('ZREM', lru, p.sticky)
    return 0
  end
  local value = redis.call('HGET', records, p.sticky)
  if not value then return 0 end
  local record = cjson.decode(value)
  record.bytes = add_bytes(record.bytes, p.bytes)
  record.last_seen_ms = now
  record.ttl_ms = p.ttl
  redis.call('HSET', records, p.sticky, cjson.encode(record))
  redis.call('ZADD', expiry, now + record.ttl_ms, p.sticky)
  for _, k in ipairs({records, expiry, lru, stats}) do
    extend(k, math.max(record.ttl_ms, 86400000))
  end
  return 1
elseif p.op == 'rotate' then
  local found = forget(p.sticky, true)
  if found then redis.call('HINCRBY', stats, 'rotations', 1) end
  return {found and 1 or 0, redis.call('HVALS', pending)}
elseif p.op == 'list' then
  local result = {}
  for _, sticky in ipairs(redis.call('ZREVRANGE', lru, 0, -1)) do
    local value = redis.call('HGET', records, sticky)
    if value then result[#result + 1] = value end
  end
  return result
elseif p.op == 'stats' then
  local values = redis.call('HMGET', stats, 'hits', 'misses', 'evictions', 'rotations')
  return cjson.encode({entries=redis.call('ZCARD', lru), hits=tonumber(values[1]) or 0,
    misses=tonumber(values[2]) or 0, evictions=tonumber(values[3]) or 0,
    rotations=tonumber(values[4]) or 0})
end
return redis.error_reply('unknown affinity operation')
