-- Drop a reservation or an in-flight create. ARGV[1] JSON: tag, id.
local p = cjson.decode(ARGV[1])
return redis.call('ZREM', 'reserve:' .. p.tag, p.id) + redis.call('ZREM', 'creating:' .. p.tag, p.id)
