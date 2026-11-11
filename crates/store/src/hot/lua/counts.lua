-- ARGV[1] JSON: tag. Returns {free, degraded free, leased, creating, reserved}.
-- KEYS[1] ready:T, passed only to name the cluster slot: every key the script
-- touches carries the same hash tag T (see common.lua).
local p = cjson.decode(ARGV[1])
local free, leased, creating, reserved, degraded = counts(p.tag, now_ms())
return { free, degraded, leased, creating, reserved }
