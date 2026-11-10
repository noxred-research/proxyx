# Policies

A policy tells ProxyX which units an org may lease, how many to keep ready, which IPs are good enough, what
to do when none is free, how blocks are handled and how much may be spent. Policies are TOML documents in
git, and can also be written through the [control API](gateway.md#control-api). The gateway and the warmer
both build their rules from the merged result, called the effective policy.

Related: [gateway.md](gateway.md) (how a request uses the policy), [providers.md](providers.md) (adapters and
the warmer), [configuration.md](configuration.md) (process settings, which are not policy).

- [Policy document](#policy-document)
- [Scopes and precedence](#scopes-and-precedence)
- [Field reference](#field-reference)
- [Effective policy](#effective-policy)
- [Validation](#validation)
- [The shipped global policy](#the-shipped-global-policy)
- [Storage, sync and changes](#storage-sync-and-changes)

## Policy document

A policy file is a list of `[[policy]]` tables. Every field except `name` is optional, and an unknown field,
a wrong type or bad syntax is an error. Durations are an integer of seconds or a string with a unit:
`30`, `30s`, `5m`, `2h`, `1d`, at most 366 days.

```toml
[[policy]]
name = "fr-web"                  # unique across all files
scope = "route_class"            # global (default) | route_class | org
match = "oxylabs_isp"            # provider id (route_class) or org id (org); absent for global
kinds = ["static", "rotating"]   # preference order
regions = ["fr/paris", "fr"]     # fallback order; required after merging
min_ready = 10

[policy.criteria]
max_risk = 75

[policy.on_empty]
rotating = "create"
```

The same document in JSON is what `PUT /v1/policies` takes, with `match` for the target and nested objects
for the sub-tables. In the TOML tables the static section is `[policy.static]` (a JSON key `static`).

`data/policies/global.toml` spells out every default and is the reference file; see
[The shipped global policy](#the-shipped-global-policy).

## Scopes and precedence

| Scope | Covers | `match` |
| --- | --- | --- |
| `global` (default) | Every org and provider. At most one in the whole set. | not allowed |
| `route_class` | One provider (a route class is a provider plus a region). | a provider id |
| `org` | One org. | an org id |

The effective policy of an org on a provider is the chain `global`, then the provider's `route_class`
policy, then the org's own policy, applied field by field:

- A field that a more specific policy sets replaces the value of a less specific one; a field it leaves
  out keeps the less specific value.
- Lists (`kinds`, `providers`, `regions`) are replaced as a whole.
- `min_ready_by_region` merges per region: the more specific policy's entries win for the same region and
  the others stay.
- Each sub-table (`criteria`, `on_empty`, `block`, `static`, `mobile_box`, `rotating`, `rotating.stability`,
  `cost`) merges per field.
- `limits` are ceilings: the **lowest** value in the chain wins, so a lower scope can lower a ceiling and
  never raise it.

A route-class policy applies to every org on that provider. An org's policy applies to that org on every
provider. Where both exist the org value wins. An org that has no policy of its own gets the global and
route-class values. Merging happens once when the set is loaded, so a request only looks the result up.

The warmer has no org of its own: it uses the policy of an org that has no policy, merged with the provider's
route class. The control API uses the probe org (`probe_org`, default `proxyx-probe`) for operator block
reports and canary results.

## Field reference

Defaults are applied after merging. "unset" means the rule is off or a derived value is used.

### Selection

| Field | Type | Default | Meaning |
| --- | --- | --- | --- |
| `name` | string | required | Unique across the set, at most 128 bytes through the API; used in errors and audit. |
| `scope` | `global`, `route_class`, `org` | `global` | See [Scopes](#scopes-and-precedence). |
| `match` | string | none | Provider id or org id, by scope. |
| `kinds` | list of `static`, `rotating` | `["static", "rotating"]` | Kinds in preference order. Not empty, no duplicates. |
| `providers` | list of provider ids | unset: every configured provider | Provider priority order. Must not be an empty list; no duplicates. |
| `regions` | list of regions | none: **required** | Regions in fallback order; not empty, no duplicates. See [Regions](#regions). |
| `pool` | `shared` | `shared` | Only `shared` is accepted. `private` is refused at load, because partitions have no org dimension; use a [customer upstream](providers.md#customer-upstreams) for a unit one org alone may use. |
| `sticky_scope` | `org`, `target`, `connection` | `org` | What the lease key is bound to when the caller sends no `sid`; see [sticky keys](gateway.md#sticky-keys). |

### Capacity

| Field | Type | Default | Meaning |
| --- | --- | --- | --- |
| `min_ready` | count | 10 | Per region. Rotating: ready sessions the warmer keeps. Static: healthy leasable IPs expected. |
| `max_ready` | count | unset: 2 x the region's `min_ready` | Most ready sessions a partition holds. It caps every session the provider has given, leased ones included. |
| `low_watermark` | count | unset: half the region's `min_ready` | Ready units below this raise the cache-low state. |
| `low_for` | duration | `2m` | How long ready units must stay below the watermark before the cache counts as low (`cache_low`, the alert's input). Zero is allowed: low at once. |
| `min_ready_by_region` | table of region to count | empty | `min_ready` overrides: the exact region, else its country, else `min_ready`. `max_ready` and `low_watermark` follow the override when unset. |

### `criteria`

What makes an IP or session good enough. The reputation rule and the light probe use them when a unit is
admitted or re-checked, and the canary and browser samples use the time and success limits.

| Field | Type | Default | Meaning |
| --- | --- | --- | --- |
| `max_risk` | 0 to 100 | 75 | Highest accepted reputation risk. A score above it, or a `tor` flag, drains the unit. From 50 up to this value the unit is re-checked soon; twice in a row drains. |
| `max_ttfb_ms` | at least 1 | 3000 | Time to first byte a probe sample may take to count as good. Clean answers over it make the unit *degraded*, not bad. |
| `max_load_ms` | at least 1 | 10000 | Page load time limit of a browser sample or canary run. |
| `min_success` | 0 to 1 | 0.66 | Lowest share of good probe requests. |
| `browser_sample` | 0 to 1 | 0.05 | Share of new candidates that also get a browser test. |
| `verdict_max_age` | duration above 0 | `24h` | A browser verdict older than this is ignored. |

### `on_score_unavailable`

`allow` (default) or `deny`: what to do when every reputation scorer is down, over budget or not configured,
and no cached score exists. `allow` treats the IP as clean (and logs a warning); `deny` treats it as
unverified, so it is not admitted. See [providers.md](providers.md#reputation-scorers).

### Lease behaviour

| Field | Type | Default | Meaning |
| --- | --- | --- | --- |
| `lease_ttl` | duration above 0 | `10m` | Idle time after which a lease ends. A request's `ttl` option may only be lower. |
| `lease_wait` | duration | `3s` | With `on_empty = wait`, how long a request waits for a free or shareable unit. |
| `create_deadline` | duration above 0 | `6s` | With `on_empty = create`, how long a new session may take (two tries). Also bounds waiting for creates other tunnels started. |
| `orgs_hard` | count, at least 1 | unset | Cap on distinct orgs per IP or session. A soft limit. |
| `max_conns_per_ip` | count, at least 1 | unset: 80% of the adapter's `max_conns_per_ip` (at least 1) | Tunnels per IP. A soft limit with a ceiling of twice the value (never above the adapter's limit). With neither set, there is no cap. |
| `rest_after_release` | duration | `30s` | How long a unit rests between two orgs. A soft limit. Zero is allowed. |
| `max_tunnels_per_org` | count, at least 1 | unset: no cap | Cap on open tunnels of an org. In a route-class policy it caps the org's tunnels on that provider only; the global or org value caps the org in total. |

`rest_after_release`, `orgs_hard` and `max_conns_per_ip` are soft limits. A unit they keep back is skipped
while another unit is free of them; with none left, the lease breaks them lowest first (rest, then
`orgs_hard`, then `max_conns`, then the monthly fair-use stop), and `lease_limit_broken_total{limit,provider}`
counts it. See [gateway.md](gateway.md#lease-walk-and-soft-limits).

### `on_empty`

What the gateway does when no unit can be leased, per kind:

| Key | Values | Default | Meaning |
| --- | --- | --- | --- |
| `static` | `wait`, `fail` | `wait` | `create` is refused for static: static IPs are rented, never created. |
| `rotating` | `create`, `wait`, `fail` | `create` | `create` opens a session inside `create_deadline`; `wait` waits up to `lease_wait`; `fail` refuses at once. |

### `block`

How block signals (from the session proxy, probes and operators) are handled, narrow to wide.

| Field | Type | Default | Meaning |
| --- | --- | --- | --- |
| `target_cooldown` | duration above 0 | `30m` | An IP that a target blocks is cooled for that target this long. |
| `escalate_targets` | count, at least 1 | 3 | Distinct targets inside `signal_window` that block the IP for all targets. |
| `escalate_signals` | count, at least 1 | 5 | Signals inside `signal_window` that block the IP for all targets. |
| `signal_window` | duration above 0 | `30m` | Window of the two escalation counts. |
| `max_cooldown_share` | above 0 up to 1 | 0.5 | Share of a static partition that may already be cooled before escalation stops (the pool guard). |

Reaction to one signal: (1) the exit IP is cooled for that target; (2) at `escalate_targets` distinct targets or
`escalate_signals` signals inside the window the IP leaves leasing for all targets (a rotating session leaves
the ready set; a static IP goes to *cooldown*, or *quarantined* after `static.quarantine_after` IP-wide
blocks in an hour; a SIM box is also marked for a rotation); (3) when `max_cooldown_share` of the shared
static IPs of the partition is already cooled, escalation stops, so a hostile target that fakes block pages
can only cool its own target. Rotating sessions need no guard. A customer's own upstream is only cooled and is
no part of the shared pool.

### `static` and `mobile_box`

`static` is care of rented IPs; `mobile_box` applies to the static subtype `mobile_box` (SIM boxes).

| Field | Type | Default | Meaning |
| --- | --- | --- | --- |
| `static.cooldown` | duration above 0 | `15m` | Rest of an IP after an IP-wide block before it is retested. |
| `static.quarantine_after` | count | 3 | IP-wide blocks within 1 hour that quarantine an IP. |
| `static.retest_every` | duration above 0 | `6h` | Retest spacing of a quarantined IP. |
| `static.recheck_every` | duration above 0 | `30m` | Re-check interval of a leasable IP. |
| `static.replace_after_checks` | count | 3 | Consecutive reputation checks that must each be bad. |
| `static.replace_min_sources` | count | 2 | Scoring services that must be above `criteria.max_risk` in each of those checks. |
| `static.replace_blocked_share` | above 0 up to 1 | 0.6 | Share of test targets that must block, on two probes in a row. |
| `static.replace_quarantine_for` | duration above 0 | `24h` | Time in quarantine that ends in a replacement request. |
| `mobile_box.rotate_attempts` | count | 3 | Failed resets in a row that make a box `replace_requested`. |
| `mobile_box.rotate_timeout` | duration above 0 | `120s` | How long a reset polls the exit IP for a change. |
| `mobile_box.rotate_min_interval` | duration | `60s` | Minimum spacing between resets of one box. |
| `mobile_box.rotate_per_hour` | count | 6 | Most resets of one box per hour. |
| `mobile_box.drain_wait` | duration | `60s` | How long a reset waits for open leases to end (a reset cuts tunnels). |
| `mobile_box.offline_after` | duration above 0 | `60s` | A silent box becomes *offline* after this. |

An IP that meets any one replacement rule (bad reputation in `replace_after_checks` consecutive checks, blocked on two probes
in a row, quarantined for `replace_quarantine_for`, or resets that keep failing) becomes `replace_requested`:
a developer replaces it in the provider panel and updates the inventory. See
[providers.md](providers.md#the-warmer).

### `rotating`

| Field | Type | Default | Meaning |
| --- | --- | --- | --- |
| `ready_ttl` | duration above 0 | `30m` | A ready session that nobody uses is drained after this. |
| `max_age` | duration above 0 | unset: 80% of the adapter's `max_session_minutes` | Total life of a session. Never more than the provider keeps it. |
| `min_remaining` | duration above 0 | `5m` | Life a session must have left to take a new lease. |
| `after_release` | `drain`, `reuse_same_org` | `drain` | What happens to a session when its lease ends: leave it to drain, or keep it for the same org. |
| `refill_concurrency` | count | 2 | Creates the warmer runs at once per partition. |
| `refill_rate` | count | 10 | Creates per minute per provider (a token bucket of this size). |
| `headroom` | count | 0 | Extra ready sessions per lease per minute: `ceil(headroom x lease rate)`; the floor of the extra target. |
| `headroom_auto` | bool | `false` | Also cover the leases that arrive while one create runs (lease rate x measured create time); `headroom` stays the floor. |
| `keepalive` | duration above 0 | `30s` | Interval of the neutral keepalive request. The effective interval is `min(keepalive, lease_ttl / 2)`. |
| `recheck_every` | duration above 0 | `5m` | Interval of the reputation re-check of a ready session (run with its keepalive). |
| `stability.changes_per_hour` | count | 2 | IP changes of a session per hour above which it drains. A changed exit IP within the limit is re-checked and adopted. |
| `stability.drops_per_hour` | count | 3 | Failed keepalives (no echo answer, or an unverifiable new IP) per hour above which it drains. Three failed keepalives in a row drain it regardless. |

### `cost` and `limits`

`cost` is the spend the warmer and the gateway keep to; `limits` are ceilings above which `cost` may not go.

| Field | Default | Meaning |
| --- | --- | --- |
| `cost.max_gb_per_day` | 5 | Rotating: traffic per provider and UTC day, in decimal GB. |
| `cost.max_creates_per_hour` | 600 | Rotating: session creates per provider and UTC hour. |
| `cost.fair_use_gb_per_ip_month` | 80 | Static: fair-use traffic per IP and month. |
| `limits.max_gb_per_day` | unset | Ceiling for `cost.max_gb_per_day`. |
| `limits.max_creates_per_hour` | unset | Ceiling for `cost.max_creates_per_hour`. |
| `limits.fair_use_gb_per_ip_month` | unset | Ceiling for `cost.fair_use_gb_per_ip_month`. |
| `limits.org_max_gb_per_day` | unset: no budget | Traffic one org may use per UTC day across all providers. At the limit, new tunnels get `503 org_budget`; open tunnels are not cut. `0` is spent from the start. |

Warmer budget behaviour: at 80% of a day or hour limit the warmer only keeps `min_ready`, one create at a time;
at 100% it creates nothing until the window ends. A `cost` value above its ceiling makes the whole set invalid.
A `cost` value that is unset while its ceiling is below the default takes the ceiling. Fair use is per IP and shared by every org on the IP, so only `global` and `route_class` policies may set
`cost.fair_use_gb_per_ip_month` or `limits.fair_use_gb_per_ip_month`; an `org` policy that does is refused.
For a static IP the gateway warns at 80% of fair use and stops new leases of the IP at 100% until the month ends.

## Regions

A region is a lowercase ISO 3166-1 alpha-2 country, optionally with a city slug: `fr` or `fr/paris`. The country
is two ASCII letters; the city is 1 to 48 characters of `[a-z0-9_]`. Input is lowercased; anything else is
refused. Both forms are written with `/` in policies and the API and with `cc` and `city` options in the
[username](gateway.md#username-grammar).

- Order matters: `regions` is the fallback order, tried in turn.
- A region **satisfies** a wanted region when it has the same country and, if the wanted region names a city,
  the same city. `fr/paris` satisfies `fr`; `fr` does not satisfy `fr/paris`.
- A request's region must be covered by a policy region: a request for `fr/paris` is allowed by `fr` or `fr/paris`;
  a request for `fr` only by `fr`.
- Rotating partitions are exactly the policy regions. A static partition is the region of an inventory entry that
  satisfies a policy region, so `fr` serves inventory in `fr/paris` and `fr/lyon`.
- For rotating providers the exit country is verified against the region's country; the city is advice only.

## Effective policy

The effective policy is the merged and defaulted result for one org on one provider. It is what the gateway,
the warmer and the control API read. Three further results are derived from it:

- **Capacity per region**: `min_ready` is the override for the exact region, else its country, else the policy
  value; `max_ready` is 2 x that unless set; `low_watermark` is half of it unless set.
- **Session life**: `max_age` is the configured value, or 80% of the adapter's provider maximum, never more than
  the maximum. A new session is shortened by up to 20% so sessions created together do not end together.
- **Connections per IP**: `max_conns_per_ip`, or 80% of the adapter's `max_conns_per_ip`, at least 1.

A request narrows the effective policy with its username options and gets a lease request: the kinds, providers,
regions and idle time it may use. See [How options narrow the policy](gateway.md#how-options-narrow-the-policy).

## Validation

Defaults are applied and every rule is checked for each merged combination: the base policy, each route class
and each org. Any failure makes the whole set invalid; the gateway and the warmer then keep their last good
set, set `config_reload_failed{source="policies"}` and log the file, policy and field to fix.

Set-level checks:

| Check | Error |
| --- | --- |
| Empty `name` | `policy "...": name must not be empty` |
| Two policies with one `name` | `duplicate policy name "..."` |
| Two `global` policies, or two for one `(scope, match)` | `duplicate <scope> policy for "..."` |
| `global` with `match` | `a global policy takes no match` |
| `route_class` or `org` without `match` | `a <scope> policy needs match` |
| `match` that is not a valid provider or org id | `match: invalid ...` |
| An `org` policy that sets a fair-use value | `fair_use_gb_per_ip_month is per IP and shared by every org; set it in a global or route_class policy` |

Field checks (reported as `<policies merged>: <field>: <reason>`):

| Field | Rule |
| --- | --- |
| `kinds` | not empty, no duplicates |
| `providers` | not empty when set, no duplicates |
| `regions` | required after merging, not empty, no duplicates |
| `pool` | only `shared` |
| `min_ready`, `min_ready_by_region` | each at most `max_ready` when set |
| `low_watermark` | at most each `min_ready` |
| `criteria.max_risk` | 0 to 100 |
| `criteria.max_ttfb_ms`, `criteria.max_load_ms` | at least 1 |
| `criteria.min_success`, `criteria.browser_sample` | 0 to 1 |
| `criteria.verdict_max_age`, `lease_ttl`, `create_deadline`, `block.target_cooldown`, `block.signal_window`, `static.cooldown`, `static.retest_every`, `static.recheck_every`, `static.replace_quarantine_for`, `mobile_box.rotate_timeout`, `mobile_box.offline_after`, `rotating.ready_ttl`, `rotating.max_age`, `rotating.min_remaining`, `rotating.keepalive`, `rotating.recheck_every` | above 0 |
| `orgs_hard`, `max_conns_per_ip`, `max_tunnels_per_org`, `block.escalate_*`, `static.quarantine_after`, `static.replace_after_checks`, `static.replace_min_sources`, `mobile_box.rotate_attempts`, `mobile_box.rotate_per_hour`, `rotating.refill_concurrency`, `rotating.refill_rate`, `rotating.stability.*` | at least 1 |
| `block.max_cooldown_share`, `static.replace_blocked_share` | above 0 up to 1 |
| `on_empty.static` | `wait` or `fail`; `create` is refused |
| `rotating.min_remaining` | below `rotating.max_age` when that is set |
| `limits.*_gb_*`, `cost.*_gb_*` | finite and at least 0 |
| `cost.*` | at most its `limits.*` ceiling: `<context>: <field> <value> is above the ceiling <ceiling>` |
| Any duration | at most 366 days |

Checks against adapters, run where policies meet adapters (when the stored set is loaded and before the API
stores a write): for every rotating provider, `rotating.min_remaining` must be below 80% of the provider's session
life (`max_age`, or 80% of `max_session_minutes`, then shortened by up to 20%), or no session could ever be leased.
The API additionally refuses a write whose policy no loaded adapter can serve: a static provider needs an
inventory entry in one of the policy regions (or the org's own), a rotating one an adapter in `kinds`.

## The shipped global policy

`data/policies/global.toml` is the global policy with every default spelled out. Loaded from
`<data_dir>/policies`, it is the reference: each key shown is the default value, and the commented keys are
the ones with no default.

| Section of the file | Fields |
| --- | --- |
| top level | `kinds = ["static", "rotating"]`, `regions = ["fr", "de"]` (the one value with no default: edit it), `pool = "shared"`, `min_ready = 10`, `low_for = "2m"`, `lease_ttl = "10m"`, `lease_wait = "3s"`, `create_deadline = "6s"`, `rest_after_release = "30s"`, `sticky_scope = "org"`, `on_score_unavailable = "allow"` |
| commented out | `providers`, `orgs_hard`, `max_tunnels_per_org`, `max_conns_per_ip`, `max_ready` and `low_watermark` (derived from `min_ready`) |
| `[policy.min_ready_by_region]` | empty; example `"fr/paris" = 20` |
| `[policy.criteria]` | `max_risk = 75`, `max_ttfb_ms = 3000`, `max_load_ms = 10000`, `min_success = 0.66`, `browser_sample = 0.05`, `verdict_max_age = "24h"` |
| `[policy.on_empty]` | `static = "wait"`, `rotating = "create"` |
| `[policy.block]` | `target_cooldown = "30m"`, `escalate_targets = 3`, `escalate_signals = 5`, `signal_window = "30m"`, `max_cooldown_share = 0.5` |
| `[policy.static]` | `cooldown = "15m"`, `quarantine_after = 3`, `retest_every = "6h"`, `recheck_every = "30m"`, `replace_after_checks = 3`, `replace_min_sources = 2`, `replace_blocked_share = 0.6`, `replace_quarantine_for = "24h"` |
| `[policy.mobile_box]` | `rotate_attempts = 3`, `rotate_timeout = "120s"`, `rotate_min_interval = "60s"`, `rotate_per_hour = 6`, `drain_wait = "60s"`, `offline_after = "60s"` |
| `[policy.rotating]` | `ready_ttl = "30m"`, `min_remaining = "5m"`, `after_release = "drain"`, `refill_concurrency = 2`, `refill_rate = 10`, `headroom = 0`, `keepalive = "30s"`, `recheck_every = "5m"`; `max_age` unset |
| `[policy.rotating.stability]` | `changes_per_hour = 2`, `drops_per_hour = 3` |
| `[policy.cost]` | `max_gb_per_day = 5`, `max_creates_per_hour = 600`, `fair_use_gb_per_ip_month = 80` |
| `[policy.limits]` | all commented out: no ceilings |

A deployment adds its own files next to it. For example, a route-class policy for one provider and a stricter
policy for one org:

```toml
[[policy]]
name = "isp-fr"
scope = "route_class"
match = "oxylabs_isp"
regions = ["fr/paris", "fr"]
max_tunnels_per_org = 100

[[policy]]
name = "acme"
scope = "org"
match = "acme"
kinds = ["rotating"]
regions = ["de"]
[policy.limits]
org_max_gb_per_day = 20
```

## Storage, sync and changes

Postgres is the source of truth. Every policy is a row per `(scope, name)` version; the document is stored in its
canonical form (unset fields omitted, durations as seconds), and a version is current until a newer one replaces
it. The gateway and the warmer load the current versions into a merged set every `reload_every` (default
30 s). A reload that fails, or yields an invalid set, keeps the last good set.

### From git

The gateway syncs the policy files under `<data_dir>/policies` into Postgres as actor `gitops` (the warmer only
reads). Details:

- A policy is written only when its document differs from the last one `gitops` stored for it, so editing one
  file, or a comment, leaves every other policy, and an operator's change to it, alone.
- Git wins for the policies it changed: the operator's version is replaced, the audit row names who was replaced
  and the sync logs a warning. A git document equal to the operator's current one still becomes git's own version.
- A policy that a git file no longer defines is deactivated, but only when `gitops` wrote its current version.
- The git set is validated together with the policies that stay (those written through the API) before anything
  is written. If the combination is invalid, nothing is written and the sync reports it; fix the conflict with
  `GET /v1/policies` and `DELETE /v1/policies/{scope}/{name}`.
- The tree that was applied is remembered in the process, and each gateway records its tree in Postgres. A gateway
  whose tree differs from the stored one leaves the stored policies alone while a gateway that runs the stored tree
  is alive, so a rolling update does not make replicas fight; once none is alive, it applies (a rollback).

### Through the API

All routes need the admin token and are described in [gateway.md](gateway.md#control-api):

| Route | Use |
| --- | --- |
| `GET /v1/policies` | List the current version of every policy, with its version and actor. |
| `PUT /v1/policies` | Store 1 to 200 documents. |
| `PUT /v1/orgs/{org}/cache-policy` | Store the policy of one org (`scope = org`, `match` the org, `name` defaults to `org-<org>`). |
| `DELETE /v1/policies/{scope}/{name}` | Stop using an API-written policy. |

Every write is validated as part of the whole set before it is stored. Per-org changes through the API are the
usual path for tenant tuning; `global` and `route_class` policies belong to git, and an API write to one of
them is an emergency change that stays until git changes that same policy. A policy that git defines and the API
deleted returns at the next reload. A policy whose current version git wrote can only be removed by deleting its
file.

A policy change takes effect on each gateway after its next reload, within `reload_every`.
