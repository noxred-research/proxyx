# Providers

ProxyX leases IPs from upstream proxy providers. A provider is described by a **provider adapter**: a TOML
file, not code. The adapter says where the upstream is, how to build the credential for one lease, which
target ports are allowed and how to reset a SIM box. The same adapter is used by the gateway to dial, by the
warmer to create and check units, and by the control API to validate a customer's upstream.

ProxyX bundles no provider accounts. The shipped adapters in `data/adapters/` are **worked examples**: the
vendor ones (Oxylabs, IPRoyal, Webshare and Bright Data) show how a real grammar is expressed, and you bring
your own accounts and verify the current grammar with your provider before use. Everything is configured in
data files and secret files; see [configuration.md](configuration.md) for process settings,
[policies.md](policies.md) for what a lease may use, and [gateway.md](gateway.md) for how a request reaches an
adapter.

- [Model](#model)
- [Adapter file](#adapter-file)
- [Options and fragments](#options-and-fragments)
- [The deterministic recipe](#the-deterministic-recipe)
- [Load-time checks](#load-time-checks)
- [Shipped adapters](#shipped-adapters)
- [Static inventory file](#static-inventory-file)
- [Local units](#local-units)
- [Customer upstreams](#customer-upstreams)
- [Mobile boxes](#mobile-boxes)
- [The warmer](#the-warmer)
- [Exit-IP verification](#exit-ip-verification)
- [Reputation scorers](#reputation-scorers)
- [Probe targets](#probe-targets)
- [Secrets directory](#secrets-directory)

## Model

| Term | Meaning |
| --- | --- |
| Provider | One adapter, identified by its id (`[a-z0-9_-]{1,48}`, for example `oxylabs_isp`). |
| Kind | `static` or `rotating`, which drives the cache, the warmer and the lease. |
| Subtype | The product family. Each subtype belongs to exactly one kind. |
| Route class / partition | A provider plus a region. The unit of warming, locking, breakers and Redis keys. |
| Unit | What one lease holds: a static IP (or SIM box, or customer upstream), or a rotating session. |

| Kind | Subtypes | What a unit is | Who makes units |
| --- | --- | --- | --- |
| `static` | `datacenter`, `isp`, `mobile_box` | A rented IP or modem from the inventory. Nothing is created. | You list them in the [inventory](#static-inventory-file); the warmer verifies them. |
| `rotating` | `residential`, `mobile`, `isp_rotating` | A quota-based provider session. `session_mode = "per_request"` instead describes an independently rotating endpoint, not a reusable pooled exit. | The warmer and gateway create sticky sessions; direct recipes also support per-request endpoints. |

`mobile_box` is a static subtype: a fixed endpoint whose exit IP changes when it is reset (see
[Mobile boxes](#mobile-boxes)).

## Adapter file

The adapters directory is `<data_dir>/adapters/` (`data_dir` defaults to `/etc/proxyx/data`). Every `*.toml`
file in it is read, in name order, with no recursion. A file holds `[[adapter]]` tables; options are
`[[adapter.option]]` sub-tables. Unknown keys are errors. The first unreadable file, TOML error, adapter that
cannot work, unreadable secret or duplicate id fails the whole load, because a provider that silently
disappears would be worse. After the first load, a reload that fails keeps the last good adapters and sets
`config_reload_failed{source="adapters"}`.

### Keys of `[[adapter]]`

| Key | Type | Default | Meaning |
| --- | --- | --- | --- |
| `id` | provider id | required | Unique across all files. |
| `kind` | `static` or `rotating` | required | Must agree with `subtype`; written out so a file reads on its own. |
| `subtype` | see the table above | required | |
| `scheme` | `http`, `https`, `socks5` or `local` | `http` | Protocol to the upstream: HTTP CONNECT, TLS-protected HTTP CONNECT, or SOCKS5. `https` encrypts the proxy hop and verifies its certificate; it does not intercept destination TLS. `local` uses the machine's own exit IP. |
| `host` | string | none | Upstream host. The only template placeholder allowed is `{opts}` (where an option with `to = "host"` goes). Required for rotating adapters. A static adapter that leaves it out dials the `host` of each inventory entry. |
| `port` | 1 to 65535 | none | Upstream port. Required for a rotating adapter unless an option sets it. A static adapter that leaves it out dials the `port` of each inventory entry (a port-per-IP gateway). |
| `user_file` | string | none | Secret file with the base username. |
| `pass_file` | string | none | Secret file with the base password. |
| `credentials_optional` | bool | `false` | A missing base username or password renders as empty instead of failing (an upstream that needs no login). |
| `user` | template | `"{base_user}{opts}"` | Username template. |
| `pass` | template | `"{base_pass}{opts}"` | Password template. |
| `allowed_ports` | list of ports | empty: any | Target ports the provider allows. A target port outside the list is `403 port_not_allowed` (when every candidate provider refuses it). |
| `max_conns_per_ip` | count above 0 | none | Provider cap on tunnels per IP, for the lease counters. It is the hard ceiling of the policy's `max_conns_per_ip`; when the policy leaves it unset, 80% of this is used. |
| `max_session_minutes` | count above 0 | none | Explicit upper bound on a requested session duration and the base of `rotating.max_age`. When unset, default sessions use 30 minutes; an option's `max` still limits rendered values. A provider without a duration option receives no duration parameter. |
| `session_mode` | `sticky` or `per_request` | `sticky` | `sticky` requires a `sid` option. `per_request` forbids `sid`, `ttl` and `strict` options and rotates exits per request. These endpoints cannot satisfy stable exit-IP pool/session validation. |
| `echo_url` | http(s) URL | none | The provider's echo endpoint, which returns the exit IP as plain text. It is one more vote in the exit-IP check and the target of rotating keepalives. |
| `public_only` | bool | `false` | The upstream address of every unit must be public routable. Set by the `customer` adapters. |
| `rotate` | table | none | How to reset a SIM box. Required for subtype `mobile_box`, refused for any other. |

Template placeholders for `user` and `pass`: `{base_user}`, `{base_pass}` (from the secret files, or from the
inventory entry's own credentials) and `{opts}` (the rendered option fragments that write to that field). Any
other placeholder, an unclosed `{` or an unmatched `}` is an error.

### Per-unit credentials

A static inventory entry may name a `credentials` file; it then replaces the adapter's base username and
password for that unit. A static adapter therefore needs no `user_file` when every entry brings its own
credentials. The file holds `username:password`; see [Secrets directory](#secrets-directory).

## Options and fragments

An option writes one fragment of the lease into one field of the upstream endpoint. The options are applied in
the order they appear in the file, and the fragments of one field are concatenated in that order.

### `[[adapter.option]]`

| Key | Applies to | Meaning |
| --- | --- | --- |
| `name` | all | One of `country`, `city`, `sid`, `ttl`, `strict`, `ip`. Each name at most once per adapter. |
| `to` | all | Where the fragment is written: `user`, `pass`, `host` or `port`. The field's template must contain `{opts}` (a `port` option needs no template). At most one option may set the port. |
| `frag` | all | Text written for the option; `{v}` marks the value, exactly once (never, for `strict`). A fragment written to `user` may not contain `:`. No other braces. |
| `strict_frag` | `sid` only | Written instead of `frag` when the lease is strict. |
| `charset` | text options | `digits`, `alpha`, `alnum`, `word` (letters, digits, `_`), `alpha_underscore` (letters, `_`) or `ip` (hex digits, `.`, `:`). Defaults: country `alpha`, city `word`, sid `alnum`, ip `ip`. A `sid` charset must be `alnum`, `word` or `digits`. |
| `len` | text options | Exact length in characters. Country defaults to 2. |
| `max_len` | text options | Longest value in characters. Default 64. `len` may not exceed an explicit `max_len`. |
| `max` | `ttl` only | Largest value, in the option's `unit`. |
| `unit` | `ttl` only | `min` (default) or `sec`. The recipe accepts a positive whole-second `Duration` and rounds up to a whole provider unit; it never rounds down or exceeds an explicit cap. |
| `case` | `country`, `city` | `keep` (default), `upper` or `lower`. |

`len`, `max_len` and `max` must be above 0. `charset`, `len` and `max_len` do not apply to `ttl` and `strict`.
`max` and `unit` belong to `ttl`, and `case` to `country` and `city`.

### What each option carries

| Option | Source | Kinds | Written when |
| --- | --- | --- | --- |
| `country` | Country of the region | both | always |
| `city` | City of the region | both | the region has a city |
| `sid` | Session id (generated from `Adapter::session_id_alphabet()`, with the adapter's `len`, else its longest allowed length) | rotating, sticky | always |
| `ttl` | Requested session duration, normalized to the provider unit; default sessions use `max_session_minutes`, or 30 minutes | rotating, sticky | always |
| `strict` | Strict-mode flag | rotating | the lease is strict; no value, only `frag` |
| `ip` | The inventory entry's IP | static | always |

A static adapter may use only `country`, `city` and `ip`. A rotating adapter may not use `ip`, and must have a
`country` option, a `host`, and a `port` (or a port option). Sticky mode also requires `sid`; per-request mode
forbids session options. When a rotating adapter's template uses `{base_user}` or `{base_pass}`, the matching
`user_file` or `pass_file` is required unless `credentials_optional` is set.

A rotating adapter without a `city` option serves country-level regions only: a lease for `fr/paris` is refused
with the option error "the adapter has no city option", so keep the policy's `regions` to countries for such a
provider. A strict lease needs a `strict` option or a `strict_frag`. Unsupported strict mode is refused, not
silently downgraded. The chosen lifetime and strictness must survive warming, reuse and upstream dialing.

## The deterministic recipe

`Adapter::recipe` renders a lease spec into an upstream endpoint (scheme, host, port, username, password, and
whether the upstream is `public_only`). It is pure: the same spec renders the same endpoint, byte for byte. The
gateway and the warmer render the same spec for a session, so a session created by one is dialed correctly by
the other.

`UnitSpec::Rotating` carries `session_id`, `ttl: Duration`, `region` and `strict`. Use
`Adapter::normalize_session_ttl` before comparing recipe options: a 61-second request becomes 120 seconds for a
minute-based provider, while IPRoyal retains 61 seconds. Zero and fractional-second durations are refused.
`Adapter::encode_session` persists the normalized duration and strict flag with the upstream session id as
`sid~seconds~0` or `sid~seconds~1`. `decode_session` reconstructs those exact inputs; legacy bare ids mean the
adapter's default lifetime and non-strict mode. Malformed identities are errors, never legacy fallbacks.
Sessions with different normalized lifetimes or strictness must not reuse each other's pooled unit.

Values outside an option's rules are **refused, never escaped**. The recipe fails when:

- a value is empty, has a character outside its `charset`, or has a length other than `len` (or above
  `max_len`);
- the `ttl` is above the adapter's `max_session_minutes` or the option's `max`, or out of range;
- a region has a city and the adapter has no `city` option;
- a spec does not fit the adapter: a static spec for a rotating adapter or the reverse, an entry of another
  provider or subtype, a strict lease with no strict support, or no host or port to dial;
- a rendered username, password or host is over 255 bytes (the SOCKS5 field limit);
- a username contains `:` or a control character (HTTP Basic splits on `:`), a password contains a control
  character, or a host has a character outside letters, digits, `.`, `-`, `_`, `:`, `[` and `]`, or is empty;
- the base username or password contains the leading text of one of the adapter's fragments, since a rendered
  option could not be told from the base;
- a needed base credential is missing (and `credentials_optional` is not set);
- with `public_only`, the host is not public routable.

Error messages name the field and the rule, never the value, so no credential reaches a log.

An entry's subtype must equal the adapter's subtype.

## Load-time checks

An adapter that cannot work is refused when the file loads: `kind` and `subtype` disagree; a template or
fragment is malformed; an option appears twice or writes to a field whose template has no `{opts}`; a static
adapter has `sid`, `ttl` or `strict`; a rotating adapter has `ip`, or lacks `country`, a host or a port; a sticky
adapter lacks `sid`; a per-request adapter sets session options; a static adapter sets per-request mode;
`port`, an `allowed_ports` entry, `max_conns_per_ip` or `max_session_minutes` is 0; `echo_url` is not an http(s)
URL with a host; `rotate` is missing for `mobile_box` or present otherwise; a secret file is unreadable or
empty; a `public_only` adapter has a literal host that is not public; or a base credential already contains a
fragment separator. A `scheme = "local"` adapter is also refused when it is not a static `datacenter` or `isp`
adapter, or sets `host`, `port`, `user_file`, `pass_file`, `public_only`, `rotate` or an option: all of them
describe an upstream proxy.

Rotating adapters are also checked against the policies: every policy's `rotating.min_remaining` must be below
the shortest life a session of the provider gets (see [policies.md](policies.md#validation)).

## Shipped adapters

Files in `data/adapters/`:

| File | `id` | Kind and subtype | Role |
| --- | --- | --- | --- |
| `oxylabs_isp.toml` | `oxylabs_isp` | static, `isp` | Rented ISP IPs, one port per IP. Example of a static adapter. |
| `oxylabs_res.toml` | `oxylabs_res` | rotating, `residential` | Options in the username. Example of a rotating adapter with a city option and a strict fragment. |
| `iproyal_res.toml` | `iproyal_res` | rotating, `residential` | Options in the password. Example of a rotating adapter without a city option. |
| `customer.toml` | `customer`, `customer_https`, `customer_socks5` | static, `datacenter` | An org's own upstream over HTTP, TLS-protected HTTP or SOCKS5. See [Customer upstreams](#customer-upstreams). |
| `vpn-pool.toml` | `vpn-pool` | static, `datacenter` | A local SOCKS5 egress proxy per VPN exit, for upstreams you operate. |
| `local.toml` | `local` | static, `datacenter` | The machine's own IP addresses, dialed straight from a bound source address. See [Local units](#local-units). |
| `webshare_res.toml` | `webshare_sticky_http`, `webshare_sticky_socks5`, `webshare_rotating_http`, `webshare_rotating_socks5` | rotating, `residential` | Numeric sticky sessions and genuine per-request rotation over HTTP or SOCKS5. Per-request endpoints are not reusable pooled exits. |
| `brightdata_zone.toml` | `brightdata_zone` | rotating, `residential` | Full dashboard-generated zone username, geographic parameters, session id and optional strict peer binding. |

The vendor grammars were read from the vendors' documentation on the dates in each file's header comment and are
shown as examples; confirm them against your own account. Rendered examples below use made-up secrets and
session ids.

### Rotating, options in the username: `oxylabs_res`

```toml
[[adapter]]
id = "oxylabs_res"
kind = "rotating"
subtype = "residential"
scheme = "http"
host = "pr.oxylabs.io"
port = 7777
user_file = "oxylabs_res_user"
pass_file = "oxylabs_res_pass"
user = "customer-{base_user}{opts}"
pass = "{base_pass}"
allowed_ports = [80, 443]
max_session_minutes = 30
echo_url = "https://ip.oxylabs.io"

[[adapter.option]]
name = "country"
to = "user"
frag = "-cc-{v}"
case = "upper"
# city (word, max_len 48), sid (alnum, len 16, strict_frag "-sessid_oneip-{v}") and
# ttl (min, max 30) follow the same pattern; see the file.
```

For region `fr/paris`, secret user `acct`, session id `Ab3dEf6hIj9kLm2n`, the username is
`customer-acct-cc-FR-city-paris-sessid-Ab3dEf6hIj9kLm2n-sesstime-30`, and the password is the base password.
The destination port must be 80 or 443; any other port answers `403 port_not_allowed`. The default `ttl` is
30 minutes. This example intentionally caps both `sessid` and `sessid_oneip` at 30 minutes; do not interpret
that conservative configured cap as a claim about every current Oxylabs product's maximum.

### Rotating, options in the password: `iproyal_res`

```toml
[[adapter]]
id = "iproyal_res"
kind = "rotating"
subtype = "residential"
host = "geo.iproyal.com"
port = 12321
user_file = "iproyal_res_user"
pass_file = "iproyal_res_pass"
user = "{base_user}"
pass = "{base_pass}{opts}"
max_session_minutes = 10080

[[adapter.option]]
name = "country"
to = "pass"
frag = "_country-{v}"
case = "lower"

[[adapter.option]]
name = "sid"
to = "pass"
frag = "_session-{v}"
charset = "alnum"
len = 8
```

The file also has `ttl` (`_lifetime-{v}s`, `unit = "sec"`, max 604800) and `strict` (`_killswitch-1`)
options. For region `fr`, session `Ab3dEf6h` and a 61-second lifetime, the password is
`<base password>_country-fr_session-Ab3dEf6h_lifetime-61s`. Bounds are exactly 1 second through 7 days,
inclusive. There is no `city` option, so this provider serves country-level regions only.

### Webshare sticky and per-request HTTP/SOCKS5 endpoints

The [primary connection reference](https://apidocs.webshare.io/proxy-connection) documents
`{username}-{country_code}-{geo_params}-{session_id}`, numeric sticky ids, and the mutually exclusive
`-rotate` suffix. The shipped examples use `p.webshare.io:80` for HTTP and `p.webshare.io:1080` for SOCKS5.
With base username `acct`, country `us`, city `los_angeles` and sticky id `1234567890123456`, both transports
render `acct-us-city_los_angeles-1234567890123456`; rotating mode renders `acct-us-city_los_angeles-rotate`.
Cities allow ASCII letters and underscores, not digits or hyphens.

The [Endpoint Generator documentation](https://help.webshare.io/en/articles/16310718-endpoint-generator-rotating-residential)
sets sticky duration in the dashboard, from 1 minute to 24 hours. There is no documented username lifetime
parameter. Set each sticky adapter's `max_session_minutes` to the actual dashboard timer before use; the
1440-minute example is valid only with a 24-hour dashboard timer. A shorter client TTL bounds the local lease;
it does not change that dashboard timer or guarantee the peer remains available. No strict replacement-blocking
flag is documented, so strict recipes fail.

`webshare_rotating_http` and `webshare_rotating_socks5` explicitly set `session_mode = "per_request"`.
Their tracking id and local TTL are not sent upstream. These direct recipe examples do not preserve a stable
exit between requests, so the stable-IP warmer and pooled session allocator exclude them. Use the sticky
adapters for pooled sessions; do not relabel a `-rotate` endpoint as sticky.

### Bright Data generic zone username

The [current zone configuration reference](https://docs.brightdata.com/proxy-networks/config-options)
documents `brd-customer-[customerID]-zone-[zone name]-[optional parameters]`. Put the complete username from
your zone's dashboard in `brightdata_zone_user`, not just a customer id or a guessed product prefix.
Confirm host, port, zone product and targeting against the zone's
[generated examples](https://brightdata.com/cp/zones/proxy_examples) before enabling the adapter.
The generic example uses `brd.superproxy.io:33335` with `-country-us`, optional `-city-sanfrancisco`,
`-session-scan42`, and strict `-const`. `-const` returns 502 when the bound peer is unavailable instead of
silently choosing another peer. Dedicated-IP `-ip-` targeting belongs to a matching dedicated zone, not this
residential example. This reference supplies no session duration parameter; local TTL is not a remote uptime
guarantee.

Session syntax and capabilities above were checked on 2026-11-11 against those primary references,
[Oxylabs session control](https://developers.oxylabs.io/products/proxies/residential-proxies/session-control),
and [IPRoyal rotation](https://docs.iproyal.com/proxies/residential/proxy/rotation).

### Static, per-IP port: `oxylabs_isp`

```toml
[[adapter]]
id = "oxylabs_isp"
kind = "static"
subtype = "isp"
scheme = "http"
host = "isp.oxylabs.io"
user_file = "oxylabs_isp_user"
pass_file = "oxylabs_isp_pass"
user = "{base_user}"
pass = "{base_pass}"
max_conns_per_ip = 100
echo_url = "https://ip.oxylabs.io"
```

There is no `port` and no options: each inventory entry carries the port of its IP (the IP, not the port, is
the key). The username and password are the base secrets, unless an entry names its own `credentials`.
`max_conns_per_ip = 100` makes the policy default 80 tunnels per IP.

### Customer upstreams: `customer`, `customer_https` and `customer_socks5`

```toml
[[adapter]]
id = "customer"
kind = "static"
subtype = "datacenter"
scheme = "http"
public_only = true
credentials_optional = true
user = "{base_user}"
pass = "{base_pass}"
```

`customer_https` uses `scheme = "https"`; `customer_socks5` uses `scheme = "socks5"`. There are no secret
files: the login comes from the org's stored customer login. See [Customer upstreams](#customer-upstreams).

### Local egress sidecars: `vpn-pool`

```toml
[[adapter]]
id = "vpn-pool"
kind = "static"
subtype = "datacenter"
scheme = "socks5"
credentials_optional = true
user = "{base_user}"
pass = "{base_pass}"
```

Each inventory entry names the sidecar's host and port, and a `credentials` file when the sidecar needs a login.
There is no `public_only`: these addresses are private by design, so use the adapter only for upstreams you
operate. Because its id contains `-`, it cannot be named with the `prov` username option; select it with the
policy's `providers` list. A provider id with `-` is also skipped by the prober.

### Writing your own

Start from the shipped file closest to your provider. A checklist:

1. Pick `kind` and `subtype`; set `scheme` and the entry point (`host`, `port`).
2. Put base secrets in files and name them with `user_file` and `pass_file`.
3. Write `user` and `pass` templates with `{opts}` where the provider expects the options.
4. Add one `[[adapter.option]]` per lease option the provider supports, with the exact `charset`, `len` or
   `max_len`, and `ttl` `max` and `unit`.
5. Set `allowed_ports`, `max_conns_per_ip`, `max_session_minutes` and `echo_url` from the provider's terms.
6. Run the gateway or warmer: a bad file fails the load with the adapter id and the reason.

## Static inventory file

Static IPs, SIM boxes and the like are listed in `<data_dir>/inventory/*.toml`. Each file holds `[[entry]]`
tables; unknown keys are errors.

```toml
# inventory/oxylabs_isp.toml
[[entry]]
provider = "oxylabs_isp"
subtype = "isp"
plan = "isp-10"
ip = "203.0.113.50"
host = "isp.oxylabs.io"
port = 8001
region = "fr/paris"
asn = 12345
credentials = "oxylabs_isp_203-0-113-50"
rental_end = "2027-01-31"
```

| Key | Type | Meaning |
| --- | --- | --- |
| `provider` | provider id | The adapter that serves the IP. |
| `subtype` | `datacenter`, `isp`, `mobile_box` | Must be a static subtype and equal the adapter's subtype. |
| `plan` | string | Provider plan or product name, for the replacement report. Optional, at most 128 bytes. |
| `ip` | IP address | The key. The expected exit IP. For a `mobile_box`, the last seen IP. Must be a public address through the API. |
| `host` | string | Upstream host (gateway or the IP itself). Used when the adapter has no `host`. A plain DNS name or IP literal. For a [`local`](#local-units) adapter: the local address to bind, an IP literal. |
| `port` | 1 to 65535 | Upstream port. Used when the adapter has no `port`. For a `local` adapter: unused, write `0`. |
| `region` | region | `cc` or `cc/city` (see [policies.md](policies.md#regions)). |
| `asn` | integer | Optional. |
| `credentials` | file name | Optional file in `secrets_dir` holding `username:password`; replaces the adapter's base credentials. |
| `box_handle` | string | Optional opaque handle for the SIM box reset (`{handle}` in the adapter's `rotate`). |
| `rental_end` | `YYYY-MM-DD` | Optional last day of the rental, a real calendar day, so the rental alert can read it. |

The file `<provider>.toml` also owns that provider when it lists no entry, so emptying the file retires the
provider's IPs. An IP may appear only once across all files, and every entry must belong to a provider that has
an adapter.

### Lifecycle

A new IP starts as `candidate` and becomes leasable when the warmer's checks pass. States:
`candidate`, `available`, `leased`, `degraded`, `cooldown`, `quarantined`, `rotating` (a SIM box being reset),
`offline`, `replace_requested`, `retired`. `available`, `leased` and `degraded` are leasable; `degraded` means
slow but clean, and is used after the normal units. Replacing the list keeps the state of known IPs, revives a
retired IP as `candidate`, and retires every IP the list leaves out.

### How it syncs

1. The **gateway** (and not the warmer) copies the inventory files into Postgres as actor `gitops`. The content
   hash of the whole directory (names and bytes) is kept in Postgres, so an unchanged tree costs one query.
2. When the hash changes, each provider that a file owns has its list replaced atomically with the file's
   entries. A provider whose file was deleted is retired the same way.
3. Nothing is written when a file does not parse, an IP is duplicated, a subtype is rotating, a `rental_end` is
   not a date, or a provider has entries but no adapter ("inventory names providers without an adapter"): the
   failure sets `config_reload_failed{source="inventory"}` and the last good state stays.
4. The gateway and warmer read the inventory from Postgres every `reload_every` (default 30 s).

The same operation is available at runtime with
[`PUT /v1/inventory/{provider}`](gateway.md#put-v1inventoryprovider). Note that a git sync replaces the list of
every provider that a file owns whenever the tree changes, so use one source of truth per provider.

## Local units

`scheme = "local"` leases the IP addresses of the machine the gateway runs on. There is no upstream proxy: for each
tunnel the gateway resolves the target, binds the unit's local address as the **source address** of the socket
and connects straight to the target, which sees that address. The normal pool machinery applies: the warmer
verifies each unit, sticky keys and `lease_ttl` keep an org on one IP, rotation by IP, per-IP limits and the
breaker work as for any static provider. It suits a server (or a VM) that owns several addresses and offers
them as its own pool. For the same machine without Postgres, Redis or the pool gateway, use the
[`proxyx edge`](edge-proxy.md) role.

The shipped `data/adapters/local.toml`:

```toml
[[adapter]]
id = "local"
kind = "static"
subtype = "datacenter"      # or "isp": a static subtype without a `rotate` call
scheme = "local"
# allowed_ports, max_conns_per_ip and echo_url work as for any adapter.
```

The adapter has no `host`, `port`, `user_file`, `pass_file`, option, `rotate` or `public_only`: all of them
describe an upstream proxy and are refused at load. `credentials_optional`, `user` and `pass` are accepted and
ignored, because no login is ever rendered. A unit has no credential, and an entry that names `credentials` is
refused.

Each unit is an inventory entry:

```toml
# inventory/local.toml
[[entry]]
provider = "local"
subtype = "datacenter"
plan = "server-a"
ip = "198.51.100.20"        # the expected exit IP
host = "198.51.100.20"      # the local address to bind (an IP literal)
port = 0                    # unused
region = "fr"
```

| Key | Meaning for a `local` unit |
| --- | --- |
| `host` | The local address bound as the source of every tunnel. It must be an IP literal that a socket can bind: not unspecified (`0.0.0.0`, `::`), multicast, broadcast or IPv6 link-local. A name, a bracketed or `host:port` form is refused when the unit is rendered. Loopback and private addresses are allowed (`127.0.0.2` on a test machine, a VPC address behind a 1:1 NAT). |
| `ip` | The **exit IP** the verification expects, and the IP that identifies the unit (`X-ProxyX-Exit-IP`, block signals, the state machine). On a plain server it is the same address as `host`. Behind a 1:1 NAT or an elastic IP (most cloud VMs) `host` is the private address of the interface and `ip` the public one. |
| `port` | Not used. Write `0`; any value is accepted and ignored. (For every other provider the API refuses a `0` port.) |
| `credentials` | Refused: there is no login. |
| `subtype` | The adapter's subtype. |

What is different from a proxy provider:

- **The address must exist where the dial runs.** The `host` must be assigned to an interface of the machine
  that binds it, and that is every process that connects through the unit: the gateway (tunnels) and the warmer
  (checks and probes). A socket may bind any local address without a capability, so no privilege such as
  `CAP_NET_BIND_SERVICE` is needed; the kernel picks the source port at connect time
  (`IP_BIND_ADDRESS_NO_PORT` lets many connections from one address share the port space). Add an address
  with, for example, `ip addr add 198.51.100.20/32 dev eth0`, or as a secondary address of the cloud provider's
  network interface. A unit whose address is not assigned fails to bind, is taken out of use for the target for
  a while and is not counted against the breaker.
- **Run the pool on that machine.** The units of a provider are leased by every gateway replica and checked by
  every warmer replica, so each of them must own the addresses. Run one gateway and one warmer on the machine
  (host networking in a container), or keep the replicas on machines that own the same addresses.
- **The target rule still applies.** The gateway refuses private, loopback, link-local and internal targets with
  `403 destination_denied` (see [Denied destinations](gateway.md#denied-destinations)). For a `local` unit it also
  resolves the target name itself and refuses a name that resolves to such an address, because no provider sits
  between the machine and the target. `allowed_ports` is the target port allow-list.
- **IP families.** A tunnel from an IPv4 unit goes to the IPv4 addresses of the target and one from an IPv6 unit
  to its IPv6 addresses; a unit never falls back to the other family, because the exit would be another address.
- **Failures are the target's, not the provider's.** A refused or timed-out connect, a name that does not
  resolve and a missing route are not counted by the route-class breaker, and the unit is not withdrawn. A
  source address that cannot be bound (not assigned, or no free port) cools the unit for that target and moves
  the tunnel to another address, still without a breaker count. A unit whose address vanished is found by the
  warmer's next exit-IP check.
- **Verification and probes go out of the same address.** The exit-IP quorum, the provider echo and the light
  probe are requests from the unit's source address with no proxy; a name they use that resolves to a private
  address is refused. The unit is verified when the exit equals the entry's `ip`.
- **Not for customers.** `PUT /v1/orgs/{org}/upstream` accepts `http` and `socks5` only; `local` is `400`,
  because the host of a `local` unit is an interface of the operator's machine. `PUT /v1/inventory/local`
  applies the same rules as the inventory file to the entries it receives.
- **Rotation** is by IP: a pool of several addresses is rotated by the sticky key and the lease walk, as for any
  static provider. There is no `rotate` call, and `mobile_box` is not available.

## Customer upstreams

An org can bring its own upstream proxy instead of using the shared pool. The control API stores it as a static
inventory unit **owned by the org**, so only that org can lease it.

- Set it with [`PUT /v1/orgs/{org}/upstream`](gateway.md#put-v1orgsorgupstream) (admin token): `scheme`
  (`http`, `https` or `socks5`), `host`, `port`, `region` and an optional login. `http` uses `customer`,
  `https` uses `customer_https`, and `socks5` uses `customer_socks5`.
- It starts as `candidate` and nothing leases it until
  [`POST .../validate`](gateway.md#post-v1orgsorgupstreamvalidate) passes: a dial through it with the stored
  login and the exit-IP quorum, whose country must be the declared region's. The warmer re-checks it with the
  same quorum; its reputation and block history are the customer's business, and it is never quarantined or
  replaced.
- **`public_only`**: the host, and every address it resolves to, must be public routable. The rule runs at
  write, at adapter load (a literal host), when the adapter renders the endpoint, and at dial, where the
  gateway resolves the host once, refuses any non-public address and connects only to the checked address.
- **Fails closed.** An org with an upstream is served by it alone. When it is not leasable the tunnel fails
  (`no_healthy_ip`, `provider_auth` and so on) and never leaves through a shared provider IP. The upstream is
  skipped by the breaker: a customer's dead or misconfigured upstream does not open the route class that all
  customer upstreams of a region share.
- The org's policy must still allow the provider (a `warning` in the `PUT` and `validate` reply when `providers`
  excludes it) and a region that satisfies the upstream's region.
- **Where the login lives.** The username and password are kept in clear text in a ProxyX-private Postgres
  table. No route returns them, the audit trail never holds them, and they reach the gateway and warmer only
  through the in-memory snapshot. Treat access to that database accordingly. Rotate with
  [`rotate-secret`](gateway.md#post-v1orgsorgupstreamrotate-secret), which checks the new login first.
- The unit's key is an unroutable address derived from the org id; it is never dialed.
- Changes reach each gateway pod at its next reload (within 30 s by default). Set the upstream before the
  org's first tunnel.

## Mobile boxes

A SIM box or modem farm is a static unit with subtype `mobile_box`: a fixed endpoint whose exit IP changes.
Its adapter needs a `rotate` table that says how to reset one box:

```toml
# Illustrative: a box controller with an HTTP API (not a shipped adapter).
[adapter.rotate]
method = "POST"                         # GET | POST | PUT
url = "https://boxes.example.net/api/boxes/{handle}/rotate"
body = '{"box": "{handle}"}'              # optional JSON body
bearer_file = "boxes_token"             # optional secret file with a bearer token
timeout = "20s"                         # default 20s
```

| Key | Meaning |
| --- | --- |
| `method` | `GET`, `POST` or `PUT`. |
| `url` | An `http` or `https` URL with a host. `{handle}` may appear after the host only, so a handle can never steer the call to another host. No other braces. |
| `body` | JSON body sent with the call; `{handle}` is replaced. |
| `bearer_file` | Secret file with a bearer token. |
| `timeout` | Duration above 0, default 20 s. |

`{handle}` is the entry's `box_handle`, which must be 1 to 64 characters of `[A-Za-z0-9_-]` (refused, never
escaped; no request is sent). The call ignores environment proxies and never follows redirects. A `2xx` answer
is success; `429` is a rate limit; any other status, a timeout or a transport error is a failure. Whether the
exit IP actually changed is checked by the warmer afterwards.

The box policy lives in [`mobile_box`](policies.md#static-and-mobile_box). The warmer's part is under
[The warmer](#the-warmer).

## The warmer

`proxyx warmer` runs the loops that keep units healthy; the gateway only leases and serves. The warmer is its
own deployment and every replica runs every loop. A partition lock in Redis (`SET NX PX 15s`, renewed) decides
which replica works on which partition, so there is no leader election. The loops:

| Loop | Interval | What it does |
| --- | --- | --- |
| `seed` | 5 s | After a Redis loss, rebuilds the leasable static IPs, the running cooldowns and the org blocks from Postgres, so no banned IP is leased. Rotating sessions are not rebuilt; reconcile refills them. |
| `locks` | 5 s | Keeps the partition locks. |
| `reconcile` | 5 s | Rotating: creates sessions to reach the target. |
| `keepalive` | 1 s | Rotating: due keepalives and evictions; browser-sample watches. |
| `static` | 30 s | Static: checks, retests, state moves and the replacement rule. |
| `boxes` | 5 s | SIM box resets. |
| `sweeper` | 30 s | Reclaims in-flight creates, reservations and lease fields that nothing owns; prunes Postgres history once an hour. |
| `gauges` | 15 s | State gauges. |

A loop that ends before shutdown stops the process, which restarts instead of running with a loop missing.

### Rotating providers

- **Create.** Per partition (each policy region of every rotating adapter), the warmer targets
  `min(max_ready, min_ready + extra)` ready sessions, where `extra` comes from `rotating.headroom` and
  `headroom_auto`. It starts at most `min(need, refill_concurrency - in flight, rate tokens, budget left)`
  creates. A create reserves a slot, renders the recipe with a new session id, runs the
  [exit-IP quorum](#exit-ip-verification) in the region, claims the exit IP (an IP already held by another
  session is `duplicate` and drains), then the [reputation rule](#reputation-scorers) and the light probe on the
  region's probe targets against the policy `criteria`. A session that fails any check never becomes ready. A
  session that is clean but slow may become `degraded`, while degraded sessions hold at most a quarter of
  `max_ready`. A browser sample then runs for `criteria.browser_sample` of new sessions.
- **Budget and breaker.** At 80% of `cost.max_gb_per_day` or `cost.max_creates_per_hour` creates slow to
  `min_ready`, one at a time; at 100% they stop until the day or hour ends. A route-class breaker shared with
  the gateway pauses creates; failed creates back off from 5 s up to 5 minutes.
- **Keepalive and eviction.** Each ready session is a job in a shared `due` set, so any replica may run it.
  A step sends a neutral request through the session to the adapter's echo endpoint (never to a target), which
  also proves the exit IP. A session is drained when it is no longer ready, reaches `max_age`, sits unused for
  `ready_ttl`, fails three keepalives in a row, exceeds `rotating.stability`, or fails the periodic reputation
  re-check (`rotating.recheck_every`) or the check of a changed exit IP. Draining stops leasing it; its open
  tunnels continue until they end or 10 minutes pass. Keepalive never extends `max_age`.

### Static providers

- **Checks.** A `candidate` IP, and every leasable IP when `static.recheck_every` has passed, gets the exit-IP
  quorum (the exit must equal the entry's IP, and its country the region), the reputation rule and the light
  probe. A pass moves a candidate to `available` (or `degraded` if clean but slow) and makes it leasable.
  A failing candidate (an exit that differs from the entry, a block page, a bad exit, a refused connection or a
  reputation drain) goes to `quarantined`. A leasable IP whose exit IP changed returns to `candidate`, and one
  that fails a check goes to `cooldown`.
- **Retest.** A cooled IP is retested after `static.cooldown`, a quarantined one after `static.retest_every`. When
  at least two IPs of a route class (and `block.max_cooldown_share` of them) rest at once, the provider is
  taken as down rather than the IPs: the class is retested at the breaker's probe spacing and failed retests do
  not count toward replacement.
- **Replacement.** When a replacement rule holds, the IP becomes `replace_requested` and the warmer logs one
  `pool_replacement_report` event (and once more every 24 h while it stays). It has no credential. Replace the
  IP in the provider panel and edit the inventory.
- **Rental.** The nearest `rental_end` per provider is published as a gauge for the rental-ending alert.
- **Redis consistency.** A unit leaves the ready set whenever its row is not leasable and returns when it is
  again; a leasable row that Redis lost is put back.
- **Customer units** get the quorum check only (see [Customer upstreams](#customer-upstreams)) and become
  available only through the API's `validate`.

### Mobile boxes

A `mobile_box` that rests in `cooldown` or `quarantined` is reset: the warmer waits up to `drain_wait` for its
leases to end (a reset cuts open tunnels), calls the adapter's `rotate`, then polls the exit IP until it
differs or `rotate_timeout` passes. The box is `rotating`, and not leasable, meanwhile. Only a changed exit IP
leads to `candidate` (and the normal checks); any other outcome counts as a failed reset and returns the box to
`quarantined`. `rotate_attempts` failures in a row make it `replace_requested`. Resets are rate limited per box
by `rotate_min_interval` and `rotate_per_hour`. A box silent for `offline_after` becomes `offline`, and returns
as `candidate` when it answers. A box is never failed for an unreachable upstream, because that is its offline
state.

## Exit-IP verification

Several echo services are asked, through the upstream, which IP they see. The result must satisfy a quorum.

| Service | Reads |
| --- | --- |
| `ipify` | `https://api.ipify.org?format=json`: IPv4 only, no country. |
| `cloudflare` | `https://www.cloudflare.com/cdn-cgi/trace`: `ip=` and `loc=` lines. |
| `ipinfo` | `https://ipinfo.io/json`: `ip` and `country`. |
| `ifconfig_co` | `https://ifconfig.co/json`: `ip` and `country_iso`. |
| provider echo | The adapter's `echo_url`: the IP as plain text, no country. Added per call. |

Rules:

- Two services must return the same IPv4 address, and that address must have strictly more votes than any
  other. The quorum is taken over the services that answered; each failure counts in
  `check_failures_total{service}`.
- The country of the exit is the strict majority among the winner's voters that report one, and must equal the
  wanted region's country. The city is advice only and is not checked.
- A static IP must equal its inventory entry (not for a SIM box, whose exit changes, nor for a customer
  upstream, whose entry is an address and not its exit).
- Each service call has a 5 s limit.
- A [`local`](#local-units) unit has no proxy: the services are asked straight from the unit's bound source
  address, so the exit they see is that machine's own address. Only IPv4 answers vote, so give a `local` unit an
  IPv4 address to be verified.

Outcomes: too few answers (an outage, not a verdict on the IP), every failure a timeout, the upstream refused or
dropped every check connection (login failure or reset), no unique winner (`disagree`), an IP or country
mismatch.

Where it runs: the warmer for every create, check and retest; the gateway when a unit's last check is old (5
minutes for a static IP, 30 s for a rotating session, 3 s limit, serving unverified when no verdict can be
reached); and the control API when validating a customer upstream.

To replace the public services (a benchmark or an isolated environment with a stub provider), set
`PROXYX_POOL_EXIT_IP_SERVICES` (`exit_ip_services`) to a comma list of `kind=url`, where `kind` is `ipify`,
`cloudflare`, `ipinfo` or `ifconfig_co`:

```sh
PROXYX_POOL_EXIT_IP_SERVICES='cloudflare=http://stub.test/trace,ipinfo=http://stub.test/json'
```

The list must contain at least one of `cloudflare`, `ipinfo` or `ifconfig_co`, because only they report the exit
country; the provider echo and `ipify` return the IP only. An unknown kind, a URL that is not http(s), or an empty
list fails startup.

## Reputation scorers

The reputation rule scores the exit IP with third-party services. A scorer is **on when its key file exists** in
`secrets_dir`; with none on, the policy's `on_score_unavailable` decides. A scorer receives only the exit IP and
the API key: no target, org or client data, and the raw reply is never kept.

| Scorer | Key file | Origin setting (default) | Daily budget |
| --- | --- | --- | --- |
| IPQS | `ipqs_api_key` | `ipqs_base_url` (`https://ipqualityscore.com`) | 30 lookups |
| AbuseIPDB | `abuseipdb_api_key` | `abuseipdb_base_url` (`https://api.abuseipdb.com`) | 900 lookups |
| Scamalytics | `scamalytics_api_key` | `scamalytics_base_url` (`https://api12.scamalytics.com`) | 15 lookups |

The origin settings are `PROXYX_POOL_IPQS_BASE_URL`, `PROXYX_POOL_ABUSEIPDB_BASE_URL` and
`PROXYX_POOL_SCAMALYTICS_BASE_URL`. They exist for benchmarks and isolated environments with a stand-in; leave
them alone otherwise. Scamalytics also needs its account name, `scamalytics_customer`
(`PROXYX_POOL_SCAMALYTICS_CUSTOMER`): a `scamalytics_api_key` without it fails startup. A key file that exists
but is empty or unreadable also fails startup. Budgets are lookups per UTC day per process and are
conservative figures under the vendors' free plans; an exhausted scorer is skipped for the day.

Rule:

- A score is 0 to 100 (higher is worse) with a `tor` flag; the `proxy` flag is recorded but ignored, because
  residential and ISP exits carry it by design.
- Scores are cached for 6 hours per scorer and IP. One scorer call has a 10 s limit.
- The worst scorer decides. A `tor` flag, or a risk above `criteria.max_risk`, is a **drain**: a rotating
  session is drained, a static IP is cooled. A risk from 50 up to `max_risk` is **recheck**: check again soon,
  and twice in a row drains. Below 50 keeps the IP.
- When no scorer gave a score (all off, over budget or failing), `on_score_unavailable` decides: `allow` keeps,
  `deny` drains.
- A creation with a deadline (the gateway's on-demand create) treats a check still running at the deadline as
  "no score available". Static scores are recorded in Postgres for the replacement report.

## Probe targets

The pages the light probe and the browser prober load through a candidate are listed in
`<data_dir>/probe-targets.toml`. If the file does not exist, the one default page `https://www.google.com/` is
used.

```toml
# Pages of a region are: global, then its country, then its city, each URL once.
global = ["https://www.google.com/"]
extra_hosts = ["google.com", "gstatic.com"]

[region]
fr = ["https://www.google.fr/"]
"fr/paris" = ["https://www.google.fr/maps"]
```

| Key | Meaning |
| --- | --- |
| `global` | URLs every region gets. |
| `[region]` | A table of region (`fr`, `fr/paris`) to a list of URLs, added after `global` for that country or city. |
| `extra_hosts` | Hosts a page needs that are not its own (assets, consent redirects). Allowed on the probe listener with their subdomains. |

URLs must be `http` or `https` with a host; a region key must be a valid region; unknown keys are errors. A file
that does not load keeps the last good one (`config_reload_failed{source="probe_targets"}`).

The gateway's **probe listener** opens only the hosts of these pages plus `extra_hosts` (and their
subdomains), on ports 80 and 443 or a page's own explicit port. Any other host is `403 destination_denied`, so a
probe token that leaks from a browser process is not an open proxy; a page whose load needs a new host fails
until it is listed in `extra_hosts`. The prober fetches the per-region list from
[`GET /v1/probe/targets`](gateway.md#get-v1probetargets).

The **light probe** makes 3 GETs per target through the upstream, reads the status, the time to first byte and
the first 16 KiB, follows up to 3 redirects and uses a 10 s limit per request. A final status that is neither
2xx nor a block is a failure that counts against `criteria.min_success` but is not a block. A block is a 429,
a 403 or 503 with a challenge marker in the body (captcha, `cf-chl`, `just a moment` and similar), or Google's
`/sorry/` redirect. A target counts as blocked when a strict majority of its samples were blocked. A sample is
good when it was clean and its first byte arrived within `criteria.max_ttfb_ms`.

## Secrets directory

Secrets are files in `secrets_dir` (`PROXYX_POOL_SECRETS_DIR`, default `/etc/proxyx/secrets`), mounted by your
secret manager. Adapters and inventory entries name a file; no secret value lives in a data file.

| File | Used by |
| --- | --- |
| `admin-token` (path `admin_token_file`) | Admin bearer token of the control API. Required for the gateway. |
| `prober-token` | Prober bearer token. Required for the gateway. |
| `probe-key` (path `probe_key_file`) | Secret that signs probe tokens. Optional; without it the probe listener refuses every login. |
| `ipqs_api_key`, `abuseipdb_api_key`, `scamalytics_api_key` | [Reputation scorers](#reputation-scorers). |
| the `user_file` and `pass_file` names of an adapter | The base username and password of that adapter. |
| the `bearer_file` of an adapter's `rotate` | Bearer token of the SIM box reset. |
| the `credentials` names of inventory entries | `username:password` of one static unit. |

Rules:

- A name must be a plain relative name: not empty, no `..`, not starting with `/`. Through the API an inventory
  `credentials` name is also limited to 128 bytes of letters, digits, `.`, `_` and `-`, not starting with `.`.
- One trailing newline is removed. A missing or empty file is refused.
- A `credentials` file holds one line `username:password`. The split is at the first `:`, so the password may
  contain `:`; the username may not be empty. The values are cached for a minute by the gateway.
- Adapter secret files are read when adapters load; rotate a secret by changing the file and waiting for the next
  reload (`reload_every`, default 30 s).
- Name files for what they hold, for example `oxylabs_isp_user` and `oxylabs_isp_203-0-113-50` (a per-IP
  credential), so an inventory file reads on its own.
