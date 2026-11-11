# proxyx-client

Rust client for integrators of [ProxyX](https://proxyx.dev). It covers both proxy products:

| Product | What you get | Module |
|---|---|---|
| **Capture sessions** (control plane, `/rpc`) | A proxy URL per unit of work. Traffic through it is intercepted and stored; you search it afterwards. | `sessions`, `traffic`, `env` |
| **Pool gateway** (rented and rotating exit IPs) | An exit chosen by the proxy username, the exit IP of each tunnel, and block reports back to the pool. | `gateway`, `signals` |

`provider` puts both behind one trait and adds a passthrough that uses no proxy.

The crate uses `reqwest` with rustls, `tokio` and `serde`. It does not depend on any server crate; the wire types are
mirrored. Licence: AGPL-3.0-only.

```toml
[dependencies]
proxyx-client = { path = "crates/client" }
```

## Capture sessions

Authenticate with a **service key** (`pxk_...`, sent as `Authorization: Bearer`). The key is bound to one org.

```rust
use proxyx_client::sessions::{CreateSessionRequest, SessionsClient};

let client = SessionsClient::new("https://control.example.com", std::env::var("PROXYX_SERVICE_KEY")?)?;

let request = CreateSessionRequest::new("acme", "crawl", "crawl-42")
    .captured_hosts(["*.example.com"])   // empty captures nothing
    .inject_header("X-Crawl-Id", "crawl-42")
    .agent("Mozilla/5.0 ... Chrome/133 ...")
    .ttl_secs(1800);

// create (or attach to the active session of the same org/source/source_id) and keep it alive
let session = client.open_session(request).await?;

let http_proxy = session.proxy_url();          // http://<session id>:password@host:8443
let socks_proxy = session.proxy_url_socks5();  // socks5://<session id>:password@host:1080
let ca_pem = session.ca_cert_pem();            // the CA that signs intercepted TLS

// ... run the crawl through the proxy ...

session.end().await?;                          // releases this hold; idempotent
session
    .wait_all_processed(std::time::Duration::from_secs(120), std::time::Duration::from_millis(500))
    .await?;                                   // captures are now searchable
```

**The session id in the proxy URL is the whole proxy credential.** Never log the URL. `Debug` on every type here redacts
it, and `Secret` has no `Display`.

### What the client enforces

- **Fail closed.** `create_session` returns credentials only if the response has `success: true`, a valid `proxy_url`
  (`http`/`https`) and `proxy_url_socks5` (`socks5`/`socks5h`), and `upstream_overrides` equal to the request's. Otherwise
  it returns `Error::InvalidCreateResponse` or `Error::UpstreamOverridesMismatch`, and releases the session the server
  created so nothing keeps holding the source. A missing field is a refusal, not "no proxy".
- **Typed errors.** 401/403 `Error::Auth`, 404 `Error::NotFound`, 409 `Error::Conflict`, 5xx `Error::Unavailable`, other 4xx
  `Error::Client` (with `retry_after` from a `Retry-After` header). `Error::is_retryable()` is true for 5xx, transport
  failures, 408 and 429.
- **Reference counting.** A second create for the same `(org_id, source, source_id)` attaches to the active session:
  `created().attached()` is true, the existing configuration wins and `created().warning()` lists the differences. Each
  create needs one `end()` (or `delete_session`).

### Keepalive

`open_session` starts a task that extends the session so a long job outlives its TTL. Defaults:

| Setting | Default | Meaning |
|---|---|---|
| `ttl_secs` | 1800 | Lifetime requested on each renewal (`new_ttl_secs`). |
| `threshold` | 0.2 | Renew with 20% of the lifetime left: sleep `max(min_sleep, remaining * 0.8)`. |
| `max_failures` | 3 | Stop after this many consecutive failed renewals. |
| `min_sleep` | 1 s | Shortest sleep. |

The loop also stops when the server answers 404 or 409 to an extend (the server uses 409 for a session that is unknown,
expired or closing). Read the outcome with `session.keepalive_state()` or watch it with `session.watch_keepalive()`:
`Running`, `Disabled`, `Cancelled`, `SessionGone`, `TooManyFailures`. It uses the server's `expires_at_ms`, so keep client
and server clocks in sync.

`end()` cancels the keepalive. **Dropping a `Session` also cancels it but does not release the session** (a drop cannot do
network I/O); the session then expires when its TTL runs out. Call `end()`.

```rust
use proxyx_client::sessions::{KeepaliveConfig, SessionOptions};

// no keepalive: the session lives for the create TTL
let options = SessionOptions { keepalive: None };
let session = client.open_session_with(request, options).await?;
```

### Proxy environment, CA bundle, browsers

A captured session intercepts TLS, so the client must trust the session CA for captured hosts and still trust public roots
for hosts the proxy only tunnels. The bundle is the session CA followed by the system roots.

```rust
// HTTP_PROXY / HTTPS_PROXY / http_proxy / https_proxy / SSL_CERT_FILE / REQUESTS_CA_BUNDLE.
// The bundle is a private temp file, deleted when `session` is dropped.
let env = session.proxy_env().await?;
let child = tokio::process::Command::new("python3").arg("crawl.py").envs(env.iter()).spawn()?;

// or choose where the bundle goes (you own the file)
let env = session.proxy_env_at(std::path::Path::new("/run/crawl/ca.pem")).await?;

// Chromium: ["--proxy-server=http://<session id>:password@host:8443"]
let args = session.browser_args();

// a reqwest client that uses the proxy and trusts the session CA
let http = session.http_client()?;
```

Chromium ignores credentials in `--proxy-server` and does not authenticate SOCKS5. Drivers that take the server, username
and password separately (Playwright, for example) are the reliable route; read them from `proxy_url()`.

`env::ca_bundle_pem`, `env::write_ca_bundle` and `env::TempCaBundle` work without a session. `system_roots_pem()` fails
when the OS store holds no certificate, so a bundle never silently lacks the public roots.

### Reading captures

```rust
use proxyx_client::traffic::{IntFilter, QueryBranch, StringFilter, TrafficQuery};

let branch = QueryBranch::for_source("crawl-42")
    .host(StringFilter::contains("example.com"))
    .status_code(IntFilter::gte(400));
let mut query = TrafficQuery::new(vec![branch]).limit(500).fetch_bodies(0, 64 * 1024);

loop {
    let page = client.search_requests(&query).await?;
    for item in &page.items {
        println!("{} {}{} -> {}", item.method, item.host, item.path, item.status_code);
    }
    match page.next_cursor {
        Some(cursor) => query.cursor = Some(cursor),
        None => break,
    }
}

let total = client.count_requests(&query).await?;
let full = client.get_capture("acme", id).await?;      // headers and both bodies
let mark = client.sequence("crawl-42", None).await?;    // watermark cursor and count
```

Branches are OR-ed; the filters inside a branch are AND-ed. A body comes back only when you set a `*_max_fetch_size`;
a larger one is `BodyFetch::TooLarge { size }`, and `get_capture` fetches it whole. WebSocket messages have the same shape
(`search_ws`, `count_ws`, `WsQueryBranch`).

`wait_all_processed` polls `/rpc/processed`, which turns true once **a** session of the source is closed. It does not
know about other sessions of the same source that are still open.

## Pool gateway

The gateway takes CONNECT on `:8080` and SOCKS5 on `:1080`. The **org key is the proxy password**. The **username**
selects the exit: `px` plus `-key-value` pairs. `PoolSelector` builds it and checks the gateway's rules locally, so you
get an error before a tunnel is refused as `option_denied`.

```rust
use std::time::Duration;
use proxyx_client::gateway::{Kind, PoolGateway, PoolSelector, Rotation};
use proxyx_client::Secret;

let selector = PoolSelector::new()
    .kind(Kind::Rotating)
    .country("fr")
    .sid("scan42")                       // same sid, same exit
    .ttl(Duration::from_secs(600));
assert_eq!(selector.username()?, "px-kind-rotating-cc-fr-ttl-10m-sid-scan42");

let org_key = Secret::new(std::env::var("PROXYX_ORG_KEY")?);
let gateway = PoolGateway::new("pool.example.com");

// a URL for a SOCKS5 client (contains the org key)
let socks = gateway.socks5_url(&selector, &org_key)?;

// reqwest, https targets only: the gateway accepts CONNECT, not absolute-URI forwarding
let client = reqwest::Client::builder().proxy(gateway.reqwest_proxy(&selector, &org_key)?).build()?;
```

Rules (from the gateway): keys are `kind` (`static`|`rotating`), `cc` (two lowercase letters), `city` (needs `cc`), `prov`,
`ttl` (`30`, `30s`, `5m`, `2h`, `1d`; not zero), `sid`, `rot` (`sticky`|`each`; `each` cannot be combined with `sid`), `strict` (`true`|`false`: ask the provider for a strict sticky session whose exit IP must not change; `PoolSelector::strict`).
Values are lowercase `[a-z0-9_]` and never contain `-`, so a provider id with `-` cannot be selected. The whole username
is at most 128 bytes. The gateway refuses a bad username instead of repairing it, so the builder refuses `FR` instead of
folding it to `fr`. `PoolSelector::parse` reads a username back with the same rules.

### Tunnel head and exit IP

`reqwest` hides the CONNECT answer. To read the gateway's headers, open the tunnel yourself:

```rust
use proxyx_client::gateway::ConnectError;

match gateway.connect_tunnel(&selector, &org_key, "example.com", 443, Duration::from_secs(10)).await {
    Ok((stream, info)) => {
        // info.session  = X-ProxyX-Pool-Session
        // info.exit_ip  = X-ProxyX-Exit-IP
        // `stream` is positioned right after the head; do your TLS handshake on it
    }
    Err(err) if err.is_retryable() => { /* back off and try again */ }
    Err(ConnectError::Refused { cause: Some(cause), .. }) => eprintln!("refused: {cause}"),
    Err(err) => return Err(err.into()),
}
```

`ConnectInfo::parse(head_bytes)` does the parsing alone. A `200` without both headers is `ConnectError::Malformed`: it did
not come from the pool.

### Refusal causes

A refusal's reason phrase is a code (`HTTP/1.1 503 cache_empty`). `gateway::Cause` mirrors the gateway's table.
`Cause::is_retryable()` is true for `org_capacity`, `cache_empty`, `no_healthy_ip`, `cache_unavailable`, `lease_timeout`,
`provider_unavailable`, `provider_timeout` and `upstream_error`. It is false for what the caller or an operator must fix:
`auth_required`, `org_disabled`, `option_denied`, `org_blocked`, `port_not_allowed`, `destination_denied`, `org_budget`
(the daily budget resets with the day) and `provider_auth`.

### Block signals

When a target blocks an exit, tell the pool so it can cool the IP down:

```rust
use proxyx_client::signals::{BlockSignal, PoolControlClient, SignalType};

let control = PoolControlClient::new("https://pool-api.example.com", org_key.expose())?;
let signal = BlockSignal::for_tunnel(&info, "example.com", 443, SignalType::RateLimited);
let outcome = control.report(&[signal]).await?;   // accepted, ignored
```

At most 500 events per request (`MAX_BATCH`). The pool ignores events that are older than an hour, or whose session or exit
IP it does not recognise for your org; they show up in `ignored`. Repeating the same batch after a 5xx does not apply an
event twice.

## Session proxy errors

When the session proxy cannot set up a tunnel it answers with `X-ProxyX-Error: <cause>`.
`sessions::ProxyErrorCause::from_headers` reads it: `session_not_found`, `session_backend_unavailable`,
`upstream_refused`, `upstream_dns`, `upstream_error`, `upstream_timeout`. A SOCKS5 failure arrives in-band as an HTTP
response with this header after a successful SOCKS5 reply.

## Providers

```rust
use proxyx_client::provider::{PassthroughProvider, ProxyProvider, SessionsProvider};

let provider: Box<dyn ProxyProvider> = if capture_enabled {
    Box::new(SessionsProvider::new(client))
} else {
    Box::new(PassthroughProvider)          // no proxy, no capture, same call sites
};
let handle = provider.acquire(request).await?;
let env = handle.proxy_env().await?;       // empty for passthrough
handle.end().await?;
```

## Tests

`cargo test -p proxyx-client` runs unit tests, loopback tests against fake control-plane, pool-API and CONNECT servers
(create, keepalive, delete, the fail-closed checks), and parity tests that compare the username grammar and the cause table
with the gateway crates.
