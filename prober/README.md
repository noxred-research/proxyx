# proxyx-prober

The ProxyX quality prober. It loads test pages in a real, local browser
through the gateway's **probe listener** and reports the measurements to the
gateway control API. ProxyX applies its policy criteria to those measurements
and decides whether to drain a route class.

## What it does

1. Polls `GET /v1/probe/targets` for work: the hourly **canary** of every
   `(route class, region)` and the on-demand **samples** that the warmer queued.
2. For each job it fetches a signed token from `POST /v1/probe/token`
   (`pt1.<expiry>.<mac>`, valid 30 minutes), launches a headless browser with
   the probe listener as its proxy (username `px-prov-<provider>-cc-<country>-sid-<sid>`,
   password the token), and loads every target `PROXYX_PROBER_RUNS_PER_TARGET`
   times, each in a fresh browser context.
3. Posts one result per job to `POST /v1/probe/results`: status, time to first
   byte, DOM content loaded, load event, block reason (for example a `403` or a
   search-engine `/sorry/` page), or the navigation error.

A failure of the route (timeout, reset, block page) is a result. A failure of
the measuring equipment (the browser does not launch, no probe token, the listener
refuses the token with `407`) is never reported: the prober pauses with
exponential backoff and reruns the job.

The browser may expose a rejected proxy login either as a navigation error or as
an HTTP `407` document. Both are equipment failures: the entire attempt is
discarded, a fresh probe token is fetched after backoff, and no route result is
posted. A temporarily missing, empty, unreadable, or invalid-UTF-8 control API
token file also uses the bounded request retries. Polling resumes after the
secret is restored or rotated; secret contents are never included in errors.

For an HTTPS target, the browser can hide a proxy authentication challenge until
navigation times out. The driver then checks the same target authority with
the original proxy credentials. This diagnostic uses the configured proxy
transport (including TLS verification), has a one-second deadline and a
4 KiB response-head limit, and always closes its connection. Only an explicit
proxy `407` changes the timeout into an equipment failure. A successful
CONNECT, DNS/connect failure, oversized or incomplete reply, `5xx`, or diagnostic
timeout leaves the original route timeout unchanged. Successful navigations
never perform this extra check.

The wire contract is documented in `src/proxyx_prober/contract.py`. The
control API side is `crates/pool-api/src/probe.rs`; the listener is described
in `crates/gateway/src/lib.rs`. The metrics are listed under "Prober" in
[`docs/metrics/pool.md`](../docs/metrics/pool.md).

## Requirements

* Python 3.12 or newer.
* A gateway with a probe secret configured, so that the probe listener
  (default port 8082) and `POST /v1/probe/token` are enabled.
* A control API bearer token for the prober, in a file.

## Run

```sh
pip install -e .            # from this directory
# wire-compat: the browser-automation library's own browser installer
playwright install chromium # downloads the browser build the driver launches
export PROXYX_PROBER_API_URL=http://localhost:8080
export PROXYX_PROBER_API_TOKEN_FILE=/run/secrets/prober-token
export PROXYX_PROBER_PROXY_URL=http://localhost:8082
python -m proxyx_prober
```

On Linux, run the installer with `--with-deps` to also install the system
libraries the browser needs. The `proxyx-prober` console script is the same entry
point. `SIGINT` and `SIGTERM` stop the prober cleanly.

Prometheus metrics are served on `/metrics` of `PROXYX_PROBER_METRICS_HOST:PROXYX_PROBER_METRICS_PORT`
(default `0.0.0.0:8081`). The `service` label is the value of `SERVICE_NAME`
(default `proxyx-prober`).

## Settings

All settings are read from environment variables with the prefix
`PROXYX_PROBER_`.

| Variable | Default | Meaning |
| --- | --- | --- |
| `PROXYX_PROBER_API_URL` | required | Control API base URL. |
| `PROXYX_PROBER_API_TOKEN_FILE` | required | File holding the control API bearer token (read on every call, so a rotated secret is picked up). |
| `PROXYX_PROBER_PROXY_URL` | `http://127.0.0.1:8082` | The gateway's probe listener (HTTP CONNECT), used as the browser's proxy. |
| `PROXYX_PROBER_RUNS_PER_TARGET` | `3` | Loads per target and job (1 up to the API's maximum). |
| `PROXYX_PROBER_MAX_CONCURRENT_PROBES` | `4` | Browsers open at once. |
| `PROXYX_PROBER_CANARY_INTERVAL_S` | `3600` | Seconds between canaries of one route class. |
| `PROXYX_PROBER_POLL_INTERVAL_S` | `30` | Seconds between fetches of the target list. |
| `PROXYX_PROBER_NAVIGATION_TIMEOUT_S` | `30` | Per-load timeout; a miss is a `timeout` result. |
| `PROXYX_PROBER_BROWSER_TTL_S` | `900` | Longest a browser may run one job (60 to 1200). The probe token lives 30 minutes, so this plus the setup wait must stay below that. |
| `PROXYX_PROBER_BROWSER_SETUP_TIMEOUT_S` | `60` | Longest wait for the browser to launch. |
| `PROXYX_PROBER_JOB_MAX_AGE_S` | `900` | A job not finished this long after it was queued is dropped. |
| `PROXYX_PROBER_BROWSER_BACKOFF_MIN_S` | `5` | First pause after a browser failure; doubles per failure. |
| `PROXYX_PROBER_BROWSER_BACKOFF_MAX_S` | `300` | Longest pause. |
| `PROXYX_PROBER_REQUEST_TIMEOUT_S` | `10` | Timeout of one control API call. |
| `PROXYX_PROBER_REQUEST_ATTEMPTS` | `3` | Attempts per control API call, first try included. |
| `PROXYX_PROBER_REQUEST_BACKOFF_S` | `0.5` | Base of the jittered backoff between attempts. |
| `PROXYX_PROBER_METRICS_HOST` | `0.0.0.0` | Bind address of the metrics endpoint. |
| `PROXYX_PROBER_METRICS_PORT` | `8081` | Port of the metrics endpoint. |
| `PROXYX_PROBER_LOG_LEVEL` | `INFO` | Python logging level. |

## Develop

```sh
pip install -e '.[dev]'
python -m pytest tests
ruff check . && ruff format --check .
```

The tests use fakes for the browser and the control API, so they need no browser
download and no network.

For a runtime check, install the browser and run the installed `proxyx-prober`
console script against an authenticated local proxy and fixture pages. Verify
successful navigation timings, HTTP errors, block pages, and navigation
timeouts. Inject `407`, unavailable probe tokens, and a missing browser
executable separately: these must produce retry metrics without route results.
Rotate the control API token file while the process runs, inspect `/metrics`,
and send `SIGTERM` during an active navigation to check browser cleanup.
Protocol stubs test failure handling, not gateway authentication or policy;
exercise the real gateway probe listener and control API separately.

## License

AGPL-3.0-only. See [LICENSE](../LICENSE).
