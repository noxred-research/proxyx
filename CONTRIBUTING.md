# Contributing to ProxyX

Thank you for considering a contribution. This guide covers how the project is organized, what a change must satisfy, and how a pull request is reviewed.

By contributing you agree that your contribution is licensed under the project license, [GNU AGPL version 3 only](LICENSE) (`AGPL-3.0-only`). There is no contributor license agreement and no DCO sign-off requirement. Do not submit code you do not have the right to license under the AGPL.

Security vulnerabilities are **not** reported through issues or pull requests; follow [SECURITY.md](SECURITY.md). Everyone taking part in the project is expected to follow the [Code of Conduct](CODE_OF_CONDUCT.md).

## Intended use and what we accept

ProxyX is built for operating proxy pools and for inspecting traffic whose owner has consented. Contributions must fit that purpose. We will decline changes that:

- add capabilities aimed at evading a site's protections, hiding abuse, or attacking third parties;
- weaken, bypass or add exceptions to destination denial, org isolation, authentication, credential redaction, per-org limits or the scope of TLS interception;
- ship real provider credentials, real customer data, harvested IP lists, captured third-party traffic or exploit payloads in code, fixtures or tests;
- bundle or endorse a specific proxy provider commercially. Provider adapters are examples of the adapter format and are documented as such.

Test only against local services and systems you own. See [Responsible use](README.md#responsible-use-and-security).

## Choose your path

| If you want to | Start here |
| --- | --- |
| Report a bug or request a feature | Open an issue with the matching form; search existing issues first |
| Ask how to use or deploy ProxyX | The [docs](docs/README.md), then the question form |
| Fix a typo or improve documentation | A pull request against `docs/` or the README; no issue needed |
| Change gateway, session proxy or control plane behavior | Open an issue first, then follow the [contribution flow](#contribution-flow) |
| Add a provider adapter example | [providers](docs/providers.md), then a pull request with the adapter and a test |
| Run the stack locally | [Development setup](#development-setup) |
| Operate or deploy ProxyX | [Operations](docs/operations.md) and the [runbooks](docs/runbooks/README.md) |

## Where to start

- Read the [architecture](docs/architecture.md) and the [configuration reference](docs/configuration.md).
- The workspace is split into crates by responsibility; the table in the architecture page says which crate owns what. A change normally stays inside one plane (pool, session or control).
- Open an issue before starting a large change so the approach can be agreed first. Small fixes and documentation corrections can go straight to a pull request.

## Development setup

- **Rust toolchain.** The version in [`rust-toolchain.toml`](rust-toolchain.toml); `rustup` installs it automatically.
- **Native build dependencies.** CMake, Clang, `perl`, `pkg-config`, OpenSSL and SASL development headers. BoringSSL (session proxy) and librdkafka (control plane) build from source. The protobuf compiler is vendored.
- **Build.** `cargo build --workspace`.
- **Datastores for tests.** Many tests need a real PostgreSQL and a Redis-compatible server on loopback. Set `PROXYX_TEST_DATABASE_URL` (for example `postgres://proxyx:proxyx@127.0.0.1:5432/proxyx_test`) and `PROXYX_TEST_REDIS_URL` (for example `redis://127.0.0.1:6379`). Tests that need them print `SKIP` and pass when the variables are unset, so a green run without them proves less than a run with them. Use a disposable Redis: tests write and delete keys.
- **Whole stack.** `docker compose -f docker/docker-compose.yml up -d --build --wait` starts every role against local datastores.

## Checks to run before opening a pull request

```
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
cargo nextest run --no-fail-fast --workspace        # or: cargo test --workspace
python3 ci/lint-provenance.py
cargo deny --locked check licenses advisories bans sources
```

If you touch `prober/`:

```
python3 -m venv .venv && .venv/bin/pip install -e 'prober[dev]'
.venv/bin/python -m pytest -q prober/tests && .venv/bin/ruff check prober
```

If you touch `docker/`, run `docker compose -f docker/docker-compose.yml config` and build the image.

## Coding standards

All Rust follows the workspace lints in [`Cargo.toml`](Cargo.toml). On top of those:

- **No `unsafe`** in crates that inherit the workspace lints (`unsafe_code = "forbid"`). Do not add exceptions.
- **No `unwrap`** in non-test code (`clippy::unwrap_used = "deny"`). Return typed errors. Release builds abort on panic, so a panic in a serving process is an outage: avoid arithmetic that can overflow a clock or a length, and check conversions.
- **Errors.** Library crates return typed errors with lowercase messages without trailing punctuation and keep the cause chain. `anyhow` is for process wiring in the binaries. Never put a secret into an error message.
- **Ownership and allocation.** Prefer borrowing to cloning, `&[T]` to `&Vec<T>`, `&str` to `&String`. Avoid allocation on the tunnel and capture hot paths.
- **Async.** Never hold a lock across `.await`. Channels are bounded. Long-lived tasks take a cancellation token and are supervised. Blocking or CPU-heavy work goes through `spawn_blocking`.
- **Logging.** Use structured `tracing` fields. Never log secrets, credentials, org keys, session ids, provider logins, cookies or request and response bodies. Use the existing redaction helpers for URLs that may carry credentials.
- **Public API.** Document public items and add a `//!` module comment. Prefer `#[must_use]` on builders and result-returning constructors.
- **Boring design.** Prefer a small direct implementation to a new abstraction, and delete code you replace.

## Tests

- Tests are deterministic and use no external network. Use loopback fixtures and the stand-in services the test suites already provide.
- A behavior change needs a test that fails without it. A bug fix needs a regression test.
- Do not put real-format provider credentials or API tokens in tests or fixtures. Build synthetic values at runtime from split parts, with a comment that they are canaries, so secret scanners do not flag the repository (`gitleaks` runs in CI).
- Metric families have a catalogue: [`docs/metrics/pool.md`](docs/metrics/pool.md) is parsed by a unit test and compared with the registry. Adding, removing or relabeling a metric means updating the matching `### \`metric_name\`` heading and its `- **Labels:**` line.

## Documentation

Update the relevant page under [`docs/`](docs/README.md) and add a [`CHANGELOG.md`](CHANGELOG.md) entry under `[Unreleased]` for user-visible behavior, configuration, API, metric or schema changes. Config keys have one reference, [`docs/configuration.md`](docs/configuration.md); do not describe the same key in two places. Documentation describes ProxyX as it is: do not reference the history of the code or names of internal systems. `ci/lint-provenance.py` enforces the identifier rules.

## Database migrations

Migrations are forward-only and embedded in the binary. Never edit a migration that has been released; add a new one. A release ships only schema changes that the previous release can run against (add before use, remove one release later), so an image rollback stays possible. Pool migrations live in `crates/store/migrations`, control plane migrations in `crates/control/migrations` (Postgres) and `crates/control/clickhouse` (ClickHouse). See [operations](docs/operations.md#migrations).

## Contribution flow

1. Fork the repository and create a branch from `main` whose name describes the change.
2. Reproduce the current behavior before editing, and add or update tests for the successful path and the relevant failures.
3. Make focused commits. A pull request should do one thing, with the smallest change that satisfies the tests.
4. Run the [checks](#checks-to-run-before-opening-a-pull-request) locally.
5. Open a pull request and fill in the template: why the change is needed, what behavior changed, the exact checks you ran, and any safety, configuration, migration or deployment impact.
6. A code owner reviews the pull request. Expect requests for tests, documentation, or a narrower scope. Do not bypass a failing check; fix it, or describe an unrelated failure precisely enough for a reviewer to reproduce it.

Keep credentials, local environment files, raw user data and generated secrets out of commits and pull requests.

### Continuous integration for external pull requests

GitHub Actions workflows run only for pull requests from code owners (the allow-list is [`.github/CODEOWNERS`](.github/CODEOWNERS)). For a pull request from a fork, a maintainer runs the checks above, with PostgreSQL and Valkey, and reports the result on the pull request. A green local run from you speeds this up; it does not replace the maintainer's run. Dependency-update pull requests are handled the same way.

## Getting help

- Questions: the [docs](docs/README.md), then the question issue form.
- Bugs and feature ideas: the matching issue form.
- Security: [SECURITY.md](SECURITY.md), never a public issue.
- Conduct concerns: [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md).

## Conduct

Be respectful and assume good faith. Discussions stay technical. Maintainers may close issues or pull requests that are abusive, off-topic or unsafe to run. The full policy is in the [Code of Conduct](CODE_OF_CONDUCT.md).
