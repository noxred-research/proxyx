## What and why

<!-- One paragraph: the change and the reason. Link the issue it closes. -->

## How it was verified

<!-- Exact commands and their result, e.g. `cargo test -p proxyx-gateway`. -->

## Checklist

- [ ] I have read the [contributing guide](https://github.com/noxred-research/proxyx/blob/main/CONTRIBUTING.md) and agree to the [Code of Conduct](https://github.com/noxred-research/proxyx/blob/main/CODE_OF_CONDUCT.md)
- [ ] `cargo fmt --all --check`, `cargo clippy --workspace --all-targets -- -D warnings` and the affected tests pass
- [ ] `python3 ci/lint-provenance.py` passes
- [ ] Config keys, routes, metrics or cause codes that changed are updated in `docs/` (metric families in `docs/metrics/*.md`)
- [ ] Database changes are new forward-only migrations; no applied migration was edited
- [ ] No change to authentication, destination denial, credential redaction or TLS interception scope, or the change is called out above with its tests
- [ ] No credentials, real customer data or captured third-party traffic in code, tests or fixtures
