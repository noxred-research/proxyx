#!/usr/bin/env bash
# Short, bounded run of every benchmark path. Fails on a startup failure, on any
# request error, and when a microbenchmark does not run.
#
#   ci/bench-smoke.sh
#   PROFILE=release ci/bench-smoke.sh
#
# Environment:
#   PROFILE                       debug (default, fast to build) or release
#   CARGO_TARGET_DIR              build directory (default: target)
#   PROXYX_BENCH_DATABASE_URL     Postgres server for the gateway run
#                                 (default postgres://postgres@127.0.0.1:45400/postgres; the
#                                 database proxyx_ops_bench is dropped and rebuilt)
#   PROXYX_BENCH_REDIS_URL        Redis for the runs, a database index nothing else uses
#                                 (default redis://127.0.0.1:45401/13; it is flushed)
#   SMOKE_SECONDS                 length of each load run (default 3)
#   SMOKE_CONCURRENCY             workers of each load run (default 8)
set -euo pipefail

cd "$(dirname "$0")/.."

PROFILE="${PROFILE:-debug}"
case "$PROFILE" in
  debug)   build_flags=();            profile_dir=debug ;;
  release) build_flags=(--release);   profile_dir=release ;;
  *) echo "bench-smoke: PROFILE must be debug or release, got '$PROFILE'" >&2; exit 2 ;;
esac

target_dir="${CARGO_TARGET_DIR:-target}"
database_url="${PROXYX_BENCH_DATABASE_URL:-postgres://postgres@127.0.0.1:45400/postgres}"
redis_url="${PROXYX_BENCH_REDIS_URL:-redis://127.0.0.1:45401/13}"
seconds="${SMOKE_SECONDS:-3}"
concurrency="${SMOKE_CONCURRENCY:-8}"
mkdir -p "$target_dir/bench-smoke"
work="$(mktemp -d "$target_dir/bench-smoke/run.XXXXXX")"
trap 'rm -rf "$work"' EXIT

echo "== build ($PROFILE)"
cargo build "${build_flags[@]}" -p proxyx-bench -p proxyx -p proxyx-intercept

bench="$target_dir/$profile_dir/proxyx-bench"
gateway_bin="$target_dir/$profile_dir/proxyx"
intercept_bin="$target_dir/$profile_dir/proxyx-intercept"
for f in "$bench" "$gateway_bin" "$intercept_bin"; do
  [ -x "$f" ] || { echo "bench-smoke: $f was not built" >&2; exit 1; }
done

# Each run writes its JSON summary to a file and prints it; a nonzero exit of the
# tool (errors, or no request completed, or a startup failure) fails the script.
run() {
  local name="$1"; shift
  echo "== $name"
  if ! timeout 180 "$bench" "$@" --json --duration "${seconds}s" --concurrency "$concurrency" \
      --workdir "$work/$name" >"$work/$name.json"; then
    echo "bench-smoke: $name failed" >&2
    cat "$work/$name.json" >&2 || true
    exit 1
  fi
  cat "$work/$name.json"
}

run gateway-tunnel  gateway --mode tunnel  --spawn "$gateway_bin" \
  --database-url "$database_url" --redis-url "$redis_url"
run gateway-forward gateway --mode forward --spawn "$gateway_bin" \
  --database-url "$database_url" --redis-url "$redis_url"
run session-passthrough session --mode passthrough --spawn "$intercept_bin" --redis-url "$redis_url"
run session-mitm        session --mode mitm        --spawn "$intercept_bin" --redis-url "$redis_url"

echo "== load tool tests (including the real session proxy)"
PROXYX_BENCH_INTERCEPT="$intercept_bin" PROXYX_TEST_REDIS_URL="$redis_url" \
  cargo test "${build_flags[@]}" -p proxyx-bench --test smoke

# The session proxy links BoringSSL and the control plane OpenSSL; their benches are
# behind features that must not be enabled together, so each runs on its own.
echo "== microbenchmarks (each benchmark runs once)"
if [ "$PROFILE" = release ]; then
  cargo bench -p proxyx-bench -- --test
  cargo bench -p proxyx-bench --features intercept-bench --bench intercept_micro -- --test
  cargo bench -p proxyx-bench --features control-bench --bench control_micro -- --test
else
  cargo test -p proxyx-bench --benches
  cargo test -p proxyx-bench --features intercept-bench --bench intercept_micro
  cargo test -p proxyx-bench --features control-bench --bench control_micro
fi

echo "bench-smoke: ok"
