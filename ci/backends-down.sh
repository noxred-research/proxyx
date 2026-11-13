#!/usr/bin/env bash
# Remove the containers ci/backends-up.sh started (same BACKENDS_SUFFIX / $GITHUB_RUN_ID).
set -uo pipefail
SUFFIX="${BACKENDS_SUFFIX:-${GITHUB_RUN_ID:-$$}}"
for name in s3 clickhouse opensearch elasticsearch kafka rabbitmq redis; do
  docker rm -f "proxyx-ci-$name-$SUFFIX" >/dev/null 2>&1 || true
done
