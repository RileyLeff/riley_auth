#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

echo "Starting test services..."
docker compose -f docker-compose.test.yml up -d --wait

cleanup() {
    echo "Stopping test services..."
    docker compose -f docker-compose.test.yml down -v
}
trap cleanup EXIT

echo "Running integration tests..."
DATABASE_URL="postgres://riley_test:riley_test@localhost:15432/riley_test" \
    cargo test -p riley-auth-api -- --include-ignored --test-threads=1 "$@"
