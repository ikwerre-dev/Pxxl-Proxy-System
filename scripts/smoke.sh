#!/usr/bin/env sh
set -eu

ADMIN_URL="${ADMIN_URL:-http://127.0.0.1:8081}"
METRICS_URL="${METRICS_URL:-http://127.0.0.1:9090}"

curl -fsS "$ADMIN_URL/healthz"
curl -fsS "$ADMIN_URL/readyz"
curl -fsS "$METRICS_URL/metrics" | grep pxxl_requests_total >/dev/null

echo "smoke checks passed"

