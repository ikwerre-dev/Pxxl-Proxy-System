#!/usr/bin/env bash
set -Eeuo pipefail

repo_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
payload_file="$(mktemp)"
trap 'rm -f "$payload_file"' EXIT

# shellcheck source=../deploy.sh
. "$repo_dir/deploy.sh"

curl() {
  local previous="" argument
  for argument in "$@"; do
    if [[ "$previous" == "-d" ]]; then
      printf '%s\n' "$argument" >>"$payload_file"
    fi
    previous="$argument"
  done
}

export PXXL_PROXY_SYNC_ROUTES=true
export PXXL_PROXY_ADMIN_URL=http://proxy.test
export PXXL_PROXY_ADMIN_TOKEN=test-token
export PXXL_GATEWAY_UPSTREAM=http://gateway:8080
export PXXL_APP_UPSTREAM=http://app:3000
export PXXL_WEB_UPSTREAM=http://web:8080
unset PXXL_GATEWAY_PROXY_DOMAINS PXXL_APP_PROXY_DOMAINS PXXL_WEB_PROXY_DOMAINS
unset PXXL_GATEWAY_ALIAS_ENABLED PXXL_GATEWAY_ALIAS_DOMAINS

sync_control_plane_routes

python3 - "$payload_file" <<'PY'
import json
import sys

with open(sys.argv[1], encoding="utf-8") as handle:
    routes = [json.loads(line) for line in handle if line.strip()]

by_domain = {route["domain"]: route for route in routes}
assert set(by_domain) == {"server.pxxl.app", "app.pxxl.app", "pxxl.app", "www.pxxl.app"}, by_domain
assert "gateway.pxxl.app" not in by_domain
assert by_domain["server.pxxl.app"]["upstreams"][0]["url"] == "http://gateway:8080"
assert by_domain["pxxl.app"]["upstreams"][0]["url"] == "http://web:8080"
assert by_domain["www.pxxl.app"]["upstreams"][0]["url"] == "http://web:8080"
app_root = next(path for path in by_domain["app.pxxl.app"]["paths"] if path["prefix"] == "/")
assert app_root["upstreams"][0]["url"] == "http://app:3000"
PY

: >"$payload_file"
export PXXL_GATEWAY_ALIAS_ENABLED=true
sync_control_plane_routes

python3 - "$payload_file" <<'PY'
import json
import sys

with open(sys.argv[1], encoding="utf-8") as handle:
    domains = {json.loads(line)["domain"] for line in handle if line.strip()}
assert "server.pxxl.app" in domains
assert "gateway.pxxl.app" in domains
PY

printf 'control_plane_route_tests_ok\n'
