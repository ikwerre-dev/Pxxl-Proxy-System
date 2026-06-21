#!/usr/bin/env bash
set -Eeuo pipefail

APP_NAME="Pxxl Proxy"
DEFAULT_BRANCH="${DEPLOY_BRANCH:-main}"
PULL_LATEST=true

log() { printf '[%s] %s\n' "$APP_NAME" "$*"; }
die() { printf '[%s] ERROR: %s\n' "$APP_NAME" "$*" >&2; exit 1; }

bool_enabled() {
  case "${1:-}" in
    1|true|TRUE|yes|YES|on|ON) return 0 ;;
    *) return 1 ;;
  esac
}

compose_cmd() {
  if command -v podman-compose >/dev/null 2>&1; then
    printf 'podman-compose'
  elif command -v podman >/dev/null 2>&1 && podman compose version >/dev/null 2>&1; then
    printf 'podman compose'
  else
    die "No Podman compose implementation found. Install podman-compose or podman compose."
  fi
}

proxy_admin_token() {
  local token="${PXXL_PROXY_ADMIN_TOKEN:-}"
  if [ -z "$token" ]; then
    token="${PXXL_ADMIN_BOOTSTRAP_TOKEN:-}"
  fi
  printf '%s' "$token"
}

prune_after_build() {
  bool_enabled "${PXXL_PRUNE_AFTER_BUILD:-true}" || return 0
  command -v podman >/dev/null 2>&1 || return 0

  log "Pruning unused Podman build/container/image data"
  podman system prune -af >/dev/null 2>&1 || log "Podman prune skipped or failed; continuing"
}

active_gateway_upstream() {
  if [ -n "${PXXL_GATEWAY_UPSTREAM:-}" ]; then
    printf '%s' "$PXXL_GATEWAY_UPSTREAM"
  elif [ -s ../gateway/.active_upstream ]; then
    tr -d '\n' < ../gateway/.active_upstream
  else
    printf ''
  fi
}

active_frontend_upstream() {
  if [ -n "${PXXL_FRONTEND_UPSTREAM:-}" ]; then
    printf '%s' "$PXXL_FRONTEND_UPSTREAM"
  elif [ -s ../frontend/.active_upstream ]; then
    tr -d '\n' < ../frontend/.active_upstream
  else
    printf ''
  fi
}

sync_control_plane_routes() {
  [ "${PXXL_PROXY_SYNC_ROUTES:-true}" = "true" ] || return 0

  local admin_url="${PXXL_PROXY_ADMIN_URL:-http://127.0.0.1:8081}"
  local token gateway_upstream frontend_upstream domain payload
  local gateway_domains="${PXXL_GATEWAY_PROXY_DOMAINS:-gateway.pxxl.app}"
  local frontend_domains="${PXXL_FRONTEND_PROXY_DOMAINS:-v3.pxxl.app}"
  local posthog_api_upstream="${PXXL_POSTHOG_API_UPSTREAM:-https://us.i.posthog.com}"
  local posthog_assets_upstream="${PXXL_POSTHOG_ASSETS_UPSTREAM:-https://us-assets.i.posthog.com}"
  local -a curl_args

  token="$(proxy_admin_token)"
  gateway_upstream="$(active_gateway_upstream)"
  frontend_upstream="$(active_frontend_upstream)"

  if [ -z "$gateway_upstream" ] && [ -z "$frontend_upstream" ]; then
    log "No active Gateway/frontend upstream markers found; skipping route sync"
    return 0
  fi

  for domain in $gateway_domains; do
    [ -n "$gateway_upstream" ] || continue
    payload=$(
      printf '{"domain":"%s","id":"gateway-%s","tls":true,"upstreams":[{"url":"%s","weight":1}]}' \
        "$domain" "$domain" "$gateway_upstream"
    )
    log "Syncing proxy route $domain -> $gateway_upstream"
    curl_args=(-fsS -X POST "$admin_url/v1/domains" -H 'Content-Type: application/json')
    if [ -n "$token" ]; then
      curl_args+=(-H "Authorization: Bearer $token")
    fi
    curl "${curl_args[@]}" -d "$payload" >/dev/null
  done

  for domain in $frontend_domains; do
    [ -n "$gateway_upstream" ] || continue
    [ -n "$frontend_upstream" ] || continue
    payload=$(
      printf '{"domain":"%s","id":"frontend-%s","tls":true,"paths":[{"prefix":"/api/surveys","upstreams":[{"url":"%s","weight":1}]},{"prefix":"/i","upstreams":[{"url":"%s","weight":1}]},{"prefix":"/e","upstreams":[{"url":"%s","weight":1}]},{"prefix":"/batch","upstreams":[{"url":"%s","weight":1}]},{"prefix":"/decide","upstreams":[{"url":"%s","weight":1}]},{"prefix":"/flags","upstreams":[{"url":"%s","weight":1}]},{"prefix":"/capture","upstreams":[{"url":"%s","weight":1}]},{"prefix":"/engage","upstreams":[{"url":"%s","weight":1}]},{"prefix":"/array","upstreams":[{"url":"%s","weight":1}]},{"prefix":"/static","upstreams":[{"url":"%s","weight":1}]},{"prefix":"/api","upstreams":[{"url":"%s","weight":1}]},{"prefix":"/","upstreams":[{"url":"%s","weight":1}]}]}' \
        "$domain" "$domain" "$posthog_api_upstream" "$posthog_api_upstream" "$posthog_api_upstream" "$posthog_api_upstream" "$posthog_api_upstream" "$posthog_api_upstream" "$posthog_api_upstream" "$posthog_api_upstream" "$posthog_assets_upstream" "$posthog_assets_upstream" "$gateway_upstream" "$frontend_upstream"
    )
    log "Syncing proxy route $domain -> /api $gateway_upstream, PostHog first-party, / $frontend_upstream"
    curl_args=(-fsS -X POST "$admin_url/v1/domains" -H 'Content-Type: application/json')
    if [ -n "$token" ]; then
      curl_args+=(-H "Authorization: Bearer $token")
    fi
    curl "${curl_args[@]}" -d "$payload" >/dev/null
  done
}

replace_edge_container_after_build() {
  command -v podman >/dev/null 2>&1 || return 0

  log "Building edge image while the current proxy keeps serving"
  podman build -f ./edge/docker/Dockerfile -t localhost/pxxl-edge:local .

  log "Replacing edge container after image build"
  podman rm -f pxxl-proxy-grafana >/dev/null 2>&1 || true
  podman rm -f pxxl-proxy-prometheus >/dev/null 2>&1 || true
  podman rm -f pxxl-proxy-edge >/dev/null 2>&1 || true
}

for arg in "$@"; do
  case "$arg" in
    --no-pull) PULL_LATEST=false ;;
    *) die "unknown argument: $arg" ;;
  esac
done

cd "$(dirname "$0")"

if [ ! -f .env ]; then
  die ".env missing. Run ./setup-podman.sh first."
fi

set -a
. ./.env
set +a

export PXXL_TRUSTED_CLIENT_IP_CIDRS="${PXXL_TRUSTED_CLIENT_IP_CIDRS:-${PXXL_TRUSTED_PROXY_CIDRS:-10.88.0.0/16,10.89.0.0/16,127.0.0.1/32,::1/128}}"

if [ "$PULL_LATEST" = true ] && git rev-parse --is-inside-work-tree >/dev/null 2>&1; then
  branch="$(git rev-parse --abbrev-ref HEAD)"
  log "Pulling latest code on ${branch:-$DEFAULT_BRANCH}"
  git fetch --prune
  git pull --ff-only origin "${branch:-$DEFAULT_BRANCH}"
elif [ "$PULL_LATEST" = false ]; then
  log "Skipping git pull because --no-pull was provided"
fi

COMPOSE="$(compose_cmd)"
compose_files=(-f docker-compose.yml)
if [ "${PXXL_ENABLE_RUNTIME_DISCOVERY:-true}" = "true" ]; then
  compose_files+=(-f docker-compose.discovery.yml)
fi

log "Using compose: $COMPOSE ${compose_files[*]}"
replace_edge_container_after_build

log "Starting proxy stack"
$COMPOSE "${compose_files[@]}" up -d

admin_health_base="${PXXL_PROXY_ADMIN_URL:-http://127.0.0.1:8081}"
admin_health_base="${admin_health_base%/}"
for url in "$admin_health_base/healthz" "$admin_health_base/readyz"; do
  log "Waiting for $url"
  ok=false
  for i in $(seq 1 45); do
    if curl -fsS "$url" >/dev/null 2>&1; then ok=true; break; fi
    sleep 2
  done
  [ "$ok" = true ] || die "Proxy endpoint did not become healthy: $url"
done

sync_control_plane_routes

log "Proxy is healthy"
prune_after_build
