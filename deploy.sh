#!/usr/bin/env bash
set -Eeuo pipefail

APP_NAME="Pxxl Proxy"
DEFAULT_BRANCH="${DEPLOY_BRANCH:-main}"

log() { printf '[%s] %s\n' "$APP_NAME" "$*"; }
die() { printf '[%s] ERROR: %s\n' "$APP_NAME" "$*" >&2; exit 1; }

compose_cmd() {
  if command -v podman-compose >/dev/null 2>&1; then
    printf 'podman-compose'
  elif command -v podman >/dev/null 2>&1 && podman compose version >/dev/null 2>&1; then
    printf 'podman compose'
  elif command -v docker >/dev/null 2>&1 && docker compose version >/dev/null 2>&1; then
    printf 'docker compose'
  elif command -v docker-compose >/dev/null 2>&1; then
    printf 'docker-compose'
  else
    die "No compose implementation found. Install podman-compose, podman compose, or docker compose pointed at Podman."
  fi
}

cd "$(dirname "$0")"

if [ ! -f .env ]; then
  die ".env missing. Run ./setup-podman.sh first."
fi

set -a
. ./.env
set +a

if git rev-parse --is-inside-work-tree >/dev/null 2>&1; then
  branch="$(git rev-parse --abbrev-ref HEAD)"
  log "Pulling latest code on ${branch:-$DEFAULT_BRANCH}"
  git fetch --prune
  git pull --ff-only origin "${branch:-$DEFAULT_BRANCH}"
fi

COMPOSE="$(compose_cmd)"
compose_files=(-f docker-compose.yml)
if [ "${PXXL_ENABLE_RUNTIME_DISCOVERY:-true}" = "true" ]; then
  compose_files+=(-f docker-compose.discovery.yml)
fi

log "Using compose: $COMPOSE ${compose_files[*]}"
log "Rebuilding and starting proxy stack"
$COMPOSE "${compose_files[@]}" up -d --build

for url in "http://127.0.0.1:8081/healthz" "http://127.0.0.1:8081/readyz"; do
  log "Waiting for $url"
  ok=false
  for i in $(seq 1 45); do
    if curl -fsS "$url" >/dev/null 2>&1; then ok=true; break; fi
    sleep 2
  done
  [ "$ok" = true ] || die "Proxy endpoint did not become healthy: $url"
done

log "Proxy is healthy"
