#!/usr/bin/env bash
set -Eeuo pipefail

APP_NAME="Pxxl Proxy"
DEFAULT_BRANCH="${DEPLOY_BRANCH:-main}"
PULL_LATEST=true

log() { printf '[%s] %s\n' "$APP_NAME" "$*"; }
die() { printf '[%s] ERROR: %s\n' "$APP_NAME" "$*" >&2; exit 1; }

compose_cmd() {
  if command -v podman-compose >/dev/null 2>&1; then
    printf 'podman-compose'
  elif command -v podman >/dev/null 2>&1 && podman compose version >/dev/null 2>&1; then
    printf 'podman compose'
  else
    die "No Podman compose implementation found. Install podman-compose or podman compose."
  fi
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
