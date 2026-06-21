#!/usr/bin/env bash
set -Eeuo pipefail

APP_NAME="Pxxl Proxy Edge"
BRANCH="${DEPLOY_BRANCH:-main}"
PULL_LATEST=true
EDGE_NAME="${PXXL_EDGE_CONTAINER_NAME:-pxxl-proxy-edge}"
WG_ADMIN_BIND="${PXXL_PROXY_ADMIN_BIND_ADDR:-10.88.0.31}"
WG_METRICS_BIND="${PXXL_PROXY_METRICS_BIND_ADDR:-10.88.0.31}"
CANDIDATE_HTTP_PORT="${PXXL_EDGE_CANDIDATE_HTTP_PORT:-18080}"
CANDIDATE_HTTPS_PORT="${PXXL_EDGE_CANDIDATE_HTTPS_PORT:-18443}"
CANDIDATE_ADMIN_PORT="${PXXL_EDGE_CANDIDATE_ADMIN_PORT:-18081}"
CANDIDATE_METRICS_PORT="${PXXL_EDGE_CANDIDATE_METRICS_PORT:-19090}"

log() { printf '[%s] %s\n' "$APP_NAME" "$*"; }
die() { printf '[%s] ERROR: %s\n' "$APP_NAME" "$*" >&2; exit 1; }

for arg in "$@"; do
  case "$arg" in
    --no-pull) PULL_LATEST=false ;;
    *) die "unknown argument: $arg" ;;
  esac
done

cd "$(dirname "$0")/.."
[ -f .env ] || die ".env missing. Run setup first."

set -a
. ./.env
set +a

if [ "$PULL_LATEST" = true ] && git rev-parse --is-inside-work-tree >/dev/null 2>&1; then
  branch="$(git rev-parse --abbrev-ref HEAD)"
  log "Pulling latest code on ${branch:-$BRANCH}"
  git fetch --prune
  git pull --ff-only origin "${branch:-$BRANCH}"
else
  log "Skipping git pull"
fi

sha="$(git rev-parse --short=12 HEAD)"
image="localhost/pxxl-edge:${sha}"
candidate="${EDGE_NAME}-candidate-${sha}"

cleanup_candidate() {
  podman rm -f "$candidate" >/dev/null 2>&1 || true
}

remove_redirects() {
  sudo iptables -t nat -D PREROUTING -p tcp --dport 80 -j REDIRECT --to-ports "$CANDIDATE_HTTP_PORT" >/dev/null 2>&1 || true
  sudo iptables -t nat -D PREROUTING -p tcp --dport 443 -j REDIRECT --to-ports "$CANDIDATE_HTTPS_PORT" >/dev/null 2>&1 || true
}

trap 'remove_redirects; cleanup_candidate' EXIT

log "Building candidate image while current edge keeps serving"
podman build -f ./edge/docker/Dockerfile -t "$image" .

cleanup_candidate

common_env=(
  -e PXXL_CONFIG=/app/config/pxxl.toml
  -e PXXL_ADMIN_ADDR=0.0.0.0:8081
  -e PXXL_METRICS_ADDR=0.0.0.0:9090
  -e "PXXL_ADMIN_EMAIL=${PXXL_ADMIN_EMAIL:-}"
  -e "PXXL_ADMIN_PASSWORD_HASH=${PXXL_ADMIN_PASSWORD_HASH:-}"
  -e "PXXL_ADMIN_BOOTSTRAP_TOKEN=${PXXL_ADMIN_BOOTSTRAP_TOKEN:-}"
  -e "PXXL_ADMIN_BOOTSTRAP_TOKEN_PERMANENT=${PXXL_ADMIN_BOOTSTRAP_TOKEN_PERMANENT:-false}"
  -e "PXXL_ADMIN_IP_ALLOWLIST=${PXXL_ADMIN_IP_ALLOWLIST:-}"
  -e "PXXL_METRICS_BEARER_TOKEN=${PXXL_METRICS_BEARER_TOKEN:-}"
  -e "PXXL_DOCKER_ENABLED=${PXXL_DOCKER_ENABLED:-false}"
  -e "PXXL_PODMAN_ENABLED=${PXXL_PODMAN_ENABLED:-false}"
  -e "PXXL_ALLOW_HOST_GATEWAY_UPSTREAMS=${PXXL_ALLOW_HOST_GATEWAY_UPSTREAMS:-false}"
  -e "PXXL_ALLOW_PRIVATE_UPSTREAMS=${PXXL_ALLOW_PRIVATE_UPSTREAMS:-true}"
  -e "PXXL_ACME_CHALLENGE_DIR=${PXXL_ACME_CHALLENGE_DIR:-/data/acme-challenges}"
  -e "PXXL_STATIC_LOCAL_CERT=${PXXL_STATIC_LOCAL_CERT:-}"
  -e "PXXL_STATIC_LOCAL_KEY=${PXXL_STATIC_LOCAL_KEY:-}"
  -e "PXXL_ACME_EMAIL=${PXXL_ACME_EMAIL:-admin@pxxl.app}"
  -e "PXXL_STATS_SNAPSHOT_PATH=${PXXL_STATS_SNAPSHOT_PATH:-/data/stats/domain-stats.json}"
  -e "PXXL_STATS_SNAPSHOT_INTERVAL_SECONDS=${PXXL_STATS_SNAPSHOT_INTERVAL_SECONDS:-10}"
  -e "PXXL_TRUSTED_CLIENT_IP_CIDRS=${PXXL_TRUSTED_CLIENT_IP_CIDRS:-${PXXL_TRUSTED_PROXY_CIDRS:-10.88.0.0/16,10.89.0.0/16,127.0.0.1/32,::1/128}}"
  -e "RUST_LOG=${RUST_LOG:-pxxl_edge=info,pxxl=info}"
)

run_edge() {
  local name="$1"
  local http_port="$2"
  local https_port="$3"
  local admin_bind="$4"
  local admin_port="$5"
  local metrics_bind="$6"
  local metrics_port="$7"

  podman run \
    --name="$name" \
    -d \
    --security-opt no-new-privileges:true \
    --read-only \
    --cap-add NET_BIND_SERVICE \
    --cap-drop ALL \
    --tmpfs /tmp \
    -v "$PWD/config:/app/config:ro" \
    -v "$PWD/data:/data" \
    --net proxy_default,frontend_default,gateway_default \
    --network-alias edge \
    -p "${http_port}:80" \
    -p "${https_port}:443" \
    -p "${admin_bind}:${admin_port}:8081" \
    -p "${metrics_bind}:${metrics_port}:9090" \
    --restart unless-stopped \
    --cpus "${PXXL_EDGE_CPUS:-1.0}" \
    -m "${PXXL_EDGE_MEMORY:-512m}" \
    "${common_env[@]}" \
    "$image" >/dev/null
}

wait_health() {
  local url="$1"
  log "Waiting for $url"
  for _ in $(seq 1 45); do
    if curl -fsS "$url" >/dev/null 2>&1; then
      return 0
    fi
    sleep 2
  done
  return 1
}

log "Starting candidate $candidate on alternate ports"
run_edge "$candidate" "$CANDIDATE_HTTP_PORT" "$CANDIDATE_HTTPS_PORT" "127.0.0.1" "$CANDIDATE_ADMIN_PORT" "127.0.0.1" "$CANDIDATE_METRICS_PORT"
wait_health "http://127.0.0.1:${CANDIDATE_ADMIN_PORT}/healthz" || die "candidate did not become healthy"
wait_health "http://127.0.0.1:${CANDIDATE_ADMIN_PORT}/readyz" || die "candidate did not become ready"

log "Redirecting public 80/443 to candidate during real-port handoff"
remove_redirects
sudo iptables -t nat -I PREROUTING 1 -p tcp --dport 80 -j REDIRECT --to-ports "$CANDIDATE_HTTP_PORT"
sudo iptables -t nat -I PREROUTING 1 -p tcp --dport 443 -j REDIRECT --to-ports "$CANDIDATE_HTTPS_PORT"
sleep 1

log "Replacing real edge container"
podman rm -f "$EDGE_NAME" >/dev/null 2>&1 || true
run_edge "$EDGE_NAME" "80" "443" "$WG_ADMIN_BIND" "8081" "$WG_METRICS_BIND" "9090"
wait_health "http://${WG_ADMIN_BIND}:8081/healthz" || die "new edge did not become healthy"
wait_health "http://${WG_ADMIN_BIND}:8081/readyz" || die "new edge did not become ready"

log "Removing temporary redirects and candidate"
remove_redirects
cleanup_candidate

log "Edge switched successfully"
