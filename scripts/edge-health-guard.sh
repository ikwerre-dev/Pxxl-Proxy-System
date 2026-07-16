#!/usr/bin/env bash
set -Eeuo pipefail

container="${PXXL_EDGE_CONTAINER_NAME:-pxxl-proxy-edge}"
timeout="${PXXL_EDGE_HEALTH_TIMEOUT_SECONDS:-3}"
restart_wait="${PXXL_EDGE_HEALTH_RESTART_WAIT_SECONDS:-5}"

log() {
  printf '[Pxxl Edge Health] %s\n' "$*"
}

admin_url() {
  local port_line host port
  port_line="$(podman port "$container" 8081/tcp 2>/dev/null | head -n 1 || true)"
  host="${port_line%:*}"
  port="${port_line##*:}"

  if [ -z "$port_line" ] || [ "$host" = "$port" ]; then
    host="${PXXL_PROXY_ADMIN_BIND_ADDR:-127.0.0.1}"
    port="${PXXL_PROXY_ADMIN_PORT:-8081}"
  fi

  printf 'http://%s:%s' "$host" "$port"
}

check_endpoint() {
  local base="$1"
  local path="$2"
  curl -fsS --max-time "$timeout" "${base}${path}" >/dev/null
}

restart_edge() {
  log "health check failed; restarting ${container}"
  podman restart "$container" >/dev/null
  sleep "$restart_wait"
}

if ! podman container exists "$container"; then
  log "container ${container} does not exist"
  exit 2
fi

base="$(admin_url)"
if check_endpoint "$base" /healthz && check_endpoint "$base" /readyz; then
  log "healthy"
  exit 0
fi

restart_edge

base="$(admin_url)"
if check_endpoint "$base" /healthz && check_endpoint "$base" /readyz; then
  log "recovered"
  exit 0
fi

log "restart did not recover ${container}"
exit 1
