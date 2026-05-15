#!/usr/bin/env sh
set -eu

NO_START="${PXXL_NO_START:-0}"
ALLOW_DIRTY="${PXXL_ALLOW_DIRTY:-0}"
VERIFY_GIT_SIGNATURE="${PXXL_VERIFY_GIT_SIGNATURE:-0}"

banner() {
  cat <<'ART'
 ____            _   ____                      
|  _ \ __  ____ | | |  _ \ _ __ _____  ___   _ 
| |_) |\ \/ / _` | | | |_) | '__/ _ \ \/ / | | |
|  __/  >  < (_| | |  __/| | | (_) >  <| |_| |
|_|    /_/\_\__, |_| |_|   |_|  \___/_/\_\\__, |
            |___/                         |___/ 

Pxxl Proxy updater
ART
}

info() {
  printf '%s\n' "==> $*"
}

warn() {
  printf '%s\n' "WARN: $*" >&2
}

fail() {
  printf '%s\n' "ERROR: $*" >&2
  exit 1
}

have() {
  command -v "$1" >/dev/null 2>&1
}

compose() {
  if docker compose version >/dev/null 2>&1; then
    docker compose "$@"
  elif have docker-compose; then
    docker-compose "$@"
  else
    fail "Docker Compose is required. Install Docker Desktop or the docker compose plugin."
  fi
}

verify_checkout_signature() {
  [ "$VERIFY_GIT_SIGNATURE" = "1" ] || return 0
  info "verifying git commit signature"
  git verify-commit HEAD >/dev/null 2>&1 \
    || fail "HEAD is not signed by a trusted key. Disable only for local testing with PXXL_VERIFY_GIT_SIGNATURE=0."
}

script_dir() {
  CDPATH= cd -- "$(dirname "$0")" 2>/dev/null && pwd
}

ensure_env_file() {
  if [ ! -f ".env" ]; then
    warn ".env was missing; creating local secrets"
    if ! have openssl; then
      fail "openssl is required to create .env secrets"
    fi
    {
      printf 'PXXL_ADMIN_BOOTSTRAP_TOKEN=%s\n' "$(openssl rand -hex 32)"
      printf 'GRAFANA_ADMIN_PASSWORD=%s\n' "$(openssl rand -hex 24)"
      if [ -S "/var/run/podman/podman.sock" ]; then
        printf 'PODMAN_SOCKET_PATH=/var/run/podman/podman.sock\n'
      else
        mkdir -p data
        : > data/podman.sock
        printf 'PODMAN_SOCKET_PATH=./data/podman.sock\n'
      fi
    } > .env
    chmod 600 .env || true
  fi
}

banner
APP_DIR="$(script_dir)"
cd "$APP_DIR"

[ -d ".git" ] || fail "update.sh must be run from a git checkout"
have git || fail "missing required command: git"
have docker || fail "missing required command: docker"
compose version >/dev/null

if ! docker info >/dev/null 2>&1; then
  fail "Docker is installed, but the daemon is not reachable. Start Docker Desktop or the Docker service and rerun this updater."
fi

if git status --porcelain --untracked-files=all | grep . >/dev/null 2>&1; then
  if [ "$ALLOW_DIRTY" = "1" ]; then
    warn "checkout has local changes; continuing because PXXL_ALLOW_DIRTY=1"
  else
    fail "checkout has local changes. Commit/stash them, or rerun with PXXL_ALLOW_DIRTY=1 if you know the risk."
  fi
fi

current_branch="$(git rev-parse --abbrev-ref HEAD)"
[ "$current_branch" != "HEAD" ] || fail "checkout is detached; check out a branch before updating"

info "fetching latest code"
git fetch --tags origin
git pull --ff-only origin "$current_branch"
verify_checkout_signature

ensure_env_file
mkdir -p data/certs data/secrets data/redis data/postgres data/clickhouse data/prometheus data/loki data/grafana

if [ "$NO_START" = "1" ]; then
  info "PXXL_NO_START=1 set; skipping docker compose restart"
  exit 0
fi

info "pulling service images"
compose pull --ignore-pull-failures

info "rebuilding and restarting Pxxl Proxy"
compose up -d --build --remove-orphans
compose ps

cat <<EOF

Update complete.

Admin API:  http://127.0.0.1:8081
Grafana:    http://127.0.0.1:3000
Metrics:    http://127.0.0.1:9090/metrics
EOF
