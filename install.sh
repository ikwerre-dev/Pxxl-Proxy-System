#!/usr/bin/env sh
set -eu

REPO_URL="${PXXL_REPO_URL:-https://github.com/ikwerre-dev/Pxxl-Proxy-System.git}"
BRANCH="${PXXL_BRANCH:-main}"
INSTALL_DIR="${PXXL_INSTALL_DIR:-$HOME/pxxl-proxy-system}"
NO_START="${PXXL_NO_START:-0}"
ALLOW_DIRTY="${PXXL_ALLOW_DIRTY:-0}"

banner() {
  cat <<'ART'
 ____            _   ____                      
|  _ \ __  ____ | | |  _ \ _ __ _____  ___   _ 
| |_) |\ \/ / _` | | | |_) | '__/ _ \ \/ / | | |
|  __/  >  < (_| | | |  __/| | | (_) >  <| |_| |
|_|    /_/\_\__, |_| |_|   |_|  \___/_/\_\\__, |
            |___/                         |___/ 

Pxxl Proxy installer
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

script_dir() {
  CDPATH= cd -- "$(dirname "$0")" 2>/dev/null && pwd
}

is_repo_dir() {
  [ -d "$1/.git" ] && [ -f "$1/docker-compose.yml" ] && [ -f "$1/Cargo.toml" ]
}

ensure_command() {
  have "$1" || fail "missing required command: $1"
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

random_hex() {
  openssl rand -hex "$1"
}

ensure_env_var() {
  key="$1"
  value="$2"
  file="$3"
  if [ -f "$file" ] && grep -q "^$key=" "$file"; then
    info "keeping existing $key in .env"
  else
    printf '%s=%s\n' "$key" "$value" >> "$file"
    info "wrote $key to .env"
  fi
}

prepare_repo() {
  caller_dir="$(script_dir)"
  if is_repo_dir "$caller_dir"; then
    APP_DIR="$caller_dir"
    info "using existing checkout: $APP_DIR"
  else
    APP_DIR="$INSTALL_DIR"
    if [ -d "$APP_DIR/.git" ]; then
      info "using existing checkout: $APP_DIR"
    elif [ -e "$APP_DIR" ]; then
      fail "install directory exists but is not a git checkout: $APP_DIR"
    else
      parent_dir="$(dirname "$APP_DIR")"
      mkdir -p "$parent_dir"
      info "cloning $REPO_URL into $APP_DIR"
      git clone --branch "$BRANCH" "$REPO_URL" "$APP_DIR"
    fi
  fi

  if git -C "$APP_DIR" status --porcelain --untracked-files=all | grep . >/dev/null 2>&1; then
    if [ "$ALLOW_DIRTY" = "1" ]; then
      warn "checkout has local changes; continuing because PXXL_ALLOW_DIRTY=1"
    else
      warn "checkout has local changes; skipping git pull to avoid overwriting your work"
      return
    fi
  fi

  info "checking for repository updates"
  git -C "$APP_DIR" fetch --tags origin
  current_branch="$(git -C "$APP_DIR" rev-parse --abbrev-ref HEAD)"
  if [ "$current_branch" = "HEAD" ]; then
    git -C "$APP_DIR" checkout "$BRANCH"
    current_branch="$BRANCH"
  fi
  git -C "$APP_DIR" pull --ff-only origin "$current_branch"
}

check_requirements() {
  info "checking requirements"
  ensure_command git
  ensure_command openssl
  ensure_command docker
  compose version >/dev/null
  if ! docker info >/dev/null 2>&1; then
    fail "Docker is installed, but the daemon is not reachable. Start Docker Desktop or the Docker service and rerun this installer."
  fi
}

prepare_env() {
  cd "$APP_DIR"
  mkdir -p data/certs data/secrets data/redis data/postgres data/clickhouse data/prometheus data/loki data/grafana

  ENV_FILE="$APP_DIR/.env"
  if [ ! -f "$ENV_FILE" ]; then
    : > "$ENV_FILE"
    chmod 600 "$ENV_FILE" || true
  fi

  ensure_env_var "PXXL_ADMIN_BOOTSTRAP_TOKEN" "$(random_hex 32)" "$ENV_FILE"
  ensure_env_var "GRAFANA_ADMIN_PASSWORD" "$(random_hex 24)" "$ENV_FILE"

  if [ -S "/var/run/podman/podman.sock" ]; then
    ensure_env_var "PODMAN_SOCKET_PATH" "/var/run/podman/podman.sock" "$ENV_FILE"
  else
    : > "$APP_DIR/data/podman.sock"
    ensure_env_var "PODMAN_SOCKET_PATH" "./data/podman.sock" "$ENV_FILE"
  fi
}

start_stack() {
  cd "$APP_DIR"
  if [ "$NO_START" = "1" ]; then
    info "PXXL_NO_START=1 set; skipping docker compose startup"
    return
  fi

  info "building and starting Pxxl Proxy"
  compose up -d --build
  compose ps
}

print_summary() {
  cat <<EOF

Pxxl Proxy is ready.

Directory:
  $APP_DIR

Useful URLs:
  Proxy HTTP:     http://127.0.0.1
  Admin API:      http://127.0.0.1:8081
  Metrics:        http://127.0.0.1:9090/metrics
  Prometheus:     http://127.0.0.1:9091
  Grafana:        http://127.0.0.1:3000

Local host entries for .pxxlhost testing:
  127.0.0.1 app.pxxlhost
  127.0.0.1 api.pxxlhost
  127.0.0.1 admin.pxxlhost

Secrets were written to:
  $APP_DIR/.env

Update later with:
  $APP_DIR/update.sh
EOF
}

banner
check_requirements
prepare_repo
prepare_env
start_stack
print_summary
