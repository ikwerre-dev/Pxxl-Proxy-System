#!/usr/bin/env sh
set -eu

REPO_URL="${PXXL_REPO_URL:-https://github.com/ikwerre-dev/Pxxl-Proxy-System.git}"
BRANCH="${PXXL_BRANCH:-main}"
INSTALL_DIR="${PXXL_INSTALL_DIR:-$HOME/pxxl-proxy-system}"
NO_START="${PXXL_NO_START:-0}"
ALLOW_DIRTY="${PXXL_ALLOW_DIRTY:-0}"
VERIFY_GIT_SIGNATURE="${PXXL_VERIFY_GIT_SIGNATURE:-0}"
SKIP_CLI="${PXXL_SKIP_CLI:-0}"

banner() {
  cat <<'ART'
PPPP  X   X X   X L      PPPP  RRRR   OOO  X   X Y   Y
P   P  X X   X X  L      P   P R   R O   O  X X   Y Y
PPPP    X     X   L      PPPP  RRRR  O   O   X     Y
P      X X   X X  L      P     R R   O   O  X X    Y
P     X   X X   X LLLLL  P     R  RR  OOO  X   X   Y

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

verify_checkout_signature() {
  [ "$VERIFY_GIT_SIGNATURE" = "1" ] || return 0
  info "verifying git commit signature"
  git -C "$APP_DIR" verify-commit HEAD >/dev/null 2>&1 \
    || fail "HEAD is not signed by a trusted key. Disable only for local testing with PXXL_VERIFY_GIT_SIGNATURE=0."
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
  verify_checkout_signature
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

install_cli() {
  if [ "$SKIP_CLI" = "1" ]; then
    info "PXXL_SKIP_CLI=1 set; skipping pxxl command install"
    return
  fi

  cli_source="$APP_DIR/bin/pxxl"
  [ -f "$cli_source" ] || {
    warn "CLI source not found at $cli_source"
    return
  }

  chmod +x "$cli_source" || true
  bin_dir="${PXXL_CLI_BIN_DIR:-${HOME:?HOME is required to choose a default CLI install directory}/.local/bin}"
  mkdir -p "$bin_dir"
  if ln -sf "$cli_source" "$bin_dir/pxxl"; then
    info "installed pxxl command to $bin_dir/pxxl"
    ensure_cli_path "$bin_dir"
  else
    warn "could not install pxxl command to $bin_dir; set PXXL_CLI_BIN_DIR to a writable directory"
  fi
}

ensure_cli_path() {
  bin_dir="$1"
  case ":${PATH:-}:" in
    *":$bin_dir:"*) return 0 ;;
    *) PATH="$bin_dir:${PATH:-}"; export PATH ;;
  esac

  if [ "${PXXL_UPDATE_PATH:-1}" != "1" ]; then
    warn "$bin_dir is not in PATH; PXXL_UPDATE_PATH=0 set, so shell profile was not updated"
    return 0
  fi

  profile="${PXXL_PATH_PROFILE:-}"
  if [ -z "$profile" ]; then
    shell_name="${SHELL:-}"
    shell_name="${shell_name##*/}"
    case "$shell_name" in
      zsh) profile="$HOME/.zshrc" ;;
      bash) profile="$HOME/.bashrc" ;;
      *) profile="$HOME/.profile" ;;
    esac
  fi

  profile_dir="$(dirname "$profile")"
  if ! { mkdir -p "$profile_dir" && touch "$profile"; }; then
    warn "could not update shell profile at $profile; run: export PATH=\"$bin_dir:\$PATH\""
    return 0
  fi

  if grep -F "# Pxxl Proxy CLI" "$profile" >/dev/null 2>&1; then
    info "shell profile already has Pxxl PATH entry: $profile"
    return 0
  fi

  if {
    printf '\n# Pxxl Proxy CLI\n'
    printf 'case ":$PATH:" in\n'
    printf '  *":%s:"*) ;;\n' "$bin_dir"
    printf '  *) export PATH="%s:$PATH" ;;\n' "$bin_dir"
    printf 'esac\n'
  } >> "$profile"; then
    info "added $bin_dir to PATH in $profile"
    info "open a new terminal, or run: . $profile"
  else
    warn "could not write PATH entry to $profile; run: export PATH=\"$bin_dir:\$PATH\""
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
  pxxl update

Command line:
  pxxl
  pxxl status
  pxxl logs
  pxxl restart
EOF
}

banner
check_requirements
prepare_repo
prepare_env
install_cli
start_stack
print_summary
