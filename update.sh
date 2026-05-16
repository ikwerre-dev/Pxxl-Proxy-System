#!/usr/bin/env sh
set -eu

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
install_cli

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

Command line:
  pxxl
  pxxl status
  pxxl logs
EOF
