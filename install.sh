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

set_env_var() {
  key="$1"
  value="$2"
  file="$3"
  tmp="$file.tmp.$$"
  if [ -f "$file" ]; then
    awk -v key="$key" -v value="$value" '
      BEGIN { found = 0 }
      index($0, key "=") == 1 { print key "=" value; found = 1; next }
      { print }
      END { if (!found) print key "=" value }
    ' "$file" > "$tmp"
  else
    printf '%s=%s\n' "$key" "$value" > "$tmp"
  fi
  mv "$tmp" "$file"
  chmod 600 "$file" || true
}

env_has_var() {
  key="$1"
  file="$2"
  [ -f "$file" ] && grep -q "^$key=" "$file"
}

env_get_var() {
  key="$1"
  file="$2"
  [ -f "$file" ] || return 0
  grep "^$key=" "$file" | tail -n 1 | sed "s/^$key=//"
}

prompt_tty() {
  prompt="$1"
  [ -r /dev/tty ] || fail "interactive setup needs a terminal; set PXXL_ADMIN_EMAIL and PXXL_ADMIN_PASSWORD instead"
  printf '%s' "$prompt" > /dev/tty
  IFS= read -r value < /dev/tty
  printf '%s' "$value"
}

prompt_secret_tty() {
  prompt="$1"
  [ -r /dev/tty ] || fail "interactive setup needs a terminal; set PXXL_ADMIN_EMAIL and PXXL_ADMIN_PASSWORD instead"
  printf '%s' "$prompt" > /dev/tty
  old_stty="$(stty -g < /dev/tty 2>/dev/null || true)"
  stty -echo < /dev/tty 2>/dev/null || true
  IFS= read -r value < /dev/tty
  [ -n "$old_stty" ] && stty "$old_stty" < /dev/tty 2>/dev/null || true
  printf '\n' > /dev/tty
  printf '%s' "$value"
}

validate_admin_email() {
  case "$1" in
    *@*.*) ;;
    *) return 1 ;;
  esac
  case "$1" in
    *[[:space:]]*|*@|@*|"") return 1 ;;
  esac
  return 0
}

hash_admin_password() {
  password="$1"
  salt="$(random_hex 16)"
  iterations="${PXXL_ADMIN_PASSWORD_ITERATIONS:-200000}"
  derived="$(openssl kdf -keylen 32 \
    -kdfopt digest:SHA256 \
    -kdfopt "pass:$password" \
    -kdfopt "salt:$salt" \
    -kdfopt "iter:$iterations" \
    PBKDF2 | tr -d ':' | tr 'A-F' 'a-f')"
  printf 'pbkdf2-sha256:%s:%s:%s' "$iterations" "$salt" "$derived"
}

prepare_admin_account() {
  file="$1"
  if env_has_var "PXXL_ADMIN_EMAIL" "$file" && env_has_var "PXXL_ADMIN_PASSWORD_HASH" "$file"; then
    ADMIN_EMAIL_VALUE="$(env_get_var "PXXL_ADMIN_EMAIL" "$file")"
    info "keeping existing initial admin account: $ADMIN_EMAIL_VALUE"
    return
  fi

  email="${PXXL_ADMIN_EMAIL:-}"
  password="${PXXL_ADMIN_PASSWORD:-}"
  password_hash="${PXXL_ADMIN_PASSWORD_HASH:-}"

  if [ -z "$email" ]; then
    email="$(prompt_tty "Initial admin email: ")"
  fi
  validate_admin_email "$email" || fail "admin email does not look valid: $email"

  if [ -z "$password_hash" ]; then
    if [ -z "$password" ]; then
      password="$(prompt_secret_tty "Initial admin password: ")"
      confirm="$(prompt_secret_tty "Confirm admin password: ")"
      [ "$password" = "$confirm" ] || fail "admin passwords did not match"
    fi
    [ "${#password}" -ge 12 ] || fail "admin password must be at least 12 characters"
    password_hash="$(hash_admin_password "$password")"
  fi

  set_env_var "PXXL_ADMIN_EMAIL" "$email" "$file"
  set_env_var "PXXL_ADMIN_PASSWORD_HASH" "$password_hash" "$file"
  ADMIN_EMAIL_VALUE="$email"
  ADMIN_PASSWORD_FOR_LOGIN="$password"
  info "stored initial admin account in .env"
}

prepare_bootstrap_token() {
  file="$1"
  BOOTSTRAP_TOKEN_CREATED=0
  INITIAL_BOOTSTRAP_TOKEN=""
  if env_has_var "PXXL_ADMIN_BOOTSTRAP_TOKEN" "$file"; then
    info "keeping existing PXXL_ADMIN_BOOTSTRAP_TOKEN in .env"
    return
  fi

  if [ -n "${PXXL_ADMIN_BOOTSTRAP_TOKEN:-}" ]; then
    INITIAL_BOOTSTRAP_TOKEN="$PXXL_ADMIN_BOOTSTRAP_TOKEN"
  else
    INITIAL_BOOTSTRAP_TOKEN="$(random_hex 32)"
  fi
  set_env_var "PXXL_ADMIN_BOOTSTRAP_TOKEN" "$INITIAL_BOOTSTRAP_TOKEN" "$file"
  BOOTSTRAP_TOKEN_CREATED=1
  info "wrote one-time PXXL_ADMIN_BOOTSTRAP_TOKEN to .env"
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
  if [ "$NO_START" != "1" ] && ! docker info >/dev/null 2>&1; then
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

  prepare_admin_account "$ENV_FILE"
  prepare_bootstrap_token "$ENV_FILE"
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

json_escape() {
  printf '%s' "$1" | sed 's/\\/\\\\/g; s/"/\\"/g'
}

issue_initial_login_token() {
  INITIAL_LOGIN_TOKEN=""
  if [ "$NO_START" = "1" ] || [ -z "${ADMIN_PASSWORD_FOR_LOGIN:-}" ]; then
    return
  fi
  if ! have curl; then
    warn "curl is not available; run pxxl login later to generate an account token"
    return
  fi

  admin_url="${PXXL_ADMIN_URL:-http://127.0.0.1:8081}"
  info "waiting for admin API to issue first account token"
  attempt=0
  while [ "$attempt" -lt 30 ]; do
    if curl -fsS "$admin_url/healthz" >/dev/null 2>&1; then
      break
    fi
    attempt=$((attempt + 1))
    sleep 1
  done

  if [ "$attempt" -ge 30 ]; then
    warn "admin API did not become reachable; run pxxl login after the stack is up"
    return
  fi

  email_json="$(json_escape "$ADMIN_EMAIL_VALUE")"
  password_json="$(json_escape "$ADMIN_PASSWORD_FOR_LOGIN")"
  response="$(curl -sS -X POST "$admin_url/v1/auth/login" \
    -H "content-type: application/json" \
    --data "{\"email\":\"$email_json\",\"password\":\"$password_json\"}" 2>/dev/null || true)"
  token="$(printf '%s' "$response" | sed -n 's/.*"token":"\([^"]*\)".*/\1/p')"
  if [ -n "$token" ]; then
    INITIAL_LOGIN_TOKEN="$token"
    info "created first Redis-backed admin token"
  else
    warn "could not create first account token automatically; run pxxl login"
  fi
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

Initial admin account:
  Email: ${ADMIN_EMAIL_VALUE:-configured}
EOF

  if [ -n "${INITIAL_LOGIN_TOKEN:-}" ]; then
    cat <<EOF
  Admin token (shown once): $INITIAL_LOGIN_TOKEN
EOF
  else
    cat <<EOF
  Admin token: run pxxl login to generate one
EOF
  fi

  if [ "${BOOTSTRAP_TOKEN_CREATED:-0}" = "1" ]; then
    cat <<EOF
  Bootstrap token (shown once): $INITIAL_BOOTSTRAP_TOKEN
EOF
  else
    cat <<EOF
  Bootstrap token: already exists in .env; run pxxl token refresh to rotate it
EOF
  fi

  cat <<EOF

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
issue_initial_login_token
print_summary
