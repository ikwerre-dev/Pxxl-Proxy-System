#!/usr/bin/env bash
set -Eeuo pipefail

APP_NAME="Pxxl Proxy setup"
log() { printf '[%s] %s\n' "$APP_NAME" "$*"; }
die() { printf '[%s] ERROR: %s\n' "$APP_NAME" "$*" >&2; exit 1; }

generate_secret() {
  if command -v openssl >/dev/null 2>&1; then openssl rand -hex 32
  elif command -v uuidgen >/dev/null 2>&1; then uuidgen | tr '[:upper:]' '[:lower:]' | tr -d '-'
  else date +%s | sha256sum | awk '{print $1}'
  fi
}

install_podman_debian() {
  log "Installing Podman and compose helpers with apt"
  sudo apt-get update
  sudo apt-get install -y podman podman-compose curl git openssl slirp4netns fuse-overlayfs uidmap
}

ensure_line() {
  file="$1"; key="$2"; value="$3"
  touch "$file"
  if grep -q "^${key}=" "$file"; then
    tmp="${file}.tmp"
    awk -v key="$key" -v value="$value" 'BEGIN { line=key "=" value } $0 ~ "^" key "=" { print line; next } { print }' "$file" > "$tmp"
    mv "$tmp" "$file"
  else
    printf '%s=%s\n' "$key" "$value" >> "$file"
  fi
}

install_user_service() {
  if ! command -v systemctl >/dev/null 2>&1; then
    log "systemctl is not available; skipping user service install"
    return
  fi

  service_dir="${HOME}/.config/systemd/user"
  service_file="${service_dir}/pxxl-proxy.service"
  mkdir -p "$service_dir"
  cat > "$service_file" <<EOF
[Unit]
Description=Pxxl Proxy Podman stack
Wants=network-online.target podman.socket
After=network-online.target podman.socket

[Service]
Type=oneshot
WorkingDirectory=$(pwd)
ExecStart=$(pwd)/deploy.sh --no-pull
ExecStop=/bin/sh -lc 'cd "$(pwd)" && $(command -v podman-compose || printf "podman compose") -f docker-compose.yml -f docker-compose.discovery.yml down'
RemainAfterExit=yes
TimeoutStartSec=0

[Install]
WantedBy=default.target
EOF

  if systemctl --user daemon-reload && systemctl --user enable pxxl-proxy.service; then
    log "Installed user service pxxl-proxy.service. It will start the proxy stack after reboot."
  else
    log "Could not enable the user service yet. After login, run: systemctl --user enable pxxl-proxy.service"
  fi
}

cd "$(dirname "$0")"

if ! command -v podman >/dev/null 2>&1; then
  if command -v apt-get >/dev/null 2>&1; then
    install_podman_debian
  else
    die "Podman is not installed. Install Podman and podman-compose for this distro, then rerun."
  fi
fi

log "Podman: $(podman --version)"

mkdir -p data/redis data/postgres data/clickhouse data/prometheus data/loki data/grafana data/certs

if command -v loginctl >/dev/null 2>&1; then
  log "Enabling lingering for user $(whoami), so rootless Podman services can survive logout"
  sudo loginctl enable-linger "$(whoami)" || true
fi

if command -v systemctl >/dev/null 2>&1; then
  log "Starting rootless Podman socket"
  systemctl --user enable --now podman.socket || log "Could not start podman.socket yet; run systemctl --user enable --now podman.socket after login"
fi

socket_path="/run/user/$(id -u)/podman/podman.sock"
if [ ! -S "$socket_path" ]; then
  log "Podman socket was not found at $socket_path yet. You may need to log out/in or run: systemctl --user start podman.socket"
else
  log "Podman socket ready at $socket_path"
fi

if [ ! -f .env ]; then
  log "Creating proxy .env"
  touch .env
fi

ensure_line .env GRAFANA_ADMIN_PASSWORD "$(generate_secret)"
ensure_line .env PXXL_ADMIN_BOOTSTRAP_TOKEN "$(generate_secret)"
ensure_line .env PXXL_DOCKER_ENABLED "false"
ensure_line .env PXXL_PODMAN_ENABLED "true"
ensure_line .env PXXL_PODMAN_SOCKET_PATH "/var/run/podman/podman.sock"
ensure_line .env PODMAN_SOCKET_PATH "$socket_path"
ensure_line .env PXXL_PODMAN_PUBLISHED_HOST "${PXXL_PODMAN_PUBLISHED_HOST:-host.containers.internal}"
chmod 600 .env

if command -v sudo >/dev/null 2>&1; then
  log "Allowing rootless containers to bind ports 80/443, if permitted"
  echo 'net.ipv4.ip_unprivileged_port_start=80' | sudo tee /etc/sysctl.d/99-pxxl-rootless-ports.conf >/dev/null || true
  sudo sysctl --system >/dev/null || true
fi

install_user_service

log "Proxy Podman setup complete. Review .env, then run ./deploy.sh"
