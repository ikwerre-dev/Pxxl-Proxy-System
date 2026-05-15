# Local Development

Use non-root ports unless you are running the binary with privileges:

```sh
PXXL_HTTP_ADDR=127.0.0.1:8080 \
PXXL_HTTPS_ADDR=127.0.0.1:8443 \
PXXL_ADMIN_ADDR=127.0.0.1:8081 \
PXXL_METRICS_ADDR=127.0.0.1:9090 \
PXXL_ADMIN_BOOTSTRAP_TOKEN="$(openssl rand -hex 32)" \
cargo run -p pxxl-edge
```

For Docker Compose, provide local-only secrets when starting the stack:

```sh
PXXL_ADMIN_BOOTSTRAP_TOKEN="$(openssl rand -hex 32)" \
GRAFANA_ADMIN_PASSWORD="$(openssl rand -hex 24)" \
docker compose up --build
```

After you create a Redis-backed admin token through `POST /v1/auth/tokens`, remove `PXXL_ADMIN_BOOTSTRAP_TOKEN` for normal restarts. Compose binds admin, metrics, Prometheus, and Grafana to `127.0.0.1` and does not publish Redis, Postgres, ClickHouse, or Loki host ports.

Add hosts:

```txt
127.0.0.1 app.pxxlhost
127.0.0.1 api.pxxlhost
127.0.0.1 admin.pxxlhost
```

The generated certificate is written to `data/certs` in Docker Compose and `/data/certs` by default inside containers.

Docker Compose persists local service state in ignored repo-local folders:

```txt
data/grafana
data/prometheus
data/loki
data/redis
data/postgres
data/clickhouse
```

Restarting or recreating containers keeps these folders. To reset local state, stop the stack and remove the specific folder you want to rebuild.

Runtime socket discovery is disabled in the default Compose stack. To test Docker/Podman label discovery locally, opt in to the discovery override:

```sh
PXXL_DOCKER_ENABLED=true docker compose -f docker-compose.yml -f docker-compose.discovery.yml up -d --build
```

Only enable that override on machines where mounting Docker/Podman sockets into the edge container is acceptable.

For wildcard DNS, configure dnsmasq:

```txt
address=/.pxxlhost/127.0.0.1
```
