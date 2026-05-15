# Pxxl Proxy

Open source Traefik + Nginx alternative by Robinson Honour.

Pxxl Proxy is a Rust-based edge proxy platform focused on low-latency HTTP routing, Docker label discovery, local TLS, in-memory DDoS controls, Prometheus metrics, and production-minded crate boundaries.

This repository currently implements the Phase 1 MVP:

- HTTP reverse proxying with Hyper and Tokio
- Domain and path routing from TOML config
- Docker container route discovery from `pxxl.*` labels
- Local self-signed TLS certificate generation in `/data/certs`
- In-memory per-domain IP blacklist and CIDR blocking
- Per-IP token-bucket request rate limiting
- Round-robin, weighted round-robin, and IP-hash load-balancer selection
- Admin API for health, routes, upstreams, cert metadata, and blacklist changes
- Prometheus metrics endpoint
- Docker, Docker Compose, CI, docs, examples, and tests

Future phases will add TCP/UDP proxying, production ACME flows, ClickHouse analytics ingestion, JWT/RBAC, dashboard UI, active health checks, circuit breakers, cluster sync, and deeper DDoS controls.

## Quick Start

With Docker:

```sh
docker compose up --build
```

Local non-root development ports:

```sh
PXXL_HTTP_ADDR=127.0.0.1:8080 \
PXXL_HTTPS_ADDR=127.0.0.1:8443 \
PXXL_ADMIN_ADDR=127.0.0.1:8081 \
PXXL_METRICS_ADDR=127.0.0.1:9090 \
cargo run -p pxxl-edge
```

Health checks:

```sh
curl http://127.0.0.1:8081/healthz
curl http://127.0.0.1:8081/readyz
curl http://127.0.0.1:9090/metrics
```

## Container Labels

Pxxl Proxy discovers enabled Docker and Podman containers through their runtime sockets:

```yaml
labels:
  - pxxl.enable=true
  - pxxl.domain=app.example.com
  - pxxl.port=3000
  - pxxl.path=/
```

Optional labels:

```yaml
labels:
  - pxxl.scheme=http
  - pxxl.host=my-service
```

Enable each provider independently in `config/pxxl.toml`:

```toml
[docker]
enabled = true
socket_path = "/var/run/docker.sock"

[podman]
enabled = true
socket_path = "/var/run/podman/podman.sock"
published_host = "host.docker.internal"
```

Containers with the same `pxxl.domain` and `pxxl.path` are merged into one route with multiple upstreams. Requests are load-balanced across those upstreams, so stopping one replica removes it from the route on the next discovery poll while traffic keeps flowing to the remaining replicas.

When Pxxl itself is running in Docker and the target is a Podman container, Podman container names are usually not resolvable from the Docker network. In that case Pxxl uses Podman's published port mapping and the configured `published_host`. For example, a Podman container labeled `pxxl.port=80` and published as `-p 8080:80` becomes `http://host.docker.internal:8080`.

## Custom Error Pages

Proxy-generated errors use HTML templates from `config/error-pages` by default. Add or edit files named by status code:

```txt
config/error-pages/404.html
config/error-pages/502.html
config/error-pages/default.html
```

Available template placeholders:

```txt
{{status_code}}
{{status_text}}
{{message}}
{{domain}}
{{path}}
```

Configure the directory in `config/pxxl.toml`:

```toml
[error_pages]
enabled = true
dir = "config/error-pages"
```

You can also override this at runtime with `PXXL_ERROR_PAGES_DIR` or disable custom HTML pages with `PXXL_ERROR_PAGES_ENABLED=false`.

## Local Wildcard Development

The default certificate includes:

- `localhost`
- `pxxlhost`
- `*.pxxlhost`

For simple local development, add host entries:

```txt
127.0.0.1 app.pxxlhost
127.0.0.1 api.pxxlhost
127.0.0.1 admin.pxxlhost
```

For true wildcard resolution, use dnsmasq or CoreDNS.

## Admin API

- `GET /healthz`
- `GET /readyz`
- `GET /v1/routes`
- `GET /v1/domains`
- `POST /v1/domains`
- `GET /v1/domains/{domain}`
- `DELETE /v1/domains/{domain}`
- `GET /v1/stats/domains`
- `GET /v1/domains/{domain}/stats`
- `GET /v1/upstreams`
- `GET /v1/certs`
- `POST /v1/blacklist/{domain_id}` with `{"ip":"203.0.113.10"}`
- `DELETE /v1/blacklist/{domain_id}/{ip}`

API-created domains are persisted in Redis and immediately loaded into the in-memory route registry. The proxy hot path does not query Redis.

Postman collection:

- `docs/postman/pxxl-proxy.postman_collection.json`
- `docs/postman/pxxl-proxy.postman_environment.json`

## Workspace

```txt
edge/
  crates/
    api/
    common/
    config/
    core/
    ddos/
    docker-discovery/
    http-proxy/
    load-balancer/
    metrics/
    redis-sync/
    storage/
    tls/
```

## Development

```sh
make fmt
make lint
make test
make run-local
```

Rust is required for local builds. Docker can build the project through the provided production Dockerfile.

## License

MIT License. Created by Robinson Honour.
