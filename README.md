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

## Docker Labels

Pxxl Proxy discovers enabled containers through the Docker socket:

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
- `GET /v1/upstreams`
- `GET /v1/certs`
- `POST /v1/blacklist/{domain_id}` with `{"ip":"203.0.113.10"}`
- `DELETE /v1/blacklist/{domain_id}/{ip}`

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

