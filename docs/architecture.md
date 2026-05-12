# Architecture

Pxxl Proxy is organized around a small hot path and several asynchronous control-plane loops.

```mermaid
flowchart LR
  Client["Client"] --> Edge["HTTP/TLS Edge Listener"]
  Edge --> Security["DDoS Checks"]
  Security --> Router["Atomic Route Registry"]
  Router --> LB["Load Balancer"]
  LB --> Upstream["Container or Service Upstream"]
  Docker["Docker Socket Poller"] --> Router
  Admin["Admin API"] --> Router
  Admin --> Security
  Edge --> Metrics["Prometheus Metrics"]
```

## Hot Path

The request hot path is:

1. Accept TCP or TLS connection.
2. Read HTTP request with Hyper.
3. Extract host and path.
4. Check in-memory blacklist and rate limiter.
5. Match route from the atomic route registry.
6. Select a healthy upstream.
7. Stream the request and response with Hyper.
8. Emit structured logs and Prometheus metrics asynchronously.

No database or Docker socket access is required to forward a request.

## Control Plane

- Static config loads from `config/pxxl.toml`.
- Docker discovery polls `/var/run/docker.sock` and replaces Docker-sourced routes atomically.
- Admin API mutates in-memory blacklist state and exposes operational views.
- Redis sync is prepared for blacklist pub/sub propagation across nodes.

## Crate Boundaries

- `common`: shared route, upstream, listener, and error types
- `config`: TOML parsing and normalization
- `core`: route registry and shared runtime state
- `http-proxy`: Hyper/Tokio proxy listeners
- `tls`: local certificate generation and rustls config
- `docker-discovery`: Docker label discovery
- `ddos`: blacklist and rate limiting
- `load-balancer`: upstream selection algorithms
- `metrics`: Prometheus registry
- `api`: admin and metrics HTTP endpoints
- `redis-sync`: blacklist pub/sub hooks
- `storage`: Postgres and ClickHouse boundary types

