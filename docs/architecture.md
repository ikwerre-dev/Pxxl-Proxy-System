# Architecture

Pxxl Proxy is organized around a small hot path and several asynchronous control-plane loops.

```mermaid
flowchart LR
  Client["Client"] --> Edge["HTTP/TLS Edge Listener"]
  Edge --> Security["DDoS Checks"]
  Edge --> GeoIP["Offline GeoIP Resolver"]
  Security --> Router["Atomic Route Registry"]
  Router --> Middleware["Middleware Chain"]
  Middleware --> Buffer["Request Buffer / Retry / Mirror"]
  Router --> LB["Load Balancer"]
  LB --> Upstream["Container or Service Upstream"]
  Docker["Docker Socket Poller"] --> Router
  Health["Active Health Checks"] --> Router
  Admin["Authenticated Admin API"] --> Router
  Admin --> Security
  Edge --> Analytics["In-Memory Route Analytics"]
  Analytics --> ClickHouse["ClickHouse pxxl_access_logs"]
  Edge --> Metrics["Prometheus Metrics"]
  Edge --> Trace["W3C traceparent Propagation"]
```

## Hot Path

The request hot path is:

1. Accept TCP or TLS connection.
2. Read HTTP request with Hyper.
3. Extract host and path.
4. Check in-memory blacklist and rate limiter.
5. Resolve location from the offline GeoIP CIDR table.
6. Match route from the atomic route registry.
7. Enforce domain rules, including IP/location allow/block lists, WAF checks, and rate limits.
8. Resolve and execute path middleware chains.
9. Buffer the request body within configured limits when retry, mirroring, content sniffing, or auth middleware needs replayable bytes.
10. Pick a traffic-split or location-specific upstream pool when rules match.
11. Select a healthy upstream using round-robin, weighted round-robin, IP-hash, least-connections, P2C, HRW, EWMA, or latency-aware strategies.
12. Apply sticky-session cookies, circuit-breaker state, in-flight limits, and backup upstream failover.
13. Forward the request with Hyper, retry when configured, and optionally mirror a sampled shadow request.
14. Apply response headers, content-type auto-detection, response buffering limits, and gzip compression.
15. Emit structured logs with generated `x-request-id`, W3C `traceparent` headers, Prometheus metrics, aggregate route stats, recent visit records, and queued ClickHouse analytics events.

No database, internet GeoIP API, Redis lookup, ClickHouse write, health-check probe, or Docker socket access is required to forward a request.

## Control Plane

- Static config loads from `config/pxxl.toml`.
- Docker discovery polls `/var/run/docker.sock` and replaces Docker-sourced routes atomically.
- Podman discovery can poll a Podman-compatible socket and map labels into the same route model.
- Admin API mutates in-memory blacklist state and exposes operational views.
- Admin API can require bearer tokens stored in Redis and optional client IP allowlists.
- API-created routes are persisted in Redis and loaded into the in-memory registry.
- Offline GeoIP records load from `config/geoip/GeoLite2-City.mmdb` at startup when present, with sibling Country/ASN MMDB files used for richer detection. CSV seed files remain supported.
- ClickHouse analytics writer consumes a best-effort queue and creates `pxxl_access_logs`.
- TLS reloader regenerates the local certificate when route domains change.
- Health checker periodically updates upstream `healthy` flags from HTTP probes.
- Passive health observes proxied failures and can mark upstreams unhealthy until recovery.
- Redis sync is prepared for blacklist pub/sub propagation across nodes.

## Crate Boundaries

- `common`: shared route, upstream, listener, and error types
- `config`: TOML parsing and normalization
- `core`: route registry and shared runtime state
- `geo`: offline CIDR-based GeoIP resolver
- `http-proxy`: Hyper/Tokio proxy listeners
- `tls`: local certificate generation and rustls config
- `docker-discovery`: Docker label discovery
- `ddos`: blacklist and rate limiting
- `load-balancer`: upstream selection algorithms
- `metrics`: Prometheus registry
- `api`: admin and metrics HTTP endpoints
- `redis-sync`: blacklist pub/sub hooks
- `storage`: ClickHouse analytics writer and storage boundary types
