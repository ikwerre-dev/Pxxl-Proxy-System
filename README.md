# Pxxl Proxy

Open source Traefik + Nginx alternative by Robinson Honour.

Pxxl Proxy is a Rust-based edge proxy platform focused on low-latency HTTP routing, Docker label discovery, local TLS, in-memory DDoS controls, offline GeoIP routing, route analytics, Prometheus metrics, and production-minded crate boundaries.

This repository currently implements the Phase 1 MVP:

- HTTP reverse proxying with Hyper and Tokio
- Domain and path routing from TOML config
- Docker container route discovery from `pxxl.*` labels
- Local self-signed TLS certificate generation and reload for dynamic domains in `/data/certs`
- In-memory per-domain IP blacklist and CIDR blocking
- Per-IP token-bucket request rate limiting
- Per-domain route rules for `www` aliases, WebSockets, headers, IP/location allow/block lists, CORS, HTTPS enforcement, WAF checks, body limits, custom rate limits, and reusable middleware chains
- Offline GeoIP lookups for country/continent analytics, blocking, and location-based upstream routing
- In-memory route analytics with aggregate counters, recent visit history, access-log APIs, and optional ClickHouse persistence
- Active and passive upstream health checks that mark unhealthy upstreams out of rotation
- Round-robin, weighted round-robin, IP-hash, least-connections, P2C, HRW, EWMA, and latency-aware load-balancer selection
- Basic auth, SHA-256 digest auth, ForwardAuth, retries, circuit breakers, in-flight request limits, sticky cookie sessions, traffic mirroring, backup upstream failover, response compression, and content-type auto-detection
- Per-request UUID tracking with `x-request-id`, OpenTelemetry-compatible `traceparent` propagation, and richer Prometheus router, service, middleware, upstream, retry, mirror, and health metrics
- Admin API auth with Redis-backed bearer tokens and optional admin IP allowlists
- Prometheus metrics endpoint
- Docker, Docker Compose, CI, docs, examples, and tests

The route schema also carries production TLS, ACME, TCP, UDP, and HTTP/3 options so the control plane can be shaped now while the listener implementations continue to mature.

## Quick Start

Install or update from this repository:

```sh
./install.sh
./update.sh
```

From a fresh machine, the installer can clone the repo for you:

```sh
curl -fsSL https://raw.githubusercontent.com/ikwerre-dev/Pxxl-Proxy-System/main/install.sh \
  | PXXL_INSTALL_DIR="$HOME/pxxl-proxy-system" sh
```

The installer checks for Git, Docker, Docker Compose, OpenSSL, and a reachable Docker daemon. It creates a local `.env`, generates first-run secrets, prepares persistent `data/` folders, and starts the Compose stack.

With Docker:

```sh
PXXL_ADMIN_BOOTSTRAP_TOKEN="$(openssl rand -hex 32)" \
GRAFANA_ADMIN_PASSWORD="$(openssl rand -hex 24)" \
docker compose up --build
```

Local non-root development ports:

```sh
PXXL_HTTP_ADDR=127.0.0.1:8080 \
PXXL_HTTPS_ADDR=127.0.0.1:8443 \
PXXL_ADMIN_ADDR=127.0.0.1:8081 \
PXXL_METRICS_ADDR=127.0.0.1:9090 \
PXXL_ADMIN_BOOTSTRAP_TOKEN="$(openssl rand -hex 32)" \
cargo run -p pxxl-edge
```

Health checks:

```sh
curl http://127.0.0.1:8081/healthz
curl http://127.0.0.1:8081/readyz
curl http://127.0.0.1:9090/metrics
```

There is no checked-in default admin token. Set `PXXL_ADMIN_BOOTSTRAP_TOKEN` for first-run local access, use it to create the first Redis-backed token, then remove the bootstrap token from your environment. By default the bootstrap token is one-shot: once at least one Redis token exists, it no longer authenticates unless `PXXL_ADMIN_BOOTSTRAP_TOKEN_PERMANENT=true` is explicitly set.

```sh
curl -H "Authorization: Bearer $PXXL_ADMIN_BOOTSTRAP_TOKEN" http://127.0.0.1:8081/v1/routes
```

Compose binds admin, metrics, Prometheus, and Grafana to `127.0.0.1` by default and keeps Redis, Postgres, ClickHouse, and Loki off host ports. Grafana uses `admin` plus the `GRAFANA_ADMIN_PASSWORD` you provide. The metrics endpoint can also require `Authorization: Bearer <token>` when `PXXL_METRICS_BEARER_TOKEN` or `[metrics].bearer_token` is set.

## Local Persistence

Docker Compose stores stateful service data in repo-local folders under `data/`:

- `data/grafana` for Grafana users, dashboards, UI changes, and datasource state
- `data/prometheus` for Prometheus time-series history
- `data/loki` for Loki log history
- `data/redis` for Redis admin tokens and dynamic route cache
- `data/postgres` and `data/clickhouse` for database state and analytics

These folders are intentionally ignored by Git. Normal `docker compose restart`, `docker compose up -d`, and `docker compose down` keep the data. To fully reset local state, stop the stack and remove the matching `data/*` folder yourself.

## Container Labels

Pxxl Proxy can discover enabled Docker and Podman containers through their runtime sockets. Runtime sockets are privileged, so the default Compose stack does not mount them. Enable label discovery only where that trust boundary is acceptable:

```sh
docker compose -f docker-compose.yml -f docker-compose.discovery.yml up -d --build
```

Then add labels to the target containers:

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
enabled = false
socket_path = "/var/run/docker.sock"

[podman]
enabled = false
socket_path = "/var/run/podman/podman.sock"
published_host = "host.docker.internal"
```

For Compose-based runtime discovery, prefer environment overrides instead of editing the base config:

```sh
PXXL_DOCKER_ENABLED=true docker compose -f docker-compose.yml -f docker-compose.discovery.yml up -d
```

Containers with the same `pxxl.domain` and `pxxl.path` are merged into one route with multiple upstreams. Requests are load-balanced across those upstreams, so stopping one replica removes it from the route on the next discovery poll while traffic keeps flowing to the remaining replicas.

When Pxxl itself is running in Docker and the target is a Podman container, Podman container names are usually not resolvable from the Docker network. In that case Pxxl uses Podman's published port mapping and the configured `published_host`. For example, a Podman container labeled `pxxl.port=80` and published as `-p 8080:80` becomes `http://host.docker.internal:8080`.

Dynamic routes from the admin API, Redis, Docker labels, and Podman labels are validated before activation. They must use `http://` upstreams, valid hostnames, and safe path prefixes. Control-plane routes reject loopback, link-local, multicast, private IP literals, `localhost`, and common internal service names such as `redis`, `postgres`, `clickhouse`, `prometheus`, `grafana`, and `loki`. Static TOML routes are treated as operator-owned and may still point at internal Compose service names.

`pxxl.path=/` is a catch-all for that domain. If a matching route exists but the selected upstream is down, the proxy returns `502 Bad Gateway`. If no route exists for the host/path, it returns `404 Not Found`.

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

## Offline GeoIP

Pxxl does not call an internet API for location detection. It loads a local CSV database at startup and does longest-prefix CIDR matching in memory.

Default config:

```toml
[geoip]
enabled = true
database_path = "config/geoip/geoip.csv"
```

CSV format:

```csv
cidr,country_code,country_name,continent_code,continent_name,region,city
203.0.113.0/24,US,United States,NA,North America,California,Los Angeles
```

The repo includes seed records for localhost and private networks only. For real public-country detection, replace or extend `config/geoip/geoip.csv` with a licensed offline CIDR database. You can override the path with `PXXL_GEOIP_DATABASE` or disable lookups with `PXXL_GEOIP_ENABLED=false`.

## Admin Auth

Admin API auth is configured in `config/pxxl.toml`:

```toml
[admin]
auth_enabled = true
token_store_key = "pxxl:admin_tokens"
ip_allowlist = ["127.0.0.1", "::1"]
```

`/healthz` and `/readyz` stay public for uptime checks. Other admin endpoints require `Authorization: Bearer <token>` when `auth_enabled = true`. Use the bootstrap token to create Redis-backed tokens:

```http
POST /v1/auth/tokens
Authorization: Bearer <bootstrap-or-admin-token>
Content-Type: application/json

{"name":"postman", "scopes":["routes:read","routes:write","analytics:read"]}
```

The raw token is returned once. Token metadata, scopes, and SHA-256 token hashes are stored in Redis with a hash index so verification does not scan every token. If `scopes` is empty, the token receives the `admin` scope. Supported scopes are `admin`, `routes:read`, `routes:write`, `tokens:read`, `tokens:write`, and `analytics:read`. Set `ip_allowlist` to bare IPs or CIDRs to restrict which clients can use the admin API. In Docker Compose, `PXXL_ADMIN_IP_ALLOWLIST` defaults to empty because host connections can appear as the Docker bridge address; set it explicitly for stricter environments.

Route-list responses redact configured auth passwords and added request-header values. Edge Basic/Digest middleware also strips the consumed `Authorization` header before proxying so upstream apps do not receive edge credentials.

## Persistent Analytics

Request analytics are still recorded in memory for fast API reads, and are also queued to ClickHouse when enabled:

```toml
[storage]
clickhouse_url = "http://pxxl:pxxl@clickhouse:8123"
analytics_enabled = true
```

Pxxl creates `pxxl_access_logs` if it can reach ClickHouse. Each request gets a generated `x-request-id`; that same value is returned to the client, forwarded upstream, included in in-memory visit/log APIs, and persisted in ClickHouse. The proxy hot path only sends to an in-memory queue; failed ClickHouse writes are logged and do not block requests.

Access logs include remote IP, route, path, upstream, status, latency, and offline GeoIP fields. Treat ClickHouse as a privileged data store and keep it on a private network unless you have a separate access-control layer.

## Active Health Checks

Pxxl periodically checks every known upstream, including normal path upstreams, location-route upstreams, and traffic-split upstreams:

```toml
[health_checks]
enabled = true
interval_seconds = 10
timeout_ms = 1500
path = "/"
```

Statuses below `500` are considered healthy. Unhealthy upstreams are marked out of rotation until a later check succeeds.

Passive health can also be enabled per route. It observes real upstream responses/errors, marks an upstream unhealthy after repeated failures, and active health checks can bring that upstream back.

## Middleware, Services, And Advanced Routing

Each path can reference reusable middleware names. A route defines the middleware objects and optional chains under `rules.middlewares` and `rules.middleware_chains`:

```json
{
  "domain": "app.pxxlhost",
  "algorithm": "p2c",
  "paths": [
    {
      "prefix": "/",
      "middlewares": ["secure-chain"],
      "upstreams": [
        { "url": "http://v1.internal:8080", "weight": 9 },
        { "url": "http://v2.internal:8080", "weight": 1 },
        { "url": "http://backup.internal:8080", "backup": true }
      ]
    }
  ],
  "rules": {
    "middleware_chains": {
      "secure-chain": ["auth", "retry", "compress"]
    },
    "middlewares": {
      "auth": {
        "basic_auth": {
          "enabled": true,
          "realm": "Pxxl",
          "users": { "demo": "secret" }
        }
      },
      "retry": {
        "retry": {
          "enabled": true,
          "attempts": 3,
          "backoff_ms": 100,
          "retry_statuses": [502, 503, 504]
        },
        "circuit_breaker": {
          "enabled": true,
          "failure_threshold": 5,
          "open_seconds": 30
        },
        "in_flight_limit": {
          "enabled": true,
          "max": 100,
          "scope": "route"
        }
      },
      "compress": {
        "compression": { "enabled": true, "min_bytes": 1024 },
        "content_type_autodetect": { "enabled": true }
      }
    },
    "sticky_sessions": {
      "enabled": true,
      "cookie_name": "pxxl_upstream",
      "http_only": true
    },
    "passive_health": {
      "enabled": true,
      "failure_threshold": 3,
      "recovery_seconds": 30,
      "failure_statuses": [500, 502, 503, 504]
    },
    "traffic_mirroring": {
      "enabled": true,
      "percent": 10,
      "upstreams": [
        { "url": "http://shadow.internal:8080" }
      ]
    }
  }
}
```

ForwardAuth uses a configured auth URL and allows the request only when the auth service returns a `2xx`. Digest auth uses SHA-256 digest validation. Retry middleware can retry buffered requests on upstream errors or configured status codes. Circuit breakers stop sending traffic to an upstream for the configured open window. Sticky sessions store a stable upstream id in a cookie and backup upstreams are used only when primary upstreams are unavailable.

`rules.services` supports reusable service definitions and weighted service targets in the API schema. Current HTTP routing still forwards from path, traffic-split, location-route, mirror, and backup upstream lists directly; service composition is represented for control-plane compatibility.

## Domain Rules

API and TOML routes can include a `rules` object. These rules are enforced before traffic is forwarded upstream:

```json
{
  "domain": "api.pxxlhost",
  "path": "/",
  "tls": true,
  "algorithm": "round_robin",
  "upstreams": [
    { "url": "http://host.docker.internal:8080", "weight": 1 }
  ],
  "rules": {
    "www_alias": true,
    "allow_websocket": false,
    "require_https": true,
    "redirect_http_to_https": true,
    "allowed_methods": ["GET", "POST", "OPTIONS"],
    "blocked_methods": ["TRACE"],
    "allowed_headers": ["host", "content-type", "authorization", "origin"],
    "blocked_headers": ["x-debug-token"],
    "required_headers": [
      { "name": "x-api-version", "value": "2026-05" }
    ],
    "strip_request_headers": ["x-powered-by"],
    "add_request_headers": {
      "x-forwarded-by": "pxxl"
    },
    "response_headers": {
      "x-proxy": "pxxl"
    },
    "ip_allowlist": ["127.0.0.1", "203.0.113.0/24"],
    "ip_blocklist": ["198.51.100.10"],
    "country_allowlist": ["US", "NG"],
    "country_blocklist": ["RU"],
    "continent_allowlist": ["NA", "AF"],
    "continent_blocklist": ["EU"],
    "location_routes": [
      {
        "name": "north-america",
        "continents": ["NA"],
        "upstreams": [
          { "url": "http://us-edge.internal:8080", "weight": 1 }
        ]
      },
      {
        "name": "nigeria",
        "countries": ["NG"],
        "upstreams": [
          { "url": "http://lagos-edge.internal:8080", "weight": 1 }
        ]
      }
    ],
    "traffic_splits": [
      {
        "name": "stable",
        "weight": 90,
        "upstreams": [
          { "url": "http://stable.internal:8080", "weight": 1 }
        ]
      },
      {
        "name": "canary",
        "weight": 10,
        "countries": ["US", "NG"],
        "upstreams": [
          { "url": "http://canary.internal:8080", "weight": 1 }
        ]
      }
    ],
    "waf": {
      "enabled": true,
      "block_path_traversal": true,
      "block_sql_injection": true,
      "block_xss": true,
      "block_bad_bots": true,
      "blocked_user_agents": ["bad-scraper"],
      "blocked_path_patterns": ["/wp-admin"],
      "blocked_query_patterns": ["debug=true"]
    },
    "rate_limit": {
      "enabled": true,
      "requests_per_minute": 120,
      "burst": 30,
      "scope": "per_ip_path",
      "status_code": 429,
      "retry_after_seconds": 5
    },
    "max_body_bytes": 1048576,
    "max_uri_length": 2048,
    "allowed_content_types": ["application/json"],
    "maintenance_mode": false,
    "preserve_host_header": false,
    "add_security_headers": true,
    "cors_allowed_origins": ["https://app.example.com"],
    "cors_allow_credentials": true,
    "cors_allowed_methods": ["GET", "POST", "OPTIONS"],
    "cors_allowed_headers": ["content-type", "authorization"],
    "cors_preflight_enabled": true,
    "request_buffering": {
      "enabled": true,
      "max_request_bytes": 16777216
    },
    "response_buffering": {
      "enabled": true,
      "max_response_bytes": 33554432
    },
    "compression": {
      "enabled": true,
      "min_bytes": 1024,
      "content_types": ["text/plain", "application/json"]
    },
    "content_type_autodetect": { "enabled": true },
    "retry": {
      "enabled": true,
      "attempts": 3,
      "backoff_ms": 100,
      "retry_statuses": [502, 503, 504]
    },
    "circuit_breaker": {
      "enabled": true,
      "failure_threshold": 5,
      "open_seconds": 30
    },
    "in_flight_limit": {
      "enabled": true,
      "max": 100,
      "scope": "route"
    },
    "sticky_sessions": {
      "enabled": true,
      "cookie_name": "pxxl_upstream",
      "http_only": true
    },
    "traffic_mirroring": {
      "enabled": true,
      "percent": 5,
      "upstreams": [
        { "url": "http://shadow.internal:8080" }
      ]
    }
  }
}
```

Defaults are permissive: if a field is missing, Pxxl keeps current proxy behavior. `allowed_headers` is strict when set, so include normal browser/client headers such as `host`, `content-type`, `authorization`, and `origin` when you use it.

`www_alias` lets `www.<domain>` match the base route. Use it only on base domains where you want that behavior.

Location rules use ISO-style country codes such as `US` or `NG` and continent codes such as `NA`, `AF`, and `EU`. Allow/block checks happen before upstream selection. `traffic_splits` are evaluated first for matching country/continent constraints, then `location_routes`; the selected upstream pool uses the domain's configured load-balancing algorithm.

WAF checks are substring-pattern based and intentionally lightweight: path traversal, common SQLi/XSS markers, known scanner user agents, and custom user-agent/path/query patterns.

Protocol-oriented options are accepted in the route schema under `rules.tls_options`, `rules.acme`, `rules.tcp`, `rules.udp`, and `rules.http3`. Today the production runtime is still HTTP/HTTPS reverse proxying; these fields are present so configs and API clients can be built against the intended Traefik-style shape while ACME, TCP, UDP, and HTTP/3 listeners are completed.

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
- `GET /v1/analytics/routes`
- `GET /v1/analytics/visits?limit=50`
- `GET /v1/domains/{domain}/visits?limit=50`
- `GET /v1/analytics/logs?limit=50`
- `GET /v1/domains/{domain}/logs?limit=50`
- `GET /v1/analytics/logs?request_id={x-request-id}`
- `GET /v1/domains/{domain}/logs?request_id={x-request-id}`
- `POST /v1/auth/tokens` with `{"name":"postman"}`
- `GET /v1/auth/tokens`
- `DELETE /v1/auth/tokens/{id}`
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
    geo/
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
