# Dynamic Routing API

Pxxl Proxy supports dynamic domain routes through the admin API.

The fast request path never queries Redis. API-created routes are persisted in Redis under `pxxl:routes`, loaded into the in-memory route registry at startup, and applied immediately after `POST /v1/domains`.

## Create or Update a Domain

```http
POST /v1/domains
Authorization: Bearer pxxl-dev-token
Content-Type: application/json

{
  "domain": "app.pxxlhost",
  "path": "/",
  "tls": true,
  "algorithm": "p2c",
  "upstreams": [
    {
      "url": "http://host.docker.internal:3000",
      "weight": 1
    }
  ],
  "rules": {
    "allow_websocket": true,
    "blocked_methods": ["TRACE"],
    "ip_blocklist": ["198.51.100.10"],
    "rate_limit": {
      "enabled": true,
      "requests_per_minute": 120,
      "burst": 30,
      "scope": "per_ip"
    },
    "sticky_sessions": {
      "enabled": true,
      "cookie_name": "pxxl_upstream"
    },
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
    }
  }
}
```

## Multiple Paths

```json
{
  "domain": "api.pxxlhost",
  "tls": true,
  "paths": [
    {
      "prefix": "/v1",
      "middlewares": ["secure-chain"],
      "upstreams": [
        { "url": "http://host.docker.internal:3001", "weight": 1 }
      ]
    },
    {
      "prefix": "/v2",
      "upstreams": [
        { "url": "http://host.docker.internal:3002", "weight": 1 }
      ]
    }
  ]
}
```

## Domain Rules

Add `rules` to the domain body to control edge behavior per domain:

```json
{
  "domain": "secure.pxxlhost",
  "path": "/",
  "tls": true,
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
    "add_request_headers": { "x-forwarded-by": "pxxl" },
    "response_headers": { "x-proxy": "pxxl" },
    "ip_allowlist": ["127.0.0.1", "203.0.113.0/24"],
    "ip_blocklist": ["198.51.100.10"],
    "country_allowlist": ["US", "NG"],
    "country_blocklist": ["RU"],
    "continent_allowlist": ["NA", "AF"],
    "continent_blocklist": ["EU"],
    "location_routes": [
      {
        "name": "nigeria",
        "countries": ["NG"],
        "upstreams": [
          { "url": "http://lagos-edge.internal:8080", "weight": 1 }
        ]
      },
      {
        "name": "north-america",
        "continents": ["NA"],
        "upstreams": [
          { "url": "http://us-edge.internal:8080", "weight": 1 }
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
      "requests_per_second": 10,
      "burst": 20,
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
    "request_buffering": {
      "enabled": true,
      "max_request_bytes": 16777216
    },
    "response_buffering": {
      "enabled": true,
      "max_response_bytes": 33554432
    },
    "sticky_sessions": {
      "enabled": true,
      "cookie_name": "pxxl_upstream"
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

Bare IPs in `ip_allowlist` and `ip_blocklist` are accepted; Pxxl treats them as single-host networks. `allowed_headers` is strict when set, so include ordinary client headers like `host`, `content-type`, `authorization`, and `origin`.

`www_alias = true` lets `www.<domain>` match the base route. Location rules use offline GeoIP data. Pxxl reads `config/geoip/geoip.csv` at startup and does not call the internet while handling requests. `country_*` fields match country codes like `US` or `NG`; `continent_*` fields match continent codes like `NA`, `AF`, or `EU`. `traffic_splits` provide weighted canary pools and may also be scoped by country/continent. If no traffic split matches, `location_routes` are evaluated in order and the first matching rule with upstreams replaces the normal path upstreams for that request.

WAF rules are lightweight substring checks for path traversal, common SQL injection/XSS markers, scanner user agents, and custom user-agent/path/query patterns.

Supported algorithms are `round_robin`, `weighted_round_robin`, `ip_hash`, `least_connections`, `p2c`, `hrw`, `ewma_latency`, and `latency_aware`.

Middleware names on `paths[].middlewares` execute in order. They can point to single middleware definitions or named chains in `rules.middleware_chains`. Runtime-supported middleware includes Basic auth, SHA-256 Digest auth, ForwardAuth, request/response buffering, gzip response compression, content-type auto-detection, retry, circuit breaker, in-flight limits, TLS client-cert forwarding when client certs are available, sticky sessions, passive health, and traffic mirroring.

Backup upstreams use `{ "backup": true }` and are selected only when primary healthy upstreams are unavailable. The route schema also accepts `transport`, `tls_options`, `acme`, `tcp`, `udp`, and `http3` fields for upcoming HTTPS-upstream transport, production ACME, TCP/UDP, and HTTP/3 listener work.

## Read APIs

```http
GET /v1/domains
GET /v1/domains/{domain}
GET /v1/stats/domains
GET /v1/domains/{domain}/stats
GET /v1/analytics/routes
GET /v1/analytics/visits?limit=50
GET /v1/domains/{domain}/visits?limit=50
GET /v1/analytics/logs?limit=50
GET /v1/domains/{domain}/logs?limit=50
DELETE /v1/domains/{domain}
```

The analytics endpoints are in-memory. Route stats include top countries, continents, paths, and upstreams. Visit/log endpoints return the most recent request events, including the resolved location and upstream. When ClickHouse analytics are enabled, the same events are persisted to `pxxl_access_logs`.

Import the Postman collection from `docs/postman/pxxl-proxy.postman_collection.json` and the environment from `docs/postman/pxxl-proxy.postman_environment.json`.
