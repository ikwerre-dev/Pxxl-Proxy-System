# API Reference

Base URL: `http://127.0.0.1:8081`

Most `/v1/*` endpoints require:

```http
Authorization: Bearer pxxl-dev-token
```

`/healthz` and `/readyz` are public. The default token is for local development; override it with `PXXL_ADMIN_BOOTSTRAP_TOKEN` or `config/pxxl.toml`.

## Auth

```http
POST /v1/auth/tokens
Content-Type: application/json

{"name":"postman"}
```

Returns the raw token once plus token metadata. Token hashes are stored in Redis.

```http
GET /v1/auth/tokens
DELETE /v1/auth/tokens/{id}
```

## Health

```http
GET /healthz
```

Returns:

```json
{"status":"ok"}
```

## Readiness

```http
GET /readyz
```

Returns the readiness state and current route count.

## Routes

```http
GET /v1/routes
```

Returns the active route snapshot.

## Dynamic Domains

```http
POST /v1/domains
Content-Type: application/json

{
  "domain": "app.pxxlhost",
  "path": "/",
  "tls": true,
  "algorithm": "round_robin",
  "upstreams": [
    {
      "url": "http://host.docker.internal:3000",
      "weight": 1,
      "backup": false,
      "transport": {
        "server_name": null,
        "insecure_skip_verify": false,
        "ca_roots": [],
        "mtls_cert_path": null,
        "mtls_key_path": null
      }
    }
  ],
  "rules": {
    "www_alias": true,
    "allow_websocket": true,
    "blocked_methods": ["TRACE"],
    "blocked_headers": ["x-debug-token"],
    "ip_blocklist": ["198.51.100.10"],
    "country_blocklist": ["RU"],
    "location_routes": [
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
      "requests_per_minute": 120,
      "burst": 30,
      "scope": "per_ip",
      "status_code": 429,
      "retry_after_seconds": 5
    },
    "add_security_headers": true,
    "request_buffering": {
      "enabled": true,
      "max_request_bytes": 16777216,
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

API-created domains are persisted in Redis and loaded into the in-memory route registry. Request forwarding does not query Redis.

```http
GET /v1/domains
GET /v1/domains/{domain}
DELETE /v1/domains/{domain}
```

## Domain Rules

`rules` is optional. Missing fields are permissive and preserve normal proxy behavior.

Available fields:

| Field | Type | Behavior |
| --- | --- | --- |
| `www_alias` | boolean | Allows `www.<domain>` to match this base-domain route. Defaults to `false`. |
| `allow_websocket` | boolean | Allows or blocks `Connection: Upgrade` + `Upgrade: websocket`. Defaults to `true`. |
| `require_https` | boolean | Rejects plain HTTP with `426 Upgrade Required`. |
| `redirect_http_to_https` | boolean | Redirects plain HTTP to HTTPS with `308 Permanent Redirect`. |
| `allowed_methods` | string array | If set, only these HTTP methods are allowed. |
| `blocked_methods` | string array | Blocks specific HTTP methods. |
| `allowed_headers` | string array | If set, every incoming request header must be in this list. |
| `blocked_headers` | string array | Blocks requests that include any listed header. |
| `required_headers` | array | Requires headers by name, optionally with an exact value: `{ "name": "x-api-version", "value": "2026-05" }`. |
| `strip_request_headers` | string array | Removes headers before forwarding upstream. |
| `add_request_headers` | object | Adds or overwrites headers before forwarding upstream. |
| `response_headers` | object | Adds or overwrites headers on upstream and generated policy responses. |
| `ip_allowlist` | string array | Allows only these IPs/CIDRs. Bare IPs are treated as `/32` or `/128`. |
| `ip_blocklist` | string array | Blocks these IPs/CIDRs. Aliases: `blacklist_ips`, `blocked_ips`. |
| `country_allowlist` | string array | Allows only requests whose offline GeoIP country code matches. Aliases: `allowed_countries`. |
| `country_blocklist` | string array | Blocks requests whose offline GeoIP country code matches. Aliases: `blocked_countries`. |
| `continent_allowlist` | string array | Allows only requests whose offline GeoIP continent code matches. Aliases: `allowed_continents`. |
| `continent_blocklist` | string array | Blocks requests whose offline GeoIP continent code matches. Aliases: `blocked_continents`. |
| `location_routes` | array | Ordered country/continent routing rules. First matching rule with upstreams overrides the normal path upstreams. |
| `traffic_splits` | array | Weighted upstream pools for canary routing. Matching country/continent constraints are optional. |
| `waf` | object | Lightweight WAF checks for traversal, SQLi/XSS markers, scanner user agents, and custom substring patterns. |
| `rate_limit` | object | Per-domain token bucket. Supports `requests_per_second`, `requests_per_minute`, `burst`, `scope`, `status_code`, and `retry_after_seconds`. |
| `max_body_bytes` | number | Rejects requests whose `Content-Length` exceeds this value with `413`. |
| `max_uri_length` | number | Rejects long URLs with `414`. |
| `allowed_content_types` | string array | Allows only these content types on body-bearing methods. |
| `maintenance_mode` | boolean | Returns `503` before upstream selection. |
| `preserve_host_header` | boolean | Keeps the original `Host` header instead of using the upstream authority. |
| `add_security_headers` | boolean | Adds `X-Frame-Options`, `X-Content-Type-Options`, `Referrer-Policy`, and `Permissions-Policy`. |
| `cors_allowed_origins` | string array | Adds CORS response headers for matching origins. Use `*` for public APIs. |
| `cors_allow_credentials` | boolean | Adds `Access-Control-Allow-Credentials: true` for allowed origins. |
| `cors_allowed_methods` | string array | Adds `Access-Control-Allow-Methods`. |
| `cors_allowed_headers` | string array | Adds `Access-Control-Allow-Headers`. |
| `cors_preflight_enabled` | boolean | Answers matching CORS preflight requests directly with `204`. Defaults to `true`. |
| `middlewares` | object | Reusable middleware definitions referenced by `paths[].middlewares`. |
| `middleware_chains` | object | Named arrays of middleware names. Chains can reference other chains up to a small recursion guard. |
| `request_buffering` | object | Buffers request bodies for retry/mirror/auth pipelines and enforces `max_request_bytes`. |
| `response_buffering` | object | Caps buffered response size with `max_response_bytes`. |
| `compression` | object | Gzips compressible responses when the client sends `Accept-Encoding: gzip`. |
| `content_type_autodetect` | object | Adds missing request/response content types from path extension or body sniffing. |
| `retry` | object | Retries buffered requests on upstream errors or configured status codes. |
| `circuit_breaker` | object | Temporarily removes repeatedly failing upstreams from selection. |
| `in_flight_limit` | object | Rejects requests above a route/domain/upstream concurrency limit. |
| `sticky_sessions` | object | Pins clients to an upstream with a stable cookie. |
| `passive_health` | object | Marks upstreams unhealthy from observed failures; active checks can recover them. |
| `traffic_mirroring` | object | Sends a sampled shadow copy of requests to mirror upstreams. |
| `client_cert_forwarding` | object | Forwards an accepted TLS client certificate to the configured upstream header when mTLS is enabled on the listener. |
| `services` | object | Reusable service definitions and weighted service targets for control-plane compatibility. |
| `upstream_transport` | object | Default upstream TLS transport options: SNI override, custom CA roots, insecure skip, and mTLS cert/key paths. |
| `tls_options` | object | Per-router TLS intent: min version, cipher suites, and client auth settings. |
| `acme` | object | ACME intent: directory URL, email, challenge type, DNS provider, and wildcard flag. |
| `tcp` | object | TCP routing intent including HostSNI and TLS passthrough. |
| `udp` | object | UDP routing intent. |
| `http3` | object | HTTP/3 entrypoint intent. |

Rate limit scopes:

```txt
per_ip
per_domain
per_ip_path
```

Location routing rule shape:

```json
{
  "name": "lagos",
  "countries": ["NG"],
  "continents": ["AF"],
  "upstreams": [
    { "url": "http://lagos-edge.internal:8080", "weight": 1 }
  ]
}
```

Traffic split rule shape:

```json
{
  "name": "canary",
  "weight": 10,
  "countries": ["US", "NG"],
  "upstreams": [
    { "url": "http://canary.internal:8080", "weight": 1 }
  ]
}
```

Middleware definition shape:

```json
{
  "chain": [],
  "basic_auth": {
    "enabled": true,
    "realm": "Pxxl",
    "users": { "demo": "secret" }
  },
  "digest_auth": {
    "enabled": true,
    "realm": "Pxxl",
    "users": { "demo": "secret" }
  },
  "forward_auth": {
    "enabled": true,
    "url": "http://auth.internal/verify",
    "request_headers": ["authorization", "cookie"],
    "response_headers": []
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
  },
  "in_flight_limit": {
    "enabled": true,
    "max": 100,
    "scope": "route"
  },
  "compression": {
    "enabled": true,
    "min_bytes": 1024
  },
  "content_type_autodetect": {
    "enabled": true
  }
}
```

Supported load-balancing algorithms:

```txt
round_robin
weighted_round_robin
ip_hash
least_connections
p2c
hrw
ewma_latency
latency_aware
```

The runtime currently proxies HTTP and HTTPS entrypoints. ACME, TCP, UDP, HTTP/3, per-router TLS cipher/client-auth selection, and HTTPS upstream mTLS fields are accepted in the route schema for control-plane compatibility, but production listener/transport implementations are still in progress.

The GeoIP resolver is fully offline. It reads `config/geoip/geoip.csv` by default. The built-in seed only knows localhost and private ranges, so add a licensed CIDR database if you need real public-country accuracy.

## Analytics and Stats

```http
GET /v1/stats/domains
GET /v1/domains/{domain}/stats
GET /v1/analytics/routes
GET /v1/analytics/visits?limit=50
GET /v1/domains/{domain}/visits?limit=50
GET /v1/analytics/logs?limit=50
GET /v1/domains/{domain}/logs?limit=50
```

Stats return in-memory per-domain counters, status buckets, average latency, last status, last-seen timestamp, top countries, top continents, top paths, and top upstreams.

Visits return recent request events with domain, method, path, status, latency, upstream, remote IP, offline GeoIP location, and timestamp. Recent visit history is in memory and capped per domain.

When `[storage].analytics_enabled = true`, the same request events are persisted to ClickHouse table `pxxl_access_logs`.

## Upstreams

```http
GET /v1/upstreams
```

Returns flattened upstreams by route and path.

## Certificates

```http
GET /v1/certs
```

Returns local certificate metadata for the Phase 1 issuer.

## Blacklist

```http
POST /v1/blacklist/{domain_id}
Content-Type: application/json

{"ip":"203.0.113.10"}
```

```http
DELETE /v1/blacklist/{domain_id}/{ip}
```
