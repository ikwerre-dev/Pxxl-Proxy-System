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
      "weight": 1
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
    "add_security_headers": true
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
