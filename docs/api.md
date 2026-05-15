# API Reference

Base URL: `http://127.0.0.1:8081`

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
    "allow_websocket": true,
    "blocked_methods": ["TRACE"],
    "blocked_headers": ["x-debug-token"],
    "ip_blocklist": ["198.51.100.10"],
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

## Stats

```http
GET /v1/stats/domains
GET /v1/domains/{domain}/stats
```

Returns in-memory per-domain counters, status buckets, average latency, last status, and last-seen timestamp.

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
