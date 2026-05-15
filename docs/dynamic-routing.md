# Dynamic Routing API

Pxxl Proxy supports dynamic domain routes through the admin API.

The fast request path never queries Redis. API-created routes are persisted in Redis under `pxxl:routes`, loaded into the in-memory route registry at startup, and applied immediately after `POST /v1/domains`.

## Create or Update a Domain

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
    "ip_blocklist": ["198.51.100.10"],
    "rate_limit": {
      "enabled": true,
      "requests_per_minute": 120,
      "burst": 30,
      "scope": "per_ip"
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
    "cors_preflight_enabled": true
  }
}
```

Bare IPs in `ip_allowlist` and `ip_blocklist` are accepted; Pxxl treats them as single-host networks. `allowed_headers` is strict when set, so include ordinary client headers like `host`, `content-type`, `authorization`, and `origin`.

## Read APIs

```http
GET /v1/domains
GET /v1/domains/{domain}
GET /v1/stats/domains
GET /v1/domains/{domain}/stats
DELETE /v1/domains/{domain}
```

Import the Postman collection from `docs/postman/pxxl-proxy.postman_collection.json` and the environment from `docs/postman/pxxl-proxy.postman_environment.json`.
