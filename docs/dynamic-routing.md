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

Location rules use offline GeoIP data. Pxxl reads `config/geoip/geoip.csv` at startup and does not call the internet while handling requests. `country_*` fields match country codes like `US` or `NG`; `continent_*` fields match continent codes like `NA`, `AF`, or `EU`. `location_routes` are evaluated in order and the first matching rule with upstreams replaces the normal path upstreams for that request.

## Read APIs

```http
GET /v1/domains
GET /v1/domains/{domain}
GET /v1/stats/domains
GET /v1/domains/{domain}/stats
GET /v1/analytics/routes
GET /v1/analytics/visits?limit=50
GET /v1/domains/{domain}/visits?limit=50
DELETE /v1/domains/{domain}
```

The analytics endpoints are in-memory. Route stats include top countries, continents, paths, and upstreams. Visit endpoints return the most recent request events, including the resolved location and upstream.

Import the Postman collection from `docs/postman/pxxl-proxy.postman_collection.json` and the environment from `docs/postman/pxxl-proxy.postman_environment.json`.
