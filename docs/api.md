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
  ]
}
```

API-created domains are persisted in Redis and loaded into the in-memory route registry. Request forwarding does not query Redis.

```http
GET /v1/domains
GET /v1/domains/{domain}
DELETE /v1/domains/{domain}
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
