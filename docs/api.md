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

