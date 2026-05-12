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
  ]
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

## Read APIs

```http
GET /v1/domains
GET /v1/domains/{domain}
GET /v1/stats/domains
GET /v1/domains/{domain}/stats
DELETE /v1/domains/{domain}
```

Import the Postman collection from `docs/postman/pxxl-proxy.postman_collection.json` and the environment from `docs/postman/pxxl-proxy.postman_environment.json`.
