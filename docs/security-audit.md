# Pxxl Proxy Security Audit

Date: 2026-05-15
Auditor/model: Codex, GPT-5
Commit: `c2077bb914cebb92c5e505391a06eb2398313e49`
Scope: Rust edge proxy, admin API, dynamic route model, Docker/Podman discovery, TLS, Redis persistence, ClickHouse analytics, Prometheus metrics, deployment defaults, docs, and tests in `/Users/robin/Documents/js_websites/pxxl/Pxxl-Proxy-System`.
Out of scope: Live internet exploitation, destructive load testing, fuzzing at scale, production infrastructure review, and scanners that were not installed locally.

## Executive Summary

The audit found no evidence that Pxxl directly embeds vulnerable NGINX, Traefik, Caddy, Envoy, HAProxy, Pingora, or known vulnerable `h2` code. The important issues are Pxxl's own control-plane and routing design choices.

Top confirmed risks:

1. The checked-in compose/config stack binds admin, metrics, Redis, Postgres, ClickHouse, Loki, Prometheus, and Grafana to host ports with local/dev secrets.
2. Authenticated API routes and Docker/Podman labels can target arbitrary upstream URLs, including internal network services, and active health checks amplify those targets.
3. Path routing and WAF checks use raw paths rather than one canonical decoded/normalized path, creating a real Traefik/Envoy/Caddy-style route and middleware bypass risk where operators split security by path.
4. Forwarded, identity, and hop-by-hop request headers are copied to upstreams unless a route explicitly strips them.
5. HTTP, HTTPS, admin, and metrics listeners spawn unbounded connection tasks and do not configure read/header/body/idle timeouts or per-peer connection limits.

Positive notes: generated error pages escape substituted values, generated headers go through `HeaderValue`/`HeaderName` validation, request and response bodies are capped by buffered byte length, the hot path does not query Redis or ClickHouse, recent visits are capped per domain, and every proxied request gets a new UUID `x-request-id`.

## Methodology

Required repo-state commands were run first:

- `pwd`: `/Users/robin/Documents/js_websites/pxxl/Pxxl-Proxy-System`
- `git rev-parse --show-toplevel || true`: `/Users/robin/Documents/js_websites/pxxl/Pxxl-Proxy-System`
- `git rev-parse HEAD || true`: `c2077bb914cebb92c5e505391a06eb2398313e49`
- `git status --short || true`: clean output
- `rg --files`: completed and listed the repository files used below
- `cargo metadata --format-version 1`: first run failed under sandbox DNS, then completed successfully after network approval

Files inspected:

- `README.md`
- `SECURITY.md`
- `config/pxxl.toml`
- `docker-compose.yml`
- `edge/docker/Dockerfile`
- `edge/src/main.rs`
- `edge/crates/common/src/lib.rs`
- `edge/crates/config/src/lib.rs`
- `edge/crates/http-proxy/src/lib.rs`
- `edge/crates/api/src/lib.rs`
- `edge/crates/core/src/lib.rs`
- `edge/crates/docker-discovery/src/lib.rs`
- `edge/crates/ddos/src/lib.rs`
- `edge/crates/load-balancer/src/lib.rs`
- `edge/crates/redis-sync/src/lib.rs`
- `edge/crates/storage/src/lib.rs`
- `edge/crates/tls/src/lib.rs`
- `edge/crates/geo/src/lib.rs`
- `edge/tests/http_proxy.rs`
- `docs/api.md`
- `docs/architecture.md`
- `docs/dynamic-routing.md`
- `docs/postman/pxxl-proxy.postman_collection.json`
- `docs/postman/pxxl-proxy.postman_environment.json`

Automated checks:

- `cargo fmt --check --all`: passed
- `cargo clippy --workspace --all-targets --all-features -- -D warnings`: passed
- `cargo test --workspace --all-features`: passed
- `cargo audit`: not run: tool unavailable
- `cargo deny check`: not run: tool unavailable
- `cargo outdated`: not run: tool unavailable
- `trivy fs --scanners vuln,secret,config .`: not run: tool unavailable
- `gitleaks detect --source . --no-git`: not run: tool unavailable
- `semgrep --config p/rust --config p/secrets --config p/owasp-top-ten .`: not run: tool unavailable

Public sources consulted on 2026-05-15 are listed in the Source Appendix. Primary sources were preferred. Where public advisories are for NGINX, Traefik, Caddy, Envoy, HAProxy, Pingora, or another project, this report labels them as not directly affecting Pxxl unless the same affected dependency or implementation is present.

## Attack Surface

Public data plane:

- HTTP listener starts from `edge/src/main.rs:142` and binds the configured address.
- HTTPS listener starts from `edge/src/main.rs:151` and uses rustls with ALPN `h2` and `http/1.1` configured in `edge/crates/tls/src/lib.rs:123`.
- Hyper parses HTTP/1.1 and HTTP/2 via `AutoBuilder::new(...).serve_connection_with_upgrades(...)` in `edge/crates/http-proxy/src/lib.rs:2342`.
- The proxy extracts `Host` from request headers, normalizes it, extracts `path_and_query`, runs the DDoS engine, GeoIP lookup, route match, domain rules, middleware, load balancing, upstream forwarding, response middleware, metrics, in-memory stats, logs, and ClickHouse queueing in `edge/crates/http-proxy/src/lib.rs:1044`.

Control plane:

- Admin API binds from `edge/crates/api/src/lib.rs:106` and protects `/v1/*` only when `AdminApiAuth.enabled` is true.
- `/healthz` and `/readyz` are public by design in `edge/crates/api/src/lib.rs:799`.
- Metrics server binds separately and returns Prometheus output without auth in `edge/crates/api/src/lib.rs:125`.
- API-created routes persist to Redis via `RedisRouteStore` and hot-load into the in-memory route registry.
- Docker and Podman discovery poll local sockets and replace container-sourced routes atomically.

Storage and observability:

- Redis stores API routes and admin token records.
- ClickHouse receives access-log rows through a bounded in-memory channel.
- Prometheus scrapes metrics.
- Loki/Promtail/Grafana are included in compose.

Deployment:

- `docker-compose.yml` publishes admin, metrics, Redis, Postgres, ClickHouse, Loki, Prometheus, and Grafana host ports.
- The edge service mounts the Docker socket and a Podman socket read-only.
- The runtime container does not set a non-root user in `edge/docker/Dockerfile`.

## CVE/GHSA/RustSec Mapping

| ID | Product/source | Class | Relevance to Pxxl | Direct/Analogous/Not affected | Local evidence |
| --- | --- | --- | --- | --- | --- |
| CVE-2023-44487 | HTTP/2 Rapid Reset, CISA/NVD | HTTP/2 DoS | Pxxl advertises `h2` over TLS and uses Hyper/h2. No local limit hardening was found. | Analogous risk; no proof of vulnerable dependency | `Cargo.lock:568`, `edge/crates/tls/src/lib.rs:126`, `edge/crates/http-proxy/src/lib.rs:2342` |
| RUSTSEC-2023-0034 / CVE-2023-26964 | RustSec `h2` | reset stream resource exhaustion | Pxxl's lockfile uses `h2 0.4.14`, not the old affected line identified by this advisory. Still relevant to HTTP/2 DoS testing. | Not affected by verified version; analogous test class | `Cargo.lock:568`, `edge/crates/tls/src/lib.rs:126` |
| RUSTSEC-2024-0332 | RustSec `h2` | CONTINUATION flood | Pxxl's lockfile uses `h2 0.4.14`. No direct affected-version finding without `cargo audit`; still relevant because HTTP/2 is enabled. | Not proven affected; analogous test class | `Cargo.lock:568`, `edge/crates/http-proxy/src/lib.rs:2342` |
| NGINX CVE-2026-42926 | NGINX/F5/NVD | HTTP/2 request injection upstream | Pxxl does not use `ngx_http_proxy_module`, `proxy_http_version 2`, or `proxy_set_body`; upstream requests are rebuilt with Hyper. | Not directly affected; analogous upstream request-injection class | `edge/crates/http-proxy/src/lib.rs:1954`, `edge/crates/http-proxy/src/lib.rs:2004` |
| NGINX CVE-2026-40460 | NGINX/F5/NVD | HTTP/3 source IP spoofing | Pxxl has `http3` config intent but no HTTP/3 runtime listener. | Not affected today; future design requirement | `edge/crates/common/src/lib.rs:685`, `edge/src/main.rs:142` |
| NGINX CVE-2026-1642 | NGINX/F5/NVD | upstream TLS injection | Pxxl does not run NGINX. Pxxl also does not yet implement proper HTTPS upstream transport options, so this is a future design check. | Not directly affected; future upstream TLS design requirement | `edge/crates/common/src/lib.rs:612`, `edge/crates/http-proxy/src/lib.rs:1032` |
| NGINX CVE-2021-23017 | NGINX official advisories | resolver memory bug | Pxxl does not use NGINX resolver code. DNS is via Rust/Hyper connector stack. | Not affected | `edge/crates/http-proxy/src/lib.rs:1032` |
| NGINX CVE-2017-7529 | NGINX official advisories | range filter integer overflow | Pxxl does not implement NGINX range filter or static file serving in inspected code. | Not affected | No static range filter implementation found |
| NGINX CVE-2013-2028 | NGINX official advisories | chunked parser stack overflow | Pxxl uses Hyper for HTTP parsing, not NGINX chunk parser. Body bytes are collected and capped after Hyper parses frames. | Not affected; parser fuzzing still recommended | `edge/crates/http-proxy/src/lib.rs:1943`, `edge/crates/http-proxy/src/lib.rs:2560` |
| HAProxy CVE-2021-40346 | HAProxy/NVD class | duplicate Content-Length request smuggling | Pxxl does not use HAProxy code. Hyper is the parser. Need explicit regression tests for duplicate CL and CL+TE. | Analogous test class | `edge/crates/http-proxy/src/lib.rs:2342`, `edge/tests/http_proxy.rs:31` |
| Traefik CVE-2025-47952 / GHSA-vrch-868g-9jx5 | Traefik GitHub advisory | encoded path traversal route bypass | Pxxl uses raw path prefix routing and only substring WAF checks. | Analogous risk confirmed | `edge/crates/common/src/lib.rs:120`, `edge/crates/http-proxy/src/lib.rs:2456` |
| Traefik CVE-2025-32431 / GHSA-6p68-w45g-48j7 | Traefik GitHub advisory | path matcher bypass | Same as above. | Analogous risk confirmed | `edge/crates/core/src/lib.rs:597`, `edge/crates/common/src/lib.rs:120` |
| Traefik GHSA-h924-8g65-j9wg / CVE-2020-15129 | Traefik GitHub advisory | X-Forwarded-Prefix open redirect | Pxxl redirects using normalized domain/path, not `X-Forwarded-Prefix`; however, Pxxl forwards other identity headers by default. | Not affected by exact redirect bug; analogous header trust class | `edge/crates/http-proxy/src/lib.rs:397`, `edge/crates/http-proxy/src/lib.rs:1960` |
| Traefik GHSA-gxrv-wf35-62w9 | Traefik GitHub advisory | HTTP/3 early-data IP allowlist bypass | Pxxl has no HTTP/3 runtime today; relevant if HTTP/3 and IP allowlists are added. | Not affected today; future design requirement | `edge/crates/common/src/lib.rs:685` |
| Caddy CVE-2026-30851 / GHSA-7r4p-vjf4-gxv4 | Caddy GitHub advisory | forward_auth identity header injection | Pxxl's forward auth copies configured request headers and the main forwarder passes client identity headers unless stripped. | Analogous risk confirmed | `edge/crates/http-proxy/src/lib.rs:1864`, `edge/crates/http-proxy/src/lib.rs:1960` |
| Caddy GHSA-g7pc-pc7g-h8jh | Caddy GitHub advisory | escaped path route/auth bypass | Pxxl raw path matching has similar normalization concerns. | Analogous risk confirmed | `edge/crates/common/src/lib.rs:120`, `edge/crates/http-proxy/src/lib.rs:2456` |
| Caddy GHSA-x76f-jf84-rqj8 | Caddy GitHub advisory | host matching case issue | Pxxl lowercases host/domain in `normalize_domain`; exact Caddy issue is not present. Host validation remains weak for malformed host text. | Not affected by exact issue; analogous host normalization class | `edge/crates/common/src/lib.rs:884`, `edge/crates/common/src/lib.rs:891` |
| Caddy GHSA-hffm-g8v7-wrv7 | Caddy GitHub advisory | mTLS fail-open | Pxxl uses `with_no_client_auth` today, so mTLS is not implemented rather than fail-open. Relevant to future `tls_options.client_auth`. | Not affected today; future design requirement | `edge/crates/tls/src/lib.rs:123`, `edge/crates/common/src/lib.rs:626` |
| Envoy GHSA-xcx5-93pw-jw2w / CVE-2019-9901 | Envoy GitHub advisory | missing path normalization | Pxxl has raw path routing and forwards the original raw path/query. | Analogous risk confirmed | `edge/crates/http-proxy/src/lib.rs:1061`, `edge/crates/http-proxy/src/lib.rs:2004` |
| Envoy GHSA-w5w5-487h-qv8q | Envoy GitHub advisory | unsafe generated header values/request smuggling | Pxxl validates generated header names/values with `HeaderName`/`HeaderValue`, so generated CRLF injection was not confirmed. Header pass-through is still a separate risk. | Not affected by exact class; analogous header safety check | `edge/crates/http-proxy/src/lib.rs:702`, `edge/crates/http-proxy/src/lib.rs:1186` |
| Envoy GHSA-ffhv-fvxq-r6mf | Envoy GitHub advisory | trusted header manipulation | Pxxl forwards many client-supplied trust headers by default. | Analogous risk confirmed | `edge/crates/http-proxy/src/lib.rs:1960`, `edge/crates/http-proxy/src/lib.rs:1598` |
| Envoy CVE-2023-35944 | Envoy/NVD | mixed-case scheme/protocol confusion | Pxxl does not use Envoy and derives scheme from listener, not client `:scheme`, but no explicit HTTP/2 scheme regression tests were found. | Not directly affected; analogous test class | `edge/crates/http-proxy/src/lib.rs:1048`, `edge/crates/http-proxy/src/lib.rs:1603` |
| NGINX HTTP/2 CVE-2019-9511, CVE-2019-9513, CVE-2019-9516, CVE-2018-16843, CVE-2018-16844 | NGINX official advisories | HTTP/2 CPU/memory DoS | Not NGINX code, but Pxxl enables HTTP/2 and has no explicit connection/header/reset hardening. | Analogous risk | `edge/crates/tls/src/lib.rs:126`, `edge/crates/http-proxy/src/lib.rs:2342` |
| NGINX HTTP/3 CVE-2024-24989, CVE-2024-24990, CVE-2024-32760, CVE-2024-31079, CVE-2024-35200, CVE-2024-34161 | NGINX official advisories | HTTP/3 implementation bugs | Pxxl has no HTTP/3 implementation today. These are future feature design requirements only. | Not affected today | `edge/crates/common/src/lib.rs:685` |
| RUSTSEC-2025-0070 / CVE-2025-8671 | RustSec Pingora MadeYouReset | HTTP/2 reset DoS | Pxxl does not use Pingora. Use as an HTTP/2 stress-test inspiration. | Not affected; analogous test class | `Cargo.lock:568`, no `pingora` dependency found |

Omissions: the prompt mentioned some future-looking NGINX CVEs. CVE-2026-42926, CVE-2026-40460, and CVE-2026-1642 have NVD/F5 records and are included above. Other unsourced or non-authoritative references were not treated as confirmed public vulnerability facts.

## Findings

### PXSA-2026-001: Compose and Config Expose Control-Plane and Data Services with Dev Credentials

- Severity: High
- Confidence: High
- Status: Confirmed
- Category: deployment
- Affected files:
  - `config/pxxl.toml:1`
  - `config/pxxl.toml:31`
  - `config/pxxl.toml:50`
  - `docker-compose.yml:12`
  - `docker-compose.yml:27`
  - `docker-compose.yml:37`
  - `docker-compose.yml:50`
  - `docker-compose.yml:65`
  - `docker-compose.yml:77`
  - `docker-compose.yml:99`
  - `docs/postman/pxxl-proxy.postman_environment.json:18`
- Public vulnerability references:
  - Caddy admin API authorization advisories, same class only: https://github.com/caddyserver/caddy/security/advisories
  - General default credential and exposed admin plane class; no direct CVE claim.
- Evidence:
  - The checked-in config binds HTTP, HTTPS, admin, and metrics to `0.0.0.0` in `config/pxxl.toml:1`.
  - Admin auth is enabled in the checked-in config, but the bootstrap token is the documented static local token `pxxl-dev-token` in `config/pxxl.toml:31`.
  - Redis and ClickHouse/Postgres defaults use unauthenticated or low-entropy local credentials in `config/pxxl.toml:50` and `config/pxxl.toml:54`.
  - Compose publishes edge admin `8081`, metrics `9090`, Redis `6379`, Postgres `5432`, ClickHouse `8123`/`9000`, Prometheus `9091`, Loki `3100`, and Grafana host ports in `docker-compose.yml:12`, `docker-compose.yml:27`, `docker-compose.yml:37`, `docker-compose.yml:50`, `docker-compose.yml:65`, `docker-compose.yml:77`, and `docker-compose.yml:99`.
  - Grafana uses `admin` / `pxxl` in `docker-compose.yml:103`.
  - The Postman environment stores `pxxl-dev-token` as the default admin token in `docs/postman/pxxl-proxy.postman_environment.json:18`.
- Exploit sketch:
  - If this compose file is used on a public host without firewalling, request `GET /v1/routes` on port `8081` with `Authorization: Bearer pxxl-dev-token`.
  - Read metrics from `:9090`, query Redis/Postgres/ClickHouse with default settings, or log into Grafana if the default password remains unchanged.
- Impact:
  - A remote attacker who can reach those host ports can administer routes, view operational metadata, inject routes through Redis if Redis is exposed, or manipulate observability data.
- Recommended fix:
  - Bind admin, metrics, Redis, Postgres, ClickHouse, Loki, Prometheus, and Grafana to `127.0.0.1` by default or remove host port publishing from the production compose file.
  - Remove static bootstrap tokens from tracked config and require `PXXL_ADMIN_BOOTSTRAP_TOKEN` from a secret store.
  - Add a production compose override with firewall labels, private networks, no public database ports, and unique generated credentials.
  - Fail startup in production mode if the bootstrap token equals `pxxl-dev-token`.
- Tests to add:
  - Compose config test asserting production compose does not publish admin/data-plane support services.
  - Startup config test rejecting known dev credentials when `PXXL_ENV=production`.
  - Admin auth negative tests for missing, wrong, malformed, lowercase `bearer`, and extra-space authorization headers.
- Residual risk:
  - Operators can still expose these services through other infrastructure. Documentation should make admin and metrics exposure a deliberate action.

### PXSA-2026-002: Dynamic Routes, Labels, and Health Checks Permit Internal SSRF by Trusted Control-Plane Inputs

- Severity: High
- Confidence: High
- Status: Confirmed
- Category: SSRF
- Affected files:
  - `edge/crates/api/src/lib.rs:702`
  - `edge/crates/api/src/lib.rs:751`
  - `edge/crates/config/src/lib.rs:392`
  - `edge/crates/docker-discovery/src/lib.rs:235`
  - `edge/crates/docker-discovery/src/lib.rs:261`
  - `edge/src/main.rs:267`
  - `edge/src/main.rs:325`
  - `edge/crates/http-proxy/src/lib.rs:2004`
- Public vulnerability references:
  - No direct CVE claim. This is the standard authenticated route-created SSRF class.
- Evidence:
  - `DomainRouteBody::into_route` accepts arbitrary `upstreams` from the admin API and converts each `url` directly into `Upstream` without scheme, hostname, private-network, or length validation in `edge/crates/api/src/lib.rs:702` and `edge/crates/api/src/lib.rs:751`.
  - TOML config upstreams are also plain strings in `edge/crates/config/src/lib.rs:392`.
  - Docker and Podman labels accept `pxxl.domain`, `pxxl.path`, `pxxl.scheme`, `pxxl.host`, and `pxxl.port`, then build `scheme://host:port` in `edge/crates/docker-discovery/src/lib.rs:235` and `edge/crates/docker-discovery/src/lib.rs:261`.
  - Active health checks collect every upstream URL and periodically send GET requests to each one in `edge/src/main.rs:267`.
  - Health-check URIs are string-built from upstream URL and health path in `edge/src/main.rs:325`.
  - Proxy forwarding string-builds the final upstream URI from the upstream base URL and original path/query in `edge/crates/http-proxy/src/lib.rs:2004`.
- Exploit sketch:
  - As an authenticated admin, create a route with `upstreams: [{"url":"http://redis:6379"}]` or `http://169.254.169.254`.
  - Or, as a user able to create container labels, set `pxxl.enable=true`, `pxxl.domain=target.pxxlhost`, `pxxl.host=redis`, and `pxxl.port=6379`.
  - Send a request through the proxy or wait for active health checks to probe the target.
- Impact:
  - If admin access is tenant-exposed or a container-label trust boundary is crossed, a tenant or compromised container can make Pxxl connect to internal services, metadata endpoints, databases, or loopback-only admin APIs.
  - Active health checks can turn a single route into recurring internal probes.
- Recommended fix:
  - Validate upstream URLs at route creation and Redis load time.
  - Allow only `http` and, once fully implemented, `https`.
  - Add default-deny private-network and link-local blocks for API-created and label-created upstreams, with explicit operator allowlists for internal service names.
  - Validate Docker/Podman labels against a configured network/container allowlist.
  - Make health checks use `HEAD` or a safe configured method, restrict redirects, and apply the same SSRF allow/deny policy.
- Tests to add:
  - API create-route tests for `127.0.0.1`, `localhost`, RFC1918, `169.254.169.254`, `redis`, `file://`, `gopher://`, malformed schemes, and overly long URLs.
  - Docker label parser tests for invalid scheme, control characters, wildcard domains, and private targets.
  - Health-check tests proving denied upstreams are not probed.
- Residual risk:
  - Reverse proxies often need internal upstreams. The remaining risk should be controlled by a clear trust model and explicit per-environment upstream allowlists.

### PXSA-2026-003: Raw Path Prefix Matching Can Bypass Path-Scoped Rules and Upstreams

- Severity: High
- Confidence: High
- Status: Confirmed
- Category: path-normalization
- Affected files:
  - `edge/crates/common/src/lib.rs:120`
  - `edge/crates/core/src/lib.rs:128`
  - `edge/crates/http-proxy/src/lib.rs:1061`
  - `edge/crates/http-proxy/src/lib.rs:2004`
  - `edge/crates/http-proxy/src/lib.rs:2450`
- Public vulnerability references:
  - CVE-2025-47952 / GHSA-vrch-868g-9jx5, Traefik, same class: https://github.com/traefik/traefik/security/advisories/GHSA-vrch-868g-9jx5
  - CVE-2025-32431 / GHSA-6p68-w45g-48j7, Traefik, same class: https://github.com/traefik/traefik/security/advisories/GHSA-6p68-w45g-48j7
  - CVE-2019-9901 / GHSA-xcx5-93pw-jw2w, Envoy, same class: https://github.com/envoyproxy/envoy/security/advisories/GHSA-xcx5-93pw-jw2w
  - GHSA-g7pc-pc7g-h8jh, Caddy, same class: https://github.com/caddyserver/caddy/security/advisories/GHSA-g7pc-pc7g-h8jh
- Evidence:
  - `PathRoute::matches` accepts a route when `path == prefix` or `path.starts_with(prefix + "/")` in `edge/crates/common/src/lib.rs:120`.
  - `RouteRegistry::find` passes the request path to route matching without percent-decoding, dot-segment cleanup, slash normalization, UTF-8 normalization, or backslash handling in `edge/crates/core/src/lib.rs:128`.
  - The proxy extracts the raw `path_and_query` from Hyper in `edge/crates/http-proxy/src/lib.rs:1061`.
  - The same raw original path/query is appended to the upstream URL in `edge/crates/http-proxy/src/lib.rs:2004`.
  - WAF checks inspect `req.uri().path()` and `query()` as lowercased strings and only look for selected substrings such as `"../"`, `"..\\"`, `"%2e%2e"`, and `"%252e%252e"` in `edge/crates/http-proxy/src/lib.rs:2450`.
- Exploit sketch:
  - Configure one public route `/api` and one protected or different route `/admin`.
  - Send paths such as `/api/../admin`, `/api/%2e%2e/admin`, `/api%2f..%2fadmin`, `/api/%252e%252e/admin`, `/api//../admin`, `/api/%2Fadmin`, or backslash variants.
  - Observe whether Pxxl applies `/api` rules while the upstream framework normalizes to `/admin`.
- Impact:
  - If an operator relies on path prefixes for auth middleware, WAF policy, in-flight limits, canary routing, or different upstream pools, a client may reach a more sensitive backend path under weaker Pxxl policy.
- Recommended fix:
  - Introduce a single canonical path pipeline before route matching and WAF: percent-decode safely, reject invalid encodings, normalize dot segments, collapse repeated slashes if configured, reject backslashes by default, and preserve a clearly separate raw path for logging.
  - Match routes and execute WAF/middleware on the same canonical representation.
  - Decide whether to forward canonical or raw path; document and test the choice.
- Tests to add:
  - Path normalization matrix covering `%2e`, `%2f`, `%5c`, double-encoding, semicolon parameters, encoded `?`/`#`, double slashes, trailing slash, uppercase percent escapes, and invalid UTF-8.
  - Integration test with `/public` and `/private` upstreams proving encoded traversal cannot switch effective upstream or middleware.
  - Fuzz target for path canonicalization.
- Residual risk:
  - Different upstream frameworks normalize paths differently. Pxxl should expose a compatibility mode only with explicit warnings and tests.

### PXSA-2026-004: Client-Supplied Trust and Hop-by-Hop Headers Reach Upstreams by Default

- Severity: High
- Confidence: High
- Status: Confirmed
- Category: routing
- Affected files:
  - `edge/crates/http-proxy/src/lib.rs:695`
  - `edge/crates/http-proxy/src/lib.rs:1588`
  - `edge/crates/http-proxy/src/lib.rs:1598`
  - `edge/crates/http-proxy/src/lib.rs:1864`
  - `edge/crates/http-proxy/src/lib.rs:1943`
  - `edge/crates/http-proxy/src/lib.rs:1954`
- Public vulnerability references:
  - CVE-2026-30851 / GHSA-7r4p-vjf4-gxv4, Caddy, same class: https://github.com/caddyserver/caddy/security/advisories/GHSA-7r4p-vjf4-gxv4
  - GHSA-ffhv-fvxq-r6mf, Envoy, same class: https://github.com/envoyproxy/envoy/security/advisories/GHSA-ffhv-fvxq-r6mf
  - GHSA-w5w5-487h-qv8q, Envoy, generated-header class considered: https://github.com/envoyproxy/envoy/security/advisories/GHSA-w5w5-487h-qv8q
- Evidence:
  - Pxxl only strips headers listed by the route in `strip_request_headers` in `edge/crates/http-proxy/src/lib.rs:695`.
  - `BufferedRequest::from_request` stores the original header map in `edge/crates/http-proxy/src/lib.rs:1943`.
  - `BufferedRequest::to_request` copies that full header map into the upstream request in `edge/crates/http-proxy/src/lib.rs:1954`.
  - The forwarder inserts Pxxl's `x-forwarded-host`, `x-forwarded-proto`, and `x-forwarded-for` in `edge/crates/http-proxy/src/lib.rs:1598`, but it does not remove client-supplied `Forwarded`, `X-Real-IP`, `X-Original-URL`, `X-Rewrite-URL`, `Proxy-Authorization`, `Proxy-Connection`, `TE`, `Trailer`, `Keep-Alive`, `Connection`, or non-websocket `Upgrade` headers.
  - ForwardAuth copies only configured request headers to the auth service in `edge/crates/http-proxy/src/lib.rs:1864`, but the main upstream request still carries all original headers unless configured otherwise.
  - Generated header names/values go through `HeaderName::from_bytes` and `HeaderValue::from_str`, which is a useful CRLF-injection protection, but it does not address pass-through trust headers.
- Exploit sketch:
  - Send `Forwarded: for=127.0.0.1;proto=https`, `X-Real-IP: 127.0.0.1`, or `X-Original-URL: /admin` to an upstream that trusts those headers.
  - Send `Connection: keep-alive, upgrade`, `Upgrade: h2c`, `TE: trailers`, or `Proxy-Authorization` and inspect what the upstream sees.
- Impact:
  - Upstreams may make authorization, logging, redirect, CSRF, or rate-limit decisions using spoofed identity or internal-routing headers.
  - Hop-by-hop header pass-through can create protocol confusion with some backends.
- Recommended fix:
  - Strip hop-by-hop headers by default: `Connection`, every token named by `Connection`, `Upgrade`, `TE`, `Trailer`, `Proxy-Authorization`, `Proxy-Connection`, `Keep-Alive`, and `Transfer-Encoding`.
  - Strip or overwrite trust headers by default: `Forwarded`, `X-Forwarded-*`, `X-Real-IP`, `X-Original-URL`, `X-Rewrite-URL`, `X-Client-IP`, and any configured identity headers.
  - Add an explicit `trusted_proxy_headers` mode for deployments behind another trusted proxy.
  - Ensure ForwardAuth response identity headers overwrite any client-supplied version before forwarding.
- Tests to add:
  - Echo-upstream tests proving each hop-by-hop and trust header is absent or overwritten.
  - ForwardAuth tests proving copied identity headers cannot be pre-seeded by clients.
  - WebSocket tests with odd `Connection` token combinations and non-websocket `Upgrade` values.
- Residual risk:
  - Some applications depend on custom forwarded headers. Provide opt-in allowlists per route with clear defaults.

### PXSA-2026-005: Listeners Lack Timeouts and Connection Concurrency Controls

- Severity: Medium
- Confidence: High
- Status: Confirmed
- Category: DoS
- Affected files:
  - `edge/crates/http-proxy/src/lib.rs:2228`
  - `edge/crates/http-proxy/src/lib.rs:2256`
  - `edge/crates/http-proxy/src/lib.rs:2317`
  - `edge/crates/http-proxy/src/lib.rs:2342`
  - `edge/crates/api/src/lib.rs:215`
  - `edge/crates/api/src/lib.rs:249`
  - `edge/crates/http-proxy/src/lib.rs:2560`
- Public vulnerability references:
  - CVE-2023-44487, HTTP/2 Rapid Reset, same DoS class: https://nvd.nist.gov/vuln/detail/CVE-2023-44487
  - RUSTSEC-2023-0034 / CVE-2023-26964, `h2`, same DoS class: https://rustsec.org/advisories/RUSTSEC-2023-0034.html
  - RUSTSEC-2024-0332, `h2`, same DoS class: https://rustsec.org/advisories/RUSTSEC-2024-0332.html
  - NGINX HTTP/2 advisories, same class: https://nginx.org/en/security_advisories.html
  - RUSTSEC-2025-0070 / CVE-2025-8671, Pingora MadeYouReset, same class: https://rustsec.org/advisories/RUSTSEC-2025-0070.html
- Evidence:
  - Plain and TLS listeners accept connections in loops and spawn per-connection tasks without a global or per-IP semaphore in `edge/crates/http-proxy/src/lib.rs:2228` and `edge/crates/http-proxy/src/lib.rs:2256`.
  - Each connection is served by a default `AutoBuilder` in `edge/crates/http-proxy/src/lib.rs:2317`.
  - Admin and metrics listeners use the same default `AutoBuilder` pattern in `edge/crates/api/src/lib.rs:215` and `edge/crates/api/src/lib.rs:249`.
  - The request/response body limit is enforced after `body.collect().await` in `edge/crates/http-proxy/src/lib.rs:2560`; this enforces byte size but does not add slow-body read deadlines.
  - No explicit header timeout, body read timeout, idle timeout, max header count/size, max concurrent streams, max resets, or per-IP connection count was found in Pxxl code.
- Exploit sketch:
  - Open many idle HTTP or HTTPS connections and keep them open.
  - Send slow request bodies that remain below the byte cap but occupy tasks.
  - Exercise HTTP/2 stream/reset/header flood tools in a test environment.
- Impact:
  - Public clients can consume sockets, tasks, memory, and CPU before normal route-level rate limiting has a chance to respond.
- Recommended fix:
  - Add listener-level semaphores for global and per-IP active connections.
  - Configure Hyper HTTP/1 and HTTP/2 builder limits where available: max header list size, max concurrent streams, keep-alive/idle timers, and HTTP/2 reset/flood safeguards.
  - Wrap request body collection and upstream response buffering in read deadlines.
  - Add admin and metrics listener protections separately.
- Tests to add:
  - Slowloris partial-header/body integration tests.
  - Many-idle-connections test with configured cap.
  - HTTP/2 stream/reset stress test in CI if a safe client is available.
  - Huge header and header-count negative tests.
- Residual risk:
  - Kernel and load balancer limits are still required for public deployment.

### PXSA-2026-006: Rate-Limit, Stats, and Load-Balancer Maps Grow Without Eviction

- Severity: Medium
- Confidence: High
- Status: Confirmed
- Category: DoS
- Affected files:
  - `edge/crates/ddos/src/lib.rs:115`
  - `edge/crates/http-proxy/src/lib.rs:191`
  - `edge/crates/http-proxy/src/lib.rs:920`
  - `edge/crates/core/src/lib.rs:264`
  - `edge/crates/core/src/lib.rs:391`
  - `edge/crates/core/src/lib.rs:531`
  - `edge/crates/load-balancer/src/lib.rs:10`
- Public vulnerability references:
  - CVE-2023-44487, HTTP/2 DoS class, analogous resource exhaustion: https://nvd.nist.gov/vuln/detail/CVE-2023-44487
  - RUSTSEC-2025-0070 / CVE-2025-8671, analogous resource exhaustion class: https://rustsec.org/advisories/RUSTSEC-2025-0070.html
- Evidence:
  - Global rate buckets are keyed by `IpAddr` in a `DashMap` in `edge/crates/ddos/src/lib.rs:115`, with no eviction path.
  - Domain policy rate buckets are keyed by domain, scope, IP, and optionally path in `edge/crates/http-proxy/src/lib.rs:191`; `PerIpPath` stores `path_without_query(path)` in `edge/crates/http-proxy/src/lib.rs:966`.
  - Domain stats maintain an unbounded `DashMap` of domains in `edge/crates/core/src/lib.rs:264`.
  - Per-domain `path_counts` and `upstream_counts` are regular hash maps incremented without cardinality limits in `edge/crates/core/src/lib.rs:391` and `edge/crates/core/src/lib.rs:531`.
  - Load-balancer counters, in-flight counts, and latency maps are unbounded `DashMap`s keyed by route/upstream strings in `edge/crates/load-balancer/src/lib.rs:10`.
- Exploit sketch:
  - With `rate_limit.scope = "per_ip_path"`, send many unique paths such as `/x/{random}` from the same source IP.
  - Create or discover many domains and paths, then send one request per unique key.
- Impact:
  - Memory usage grows with attacker-controlled path/domain/key cardinality and may degrade or terminate the process over time.
- Recommended fix:
  - Use bounded caches with TTL eviction for global and per-route rate buckets.
  - Bound `path_counts` and `upstream_counts`, using top-K sketches or capped maps.
  - Remove load-balancer keys when routes are deleted or route source is replaced.
  - Add metrics for evicted and dropped cardinality keys.
- Tests to add:
  - Unit tests proving bucket eviction after TTL.
  - High-cardinality path test ensuring map size caps.
  - Route deletion test ensuring load-balancer state is removed.
- Residual risk:
  - Attackers can still force churn; expose cache cap metrics and alert on sustained eviction.

### PXSA-2026-007: Redis Is a High-Trust Persistence Plane with Weak Defaults and Costly Token Verification

- Severity: Medium
- Confidence: High
- Status: Confirmed
- Category: auth
- Affected files:
  - `config/pxxl.toml:50`
  - `docker-compose.yml:27`
  - `edge/crates/redis-sync/src/lib.rs:66`
  - `edge/crates/redis-sync/src/lib.rs:110`
  - `edge/crates/redis-sync/src/lib.rs:152`
  - `edge/crates/redis-sync/src/lib.rs:221`
  - `edge/crates/api/src/lib.rs:195`
- Public vulnerability references:
  - No direct CVE claim. This is a token storage and trusted persistence design issue.
- Evidence:
  - The default Redis URL is `redis://redis:6379` in `config/pxxl.toml:50`, and compose publishes Redis to the host in `docker-compose.yml:27`.
  - Redis routes are loaded by deserializing JSON and normalizing only the domain/source in `edge/crates/redis-sync/src/lib.rs:66`. The same route validation used for API route creation is not centralized.
  - Created tokens are high-entropy UUID-based strings, but records store unsalted SHA-256 hashes in `edge/crates/redis-sync/src/lib.rs:110` and `edge/crates/redis-sync/src/lib.rs:221`.
  - Token verification loads every token record with `HVALS`, scans each hash, and writes `last_used_unix_ms` back to Redis on every successful authenticated request in `edge/crates/redis-sync/src/lib.rs:152`.
  - Admin auth returns Redis verification errors in API responses in `edge/crates/api/src/lib.rs:195`.
- Exploit sketch:
  - If Redis is exposed or compromised, write a `pxxl:routes` hash entry pointing a domain to an internal service, then restart Pxxl.
  - Insert many token records so each authenticated request performs a large Redis scan.
- Impact:
  - Redis compromise becomes route compromise and token-record compromise.
  - Token verification cost grows linearly with stored tokens and can become an admin API DoS.
- Recommended fix:
  - Do not publish Redis by default; require Redis AUTH/TLS or a private network.
  - Store tokens as `hash -> record_id` or use Redis hashes keyed by token hash so verification is O(1).
  - Use HMAC-SHA-256 with a server-side pepper or Argon2id for lower-entropy future token formats; keep high-entropy random tokens.
  - Add token TTLs, scopes, and last-used update throttling.
  - Revalidate Redis-loaded routes through the same validator used by API route creation.
  - Return generic `authentication backend unavailable` errors to clients.
- Tests to add:
  - Redis route load rejects invalid domains, private upstreams when policy forbids them, invalid schemes, and empty paths.
  - Token verification remains O(1) with many records.
  - List token endpoint never returns hashes.
- Residual risk:
  - Redis remains a privileged control-plane dependency. Run it on a private network with backups, auth, TLS, and monitoring.

### PXSA-2026-008: Admin API Request Bodies Are Collected Without Size Limits

- Severity: Medium
- Confidence: High
- Status: Confirmed
- Category: DoS
- Affected files:
  - `edge/crates/api/src/lib.rs:540`
  - `edge/crates/api/src/lib.rs:590`
  - `edge/crates/api/src/lib.rs:627`
- Public vulnerability references:
  - No direct CVE claim. This is a generic API resource exhaustion class.
- Evidence:
  - Blacklist mutation collects the entire request body with `req.into_body().collect().await` in `edge/crates/api/src/lib.rs:540`.
  - Domain creation collects the entire body in `edge/crates/api/src/lib.rs:590`.
  - Token creation collects the entire body in `edge/crates/api/src/lib.rs:627`.
  - Unlike proxy request forwarding, these API paths do not use `collect_body_with_limit`.
- Exploit sketch:
  - With a valid token, or if admin auth is disabled/misconfigured, send a very large JSON body to `/v1/domains` or `/v1/auth/tokens`.
  - Repeat to consume memory and tasks.
- Impact:
  - Authenticated or accidentally unauthenticated clients can consume memory in the admin API.
- Recommended fix:
  - Add a shared bounded body collector for admin API requests.
  - Set a small default admin JSON body cap, for example 1 MiB or less.
  - Add length limits for token names, route IDs, domains, headers, middleware names, and path arrays.
- Tests to add:
  - `/v1/domains`, `/v1/auth/tokens`, and blacklist endpoints return `413` above the configured API body limit.
  - Boundary tests for maximum route JSON size and maximum token name length.
- Residual risk:
  - Large valid route configurations may still be expensive to validate; enforce object count and string length caps too.

### PXSA-2026-009: TLS Is Local Single-Certificate Mode and Dynamic SAN Regeneration Can Be Abused

- Severity: Medium
- Confidence: High
- Status: Confirmed
- Category: TLS
- Affected files:
  - `config/pxxl.toml:7`
  - `edge/crates/tls/src/lib.rs:83`
  - `edge/crates/tls/src/lib.rs:95`
  - `edge/crates/tls/src/lib.rs:123`
  - `edge/crates/tls/src/lib.rs:177`
  - `edge/src/main.rs:357`
  - `edge/src/main.rs:396`
- Public vulnerability references:
  - GHSA-hffm-g8v7-wrv7, Caddy mTLS fail-open, future mTLS design class: https://github.com/caddyserver/caddy/security/advisories/GHSA-hffm-g8v7-wrv7
  - NGINX CVE-2026-40460, future HTTP/3 client-IP design class: https://nvd.nist.gov/vuln/detail/CVE-2026-40460
- Evidence:
  - The checked-in TLS mode is `local` in `config/pxxl.toml:7`.
  - `LocalCertificateStore::regenerate_certificate` writes a local cert and private key with normal filesystem defaults in `edge/crates/tls/src/lib.rs:83` and `edge/crates/tls/src/lib.rs:95`.
  - rustls is configured with `.with_no_client_auth()` and a single certificate in `edge/crates/tls/src/lib.rs:123`.
  - SANs are generated from every route domain plus defaults in `edge/crates/tls/src/lib.rs:177` and `edge/src/main.rs:396`.
  - A TLS reloader wakes every 5 seconds and regenerates the certificate whenever the domain set changes in `edge/src/main.rs:357`.
- Exploit sketch:
  - As an authenticated admin, repeatedly create/delete domains with long but parseable names.
  - Observe repeated local certificate generation and reload attempts.
- Impact:
  - Local self-signed mode is not production TLS.
  - Dynamic domain churn can create CPU and filesystem write pressure.
  - There is no SNI-specific certificate selection, production ACME, OCSP, explicit TLS policy, or listener mTLS enforcement.
- Recommended fix:
  - Clearly separate `local` and `production` TLS modes and fail production startup if local mode is active.
  - Validate domain names and cap SAN count/length.
  - Debounce certificate regeneration and rate-limit route changes.
  - Set private key file permissions explicitly to `0600`.
  - Implement SNI-aware certificate selection before production multi-domain use.
  - Treat mTLS config as unenforced until listener client-auth validation is implemented.
- Tests to add:
  - Cert regeneration rate-limit tests.
  - Domain/SAN validation tests for length, wildcard placement, invalid characters, and IDNA.
  - Private key permission test on Unix.
  - mTLS negative tests once client-auth is implemented.
- Residual risk:
  - ACME and multi-tenant TLS need a separate threat model for domain ownership validation and renewal failure behavior.

### PXSA-2026-010: Security-Looking Future Route Fields Are Accepted but Not Enforced

- Severity: Medium
- Confidence: High
- Status: Confirmed
- Category: config
- Affected files:
  - `edge/crates/common/src/lib.rs:612`
  - `edge/crates/common/src/lib.rs:626`
  - `edge/crates/common/src/lib.rs:644`
  - `edge/crates/common/src/lib.rs:669`
  - `edge/crates/http-proxy/src/lib.rs:1583`
  - `README.md:448`
  - `docs/dynamic-routing.md:246`
- Public vulnerability references:
  - NGINX CVE-2026-1642, upstream TLS design class: https://nvd.nist.gov/vuln/detail/CVE-2026-1642
  - NGINX CVE-2026-40460, HTTP/3 future class: https://nvd.nist.gov/vuln/detail/CVE-2026-40460
  - GHSA-hffm-g8v7-wrv7, mTLS future class: https://github.com/caddyserver/caddy/security/advisories/GHSA-hffm-g8v7-wrv7
- Evidence:
  - `UpstreamTransport` includes `server_name`, `insecure_skip_verify`, custom CA roots, and mTLS paths in `edge/crates/common/src/lib.rs:612`.
  - `RouterTlsOptions`, ACME, TCP, UDP, and HTTP/3 config shapes exist in `edge/crates/common/src/lib.rs:626`, `edge/crates/common/src/lib.rs:644`, and `edge/crates/common/src/lib.rs:669`.
  - The forwarding implementation uses a single `HttpConnector` and does not read `upstream.transport`, `rules.upstream_transport`, `rules.tls_options`, `rules.acme`, `rules.tcp`, `rules.udp`, or `rules.http3` in `edge/crates/http-proxy/src/lib.rs:1583`.
  - The docs say these fields are accepted for future work in `README.md:448` and `docs/dynamic-routing.md:246`, but API clients can still submit them today.
- Exploit sketch:
  - Submit a route with `transport.insecure_skip_verify=false`, `ca_roots`, or `tls_options.client_auth.required=true`.
  - Observe that the runtime does not enforce those settings.
- Impact:
  - Operators may believe upstream TLS verification, route mTLS, TCP/UDP, ACME, or HTTP/3 protections are active when they are only stored in config.
- Recommended fix:
  - Reject unimplemented security-sensitive fields at API/config load time unless an explicit `experimental_accept_unimplemented_fields` flag is enabled.
  - Add an `effective_features` field to route read APIs showing what is actually enforced.
  - Implement HTTPS upstream transport with rustls before accepting custom CA/SNI/mTLS settings.
- Tests to add:
  - API tests that unimplemented security fields are rejected or surfaced as inactive.
  - Snapshot tests for `GET /v1/domains/{domain}` showing effective security state.
- Residual risk:
  - Compatibility with early clients may require a migration period. Do not silently accept inert security controls.

### PXSA-2026-011: Docker/Podman Socket Discovery Expands the Trust Boundary

- Severity: Medium
- Confidence: High
- Status: Confirmed
- Category: deployment
- Affected files:
  - `config/pxxl.toml:12`
  - `docker-compose.yml:17`
  - `docker-compose.yml:88`
  - `edge/crates/docker-discovery/src/lib.rs:69`
  - `edge/crates/docker-discovery/src/lib.rs:187`
  - `edge/crates/docker-discovery/src/lib.rs:328`
- Public vulnerability references:
  - No direct CVE claim. This is a container socket and label trust-boundary issue.
- Evidence:
  - Docker and Podman discovery are enabled in the checked-in config in `config/pxxl.toml:12`.
  - The edge service mounts Docker and Podman sockets read-only in `docker-compose.yml:17`.
  - Promtail also mounts the Docker socket in `docker-compose.yml:88`.
  - Discovery sends raw HTTP over the Unix socket and reads the full response into memory with `read_to_end` in `edge/crates/docker-discovery/src/lib.rs:69`.
  - A container with `pxxl.enable=true` and label control can create a route via `route_from_labels` in `edge/crates/docker-discovery/src/lib.rs:187`.
  - The Docker response parser decodes chunked bodies but does not enforce a maximum response size in `edge/crates/docker-discovery/src/lib.rs:328`.
- Exploit sketch:
  - A user who can start a container with labels sets `pxxl.domain=admin.example.com` and points `pxxl.host`/`pxxl.port` to a chosen target.
  - A compromised Docker API endpoint returns a very large `/containers/json` response.
- Impact:
  - Container label control becomes route control.
  - Docker socket exposure remains sensitive even read-only because it reveals metadata and broadens local attack paths.
  - A malicious or compromised socket endpoint can consume memory during discovery.
- Recommended fix:
  - Disable Docker/Podman discovery by default in production examples.
  - Add container/network allowlists and domain suffix allowlists for labels.
  - Enforce maximum Docker API response size and strict chunk parsing.
  - Prefer a least-privilege discovery sidecar that exposes only approved labels rather than mounting the raw container runtime socket into the edge proxy.
- Tests to add:
  - Label allowlist/denylist tests.
  - Oversized Docker API response test.
  - Malformed chunked response tests, including missing CRLF and oversized chunks.
- Residual risk:
  - Any auto-discovery system turns orchestration metadata into routing authority. Keep that boundary explicit.

### PXSA-2026-012: Analytics and ClickHouse Error Handling Need Privacy and Size Hardening

- Severity: Low
- Confidence: High
- Status: Confirmed
- Category: privacy
- Affected files:
  - `edge/crates/core/src/lib.rs:407`
  - `edge/crates/storage/src/lib.rs:60`
  - `edge/crates/storage/src/lib.rs:144`
  - `edge/crates/storage/src/lib.rs:155`
  - `docker-compose.yml:50`
- Public vulnerability references:
  - No direct CVE claim. This is privacy and resource-hardening guidance.
- Evidence:
  - Recent visits store request ID, domain, method, path, status, upstream, remote IP, and GeoIP data in memory in `edge/crates/core/src/lib.rs:407`.
  - ClickHouse rows persist request ID, path, upstream, remote IP, country, region, and city fields in `edge/crates/storage/src/lib.rs:60`.
  - ClickHouse writes collect the entire error response body with `collect().await?.to_bytes()` in `edge/crates/storage/src/lib.rs:155` and include it in an error message in `edge/crates/storage/src/lib.rs:157`.
  - Compose publishes ClickHouse host ports in `docker-compose.yml:50`.
- Exploit sketch:
  - A compromised ClickHouse endpoint returns a very large error body to a schema or insert request.
  - An operator exposes ClickHouse and the analytics table to users who should not see raw IP/path data.
- Impact:
  - Privacy exposure of IP and path data.
  - Possible memory pressure or sensitive-error logging from oversized ClickHouse responses.
- Recommended fix:
  - Bound ClickHouse error body reads.
  - Redact or hash IP addresses where full IP retention is not required.
  - Document retention defaults and deletion procedures.
  - Do not publish ClickHouse ports outside private networks.
- Tests to add:
  - ClickHouse error body cap test.
  - Privacy config tests for IP redaction/hashing once implemented.
- Residual risk:
  - Access logs are inherently sensitive. Treat ClickHouse as a privileged data store.

### PXSA-2026-013: Docs Understate Runtime Body Limit Behavior

- Severity: Low
- Confidence: High
- Status: Confirmed
- Category: observability
- Affected files:
  - `docs/api.md:220`
  - `edge/crates/http-proxy/src/lib.rs:533`
  - `edge/crates/http-proxy/src/lib.rs:1289`
  - `edge/crates/http-proxy/src/lib.rs:2560`
- Public vulnerability references:
  - HAProxy CVE-2021-40346, request smuggling class considered but not directly affected: https://nvd.nist.gov/vuln/detail/CVE-2021-40346
- Evidence:
  - Docs say `max_body_bytes` rejects requests whose `Content-Length` exceeds the value in `docs/api.md:220`.
  - The policy pre-check does reject oversized `Content-Length` in `edge/crates/http-proxy/src/lib.rs:533`.
  - The actual forwarding path also computes `request_body_limit` and buffers the request body in `edge/crates/http-proxy/src/lib.rs:1289`.
  - `collect_body_with_limit` rejects when collected byte length exceeds the limit in `edge/crates/http-proxy/src/lib.rs:2560`.
- Exploit sketch:
  - Not an exploit. This is a documentation mismatch that can cause testers to look for a chunked-body bypass that the current code largely prevents by byte count.
- Impact:
  - Operators and auditors may misunderstand which body limits are enforced and where slow-body timeout gaps remain.
- Recommended fix:
  - Update docs to say `Content-Length` is pre-checked and the collected body is also capped; separately document missing read-timeout protections.
- Tests to add:
  - Chunked or streaming body above `max_body_bytes` returns `413`.
  - Slow body under the cap times out once timeout support is added.
- Residual risk:
  - Body size caps do not replace read deadlines and connection limits.

## Positive Security Properties

- Generated request IDs are server-side UUIDs; client-provided `x-request-id` is overwritten before upstream forwarding and response return in `edge/crates/http-proxy/src/lib.rs:1052`, `edge/crates/http-proxy/src/lib.rs:2619`, and `edge/tests/http_proxy.rs:73`.
- Generated headers use `HeaderName::from_bytes` and `HeaderValue::from_str` in many paths, reducing CRLF/header injection risk for Pxxl-generated headers.
- Error-page template substitutions escape HTML for status, message, domain, and path in `edge/crates/http-proxy/src/lib.rs:2970`.
- Request and response bodies are capped by collected byte length in `edge/crates/http-proxy/src/lib.rs:2560`.
- The hot path records stats and sends ClickHouse analytics through an in-memory channel; it does not query Redis or ClickHouse before forwarding in `edge/src/main.rs:81` and `edge/crates/core/src/lib.rs:282`.
- Recent visits are capped at 200 per domain in `edge/crates/core/src/lib.rs:22` and `edge/crates/core/src/lib.rs:420`.
- Token list responses expose `AdminTokenView`, not `token_hash`, in `edge/crates/redis-sync/src/lib.rs:43` and `edge/crates/redis-sync/src/lib.rs:133`.
- API `/healthz` and `/readyz` are explicitly public; `/v1/*` is protected when admin auth is enabled in `edge/crates/api/src/lib.rs:176`.
- Offline GeoIP uses local CSV/built-in CIDR records and does not call the internet during request handling in `edge/crates/geo/src/lib.rs:40`.
- Route registry updates use atomic snapshot replacement through `ArcSwap` in `edge/crates/core/src/lib.rs:24`.

## Test Plan

Unit tests:

- Canonical path normalization matrix for dot segments, percent-encoding, double encoding, backslashes, semicolons, encoded query/hash delimiters, invalid UTF-8, trailing dots, and duplicate slashes.
- `normalize_domain` and `host_without_port` tests for trailing dots, uppercase, ports, IPv6 literals, malformed brackets, whitespace, userinfo-like values, and control characters.
- Upstream validator tests for scheme, host, port, path, credentials, private networks, link-local, loopback, Unix/file/gopher URLs, and length caps.
- Rate-limiter eviction and bounded stats-map tests.
- Token store tests for O(1) verification, TTLs, scopes, and no returned hashes.

Integration tests:

- Duplicate `Content-Length`, conflicting `Content-Length` plus `Transfer-Encoding`, absolute-form URI, huge header, huge header count, and odd upgrade requests.
- Chunked or streaming body larger than `max_body_bytes` returns `413`.
- Slowloris partial-header and slow-body tests once timeouts are implemented.
- Two upstreams with `/public` and `/private` routes to prove normalized traversal does not bypass path middleware.
- Echo-upstream tests proving hop-by-hop and trust headers are stripped or overwritten.
- Admin API auth negative tests: no token, malformed Authorization, lowercase `bearer`, extra spaces, wrong token, Redis outage, disallowed IP.
- SSRF route creation tests for loopback/private/link-local/metadata endpoints and unsupported schemes.
- Docker/Podman label tests for invalid labels, domain suffix allowlists, and multiple containers with the same route.
- Health-check tests proving blocked upstreams are never probed.

Fuzz targets:

- Path canonicalizer.
- Host/domain parser.
- Docker HTTP response parser and chunked decoder.
- Route JSON/TOML deserializer and validator.
- WAF input normalization.

Docker-compose hardening tests:

- Production compose must not publish support-service ports.
- Edge container must run non-root, set `read_only`, use `cap_drop`, and have `no-new-privileges`.
- Secrets must not equal known dev defaults.

## Recommended Remediation Roadmap

1. Must fix before public exposure:
   - Remove public host port exposure for admin, metrics, Redis, Postgres, ClickHouse, Loki, Prometheus, and Grafana.
   - Remove tracked/static bootstrap token from production config and reject known dev tokens in production mode.
   - Add upstream validation and SSRF controls for API, Redis-loaded, Docker, and Podman routes.
   - Strip hop-by-hop and trust headers by default.
   - Add listener-level connection, timeout, and HTTP/2 limits.

2. Should fix before beta:
   - Implement canonical path normalization before routing/WAF/middleware.
   - Add bounded admin API body collection.
   - Add TTL/cap eviction for rate-limit buckets, stats maps, and load-balancer maps.
   - Add Redis auth/TLS/private-network requirements and O(1) token verification.
   - Add Docker/Podman label allowlists and socket response size caps.

3. Defense-in-depth:
   - Add non-root runtime user, read-only filesystem, `cap_drop`, `no-new-privileges`, healthcheck, resource limits, pinned image digests, SBOM generation, and image signing.
   - Bound ClickHouse error bodies and document analytics privacy retention.
   - Add explicit security-state output for route APIs.
   - Update docs for body limit behavior and production safety.

4. Future feature requirements:
   - ACME: account key storage, DNS provider secret isolation, challenge route isolation, rate limits, domain ownership validation, wildcard DNS challenge controls, renewal failure behavior, and audit logs.
   - TCP/UDP: protocol confusion tests, SNI routing controls, TLS passthrough safety, proxy protocol trust boundaries, per-peer limits, and logging.
   - HTTP/3: no 0-RTT unless every security decision is replay-safe, verified client-IP source handling, QUIC connection limits, and HTTP/3-specific memory/fuzz testing.
   - Dashboard UI: CSRF, XSS, secure sessions, RBAC, password hashing, MFA, audit logs, and clickjacking headers.
   - Cluster sync: mTLS, signed route updates, replay protection, conflict handling, and consistency semantics.
   - Middleware/plugin system: sandboxing, signed plugins, supply-chain scanning, filesystem path controls, and tenant isolation.

## Tool Output Appendix

Repository state:

- Working directory: `/Users/robin/Documents/js_websites/pxxl/Pxxl-Proxy-System`
- Git top level: `/Users/robin/Documents/js_websites/pxxl/Pxxl-Proxy-System`
- Commit: `c2077bb914cebb92c5e505391a06eb2398313e49`
- `git status --short`: clean at audit start
- `rg --files`: completed
- `cargo metadata --format-version 1`: completed after network approval; initial sandbox run failed DNS resolution for `static.crates.io`

Dependency versions verified in `Cargo.lock`:

- `hyper 1.9.0`
- `hyper-util 0.1.20`
- `h2 0.4.14`
- `tokio 1.52.3`
- `rustls 0.23.40`
- `rcgen 0.12.1`
- `redis 0.27.6`
- `url 2.5.8`
- `serde_json 1.0.149`
- `sha2 0.10.9`
- `uuid 1.23.1`
- `prometheus 0.13.4`
- `dashmap 6.1.0`
- `argon2` and `jsonwebtoken` are declared in workspace `Cargo.toml` but no runtime use was found by `rg`

Checks:

- `cargo fmt --check --all`: passed
- `cargo clippy --workspace --all-targets --all-features -- -D warnings`: passed
- `cargo test --workspace --all-features`: passed
  - common: 4 tests
  - config: 8 tests
  - core: 9 tests
  - ddos: 3 tests
  - docker-discovery: 9 tests
  - http-proxy integration: 12 tests
  - geo: 2 tests
  - http-proxy unit: 2 tests
  - load-balancer: 3 tests
  - metrics: 1 test
  - tls: 1 test
  - doctests: 0 tests
- `cargo audit`: not run: tool unavailable
- `cargo deny check`: not run: tool unavailable
- `cargo outdated`: not run: tool unavailable
- `trivy fs --scanners vuln,secret,config .`: not run: tool unavailable
- `gitleaks detect --source . --no-git`: not run: tool unavailable
- `semgrep --config p/rust --config p/secrets --config p/owasp-top-ten .`: not run: tool unavailable

## Source Appendix

Sources retrieved on 2026-05-15:

- CISA HTTP/2 Rapid Reset alert: https://www.cisa.gov/news-events/alerts/2023/10/10/http2-rapid-reset-vulnerability-cve-2023-44487
- NVD CVE-2023-44487: https://nvd.nist.gov/vuln/detail/CVE-2023-44487
- RustSec RUSTSEC-2023-0034: https://rustsec.org/advisories/RUSTSEC-2023-0034.html
- RustSec RUSTSEC-2024-0332: https://rustsec.org/advisories/RUSTSEC-2024-0332.html
- RustSec RUSTSEC-2025-0070: https://rustsec.org/advisories/RUSTSEC-2025-0070.html
- NGINX official security advisories: https://nginx.org/en/security_advisories.html
- NVD CVE-2026-42926: https://nvd.nist.gov/vuln/detail/CVE-2026-42926
- Debian tracker CVE-2026-42926: https://security-tracker.debian.org/tracker/CVE-2026-42926
- NVD CVE-2026-40460: https://nvd.nist.gov/vuln/detail/CVE-2026-40460
- NVD CVE-2026-1642: https://nvd.nist.gov/vuln/detail/CVE-2026-1642
- NVD CVE-2023-35944: https://nvd.nist.gov/vuln/detail/CVE-2023-35944
- NVD CVE-2021-40346: https://nvd.nist.gov/vuln/detail/CVE-2021-40346
- Traefik GHSA-vrch-868g-9jx5 / CVE-2025-47952: https://github.com/traefik/traefik/security/advisories/GHSA-vrch-868g-9jx5
- Traefik GHSA-6p68-w45g-48j7 / CVE-2025-32431: https://github.com/traefik/traefik/security/advisories/GHSA-6p68-w45g-48j7
- Traefik GHSA-h924-8g65-j9wg / CVE-2020-15129: https://github.com/traefik/traefik/security/advisories/GHSA-h924-8g65-j9wg
- Traefik GHSA-gxrv-wf35-62w9: https://github.com/traefik/traefik/security/advisories/GHSA-gxrv-wf35-62w9
- Caddy GHSA-g7pc-pc7g-h8jh: https://github.com/caddyserver/caddy/security/advisories/GHSA-g7pc-pc7g-h8jh
- Caddy GHSA-x76f-jf84-rqj8: https://github.com/caddyserver/caddy/security/advisories/GHSA-x76f-jf84-rqj8
- Caddy GHSA-7r4p-vjf4-gxv4 / CVE-2026-30851: https://github.com/caddyserver/caddy/security/advisories/GHSA-7r4p-vjf4-gxv4
- Caddy GHSA-hffm-g8v7-wrv7: https://github.com/caddyserver/caddy/security/advisories/GHSA-hffm-g8v7-wrv7
- Envoy GHSA-xcx5-93pw-jw2w / CVE-2019-9901: https://github.com/envoyproxy/envoy/security/advisories/GHSA-xcx5-93pw-jw2w
- Envoy GHSA-w5w5-487h-qv8q: https://github.com/envoyproxy/envoy/security/advisories/GHSA-w5w5-487h-qv8q
- Envoy GHSA-ffhv-fvxq-r6mf: https://github.com/envoyproxy/envoy/security/advisories/GHSA-ffhv-fvxq-r6mf
- Envoy CVE-2023-35944 advisory reference via NVD: https://github.com/envoyproxy/envoy/security/advisories/GHSA-pvgm-7jpg-pw5g

