# Pxxl Proxy Vulnerability Scan

Date: 2026-05-15
Auditor/model: Codex manual security review fallback; requested `@codex-security` plugin was not available in this session.
Commit: `1e314b7f63452c941ef6e48bdfe4ee56f2e5f5fd`
Scope: Rust edge proxy, admin API, Docker/Podman discovery, TLS, Redis persistence, ClickHouse analytics, compose/runtime defaults, install/update scripts.
Out of scope: destructive exploitation, external internet scanning of running hosts, and scanners not installed locally.

## Executive Summary

The current tree already fixed several earlier high-risk issues: admin and metrics are loopback-published in Compose, Docker/Podman discovery is opt-in, dynamic route quotas exist, dynamic route validation rejects direct private IPs/control-plane service names, route path matching now canonicalizes percent-encoded traversal, response hop-by-hop headers are stripped, and the main Rust checks pass.

The biggest residual security issues are:

1. Basic/Digest middleware consumes `Authorization` but forwards that same header to upstreams.
2. Dynamic upstream SSRF protection blocks private IP literals but still allows DNS names that resolve to private/host networks, including `host.docker.internal`.
3. Streaming request/response size limits can trigger after partial upstream/client forwarding, producing partial side effects and 502-style behavior instead of clean early rejection.
4. HTTP/2 is enabled but Pxxl does not set explicit HTTP/2 anti-DoS limits beyond a coarse connection semaphore and total connection timeout.
5. Metrics have no authentication at the application layer; Compose binds them to loopback, but any wider bind exposes route/upstream labels.
6. The bootstrap admin token remains a permanent root credential for as long as the environment variable is set.

## Methodology

Commands run:

| Command | Result |
| --- | --- |
| `pwd` | `/Users/robin/Documents/js_websites/pxxl/Pxxl-Proxy-System` |
| `git rev-parse --show-toplevel` | `/Users/robin/Documents/js_websites/pxxl/Pxxl-Proxy-System` |
| `git rev-parse HEAD` | `1e314b7f63452c941ef6e48bdfe4ee56f2e5f5fd` |
| `git status --short --untracked-files=all` | Dirty tree with prior security fixes, docs, `install.sh`, `update.sh`, and `docker-compose.discovery.yml` |
| `rg --files` | Completed |
| `cargo metadata --format-version 1` | Completed |
| `cargo fmt --check --all` | Passed |
| `cargo clippy --workspace --all-targets --all-features -- -D warnings` | Passed |
| `cargo test --workspace --all-features` | Passed |
| `sh -n install.sh`; `sh -n update.sh` | Passed |
| `docker compose config` | Passed with test env values |
| `docker compose -f docker-compose.yml -f docker-compose.discovery.yml config` | Passed with test env values |
| `cargo audit` | Not run: tool unavailable |
| `cargo deny check` | Not run: tool unavailable |
| `cargo outdated` | Not run: tool unavailable |
| `trivy fs --scanners vuln,secret,config .` | Not run: tool unavailable |
| `gitleaks detect --source . --no-git` | Not run: tool unavailable |
| `semgrep --config p/rust --config p/secrets --config p/owasp-top-ten .` | Not run: tool unavailable |
| `shellcheck install.sh update.sh` | Not run: tool unavailable |

Important dependency versions observed with `cargo tree -p pxxl-edge`:

- `hyper v1.9.0`
- `h2 v0.4.14`
- `tokio v1.52.3`
- `rustls v0.23.40`
- `tokio-rustls v0.26.4`
- `redis v0.27.6`
- `url v2.5.8`
- `serde_json v1.0.149`
- `sha2 v0.10.9`
- `uuid v1.23.1`
- `prometheus v0.13.4`
- `dashmap v6.1.0`
- `rcgen v0.12.1`
- `ring v0.17.14`
- `aws-lc-rs v1.17.0`

## CVE/GHSA/RustSec Mapping

Do not read this table as "Pxxl is affected" unless the status says so. Most public reverse-proxy CVEs are used here as same-class checks because Pxxl does not embed NGINX, Traefik, Caddy, Envoy, or HAProxy code.

| ID | Source | Class | Relevance to Pxxl | Status | Local evidence |
| --- | --- | --- | --- | --- | --- |
| CVE-2023-44487 | CISA/CVE.org HTTP/2 Rapid Reset | HTTP/2 request/reset DoS | Pxxl advertises HTTP/2 over TLS. | Analogous risk, not proven affected | `edge/crates/tls/src/lib.rs:126`, `edge/crates/tls/src/lib.rs:129`, `edge/crates/http-proxy/src/lib.rs:2787` |
| RUSTSEC-2023-0034 / CVE-2023-26964 | RustSec `h2` reset stream resource exhaustion | HTTP/2 dependency DoS | Pxxl uses `h2` transitively through Hyper. | Needs `cargo audit`; local `h2 v0.4.14` observed, no direct affected claim made | `cargo tree -p pxxl-edge` |
| RUSTSEC-2024-0332 | RustSec `h2` CONTINUATION flood | HTTP/2 header-continuation DoS | Same dependency family and protocol surface. | Needs `cargo audit`; no direct affected claim made | `cargo tree -p pxxl-edge` |
| HAProxy CVE-2021-40346 | HAProxy duplicate `Content-Length` request smuggling | Parser/request smuggling | Pxxl relies on Hyper parser, not HAProxy parser. Tests should cover duplicate CL and CL+TE. | Analogous test class | `edge/crates/http-proxy/src/lib.rs:2763` |
| Traefik CVE-2025-47952 / GHSA-vrch-868g-9jx5 | URL-encoded path traversal bypassing path routing/middleware | Path normalization | Pxxl now canonicalizes path before route matching and forwarding. | Not directly affected based on reviewed code; keep regression tests | `edge/crates/http-proxy/src/lib.rs:1098`, `edge/crates/common/src/lib.rs:989` |
| Traefik CVE-2025-32431 / GHSA-6p68-w45g-48j7 | Path matcher bypass | Prefix route matching | Pxxl uses longest-prefix routing on canonicalized paths. | Analogous test class | `edge/crates/common/src/lib.rs:855`, `edge/crates/http-proxy/src/lib.rs:1209` |
| Caddy GHSA-g7pc-pc7g-h8jh | Escaped-path route/auth bypass | Path normalization | Same class, but Pxxl decodes up to 4 times and normalizes dot segments. | Not directly affected based on reviewed code | `edge/crates/common/src/lib.rs:997` |
| Caddy CVE-2026-30851 / GHSA-7r4p-vjf4-gxv4 | Forward auth trusted header injection | Auth/identity header trust | Pxxl strips common forwarded identity headers before upstream forwarding, but leaks consumed `Authorization`. | Analogous risk confirmed | `edge/crates/http-proxy/src/lib.rs:2380`, `edge/crates/http-proxy/src/lib.rs:2404` |
| Envoy GHSA-xcx5-93pw-jw2w | Missing path normalization | Routing/access-control bypass | Same class; Pxxl has canonical path logic. | Analogous test class | `edge/crates/common/src/lib.rs:989` |
| Envoy GHSA-w5w5-487h-qv8q | Unsafe generated header value / request smuggling | Header generation | Pxxl uses `HeaderValue::from_str` for dynamic headers. | Not directly affected based on reviewed code, keep tests | `edge/crates/http-proxy/src/lib.rs:726`, `edge/crates/http-proxy/src/lib.rs:1868` |
| Envoy GHSA-ffhv-fvxq-r6mf | Trusted header manipulation | Identity/header spoofing | Pxxl strips common client-supplied forwarded headers before upstream forwarding. | Partly mitigated | `edge/crates/http-proxy/src/lib.rs:2380` |
| NGINX HTTP/2 advisories | NGINX official advisories | HTTP/2 parser/resource DoS | Pxxl does not use NGINX; relevant only as HTTP/2 hardening checklist. | Analogous risk | `edge/crates/tls/src/lib.rs:129` |
| Docker daemon socket guidance | Docker official docs | Runtime socket privilege boundary | Pxxl discovery override mounts Docker/Podman sockets. | Deployment risk confirmed when discovery is enabled | `docker-compose.discovery.yml:9`, `docker-compose.discovery.yml:10` |

## Findings

### PXSA-2026-101: Edge Basic/Digest Credentials Are Forwarded To Upstreams

- Severity: High
- Confidence: High
- Status: Confirmed
- Category: auth, header-spoofing
- Affected files:
  - `edge/crates/http-proxy/src/lib.rs:1267`
  - `edge/crates/http-proxy/src/lib.rs:1284`
  - `edge/crates/http-proxy/src/lib.rs:1924`
  - `edge/crates/http-proxy/src/lib.rs:2309`
  - `edge/crates/http-proxy/src/lib.rs:2380`
- Public vulnerability references:
  - Caddy CVE-2026-30851 / GHSA-7r4p-vjf4-gxv4, same class: forwarded auth/identity header handling.
- Evidence:
  - `evaluate_basic_auth` and `evaluate_digest_auth` validate the client `Authorization` header at `edge/crates/http-proxy/src/lib.rs:1267` and `edge/crates/http-proxy/src/lib.rs:1284`.
  - The forwarding paths call `strip_forwarded_request_headers` at `edge/crates/http-proxy/src/lib.rs:1924` and `edge/crates/http-proxy/src/lib.rs:2309`.
  - `strip_forwarded_request_headers` removes `proxy-authorization` and forwarded identity headers, but it does not remove `authorization` at `edge/crates/http-proxy/src/lib.rs:2395`.
- Exploit sketch:
  - Configure a route with Basic or Digest middleware.
  - Authenticate successfully through Pxxl.
  - Observe the upstream application or upstream logs receiving the edge authentication `Authorization` header.
- Impact:
  - Any upstream, mirror upstream, or compromised app behind the route can capture credentials intended for the edge proxy.
- Recommended fix:
  - After Basic/Digest middleware succeeds, remove `Authorization` before forwarding by default.
  - Add an explicit route option such as `forward_authorization = true` only for routes that intentionally pass application auth through.
  - Also strip `Authorization` from traffic-mirroring requests unless explicitly allowed.
- Tests to add:
  - Basic auth route should authenticate at edge and upstream should not receive `Authorization`.
  - Digest auth route should authenticate at edge and upstream should not receive `Authorization`.
  - Optional pass-through mode should preserve the header only when explicitly enabled.
- Residual risk:
  - Application-level authentication behind Pxxl still needs a clear policy for whether `Authorization` belongs to edge auth or origin auth.

### PXSA-2026-102: DNS-Based SSRF And Host-Gateway SSRF Remain Possible For Dynamic Routes

- Severity: High when the admin API is tenant-accessible; Medium for single trusted-admin deployments.
- Confidence: High
- Status: Confirmed
- Category: SSRF, routing
- Affected files:
  - `edge/crates/common/src/lib.rs:1087`
  - `edge/crates/common/src/lib.rs:1117`
  - `edge/crates/common/src/lib.rs:1144`
  - `edge/crates/common/src/lib.rs:1155`
  - `edge/src/main.rs:306`
- Public vulnerability references:
  - Generic SSRF class; no direct CVE claim.
- Evidence:
  - `validate_upstream_host` rejects `localhost`, private IP literals, link-local IP literals, multicast, and unspecified IPs at `edge/crates/common/src/lib.rs:1144`.
  - It only checks literal IPs with `host.parse::<IpAddr>()` at `edge/crates/common/src/lib.rs:1155`.
  - DNS names that resolve to private addresses, link-local metadata addresses, or the host gateway are still accepted if they are not in the static reserved-host list.
  - `host.docker.internal` is not rejected by the generic upstream validator, and can reach host services in common Docker/Podman setups.
  - Health checks periodically send GET requests to configured upstreams at `edge/src/main.rs:306`.
- Exploit sketch:
  - An authenticated route creator sets upstream to `http://host.docker.internal:8080` or `http://attacker.example`, where DNS resolves to an internal IP.
  - Pxxl sends proxy traffic and health checks to that address from inside the container/network.
- Impact:
  - Authenticated tenants or compromised Redis/labels can reach internal services reachable from the edge container, even though direct private IP literals are blocked.
- Recommended fix:
  - Resolve upstream hostnames at route creation and request/health-check time.
  - Reject resolved private, loopback, link-local, multicast, unspecified, metadata, Docker gateway, and Kubernetes service CIDR addresses unless an explicit admin allowlist permits them.
  - Add a separate `allow_private_upstreams` setting that defaults to false for API/label routes.
  - Apply the same checks to forward-auth URLs, mirror upstreams, geo upstreams, split upstreams, and health checks.
- Tests to add:
  - Dynamic route creation rejects `host.docker.internal`.
  - Dynamic route creation rejects DNS names resolving to `127.0.0.1`, RFC1918, `169.254.169.254`, and IPv6 ULA/link-local.
  - Health checker refuses to probe newly private-resolved hosts.
- Residual risk:
  - DNS can change after validation, so request-time enforcement or a pinned resolver/cache policy is still needed.

### PXSA-2026-103: Streaming Body Limits Are Enforced After Partial Forwarding

- Severity: Medium
- Confidence: High
- Status: Confirmed
- Category: DoS, request-smuggling-adjacent
- Affected files:
  - `edge/crates/http-proxy/src/lib.rs:1415`
  - `edge/crates/http-proxy/src/lib.rs:1507`
  - `edge/crates/http-proxy/src/lib.rs:1559`
  - `edge/crates/http-proxy/src/lib.rs:1919`
  - `edge/crates/http-proxy/src/lib.rs:1974`
- Public vulnerability references:
  - HTTP request body abuse and slow body classes; no direct CVE claim.
- Evidence:
  - The default non-buffered path calls `forward_streaming` at `edge/crates/http-proxy/src/lib.rs:1415`.
  - `forward_streaming` wraps the incoming request body in `Limited` at `edge/crates/http-proxy/src/lib.rs:1919`, then sends it to the upstream.
  - If the limit is exceeded while the stream is already in progress, the proxy maps the upstream request failure to `502 Bad Gateway` at `edge/crates/http-proxy/src/lib.rs:1507`.
  - The buffered path correctly returns `413 Payload Too Large` before upstream forwarding at `edge/crates/http-proxy/src/lib.rs:1559`.
  - Streaming responses are also limited after headers/body may already be flowing to the client at `edge/crates/http-proxy/src/lib.rs:1974`.
- Exploit sketch:
  - Send a chunked POST without `Content-Length` to a route that does not require buffering.
  - Exceed `max_body_bytes` after the upstream has already received part of the body.
- Impact:
  - Upstreams can observe partial requests or side effects before Pxxl detects the oversized body.
  - Clients receive a generic upstream failure instead of a deterministic early 413.
- Recommended fix:
  - If `max_body_bytes` is set for methods with request bodies, buffer and validate before forwarding unless an explicit streaming mode accepts partial-forwarding semantics.
  - Add a request-body limiting wrapper that maps local size failures to a controlled Pxxl response before upstream dispatch where possible.
  - For responses, document streaming-limit behavior or buffer responses when strict `max_response_bytes` is required.
- Tests to add:
  - Chunked body over limit returns 413 and upstream receives no body for strict routes.
  - Streaming mode over limit is explicitly tested and documented.
  - Oversized upstream response limit behavior is covered for buffered and streaming paths.
- Residual risk:
  - Strict size enforcement and fully streaming proxying are in tension; the route model should make that tradeoff explicit.

### PXSA-2026-104: HTTP/2 Is Enabled Without Explicit Protocol-Level DoS Tuning

- Severity: Medium
- Confidence: Medium
- Status: Likely
- Category: DoS
- Affected files:
  - `edge/crates/tls/src/lib.rs:126`
  - `edge/crates/tls/src/lib.rs:129`
  - `edge/crates/http-proxy/src/lib.rs:2670`
  - `edge/crates/http-proxy/src/lib.rs:2788`
  - `edge/crates/http-proxy/src/lib.rs:2790`
- Public vulnerability references:
  - CVE-2023-44487, same class.
  - RUSTSEC-2023-0034 / CVE-2023-26964, dependency class.
  - RUSTSEC-2024-0332, dependency class.
  - NGINX HTTP/2 DoS advisories, same class only.
- Evidence:
  - TLS config advertises `h2` at `edge/crates/tls/src/lib.rs:129`.
  - The server uses `AutoBuilder::new(TokioExecutor::new())` at `edge/crates/http-proxy/src/lib.rs:2788` with no visible HTTP/2-specific settings.
  - There is a global connection semaphore at `edge/crates/http-proxy/src/lib.rs:2670` and a coarse total connection timeout at `edge/crates/http-proxy/src/lib.rs:2790`, but no per-IP concurrency, stream reset budget, max concurrent streams, header-list size, or per-request read deadlines in Pxxl code.
  - `h2 v0.4.14` was observed locally, but `cargo audit` was unavailable, so this report does not claim a direct vulnerable dependency.
- Exploit sketch:
  - Use safe local tests to open many HTTP/2 streams/resets or large continuation/header sequences against the TLS listener.
- Impact:
  - A low-bandwidth client may be able to consume CPU/memory/connection slots more efficiently than normal HTTP/1 traffic.
- Recommended fix:
  - Configure Hyper/h2 limits explicitly: max concurrent streams, max frame/header list size, max pending accepts, per-IP concurrent connections, idle timeout, header read timeout, and request body read timeout.
  - Add an option to disable HTTP/2 until hardened.
  - Add `cargo audit` and dependency advisory checks in CI.
- Tests to add:
  - HTTP/2 rapid reset regression test if the test client supports it.
  - Header continuation/large-header matrix.
  - Many idle h2 stream tests.
- Residual risk:
  - HTTP/2 DoS classes are implementation-specific and evolve quickly; this needs ongoing dependency monitoring.

### PXSA-2026-105: Metrics Endpoint Has No Application-Layer Authentication

- Severity: Medium
- Confidence: High
- Status: Confirmed
- Category: observability, deployment
- Affected files:
  - `edge/crates/api/src/lib.rs:274`
  - `edge/crates/api/src/lib.rs:291`
  - `docker-compose.yml:11`
  - `docker-compose.yml:21`
  - `docker-compose.yml:22`
- Public vulnerability references:
  - Generic unauthenticated metrics exposure class; no direct CVE claim.
- Evidence:
  - `run_metrics_listener` serves metrics for every request at `edge/crates/api/src/lib.rs:291`.
  - Compose sets the in-container metrics listener to `0.0.0.0:9090` at `docker-compose.yml:12`, but host-publishes it only to `127.0.0.1:9090` at `docker-compose.yml:22`.
  - This is acceptable for local Compose, but a Kubernetes Service, changed port binding, or direct container network exposure would publish route/domain/upstream labels without auth.
- Exploit sketch:
  - Expose `PXXL_METRICS_ADDR=0.0.0.0:9090` through a public Service or host binding.
  - Request `/metrics` without credentials.
- Impact:
  - Leaks domain names, upstream URLs, request status distributions, and other operational metadata.
- Recommended fix:
  - Add optional bearer-token or mTLS protection for metrics.
  - Keep loopback/private bind as default.
  - Document Prometheus scrape authentication examples.
- Tests to add:
  - Metrics endpoint requires auth when configured.
  - Compose config remains loopback-only by default.
- Residual risk:
  - Prometheus and Grafana themselves must be access-controlled by deployment networking.

### PXSA-2026-106: Bootstrap Admin Token Is Permanent While Environment Variable Remains Set

- Severity: Medium
- Confidence: High
- Status: Confirmed
- Category: auth, config
- Affected files:
  - `edge/crates/api/src/lib.rs:196`
  - `edge/src/main.rs:492`
  - `README.md:73`
- Public vulnerability references:
  - Default/admin credential exposure class; no direct CVE claim.
- Evidence:
  - `PXXL_ADMIN_BOOTSTRAP_TOKEN` is loaded into config at `edge/src/main.rs:492`.
  - `AdminApiAuth::authorize` accepts that token before consulting Redis at `edge/crates/api/src/lib.rs:196`.
  - Redis-backed tokens can be revoked, but the bootstrap token cannot be revoked through the API.
  - README correctly instructs operators to remove it after creating a Redis-backed token, but the code does not enforce first-use or expiry.
- Exploit sketch:
  - Operator leaves `PXXL_ADMIN_BOOTSTRAP_TOKEN` in Compose/systemd/Kubernetes env.
  - Anyone who obtains that token has full admin API access until the service environment changes and the proxy restarts.
- Impact:
  - Long-lived root credential with no token-list visibility, expiry, or revocation API.
- Recommended fix:
  - Support one-shot bootstrap: use it only to create the first Redis token, then reject it.
  - Alternatively require `PXXL_BOOTSTRAP_TOKEN_ALLOW_PERMANENT=true` for permanent behavior.
  - Emit a high-severity startup warning if a bootstrap token is set outside local/dev.
- Tests to add:
  - Bootstrap token cannot authenticate after first Redis token is created when one-shot mode is enabled.
  - Bootstrap token never appears in token listing.
- Residual risk:
  - First-run credentials still need secure delivery to the operator.

### PXSA-2026-107: Route Snapshots Expose Embedded Basic/Digest Passwords To Any Admin Token

- Severity: Medium
- Confidence: High
- Status: Confirmed
- Category: auth, privacy
- Affected files:
  - `edge/crates/common/src/lib.rs:376`
  - `edge/crates/common/src/lib.rs:396`
  - `edge/crates/api/src/lib.rs:349`
  - `edge/crates/api/src/lib.rs:353`
- Public vulnerability references:
  - Secret exposure class; no direct CVE claim.
- Evidence:
  - Basic and Digest middleware user maps store cleartext password values at `edge/crates/common/src/lib.rs:376` and `edge/crates/common/src/lib.rs:396`.
  - `GET /v1/routes` and `GET /v1/domains` return full route snapshots at `edge/crates/api/src/lib.rs:349` and `edge/crates/api/src/lib.rs:353`.
  - Any valid admin token can read route definitions, including embedded auth middleware configuration.
- Exploit sketch:
  - Create a route with `basic_auth.users`.
  - Call `GET /v1/routes` with any valid admin token.
  - Observe the configured route password values in the JSON response.
- Impact:
  - Lower-trust admin tokens can read secrets for every protected route.
  - Redis route storage also contains plaintext route secrets.
- Recommended fix:
  - Store Basic/Digest passwords as Argon2id/bcrypt hashes or HA1-style digest hashes as appropriate.
  - Redact secret fields from route-list APIs by default.
  - Add a separate privileged secret-read endpoint only if absolutely necessary.
  - Add token scopes/RBAC before multi-tenant use.
- Tests to add:
  - Route list redacts auth middleware secrets.
  - Runtime auth still works with hashed password storage.
- Residual risk:
  - Route configs often contain secrets in headers too; redact `add_request_headers`, forward-auth credentials, and future TLS key material consistently.

### PXSA-2026-108: ForwardAuth `response_headers` Configuration Is Ignored

- Severity: Low
- Confidence: High
- Status: Confirmed
- Category: auth, config
- Affected files:
  - `edge/crates/common/src/lib.rs:416`
  - `edge/crates/http-proxy/src/lib.rs:2212`
  - `docs/api.md:305`
- Public vulnerability references:
  - Caddy CVE-2026-30851 / GHSA-7r4p-vjf4-gxv4, same design area but not the same bug.
- Evidence:
  - `ForwardAuthConfig` defines `response_headers` at `edge/crates/common/src/lib.rs:423`.
  - `run_forward_auth` only copies configured request headers to the auth service and returns `response.status().is_success()` at `edge/crates/http-proxy/src/lib.rs:2212`.
  - It does not copy, sanitize, or strip configured headers from the forward-auth response into the upstream request.
- Exploit sketch:
  - Configure `forward_auth.response_headers = ["x-user-id"]`.
  - Have the auth service return `x-user-id`.
  - The upstream does not receive it; operators may incorrectly assume identity propagation is enforced.
- Impact:
  - Misconfiguration can create authorization gaps if upstreams expect identity headers from forward-auth.
- Recommended fix:
  - Either implement response header propagation with strict stripping of client-supplied identity headers, or reject non-empty `response_headers` until supported.
  - Document exact behavior.
- Tests to add:
  - Non-empty `forward_auth.response_headers` is rejected until implemented.
  - Once implemented, client-supplied identity headers are stripped before trusted auth response headers are added.
- Residual risk:
  - Forward-auth identity propagation is easy to get wrong; default deny and explicit allowlists are safer.

### PXSA-2026-109: Admin API Has No RBAC Or Tenant Ownership Model

- Severity: Medium for multi-tenant use; Low for single-operator local deployments.
- Confidence: High
- Status: Confirmed
- Category: auth, privacy
- Affected files:
  - `edge/crates/api/src/lib.rs:349`
  - `edge/crates/api/src/lib.rs:357`
  - `edge/crates/api/src/lib.rs:371`
  - `edge/crates/api/src/lib.rs:378`
  - `edge/crates/api/src/lib.rs:731`
- Public vulnerability references:
  - General authorization design class; no direct CVE claim.
- Evidence:
  - All authenticated admin tokens share the same authority to list routes, create domains, list analytics, list logs, and manage tokens.
  - Analytics/log endpoints expose recent visits and request IDs at `edge/crates/api/src/lib.rs:371` and `edge/crates/api/src/lib.rs:378`.
  - There is no owner/tenant field in routes or token scopes in the token view.
- Exploit sketch:
  - Give a token to a tenant to manage one domain.
  - That token can list/modify all routes and inspect all route analytics.
- Impact:
  - Full tenant isolation break if the admin API is used by more than one trusted operator.
- Recommended fix:
  - Add token scopes such as `routes:read`, `routes:write`, `tokens:write`, `analytics:read`.
  - Add route ownership/namespace fields and enforce them on every API endpoint.
  - Keep a distinct break-glass super-admin token.
- Tests to add:
  - Token scoped to one domain cannot list, modify, delete, or view analytics for another domain.
  - Token without `tokens:write` cannot create or revoke tokens.
- Residual risk:
  - RBAC must also apply to Docker/Podman label discovery if labels can be tenant controlled.

### PXSA-2026-110: ClickHouse Analytics Requests Have No Request Timeout Or Circuit Breaker

- Severity: Low
- Confidence: Medium
- Status: Likely
- Category: observability, DoS
- Affected files:
  - `edge/crates/storage/src/lib.rs:146`
  - `edge/crates/storage/src/lib.rs:155`
  - `edge/src/main.rs:86`
- Public vulnerability references:
  - Generic dependency hang/resource exhaustion class; no direct CVE claim.
- Evidence:
  - The analytics channel is bounded at startup with size 4096 at `edge/src/main.rs:86`.
  - `post_sql` sends the ClickHouse HTTP request at `edge/crates/storage/src/lib.rs:155` without an explicit timeout.
  - Error response bodies are capped, which is good, but a hanging TCP/HTTP request can stall the writer task.
- Exploit sketch:
  - Point `PXXL_CLICKHOUSE_URL` at a slow endpoint or let ClickHouse accept connections without responding.
  - Observe the analytics writer hanging and the bounded channel eventually dropping/withholding events.
- Impact:
  - Loss of access-log analytics and delayed observability during ClickHouse outages.
- Recommended fix:
  - Wrap ClickHouse requests in `tokio::time::timeout`.
  - Add circuit breaker/backoff and a dropped-event metric.
  - Prefer a configured HTTP client timeout if available.
- Tests to add:
  - ClickHouse request timeout increments a metric and the writer continues.
  - Large error body remains capped.
- Residual risk:
  - Analytics should remain best-effort and must not block the request hot path.

### PXSA-2026-111: Runtime Discovery Socket Mounts Remain A High-Trust Boundary

- Severity: Medium
- Confidence: High
- Status: Confirmed when discovery override/profile is enabled.
- Category: deployment, routing
- Affected files:
  - `docker-compose.discovery.yml:9`
  - `docker-compose.discovery.yml:10`
  - `docker-compose.yml:99`
  - `docker-compose.yml:106`
  - `docker-compose.yml:108`
- Public vulnerability references:
  - Docker official daemon socket hardening guidance, same class.
- Evidence:
  - Default Compose disables Docker/Podman discovery, but `docker-compose.discovery.yml` mounts `/var/run/docker.sock` and a Podman socket into the edge container.
  - Promtail also mounts `/var/run/docker.sock` when the `runtime-discovery` profile is enabled.
  - A socket mounted read-only at the filesystem level can still expose a powerful API surface depending on the daemon/API operations allowed.
- Exploit sketch:
  - Enable discovery in a multi-tenant container host.
  - Any user or compromised build process able to run containers with `pxxl.*` labels can influence proxy routes.
- Impact:
  - Route injection and runtime metadata exposure from the container runtime boundary.
- Recommended fix:
  - Prefer a narrow socket proxy that exposes only safe read endpoints required for discovery.
  - Add container allowlists by image, label owner, network, namespace, or Compose project.
  - Document discovery as high-trust and disabled by default.
- Tests to add:
  - Discovery ignores containers outside allowed networks/projects.
  - Malformed or hostile labels are rejected and logged.
- Residual risk:
  - Runtime-label discovery is inherently privileged; treat label writers as route administrators.

### PXSA-2026-112: Supply-Chain And Installer Hardening Gaps

- Severity: Low
- Confidence: High
- Status: Confirmed
- Category: supply-chain, deployment
- Affected files:
  - `edge/docker/Dockerfile:3`
  - `edge/docker/Dockerfile:13`
  - `docker-compose.yml:48`
  - `docker-compose.yml:67`
  - `docker-compose.yml:79`
  - `docker-compose.yml:91`
  - `docker-compose.yml:113`
  - `install.sh`
  - `update.sh`
- Public vulnerability references:
  - Generic supply-chain hardening class; no direct CVE claim.
- Evidence:
  - Dockerfile uses moving tags such as `rust:1-bookworm` and `debian:bookworm-slim`.
  - Compose images are version-tagged but not digest-pinned.
  - `install.sh` clones from a repo/branch and runs Compose, while `update.sh` pulls and rebuilds; neither verifies signed tags, commits, or image digests.
  - External scanner tools were unavailable locally, so image CVEs were not enumerated here.
- Exploit sketch:
  - A compromised registry tag or repo branch changes the installed artifact without digest/signature verification.
- Impact:
  - Operators cannot prove that the installed code/image matches a reviewed release.
- Recommended fix:
  - Pin production images by digest.
  - Publish signed release tags and have `install.sh`/`update.sh` verify them.
  - Generate SBOMs and run Trivy/Grype in CI.
  - Add `cargo audit`/`cargo deny` to CI.
- Tests to add:
  - Installer refuses unsigned or untrusted release refs in production mode.
  - CI fails on known-vulnerable dependency fixtures.
- Residual risk:
  - Dependency advisories change over time; this needs scheduled scanning.

## Positive Security Properties Verified

- Missing config fails closed unless `PXXL_ALLOW_DEFAULT_CONFIG=true` is set: `edge/src/main.rs:46`.
- Admin auth defaults to enabled in code and config: `edge/crates/config/src/lib.rs:195`, `config/pxxl.toml:31`.
- Compose host-publishes admin, metrics, Prometheus, and Grafana on loopback only: `docker-compose.yml:21`, `docker-compose.yml:22`, `docker-compose.yml:83`, `docker-compose.yml:120`.
- The runtime container drops Linux capabilities, runs read-only, uses a non-root user, and sets `no-new-privileges`: `docker-compose.yml:26`, `docker-compose.yml:29`, `docker-compose.yml:31`, `edge/docker/Dockerfile:24`.
- Path canonicalization decodes nested percent-encoding, rejects controls, normalizes backslashes and dot segments: `edge/crates/common/src/lib.rs:989`.
- Route matching uses canonical host/path and returns 404 for no route instead of 502: `edge/crates/http-proxy/src/lib.rs:1098`, `edge/crates/http-proxy/src/lib.rs:1209`.
- Hop-by-hop request and response headers are stripped: `edge/crates/http-proxy/src/lib.rs:2380`, `edge/crates/http-proxy/src/lib.rs:2418`.
- Dynamic Redis routes are revalidated on load and write: `edge/crates/redis-sync/src/lib.rs:67`, `edge/crates/redis-sync/src/lib.rs:95`.
- Local TLS private key permissions are restricted on Unix: `edge/crates/tls/src/lib.rs:109`.
- ClickHouse error body collection is capped: `edge/crates/storage/src/lib.rs:157`.

## Recommended Remediation Roadmap

Must fix before public or tenant-facing admin access:

1. Strip consumed Basic/Digest `Authorization` headers before forwarding.
2. Add DNS-resolution based upstream SSRF enforcement, including `host.docker.internal` and metadata/private/link-local ranges.
3. Redact route secrets and store Basic/Digest credentials as hashes.
4. Add token scopes/RBAC if anyone besides one trusted operator will use the admin API.

Should fix before beta:

1. Make body/response limit semantics explicit and add strict pre-forward buffering mode for routes with `max_body_bytes`.
2. Add HTTP/2 limits and a config switch to disable HTTP/2.
3. Add auth/mTLS option for metrics.
4. Make bootstrap tokens one-shot or expiring.
5. Reject unsupported `forward_auth.response_headers` or implement it safely.

Defense in depth:

1. Add ClickHouse request timeouts, backoff, and dropped-event metrics.
2. Replace raw Docker/Podman socket mounts with a narrow discovery proxy/allowlist.
3. Pin production images by digest, sign releases, add SBOMs.
4. Add `cargo audit`, `cargo deny`, Trivy/Grype, gitleaks, and Semgrep to CI.

## Test Plan

Unit/integration tests to add:

- Edge auth should not forward consumed `Authorization`.
- Optional app-auth pass-through should be explicit and tested.
- Dynamic route validation should reject `host.docker.internal`.
- Dynamic route validation should reject DNS names resolving to private/loopback/link-local/metadata addresses.
- ForwardAuth URLs should use the same dynamic SSRF validator.
- Chunked body over strict limit should return 413 before upstream receives data.
- Streaming response limit behavior should be explicit and covered.
- Metrics auth should reject missing/invalid token when enabled.
- Bootstrap token should expire or become invalid after first token creation if one-shot mode is enabled.
- Route list API should redact Basic/Digest/header secrets.
- Scoped token cannot read or mutate another domain.
- ClickHouse write timeout should not kill or stall the analytics worker.
- HTTP/2 rapid reset, continuation/header, many-stream, and slow-body tests.
- Discovery should ignore containers outside allowed project/network/label owner.

Fuzz targets:

- Host header parser and `host_without_port`.
- Path canonicalization including `%2f`, `%5c`, `%252e`, invalid UTF-8, dot segments, semicolons, query boundaries.
- Docker/Podman chunked API response parser and label parser.
- Digest authorization parser.

## Tool Output Appendix

- Rust formatting, clippy, tests, shell syntax checks, and Compose config rendering passed.
- Security scanners were unavailable in this environment, so no local dependency/image/secret scanner output is claimed.
- The tree was dirty before this scan due to prior security remediation work; this report does not revert or normalize those changes.

## Source Appendix

Retrieved 2026-05-15:

- RustSec RUSTSEC-2023-0034: https://rustsec.org/advisories/RUSTSEC-2023-0034.html
- RustSec advisory index for `h2`: https://rustsec.org/packages/h2.html
- CVE.org CVE-2023-44487: https://www.cve.org/CVERecord?id=CVE-2023-44487
- CISA HTTP/2 Rapid Reset alert: https://www.cisa.gov/news-events/alerts/2023/10/10/http2-rapid-reset-vulnerability-cve-2023-44487
- NGINX security advisories: https://nginx.org/en/security_advisories.html
- Traefik security advisories: https://github.com/traefik/traefik/security/advisories
- Traefik GHSA-vrch-868g-9jx5: https://github.com/traefik/traefik/security/advisories/GHSA-vrch-868g-9jx5
- Caddy security advisories: https://github.com/caddyserver/caddy/security/advisories
- Caddy GHSA-7r4p-vjf4-gxv4: https://github.com/caddyserver/caddy/security/advisories/GHSA-7r4p-vjf4-gxv4
- Envoy security advisories: https://github.com/envoyproxy/envoy/security/advisories
- HAProxy duplicate Content-Length advisory writeup: https://www.haproxy.com/blog/september-2021-duplicate-content-length-header-fixed
- Docker daemon socket hardening: https://docs.docker.com/engine/security/protect-access/
