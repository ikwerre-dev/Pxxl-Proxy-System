# Pxxl Proxy Security Audit Prompt

Copy/paste the prompt below into the model that should audit this repository.

```text
You are a senior application security engineer auditing a Rust edge reverse proxy called Pxxl Proxy.

Your job is to inspect the actual codebase, compare its behavior to known public vulnerability classes from reverse proxies and HTTP stacks, and produce a final Markdown audit file at:

docs/security-audit.md

Do not hallucinate. Do not claim the project is affected by an NGINX, Traefik, Caddy, Envoy, HAProxy, Hyper, h2, RustSec, GHSA, or CVE issue unless you can prove the same vulnerable implementation or dependency/version is present. When a public CVE only inspires a similar class of checks, label it as "analogous risk" or "CVE-inspired test", not "affected".

Repository root:

/Users/robin/Documents/js_websites/pxxl/Pxxl-Proxy-System

Current project facts to verify from the code, not from this prompt alone:

- Pxxl is a Rust reverse proxy/edge system built with Hyper, Tokio, rustls, Redis, Docker/Podman discovery, offline GeoIP, Prometheus metrics, ClickHouse analytics, and a custom admin API.
- Main entrypoint: edge/src/main.rs
- HTTP/HTTPS proxy path: edge/crates/http-proxy/src/lib.rs
- Route model and security rules: edge/crates/common/src/lib.rs
- Route registry, stats, and health state: edge/crates/core/src/lib.rs
- Admin API and admin auth: edge/crates/api/src/lib.rs
- Docker/Podman label discovery: edge/crates/docker-discovery/src/lib.rs
- Load balancing: edge/crates/load-balancer/src/lib.rs
- TLS certificate generation/reload: edge/crates/tls/src/lib.rs
- Redis persistence/token store: edge/crates/redis-sync/src/lib.rs
- DDoS/rate-limit/blacklist engine: edge/crates/ddos/src/lib.rs
- ClickHouse analytics writer: edge/crates/storage/src/lib.rs
- Config defaults: config/pxxl.toml and edge/crates/config/src/lib.rs
- Container/runtime exposure: docker-compose.yml and edge/docker/Dockerfile

Required methodology:

1. Start by recording exact repo state:
   - `pwd`
   - `git rev-parse --show-toplevel || true`
   - `git rev-parse HEAD || true`
   - `git status --short || true`
   - `rg --files`
   - `cargo metadata --format-version 1`

2. Read the code before making claims. At minimum inspect:
   - README.md
   - SECURITY.md
   - config/pxxl.toml
   - docker-compose.yml
   - edge/docker/Dockerfile
   - edge/src/main.rs
   - edge/crates/common/src/lib.rs
   - edge/crates/config/src/lib.rs
   - edge/crates/http-proxy/src/lib.rs
   - edge/crates/api/src/lib.rs
   - edge/crates/core/src/lib.rs
   - edge/crates/docker-discovery/src/lib.rs
   - edge/crates/ddos/src/lib.rs
   - edge/crates/load-balancer/src/lib.rs
   - edge/crates/redis-sync/src/lib.rs
   - edge/crates/storage/src/lib.rs
   - edge/crates/tls/src/lib.rs
   - edge/crates/geo/src/lib.rs
   - edge/tests/http_proxy.rs
   - docs/api.md
   - docs/architecture.md
   - docs/dynamic-routing.md

3. Run available automated checks and record whether each passed, failed, or was unavailable:
   - `cargo fmt --check --all`
   - `cargo clippy --workspace --all-targets --all-features -- -D warnings`
   - `cargo test --workspace --all-features`
   - `cargo audit` if installed
   - `cargo deny check` if installed
   - `cargo outdated` if installed
   - `trivy fs --scanners vuln,secret,config .` if installed
   - `gitleaks detect --source . --no-git` if installed
   - `semgrep --config p/rust --config p/secrets --config p/owasp-top-ten .` if installed

4. If a tool is unavailable, do not fail the audit. Write "not run: tool unavailable" in the final report.

5. Use current public vulnerability sources. Prefer primary sources:
   - NGINX official advisories: https://nginx.org/en/security_advisories.html
   - Traefik GitHub advisories: https://github.com/traefik/traefik/security/advisories
   - Caddy GitHub advisories: https://github.com/caddyserver/caddy/security/advisories
   - Envoy GitHub advisories: https://github.com/envoyproxy/envoy/security/advisories
   - HAProxy official/vendor advisories, for example CVE-2021-40346 request smuggling references
   - RustSec advisories: https://rustsec.org/advisories/
   - GitHub Advisory Database: https://github.com/advisories
   - NVD: https://nvd.nist.gov/
   - CVE.org records: https://www.cve.org/
   - CISA known exploited and HTTP/2 Rapid Reset alert: https://www.cisa.gov/news-events/alerts/2023/10/10/http2-rapid-reset-vulnerability-cve-2023-44487

6. For every public CVE/GHSA/RustSec item you mention, include:
   - ID
   - Source URL
   - Why it is relevant to Pxxl
   - Whether Pxxl is directly affected, indirectly affected through a dependency, not affected, or only has an analogous risk
   - Evidence from local files and line numbers

7. Do not overfit to known CVEs. Also audit ordinary design mistakes, unsafe defaults, abuse cases, and missing controls.

8. The final file must be self-contained. A reader should understand the attack surface, findings, proof/evidence, remediation, and residual risk without reading this prompt.

Threat model:

- Public internet clients can hit HTTP and HTTPS listeners.
- A malicious client can send malformed HTTP/1.1 and HTTP/2 requests, huge headers, duplicate headers, strange Host values, encoded paths, chunked bodies, slow bodies, upgrade requests, CORS preflights, and request floods.
- A tenant/admin user may be allowed to create dynamic routes through the admin API.
- A compromised Redis instance may inject persisted API routes or token records.
- A compromised Docker/Podman container, or any user able to set labels, may attempt to create proxy routes via `pxxl.*` labels.
- A malicious upstream may send huge responses, odd headers, partial responses, slow responses, or redirects.
- A compromised ClickHouse endpoint may return large error bodies.
- The proxy may run in Docker with mounted Docker/Podman sockets and public ports.
- Metrics, admin API, Redis, Postgres, ClickHouse, Grafana, Loki, and Prometheus may be exposed by docker-compose defaults.
- Operators may accidentally run local/dev defaults in public environments.
- Future features include ACME, TCP/UDP, dashboard UI, circuit breakers, cluster sync, and deeper DDoS controls; identify security design requirements for those too.

Core code paths to trace:

1. Startup/config:
   - edge/src/main.rs
   - edge/crates/config/src/lib.rs
   - config/pxxl.toml
   - env overrides such as PXXL_ADMIN_AUTH_ENABLED, PXXL_ADMIN_BOOTSTRAP_TOKEN, PXXL_ADMIN_IP_ALLOWLIST, PXXL_CLICKHOUSE_URL

2. HTTP request lifecycle:
   - accept connection
   - Hyper parses request
   - Host and path extracted
   - remote peer IP captured
   - global blacklist/rate limiter runs
   - offline GeoIP lookup runs
   - route registry host/path match runs
   - domain rules/WAF/CORS/body/header/method checks run
   - traffic split/location route selected
   - load balancer picks upstream
   - upstream URI built
   - forwarding headers set
   - upstream response returned
   - metrics/stats/ClickHouse queue updated

3. Control plane:
   - Admin API route create/delete/list
   - Admin auth and token creation/revocation
   - Redis route store and token store
   - Docker/Podman polling
   - health checks
   - TLS certificate regeneration/reload

Mandatory audit areas and specific checks:

### A. HTTP parser, request smuggling, and protocol confusion

Check for:

- Duplicate `Content-Length` handling.
- Conflicting `Content-Length` and `Transfer-Encoding`.
- Chunked transfer handling, especially body-size limits when no `Content-Length` exists.
- CRLF injection in request headers, generated headers, upstream URLs, route domains, error pages, and redirects.
- HTTP/2 to HTTP/1.1 downgrades or upstream translation risks.
- Absolute-form request URI handling.
- CONNECT, TRACE, OPTIONS, PRI, and unusual methods.
- Header casing and duplicate header behavior.
- Hop-by-hop headers: `Connection`, `Upgrade`, `TE`, `Trailer`, `Proxy-Authorization`, `Proxy-Connection`, `Keep-Alive`, `Transfer-Encoding`.
- Whether the proxy forwards hop-by-hop headers incorrectly.
- Whether `serve_connection_with_upgrades` plus WebSocket handling safely proxies upgrades.
- Whether upgrade handling can bypass `allow_websocket = false`.
- Whether Hyper/h2 versions in Cargo.lock are patched for known h2 issues.

Use these public vulnerability classes as inspiration:

- CVE-2023-44487 HTTP/2 Rapid Reset DoS.
- RUSTSEC-2023-0034 / CVE-2023-26964: h2 reset stream memory/resource exhaustion.
- RUSTSEC-2024-0332: h2 CONTINUATION flood.
- NGINX HTTP/2 CPU/memory exhaustion advisories such as CVE-2019-9511, CVE-2019-9513, CVE-2019-9516, CVE-2018-16843, CVE-2018-16844.
- NGINX CVE-2026-42926: HTTP/2 request injection in ngx_http_proxy_module, as an analogous class for proxy request injection.
- HAProxy CVE-2021-40346: duplicate Content-Length / request smuggling / ACL bypass.
- Envoy GHSA-w5w5-487h-qv8q: unsafe header value generation causing request smuggling/security policy bypass.
- Envoy CVE-2023-35944: scheme normalization / mixed-case scheme checks.
- Apache/Traffic Server request smuggling CVEs as analogous checks only.

Required test ideas:

- Send duplicate `Content-Length` headers.
- Send `Content-Length` plus `Transfer-Encoding: chunked`.
- Send chunked body exceeding `max_body_bytes` without `Content-Length`.
- Send many HTTP/2 streams and resets if a local test client supports it.
- Send huge headers and huge header count.
- Send slowloris-style partial headers/body.
- Send absolute URI requests: `GET http://victim/path HTTP/1.1`.
- Send `Connection: keep-alive, upgrade` and odd `Upgrade` values.

### B. Path normalization, route matching, and middleware/rule bypass

Pxxl route matching currently appears to use host + longest prefix path matching. Verify exact behavior in:

- edge/crates/common/src/lib.rs
- edge/crates/core/src/lib.rs
- edge/crates/http-proxy/src/lib.rs

Check for:

- Raw path versus decoded path mismatch.
- `%2e%2e`, `%252e%252e`, `%2f`, `%5c`, backslash, semicolon, double slash, dot-segments, mixed encoding, UTF-8 normalization.
- Prefix bypass: `/api%2f..%2fadmin`, `/api/../admin`, `/api/%2e%2e/admin`, `/api//../admin`.
- Path and query confusion: `?`, encoded `?`, encoded `#`.
- Whether `max_uri_length` checks the full path/query but route matching uses a different representation.
- Whether WAF checks the same normalized representation used for route matching and upstream forwarding.
- Whether upstream receives a path that bypassed policy intended for a different Pxxl route.
- Whether `www_alias` can create unintended host matches.
- Whether trailing dots, ports, IPv6 literals, punycode, uppercase, and IDNA hostnames are handled safely.

Use these public vulnerability classes as inspiration:

- Traefik GHSA-vrch-868g-9jx5 / CVE-2025-47952: URL-encoded path traversal bypassing path routing/middleware.
- Traefik GHSA-6p68-w45g-48j7 / CVE-2025-32431: path matcher vulnerability.
- Envoy GHSA-xcx5-93pw-jw2w: missing HTTP URL path normalization allowing routing/access-control bypass.
- Caddy GHSA-g7pc-pc7g-h8jh: escaped-path branch skips case normalization, enabling path-based route/auth bypass.
- NGINX CVE-2013-4547: request line parsing vulnerability, as an analogous parser/routing check.
- NGINX CVE-2009-3898 and Windows path advisories as analogous path traversal checks if file serving is ever added.

Required test ideas:

- Create two routes, one protected `/private` and one public `/public`, pointing to different echo upstreams.
- Try all encoded traversal variants to see whether a request reaches the private upstream or bypasses route rules.
- Confirm that WAF checks cannot be bypassed by double encoding.
- Confirm route selection and upstream URI construction use one consistent canonical path.

### C. Host, forwarded headers, and identity/header spoofing

Check:

- `normalize_domain`, `host_without_port`, and IPv6 handling.
- Host header with spaces, trailing dots, multiple ports, userinfo-like values, CRLF attempts, mixed case, IDNA/punycode.
- Whether client-supplied `X-Forwarded-For`, `X-Forwarded-Host`, `X-Forwarded-Proto`, `Forwarded`, `X-Real-IP`, `X-Original-URL`, `X-Rewrite-URL`, or identity headers can spoof upstream trust.
- Whether Pxxl overwrites or appends to `X-Forwarded-For`.
- Whether `preserve_host_header = true` can confuse upstream virtual hosts.
- Whether `add_request_headers` can be used by an admin/tenant to forge identity or internal headers.
- Whether `strip_request_headers` should default-strip sensitive headers before adding trusted values.

Use these public vulnerability classes as inspiration:

- Caddy GHSA-7r4p-vjf4-gxv4 / CVE-2026-30851: forward_auth copy_headers did not strip client-supplied identity headers.
- Traefik GHSA-62c8-mh53-4cqv: HTTP client can remove/affect X-Forwarded headers.
- Traefik CVE-2020-15129 and GHSA-h924-8g65-j9wg: X-Forwarded-Prefix open redirect.
- Envoy GHSA-ffhv-fvxq-r6mf: external clients manipulating `x-envoy` headers.
- Envoy GHSA-w5w5-487h-qv8q: generated header values not escaped.

Required test ideas:

- Send forged `X-Forwarded-For`, `X-Forwarded-Host`, `X-Forwarded-Proto` and inspect upstream.
- Send forged identity headers while using `add_request_headers` and `strip_request_headers`.
- Send Host headers with uppercase, trailing dot, port, IPv6, and weird delimiters.
- Attempt redirect injection through Host/path when `redirect_http_to_https` is enabled.

### D. Admin API authentication and authorization

Inspect:

- edge/crates/api/src/lib.rs
- edge/crates/redis-sync/src/lib.rs
- edge/src/main.rs
- config/pxxl.toml
- docker-compose.yml
- docs/api.md

Check:

- Default admin bind address and compose port exposure.
- Default bootstrap token `pxxl-dev-token` in config/docs/Postman environment.
- Whether `AdminConfig::default()` has auth disabled and when that default is used.
- Whether `/healthz` and `/readyz` intentionally expose route counts.
- Whether the metrics endpoint is unauthenticated.
- Whether admin API should require HTTPS/mTLS or be bound to localhost/private network.
- Whether bearer token parsing accepts unsafe forms or rejects valid expected forms.
- Whether bootstrap token is permanent and cannot be revoked.
- Whether token hashes use plain SHA-256 without salt/pepper/KDF.
- Whether token verification scans all tokens and writes last-used on every authenticated request, creating latency/DoS opportunities.
- Whether Redis outage locks admin users out.
- Whether token names/IDs are length-limited.
- Whether admin IP allowlist uses direct peer IP only and fails behind a trusted proxy.
- Whether all `/v1/*` endpoints are protected.
- Whether route creation has tenant/ownership authorization or any authenticated admin can modify all domains.
- Whether error responses leak internals such as Redis errors.

Use these public vulnerability classes as inspiration:

- Caddy remote admin authorization bypass advisories such as GHSA-x5w9-xh9r-mvfc and GHSA-gx7w-56w6-g48x.
- Caddy admin/path matcher normalization advisories.
- General API auth bypass, bearer token leakage, default credential exposure, and weak token storage.

Required test ideas:

- Access all admin endpoints without a token.
- Access with malformed Authorization headers.
- Access with lowercase `bearer`.
- Access with extra spaces.
- Access from disallowed IP if possible.
- Create route with default token from public compose setup.
- Confirm token hashes are not returned by list endpoint.
- Confirm raw token is returned once only.

### E. Dynamic route creation, SSRF, and upstream safety

Inspect:

- `DomainRouteBody::into_route`
- `Upstream::authority`
- `build_upstream_uri`
- Docker label parser
- health check URI builder
- ClickHouse endpoint parsing

Check:

- Whether admin-created upstream URLs can target internal services: `127.0.0.1`, `localhost`, Docker network services, Redis, ClickHouse, cloud metadata `169.254.169.254`, link-local, RFC1918, Unix sockets, file URLs.
- Whether upstream scheme is validated to `http`/`https`.
- Whether `https://` upstreams actually work with `HttpConnector` or fail open/closed.
- Whether unsupported schemes can crash, hang, or be interpreted unexpectedly.
- Whether upstream path embedded in upstream URL interacts with original path.
- Whether route domains and upstream URLs are length-limited.
- Whether health checks amplify SSRF by probing attacker-supplied upstreams every interval.
- Whether health checks use GET and could trigger side effects.
- Whether health checks should restrict status codes, host headers, redirects, TLS validation, and timeouts.
- Whether route creation should support allowlists/denylists for private networks.
- Whether Docker labels from untrusted containers can route arbitrary domains to arbitrary hosts.

Required test ideas:

- Try upstreams: `http://169.254.169.254`, `http://127.0.0.1:8081`, `http://redis:6379`, `file:///etc/passwd`, `gopher://`, `https://example.com`, `http://host:port/base`.
- Observe route create result, health check behavior, and request behavior.
- Try very long domain/path/upstream values.
- Try route domain containing control characters, spaces, wildcard, leading/trailing dots, IDNA.

### F. Rate limiting, DDoS, resource exhaustion, and slow clients

Inspect:

- edge/crates/ddos/src/lib.rs
- PolicyRateLimiter in edge/crates/http-proxy/src/lib.rs
- Hyper server configuration in edge/crates/http-proxy/src/lib.rs
- `max_body_bytes` implementation
- `max_uri_length` implementation

Check:

- Global buckets keyed by IP are never evicted.
- Domain policy buckets keyed by domain/path/IP are never evicted.
- `per_ip_path` can be forced to allocate unbounded keys with random paths.
- Global rate limit applies before route matching and uses peer IP only.
- No connection limit, per-IP concurrent connection limit, read timeout, header timeout, body timeout, idle timeout, or max header size is configured in Pxxl code.
- `max_body_bytes` only checks `Content-Length`, not actual streamed body.
- Huge responses are streamed without response size limit.
- Error page templates and analytics path storage can amplify memory usage with long paths.
- ClickHouse channel is bounded but dropped events are silently ignored; check whether this is acceptable.
- HTTP/2 Rapid Reset, CONTINUATION flood, and reset stream resource exhaustion are addressed by dependency versions and server config.

Use these public vulnerability classes as inspiration:

- CVE-2023-44487 HTTP/2 Rapid Reset.
- RUSTSEC-2023-0034 / CVE-2023-26964 h2 reset stream memory exhaustion.
- RUSTSEC-2024-0332 h2 CONTINUATION flood.
- NGINX HTTP/2 CPU/memory advisories.
- Pingora MadeYouReset CVE-2025-8671 as an analogous HTTP/2 reset DoS class.

Required test ideas:

- Flood unique source paths under `per_ip_path`.
- Use chunked body with no `Content-Length`.
- Hold connections open slowly.
- Open many idle connections.
- Send huge response from upstream.
- Send many requests to admin token verification endpoint with many Redis tokens.

### G. TLS, certificates, ACME readiness, and future HTTP/3

Inspect:

- edge/crates/tls/src/lib.rs
- TLS reloader in edge/src/main.rs
- rustls config and ALPN protocols
- config/pxxl.toml

Check:

- Self-signed local certificate use in production.
- TLS mode field is present but may not support production ACME.
- Certificate files permissions after write.
- Private key storage path and Docker volume permissions.
- Certificate regeneration every time domain set changes; route-creation DoS by adding many domains.
- SAN length/domain validation.
- No SNI-based certificate selection; single certificate for all route domains.
- No client certificate auth.
- No explicit TLS min version/cipher policy, if rustls defaults are relied upon.
- No OCSP/stapling.
- No ACME account/key lifecycle.
- HTTP/3/QUIC not currently implemented; if added, design must address early data, client IP spoofing, and HTTP/3 memory corruption classes.

Use these public vulnerability classes as inspiration:

- NGINX HTTP/3 advisories: CVE-2024-24989, CVE-2024-24990, CVE-2024-32760, CVE-2024-31079, CVE-2024-35200, CVE-2024-34161, CVE-2026-40460.
- Traefik GHSA-gxrv-wf35-62w9: bypassing IP allowlists via HTTP/3 early data in QUIC 0-RTT.
- Caddy GHSA-hffm-g8v7-wrv7: mTLS fail-open when CA file missing/malformed, as a future mTLS design check.
- NGINX CVE-2025-23419 SSL session reuse and CVE-2026-1642 SSL upstream injection as TLS/upstream classes.

### H. WAF and policy enforcement correctness

Inspect WAF/policy code in edge/crates/http-proxy/src/lib.rs and rule model in edge/crates/common/src/lib.rs.

Check:

- WAF is substring-based and not a full parser.
- No body inspection.
- No percent-decoding normalization before WAF checks.
- SQLi/XSS checks only cover a few markers.
- Path traversal checks are not comprehensive.
- Custom patterns are substring-based and may produce false positives/false negatives.
- WAF runs before route forwarding but after route matching; assess whether this matters.
- Policy checks are domain-level, not path-level, despite path-level `middlewares` field existing.
- `middlewares` are stored but not executed; verify if dead config creates false sense of security.
- `allowed_headers` can break normal clients and may miss pseudo/hop-by-hop behavior.
- `cors_allowed_origins = ["*"]` with credentials should be reviewed.

### I. CORS, security headers, redirects, and generated responses

Check:

- CORS preflight response behavior.
- Whether CORS preflight bypasses auth-like policy that should still apply.
- Whether wildcard origins are echoed.
- Whether credentials can combine with wildcard behavior.
- Whether security headers are sufficient: HSTS, CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy.
- Generated error pages escape placeholders.
- Custom template loading cannot include scripts from untrusted data.
- Redirect `Location` header cannot be poisoned through Host/path.

### J. Docker/Podman discovery and container runtime risk

Inspect:

- edge/crates/docker-discovery/src/lib.rs
- docker-compose.yml
- monitoring/promtail/promtail-config.yml

Check:

- Docker socket mounted read-only is still highly sensitive.
- Promtail also mounts Docker socket.
- Any compromised container with label control can create routes.
- `pxxl.scheme`, `pxxl.host`, `pxxl.domain`, `pxxl.path`, `pxxl.port` are not strongly validated.
- Docker socket HTTP response parser reads entire response into memory.
- Chunked response decoder should reject malformed chunk extensions and oversized bodies safely.
- Polling replaces all Docker-sourced routes atomically; check race/route-flap abuse.
- Podman published-host behavior can route to host.docker.internal.
- No network-scoping or container allowlist.

### K. Persistence, Redis, ClickHouse, and analytics

Inspect:

- edge/crates/redis-sync/src/lib.rs
- edge/crates/storage/src/lib.rs
- edge/crates/core/src/lib.rs
- config/pxxl.toml
- docker-compose.yml

Check:

- Redis URL has no TLS/auth by default.
- Redis compromise can inject routes or token records.
- Route JSON loaded from Redis should be validated the same as API routes.
- Token hashes are SHA-256, not Argon2/HMAC/pepper.
- Token records can be created without TTL/expiry/scope.
- ClickHouse credentials appear in config and compose defaults.
- ClickHouse endpoint URL credentials are stripped from URI before request; verify they do not leak in logs.
- ClickHouse error response body may be logged and could be large/sensitive.
- Analytics record remote IP and location; assess privacy.
- Recent visit history is capped per domain but domains can be unbounded.
- In-memory per-domain stats can grow with unbounded route/domain creation.

### L. Config, secrets, and deployment hardening

Inspect:

- config/pxxl.toml
- docker-compose.yml
- edge/docker/Dockerfile
- examples/kubernetes-deployment.yaml
- docs

Check:

- Default credentials: admin bootstrap token, Postgres password, ClickHouse password, Grafana password.
- Admin, metrics, Redis, Postgres, ClickHouse, Grafana, Loki, Prometheus ports exposed on host.
- Runtime container runs as root unless Dockerfile sets USER.
- Filesystem not read-only.
- No cap_drop/security_opt/no-new-privileges.
- Docker images use floating tags.
- No SBOM generation.
- No image signing.
- No container healthcheck.
- No resource limits.
- No network segmentation.
- Config docs warn about dev-only defaults.
- Secrets are in tracked config/docs/Postman environment.

### M. Supply chain and dependency audit

Check:

- Cargo.lock dependency versions.
- Direct dependencies: hyper, hyper-util, h2, tokio, rustls, rcgen, redis, url, serde_json, jsonwebtoken, argon2, sha2, uuid, prometheus, dashmap.
- Run cargo audit or manually compare important dependencies to RustSec/GHSA.
- Review base images and service images in docker-compose with Trivy or vendor advisories.
- Check for unused security-sensitive dependencies such as jsonwebtoken/argon2 if not used.
- Check license/compliance if relevant.

Current dependency versions observed previously, but verify locally:

- hyper around 1.9.x
- h2 around 0.4.x
- rustls around 0.23.x
- redis around 0.27.x
- tokio around 1.52.x

Do not assume these are safe. Verify with cargo audit/RustSec/GHSA.

### N. Future feature security requirements

For features listed as future or partially implemented, include a security checklist:

- ACME/Let's Encrypt: account key storage, challenge isolation, rate limits, wildcard DNS challenge, DNS provider secrets, domain ownership validation, renewal failure behavior.
- TCP/UDP proxying: protocol confusion, SNI routing, TLS passthrough, proxy protocol, connection limits.
- Dashboard UI: CSRF, XSS, session storage, RBAC, password hashing, MFA, audit logs.
- Cluster sync: auth, mTLS, replay protection, signed route updates, eventual consistency risks.
- Circuit breakers: failure amplification and tenant isolation.
- Plugin/middleware system: sandboxing, path traversal, supply chain, signed plugins.

Finding format:

Every finding must use this structure:

### PXSA-YYYY-NNN: Short Title

- Severity: Critical | High | Medium | Low | Informational
- Confidence: High | Medium | Low
- Status: Confirmed | Likely | Hypothesis | Not affected
- Category: auth | routing | path-normalization | request-smuggling | DoS | SSRF | deployment | supply-chain | privacy | TLS | observability | config
- Affected files:
  - path:line
  - path:line
- Public vulnerability references:
  - CVE/GHSA/RUSTSEC ID, URL, and "direct dependency", "same class", or "not affected but relevant"
- Evidence:
  - Explain the exact code behavior with file/line references.
- Exploit sketch:
  - Safe, minimal reproduction steps or pseudocode.
  - Do not provide destructive exploit tooling.
- Impact:
  - Who can exploit it and what they gain.
- Recommended fix:
  - Concrete code/config change.
- Tests to add:
  - Unit/integration/fuzz tests.
- Residual risk:
  - What remains even after the fix.

Severity rubric:

- Critical: unauthenticated remote code execution, full admin bypass, full tenant isolation bypass, arbitrary internal SSRF from unauthenticated user, private key/token disclosure, or reliable request smuggling that bypasses admin/security policy.
- High: authenticated admin/token abuse with broad impact, route/path policy bypass, serious DoS with low effort, SSRF by authenticated tenant, weak default public exposure, token forgery/reuse, trusted-header identity injection.
- Medium: hardening gaps that matter in production, partial bypasses, missing limits requiring higher effort, sensitive metadata exposure, weak token storage, insecure defaults limited to dev.
- Low: defense-in-depth, docs mismatch, limited information disclosure, non-exploitable robustness issues.
- Informational: future design requirements, missing tests, tool unavailable.

Required final file structure:

# Pxxl Proxy Security Audit

Date:
Auditor/model:
Commit:
Scope:
Out of scope:

## Executive Summary

Short summary of the most important confirmed risks. Do not exaggerate.

## Methodology

Commands run, tools used, sources consulted, and limitations.

## Attack Surface

Describe public listeners, admin API, metrics, route API, Docker/Podman socket, Redis, ClickHouse, TLS, health checks, analytics, and deployment.

## CVE/GHSA/RustSec Mapping

A table with:

ID | Product/source | Class | Relevance to Pxxl | Direct/Analogous/Not affected | Local evidence

Include at least these classes if relevant:

- CVE-2023-44487 HTTP/2 Rapid Reset.
- RUSTSEC-2023-0034 / CVE-2023-26964 h2 reset stream DoS.
- RUSTSEC-2024-0332 h2 CONTINUATION flood.
- NGINX CVE-2026-42926 HTTP/2 request injection.
- NGINX CVE-2026-40460 HTTP/3 address spoofing.
- NGINX CVE-2026-1642 SSL upstream injection.
- NGINX CVE-2021-23017 resolver memory bug.
- NGINX CVE-2017-7529 range filter integer overflow.
- NGINX CVE-2013-2028 chunked parser stack overflow.
- HAProxy CVE-2021-40346 HTTP request smuggling.
- Traefik CVE-2025-47952 / GHSA-vrch-868g-9jx5 path traversal via URL encoding.
- Traefik CVE-2025-32431 / GHSA-6p68-w45g-48j7 path matcher vulnerability.
- Traefik GHSA-h924-8g65-j9wg / CVE-2020-15129 X-Forwarded-Prefix open redirect class.
- Traefik GHSA-gxrv-wf35-62w9 HTTP/3 early-data IP allowlist bypass.
- Caddy CVE-2026-30851 / GHSA-7r4p-vjf4-gxv4 forward_auth header injection.
- Caddy GHSA-g7pc-pc7g-h8jh escaped path route bypass.
- Caddy GHSA-x76f-jf84-rqj8 host matching case issue.
- Caddy GHSA-hffm-g8v7-wrv7 mTLS fail-open.
- Envoy GHSA-xcx5-93pw-jw2w path normalization.
- Envoy GHSA-w5w5-487h-qv8q header escaping/request smuggling.
- Envoy GHSA-ffhv-fvxq-r6mf trusted header manipulation.
- Envoy CVE-2023-35944 scheme normalization.

Add or remove items based on current verified sources, but explain omissions.

## Findings

List findings sorted by severity, then confidence.

## Positive Security Properties

Document things the code already does well, such as in-memory hot path, escaping generated error pages, HeaderValue validation, no Redis lookup on request forwarding, bounded recent visits per domain, etc. Only list what you verified.

## Test Plan

Concrete tests to add:

- Unit tests.
- Integration tests.
- Fuzz targets.
- Docker-compose hardening tests.
- Negative admin-auth tests.
- Path normalization matrix.
- Header/request smuggling matrix.
- SSRF route creation tests.
- Rate-limit bucket eviction/resource tests.

## Recommended Remediation Roadmap

Order fixes:

1. Must fix before public exposure.
2. Should fix before beta.
3. Defense-in-depth.
4. Future feature requirements.

## Tool Output Appendix

Summarize command outputs. Do not paste massive logs.

## Source Appendix

List all public sources with URLs and retrieval date.

Non-hallucination rules:

- If you did not inspect a file, say so.
- If a command failed, include the failure.
- If a CVE belongs to NGINX/Traefik/Caddy/Envoy/HAProxy but Pxxl does not use that code, say "not directly affected".
- If Pxxl uses a Rust dependency with a known RustSec/GHSA advisory, verify the version in Cargo.lock before claiming affected.
- If exploitability depends on configuration, state the required configuration.
- If the code has a protective behavior, mention it even if there is still residual risk.
- Avoid generic statements such as "may be vulnerable" without evidence. Use "hypothesis" and explain exactly what must be tested.
- Prefer exact file links and line numbers in the report.

Suggested high-priority hypotheses to verify first:

1. Admin and metrics exposure: config and docker-compose bind admin/metrics to 0.0.0.0 and publish host ports; default admin token is documented and configured. Determine whether this is dev-only or a production footgun.
2. Route-created SSRF: authenticated admin/API-created routes and Docker labels can point upstreams at internal services. Determine whether this is intended trusted-admin behavior or tenant-exposed risk.
3. Path normalization bypass: route matching appears prefix-based on the raw path. Test encoded traversal and double-encoding against route rules and WAF.
4. Body limit bypass: `max_body_bytes` appears to rely on `Content-Length`; test chunked bodies and streaming bodies.
5. Unbounded rate-limit buckets: per-IP and per-IP-path buckets may grow indefinitely. Test high-cardinality paths/IPs.
6. Docker socket trust boundary: docker-compose mounts Docker and Podman sockets; labels can create routes. Evaluate container-to-route trust.
7. Weak token storage/defaults: Redis token hashes use SHA-256, bootstrap token is static, and default config contains dev secrets. Evaluate production impact.
8. HTTP/2 DoS: Hyper/h2 versions need verification against RustSec and config hardening.
9. Health-check SSRF/amplification: health checks probe every upstream periodically.
10. TLS local cert regeneration DoS: dynamic route domains trigger SAN changes and cert regeneration.

When done, write docs/security-audit.md and include a short "Audit completed" summary with the top 5 confirmed risks and the path to the file.
```

## Advisory Sources Used While Building This Prompt

- NGINX official security advisories: https://nginx.org/en/security_advisories.html
- Traefik security advisories: https://github.com/traefik/traefik/security/advisories
- Caddy security advisories: https://github.com/caddyserver/caddy/security/advisories
- CISA HTTP/2 Rapid Reset alert: https://www.cisa.gov/news-events/alerts/2023/10/10/http2-rapid-reset-vulnerability-cve-2023-44487
- RustSec h2 reset stream advisory: https://rustsec.org/advisories/RUSTSEC-2023-0034.html
- RustSec h2 CONTINUATION flood advisory: https://rustsec.org/advisories/RUSTSEC-2024-0332.html
- HAProxy CVE-2021-40346 vendor write-up: https://www.haproxy.com/blog/september-2021-duplicate-content-length-header-fixed
- Envoy security advisories: https://github.com/envoyproxy/envoy/security/advisories
