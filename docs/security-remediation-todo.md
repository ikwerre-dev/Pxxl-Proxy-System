# Pxxl Security Remediation TODO

Date: 2026-05-15
Source audit: `docs/security-audit.md`
Latest CVE pass: `docs/cve-findings.md`
Latest Codex security pass: `docs/codex-security-findings.md`

This tracks the remediation pass against each PXSA finding. "Fixed" means code/config/docs were changed in this pass. "Mitigated" means the dangerous default or active exploit path is closed, while larger product work remains tracked.

## Completed

| Finding | Status | What changed |
| --- | --- | --- |
| PXSA-2026-001: Compose and Config Expose Control-Plane and Data Services with Dev Credentials | Fixed | Removed the checked-in bootstrap token, loopback-bound admin/metrics/Prometheus/Grafana host ports, stopped publishing Redis/Postgres/ClickHouse/Loki, required `GRAFANA_ADMIN_PASSWORD`, added production startup guards for weak bootstrap tokens and wildcard admin/metrics listeners, and updated README/API/Postman docs. |
| PXSA-2026-002: Dynamic Routes, Labels, and Health Checks Permit Internal SSRF by Trusted Control-Plane Inputs | Fixed | Added route/upstream/domain/path validation in `pxxl-common`, applied it to API routes, Redis-loaded routes, and Docker/Podman discovery, rejected unsupported schemes, URL credentials/fragments, unsafe IP literals, localhost names, and common internal service names before routes or health checks can use them. |
| PXSA-2026-003: Raw Path Prefix Matching Can Bypass Path-Scoped Rules and Upstreams | Fixed | Added percent-decoding and dot-segment canonicalization, route matching on canonical paths, upstream forwarding of the same canonical path, and WAF checks against both raw and canonical forms. |
| PXSA-2026-004: Client-Supplied Trust and Hop-by-Hop Headers Reach Upstreams by Default | Fixed | Default-stripped hop-by-hop headers, `Connection` nominated headers, forwarded/trust headers, `X-Original-URL`, `X-Rewrite-URL`, and related spoofable identity headers before adding Pxxl-owned forwarding headers. |
| PXSA-2026-005: Listeners Lack Timeouts and Connection Concurrency Controls | Mitigated | Added global semaphore limits for edge, admin, and metrics listeners plus connection-level timeouts. Per-IP connection accounting and dedicated slow-header/body deadlines remain future hardening. |
| PXSA-2026-006: Rate-Limit, Stats, and Load-Balancer Maps Grow Without Eviction | Fixed | Added stale bucket eviction to global and policy rate limiters, capped stats counter cardinality with an overflow bucket, and bounded load-balancer state maps. |
| PXSA-2026-007: Redis Is a High-Trust Persistence Plane with Weak Defaults and Costly Token Verification | Fixed | Redis-loaded routes now pass dynamic route validation, token verification uses a Redis hash index instead of scanning every token, token names are length-limited, auth backend errors are generic to clients, and Compose no longer publishes Redis. |
| PXSA-2026-008: Admin API Request Bodies Are Collected Without Size Limits | Fixed | Added a shared 1 MiB streaming admin body collector and wired it into domain creation, blacklist mutation, and token creation endpoints with `413` responses. |
| PXSA-2026-009: TLS Is Local Single-Certificate Mode and Dynamic SAN Regeneration Can Be Abused | Mitigated | Certificate domain lists are filtered, sorted, deduplicated, and capped; private key files are written with `0600` permissions on Unix; production startup rejects unsafe admin/metrics exposure. Production ACME, SNI-specific certificates, OCSP, and listener mTLS remain planned feature work. |
| PXSA-2026-010: Security-Looking Future Route Fields Are Accepted but Not Enforced | Mitigated | Docs now state that HTTP upstream TLS transport, ACME, TCP, UDP, HTTP/3, and per-router TLS options are schema intent only. API-created `https://` upstreams are rejected until verified upstream TLS transport exists. |
| PXSA-2026-011: Docker/Podman Socket Discovery Expands the Trust Boundary | Mitigated | Docker/Podman route labels now go through dynamic route validation, Docker API socket responses are size-capped, malformed chunked socket responses are bounded, and the runtime container runs with dropped capabilities, no-new-privileges, read-only root filesystem, and resource limits in Compose. A least-privilege discovery sidecar and domain/network allowlists remain future hardening. |
| PXSA-2026-012: Analytics and ClickHouse Error Handling Need Privacy and Size Hardening | Fixed | ClickHouse error bodies are read with a 16 KiB cap, ClickHouse host ports are no longer published by Compose, and docs now call out access-log privacy. |
| PXSA-2026-013: Docs Understate Runtime Body Limit Behavior | Fixed | Updated API and dynamic-routing docs to say `max_body_bytes` pre-checks `Content-Length` and also caps collected streaming/chunked bodies. |
| CVE-FIND-2026-001: Digest Auth Replay and URI Confusion | Fixed | Added signed expiring digest nonces, `qop=auth` enforcement, nonce-count/client-nonce validation, canonical URI binding, replay tracking, and integration tests. |
| CVE-FIND-2026-002: Upstream Response Hop-by-Hop Headers Are Forwarded | Fixed | Added response-side hop-by-hop and `Connection` nominated header stripping in both buffered and streaming response paths, with regression coverage. |
| CVE-FIND-2026-003: Request and Response Bodies Are Always Buffered | Fixed | Added bounded streaming forwarding as the default path and kept buffering only for features that need replay or body inspection. |
| CVE-FIND-2026-004: Missing Config Falls Back to Unsafe Defaults | Fixed | Startup now fails closed on a missing config unless `PXXL_ALLOW_DEFAULT_CONFIG=true`; admin/metrics defaults are loopback-only and admin auth defaults on. |
| CVE-FIND-2026-005: Docker/Podman Socket Mounts Are Privileged Trust Boundaries | Fixed by default | Removed default runtime socket mounts from Compose, disabled discovery by default, added explicit discovery override compose file and env toggles. |
| CVE-FIND-2026-006: CORS Preflight Bypasses Domain Rate Limits | Fixed | Moved per-domain rate-limit enforcement before successful CORS preflight responses and added a regression test. |
| CVE-FIND-2026-007: Route and Upstream Counts Have No Quotas | Fixed | Added route/path/upstream/mirror quotas for API, Redis, and Docker/Podman label sources. |
| PXSA-2026-101: Edge Basic/Digest Credentials Are Forwarded To Upstreams | Fixed | Basic/Digest middleware now removes consumed edge `Authorization` before upstream forwarding, with regression coverage proving the upstream no longer receives it. |
| PXSA-2026-102: DNS-Based SSRF And Host-Gateway SSRF Remain Possible For Dynamic Routes | Mitigated | API-created routes now reject host-gateway upstreams and resolve DNS names to reject private/loopback/link-local/metadata targets; API routes are also checked again at request and health-check time. Docker/Podman label routes remain a trusted discovery boundary. |
| PXSA-2026-103: Streaming Body Limits Are Enforced After Partial Forwarding | Fixed | Routes that set `max_body_bytes` now use strict buffered validation before upstream forwarding and return `413` before the upstream is contacted. |
| PXSA-2026-104: HTTP/2 Is Enabled Without Explicit Protocol-Level DoS Tuning | Mitigated | Edge/admin/metrics Hyper auto builders now set HTTP/1 header read limits and HTTP/2 stream, reset, frame, header-list, send-buffer, and keepalive limits. |
| PXSA-2026-105: Metrics Endpoint Has No Application-Layer Authentication | Fixed | Added optional metrics bearer authentication through `[metrics].bearer_token` or `PXXL_METRICS_BEARER_TOKEN`; Compose still binds metrics to loopback by default. |
| PXSA-2026-106: Bootstrap Admin Token Is Permanent While Environment Variable Remains Set | Fixed | Bootstrap tokens are one-shot by default and stop authenticating once Redis contains any admin token; permanent bootstrap now requires `PXXL_ADMIN_BOOTSTRAP_TOKEN_PERMANENT=true`. |
| PXSA-2026-107: Route Snapshots Expose Embedded Basic/Digest Passwords To Any Admin Token | Mitigated | Admin route-list/domain responses now redact Basic/Digest password values and added request-header values. Runtime route auth still accepts existing plaintext route config, so hashed route-secret storage remains product work. |
| PXSA-2026-108: ForwardAuth `response_headers` Configuration Is Ignored | Fixed | Non-empty `forward_auth.response_headers` is now rejected during route validation until trusted response-header propagation is implemented safely. |
| PXSA-2026-109: Admin API Has No RBAC Or Tenant Ownership Model | Mitigated | Added token scopes for route read/write, token read/write, and analytics read endpoints. Domain ownership/tenant isolation remains product work. |
| PXSA-2026-110: ClickHouse Analytics Requests Have No Request Timeout Or Circuit Breaker | Mitigated | ClickHouse writes now have a bounded request timeout. Backoff/circuit metrics remain product hardening. |
| PXSA-2026-111: Runtime Discovery Socket Mounts Remain A High-Trust Boundary | Mitigated | Discovery remains opt-in, labels still pass route validation, and docs keep the socket boundary explicit. A least-privilege socket proxy/container allowlist remains product work. |
| PXSA-2026-112: Supply-Chain And Installer Hardening Gaps | Mitigated | `install.sh` and `update.sh` can now enforce signed git commits with `PXXL_VERIFY_GIT_SIGNATURE=1`. Digest-pinned images/SBOM/signing remain release hardening. |

## Additional Hardening Completed

- Runtime Docker image now creates and runs as a non-root `pxxl` user.
- Compose adds `read_only`, `/tmp` tmpfs, `cap_drop: ALL`, `cap_add: NET_BIND_SERVICE`, `no-new-privileges`, CPU/memory limits, and persistent Grafana/Prometheus/Loki/Redis/Postgres/ClickHouse data directories.
- Kubernetes example no longer exposes admin/metrics through the public Service and adds non-root, read-only filesystem, capability, and resource settings.
- Postman environment no longer stores a default bearer token.
- Admin tokens now support scopes: `admin`, `routes:read`, `routes:write`, `tokens:read`, `tokens:write`, and `analytics:read`.
- Optional metrics bearer auth is available for deployments that expose `/metrics` beyond loopback/private scrape networks.

## Still Tracked For Product Work

- Add configurable dynamic-upstream allowlists for API routes in environments that intentionally route to internal private networks.
- Store Basic/Digest route credentials as password hashes or digest HA1 hashes rather than plaintext route config.
- Add route/domain ownership in addition to token scopes for true multi-tenant admin isolation.
- Add per-IP connection limits and more granular slow-header, slow-body, idle, and upstream response deadlines.
- Add production ACME/Let's Encrypt issuance with account-key protection, challenge isolation, renewal failure handling, DNS provider secret isolation, and audit logs.
- Add SNI-specific certificate selection and listener mTLS before enabling per-router client-auth settings.
- Implement HTTPS upstream transport with rustls verification before accepting custom CA roots, SNI overrides, insecure-skip, or upstream mTLS settings.
- Build a least-privilege Docker/Podman discovery sidecar or container allowlist model for multi-tenant environments.
- Pin production image references by digest, publish signed release tags, generate SBOMs, and enforce image/dependency vulnerability scanning in CI.
- Add fuzz/integration matrices for encoded paths, duplicate headers, request smuggling cases, slow clients, and SSRF route creation.
