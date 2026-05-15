# Codex Security Fix Report

Date: 2026-05-15
Source: `docs/codex-security-findings.md`

## Summary

This pass fixed or mitigated every confirmed finding from the Codex security scan. Some items are fully closed in code; a few are mitigated because the complete production-grade version is larger product work, such as tenant domain ownership, hashed route-secret storage, a Docker socket proxy, and digest-pinned release images.

## Findings

| Finding | Status | Fix |
| --- | --- | --- |
| PXSA-2026-101 | Fixed | Basic/Digest auth strips consumed `Authorization` before forwarding. |
| PXSA-2026-102 | Mitigated | API routes reject host-gateway upstreams and DNS names resolving to unsafe IPs at creation, request, and health-check time. Docker/Podman discovery remains an explicitly trusted boundary. |
| PXSA-2026-103 | Fixed | Routes with `max_body_bytes` buffer and validate before upstream forwarding, returning `413` without contacting upstream. |
| PXSA-2026-104 | Mitigated | Hyper builders now set HTTP/1 header timeout/limits and HTTP/2 stream, reset, frame, header-list, send-buffer, and keepalive limits. |
| PXSA-2026-105 | Fixed | Added optional `/metrics` bearer auth via `[metrics].bearer_token` or `PXXL_METRICS_BEARER_TOKEN`. |
| PXSA-2026-106 | Fixed | Bootstrap token is one-shot by default after the first Redis admin token exists. |
| PXSA-2026-107 | Mitigated | Route-list/domain API responses redact auth password maps and added request-header values. Hashing route-stored credentials remains tracked. |
| PXSA-2026-108 | Fixed | Non-empty `forward_auth.response_headers` is rejected until trusted propagation is implemented. |
| PXSA-2026-109 | Mitigated | Admin tokens now support endpoint scopes. Tenant/domain ownership remains tracked. |
| PXSA-2026-110 | Mitigated | ClickHouse writes now have a bounded request timeout. |
| PXSA-2026-111 | Mitigated | Runtime socket discovery remains opt-in and documented as trusted; a least-privilege socket proxy remains tracked. |
| PXSA-2026-112 | Mitigated | Installer/updater can require signed git commits with `PXXL_VERIFY_GIT_SIGNATURE=1`; image digest pinning/SBOMs remain tracked. |

## Validation

- `cargo fmt --check --all`: passed
- `cargo clippy --workspace --all-targets --all-features -- -D warnings`: passed
- `cargo test --workspace --all-features`: passed
- `sh -n install.sh`: passed
- `sh -n update.sh`: passed
- `docker compose config`: passed with test env values
- `docker compose -f docker-compose.yml -f docker-compose.discovery.yml config`: passed with test env values

## Regression Coverage Added

- Basic auth no longer forwards edge `Authorization` to upstreams.
- Strict `max_body_bytes` rejects oversized bodies before upstream forwarding.
- API network safety rejects `host.docker.internal`.
- Route API redaction removes middleware passwords and added request-header values.
- Token scope validation accepts supported scopes and rejects unsupported ones.
- ForwardAuth non-empty `response_headers` fails validation.
