# Security Policy

Pxxl Proxy is an edge-facing project, so security reports are taken seriously.

## Supported Versions

The `main` branch is the active development branch for the Phase 1 MVP.

## Reporting a Vulnerability

Please do not open public issues for exploitable vulnerabilities.

Send reports to Robinson Honour with:

- Affected component
- Reproduction steps
- Impact
- Suggested fix, if known

## Security Design Principles

- Request-path decisions must not depend on blocking databases.
- Blacklists must be served from memory.
- Secrets belong in `/data/secrets` or external secret stores.
- Password hashing must use Argon2 when dashboard authentication lands.
- Metrics and admin APIs should be protected before public exposure.

