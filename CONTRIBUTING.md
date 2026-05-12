# Contributing

Thanks for helping build Pxxl Proxy.

## Local Checks

Run these before opening a pull request:

```sh
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace --all-targets
```

## Design Rules

- Keep request-path operations non-blocking.
- Do not add database calls to proxy forwarding decisions.
- Keep blacklist checks memory-only.
- Prefer small crates with clear ownership.
- Add tests for route matching, security decisions, load balancing, and proxy behavior.
- Use structured tracing fields for operational events.

## Pull Requests

Each PR should include:

- A clear description of user-visible behavior
- Tests or a reason tests are not applicable
- Any config, Docker, or API changes
- Migration notes when persisted data changes

