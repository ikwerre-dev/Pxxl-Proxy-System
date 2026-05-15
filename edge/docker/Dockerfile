# syntax=docker/dockerfile:1.7

FROM rust:1-bookworm AS builder
WORKDIR /src
COPY Cargo.toml ./
COPY Cargo.lock ./
COPY edge ./edge
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/src/target \
    cargo build --release -p pxxl-edge \
    && cp /src/target/release/pxxl-edge /tmp/pxxl-edge

FROM debian:bookworm-slim AS runtime
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY --from=builder /tmp/pxxl-edge /usr/local/bin/pxxl-edge
COPY config ./config
RUN mkdir -p /data/certs /data/secrets
EXPOSE 80 443 8081 9090
ENTRYPOINT ["pxxl-edge"]
