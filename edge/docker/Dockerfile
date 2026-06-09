# syntax=docker/dockerfile:1.7

FROM docker.io/library/rust:1-bookworm AS builder
WORKDIR /src
COPY Cargo.toml ./
COPY Cargo.lock ./
COPY config ./config
COPY edge ./edge
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/src/target \
    cargo build --release -p pxxl-edge \
    && cp /src/target/release/pxxl-edge /tmp/pxxl-edge

FROM docker.io/library/debian:bookworm-slim AS runtime
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates certbot \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY --from=builder /tmp/pxxl-edge /usr/local/bin/pxxl-edge
COPY config ./config
RUN groupadd --system pxxl \
    && useradd --system --gid pxxl --home-dir /nonexistent --shell /usr/sbin/nologin pxxl \
    && mkdir -p /data/certs /data/secrets \
    && chown -R pxxl:pxxl /data /app /usr/local/bin/pxxl-edge
USER pxxl
EXPOSE 80 443 8081 9090
ENTRYPOINT ["pxxl-edge"]
