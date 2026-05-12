#!/usr/bin/env sh
set -eu

export PXXL_HTTP_ADDR="${PXXL_HTTP_ADDR:-127.0.0.1:8080}"
export PXXL_HTTPS_ADDR="${PXXL_HTTPS_ADDR:-127.0.0.1:8443}"
export PXXL_ADMIN_ADDR="${PXXL_ADMIN_ADDR:-127.0.0.1:8081}"
export PXXL_METRICS_ADDR="${PXXL_METRICS_ADDR:-127.0.0.1:9090}"
export PXXL_CERT_DIR="${PXXL_CERT_DIR:-data/certs}"

cargo run -p pxxl-edge

