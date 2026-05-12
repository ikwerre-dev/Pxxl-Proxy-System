# Local Development

Use non-root ports unless you are running the binary with privileges:

```sh
PXXL_HTTP_ADDR=127.0.0.1:8080 \
PXXL_HTTPS_ADDR=127.0.0.1:8443 \
PXXL_ADMIN_ADDR=127.0.0.1:8081 \
PXXL_METRICS_ADDR=127.0.0.1:9090 \
cargo run -p pxxl-edge
```

Add hosts:

```txt
127.0.0.1 app.pxxlhost
127.0.0.1 api.pxxlhost
127.0.0.1 admin.pxxlhost
```

The generated certificate is written to `data/certs` in Docker Compose and `/data/certs` by default inside containers.

For wildcard DNS, configure dnsmasq:

```txt
address=/.pxxlhost/127.0.0.1
```

