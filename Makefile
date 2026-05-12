.PHONY: fmt lint test bench run-local docker-build compose-up compose-down smoke

fmt:
	cargo fmt --all

lint:
	cargo clippy --workspace --all-targets -- -D warnings

test:
	cargo test --workspace --all-targets

bench:
	cargo bench -p pxxl-edge

run-local:
	sh scripts/dev-local.sh

docker-build:
	docker build -f edge/docker/Dockerfile -t pxxl/edge:local .

compose-up:
	docker compose up --build

compose-down:
	docker compose down

smoke:
	sh scripts/smoke.sh

