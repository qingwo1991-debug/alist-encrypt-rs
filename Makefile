.PHONY: fmt test build run

fmt:
	cargo fmt --all -- --check

test:
	cargo test

build:
	cargo build --release

run:
	cargo run
