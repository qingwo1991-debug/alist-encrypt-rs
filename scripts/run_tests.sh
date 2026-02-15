#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."
unset http_proxy https_proxy HTTP_PROXY HTTPS_PROXY
export CARGO_HOME=${CARGO_HOME:-/tmp/cargo}

cargo fmt --all -- --check
cargo test
