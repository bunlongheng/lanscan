#!/usr/bin/env bash
# Manual CI gate for lanscan.
#
# Runs the same checks the CircleCI `test` job runs, locally. Use this until
# CircleCI is enabled (billing). Run it before every push.
#
#   ./scripts/ci.sh          # fmt check + clippy + tests
#   ./scripts/ci.sh release  # also build the optimized release binary
set -euo pipefail
cd "$(dirname "$0")/.."

echo "==> cargo fmt --all --check"
cargo fmt --all --check

echo "==> cargo clippy --all-targets -- -D warnings"
cargo clippy --all-targets -- -D warnings

echo "==> cargo test --all"
cargo test --all

if [[ "${1:-}" == "release" ]]; then
  echo "==> cargo build --release"
  cargo build --release
  echo "==> binary: target/release/lanscan"
fi

echo "==> CI passed"
