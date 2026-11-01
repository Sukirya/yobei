#!/usr/bin/env bash
# Full quality gate (ADR-0007). Run from anywhere; the script cd's to the
# repository root.
set -euo pipefail
cd "$(dirname "$0")/.."

echo "==> core: format"
cargo fmt --manifest-path crates/yobei-core/Cargo.toml -- --check

echo "==> core: clippy"
cargo clippy --manifest-path crates/yobei-core/Cargo.toml --all-targets -- -D warnings

echo "==> core: tests"
cargo test --manifest-path crates/yobei-core/Cargo.toml

echo "==> app shell: format"
cargo fmt --manifest-path src-tauri/Cargo.toml -- --check

echo "==> app shell: clippy"
cargo clippy --manifest-path src-tauri/Cargo.toml --all-targets -- -D warnings

echo "==> frontend: svelte-check"
bun run check

echo "==> sync worker: typecheck"
(cd workers/sync && bun run typecheck)

echo "All checks passed."
