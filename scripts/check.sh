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

echo "==> biometric plugin: format"
cargo fmt --manifest-path crates/tauri-plugin-yobei-biometric/Cargo.toml -- --check

echo "==> biometric plugin: clippy"
cargo clippy --manifest-path crates/tauri-plugin-yobei-biometric/Cargo.toml --all-targets -- -D warnings

echo "==> app shell: format"
cargo fmt --manifest-path src-tauri/Cargo.toml -- --check

echo "==> app shell: clippy"
cargo clippy --manifest-path src-tauri/Cargo.toml --all-targets -- -D warnings

echo "==> frontend: svelte-check"
bun run check

echo "==> browser extension: manifest + syntax"
node -e "JSON.parse(require('fs').readFileSync('browser-extension/manifest.json','utf8'))"
for f in browser-extension/*.js; do node --check "$f"; done

echo "==> sync worker: typecheck"
(cd workers/sync && bun run typecheck)

echo "All checks passed."
