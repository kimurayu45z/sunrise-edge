#!/usr/bin/env bash
set -euo pipefail

project_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$project_root"

cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-targets --all-features

npm --prefix adapters/cloudflare-workers run check

for adapter in deno vercel supabase-edge aws-lambda; do
  (
    cd "adapters/$adapter"
    deno task check
  )
done

git diff --check
