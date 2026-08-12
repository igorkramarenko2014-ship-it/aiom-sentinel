#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
temp_root="${RUNNER_TEMP:-${TMPDIR:-/tmp}}"
target_dir="${CARGO_TARGET_DIR:-$temp_root/aiom-sentinel-slice3c-target}"
demo_output="$(mktemp "${TMPDIR:-/tmp}/aiom-sentinel-slice3c.XXXXXX")"
trap 'rm -f "$demo_output"' EXIT

cd "$repo_root"
CARGO_NET_OFFLINE=true CARGO_TARGET_DIR="$target_dir" \
  cargo test -p sentinel-product-service s3c_t --locked
CARGO_NET_OFFLINE=true CARGO_TARGET_DIR="$target_dir" \
  cargo run -q -p sentinel-product-service --bin slice3c_demo --locked >"$demo_output"

required_markers=(
  "DETECTION: MATCH"
  "IDENTITY: digest="
  "CONTROL_POLICY: action=Audit effect_enabled=false"
  "CONTROL_EFFECT: NOT_EXECUTED"
  "POLICY: action=Quarantine effect_enabled=true"
  "TRANSACTION: planned"
  "QUARANTINE: committed"
  "RECEIPT: emitted"
  "SOURCE_POST_STATE: absent=true"
  "KEY_AUTHORITY: TestKeyProvider"
  "TAURI_TRANSACTIONAL_RESPONSE_WIRING: NOT_ENABLED"
  "PRODUCTION_KEY_AUTHORITY: NOT_IMPLEMENTED"
  "AUTOMATIC_PRODUCTION_EFFECTS: DISABLED"
)

for marker in "${required_markers[@]}"; do
  grep -Fq "$marker" "$demo_output"
done

cat "$demo_output"
printf '%s\n' "AIOM_SENTINEL_SLICE_3C_DEMO: PASS"
