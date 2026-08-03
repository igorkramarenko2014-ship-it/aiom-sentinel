#!/usr/bin/env bash
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
first="$root/migrations/0001_create_fingerprint_registry.sql"
second="$root/migrations/0002_add_fingerprint_indexes.sql"

files="$(find "$root/migrations" -maxdepth 1 -type f -name '*.sql' | wc -l | tr -d ' ')"
tables="$(grep -c '^CREATE TABLE' "$first" || true)"
indexes="$(grep -c '^CREATE INDEX' "$second" || true)"
drops="$(grep -h -ciE '^\s*DROP\b' "$root"/migrations/*.sql || true)"
drops="$(printf '%s\n' "$drops" | awk '{ total += $1 } END { print total + 0 }')"
generated="$(grep -c 'authority_state TEXT GENERATED' "$first" || true)"
set_unique="$(grep -c 'UNIQUE (fingerprint_set_id, sha256)' "$first" || true)"
classification="$(grep -c 'classification IN (' "$first" || true)"
composite_fk="$(grep -c 'FOREIGN KEY (source_artifact_id, fingerprint_set_id)' "$first" || true)"
sha256_length="$(grep -c 'octet_length(digest) = 32' "$first" || true)"

[[ "$files" == 2 ]] || { echo "MIGRATION_STATIC_GATE: FAIL migration_files=$files expected=2"; exit 1; }
[[ "$tables" == 3 ]] || { echo "MIGRATION_STATIC_GATE: FAIL tables=$tables expected=3"; exit 1; }
[[ "$indexes" == 2 ]] || { echo "MIGRATION_STATIC_GATE: FAIL indexes=$indexes expected=2"; exit 1; }
[[ "$drops" == 0 ]] || { echo "MIGRATION_STATIC_GATE: FAIL drops=$drops expected=0"; exit 1; }
[[ "$generated" == 1 ]] || { echo "MIGRATION_STATIC_GATE: FAIL generated_authority_state=$generated expected=1"; exit 1; }
[[ "$set_unique" == 1 ]] || { echo "MIGRATION_STATIC_GATE: FAIL set_scoped_sha256_unique=$set_unique expected=1"; exit 1; }
[[ "$classification" == 1 ]] || { echo "MIGRATION_STATIC_GATE: FAIL classification_check=$classification expected=1"; exit 1; }
[[ "$composite_fk" == 1 ]] || { echo "MIGRATION_STATIC_GATE: FAIL composite_fk=$composite_fk expected=1"; exit 1; }
[[ "$sha256_length" == 1 ]] || { echo "MIGRATION_STATIC_GATE: FAIL sha256_length_check=$sha256_length expected=1"; exit 1; }

echo "MIGRATION_STATIC_GATE: PASS migration_files=$files tables=$tables indexes=$indexes drops=$drops generated_authority_state=$generated set_scoped_sha256_unique=$set_unique classification_check=$classification composite_fk=$composite_fk sha256_length_check=$sha256_length"
