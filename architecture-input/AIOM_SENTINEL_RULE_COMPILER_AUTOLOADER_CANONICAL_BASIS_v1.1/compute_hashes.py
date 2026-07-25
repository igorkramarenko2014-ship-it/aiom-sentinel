#!/usr/bin/env python3
"""Computes SHA256SUMS.txt and MANIFEST.json for the pack."""
import hashlib, json, os, sys
from pathlib import Path

BASE = Path(__file__).resolve().parent
EXCLUDE = {Path(__file__).name, 'SHA256SUMS.txt', 'MANIFEST.json'}

def sha256_file(p):
    h = hashlib.sha256()
    with open(p, 'rb') as f:
        for chunk in iter(lambda: f.read(65536), b''):
            h.update(chunk)
    return h.hexdigest()

files = []
for root, dirs, fnames in os.walk(BASE):
    rootp = Path(root)
    for f in fnames:
        if f in EXCLUDE:
            continue
        rel = rootp.relative_to(BASE) / f
        full = rootp / f
        files.append((str(rel).replace('\\', '/'), sha256_file(full), full.stat().st_size))

files.sort()

# Write SHA256SUMS including MANIFEST (but not itself)
with open(BASE / 'SHA256SUMS.txt', 'w', encoding='utf-8') as f:
    for rel, h, _ in files:
        f.write(f"{h}  {rel}\n")

# Build manifest (excluding self and SHA256SUMS)
manifest_files = [{"path": rel, "sha256": h, "size": s, "role": "OTHER"} for rel, h, s in files]
manifest = {
    "bundle_id": hashlib.sha256(json.dumps(manifest_files, sort_keys=True).encode()).hexdigest(),
    "bundle_version": 1,
    "schema_version": "1.0",
    "compiler": {
        "compiler_name": "compute_hashes.py",
        "compiler_version": "1.0.0",
        "compiler_sha256": sha256_file(__file__)
    },
    "files": manifest_files,
    "lifecycle": "TEST",
    "validity_window": {
        "not_before": "2026-07-21T00:00:00Z",
        "not_after": "2099-12-31T23:59:59Z"
    },
    "required_capabilities": []
}
# canonical_manifest_hash: hash of manifest without the hash field itself
manifest_copy = {k: v for k, v in manifest.items() if k != "canonical_manifest_hash"}
canonical_hash = hashlib.sha256(json.dumps(manifest_copy, sort_keys=True, separators=(',', ':')).encode()).hexdigest()
manifest["canonical_manifest_hash"] = canonical_hash

with open(BASE / 'MANIFEST.json', 'w', encoding='utf-8') as f:
    json.dump(manifest, f, indent=2, sort_keys=True)
print("SHA256SUMS.txt and MANIFEST.json generated.")
