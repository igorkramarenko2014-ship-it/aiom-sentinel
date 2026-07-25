#!/usr/bin/env python3
"""
Independent verifier for AIOM Sentinel contract pack.
Usage:
  python VERIFY_PACK.py --self-test   # run mutation tests
  python VERIFY_PACK.py                # verify current pack
"""
import json, hashlib, os, sys, shutil, tempfile, re, datetime
from pathlib import Path

BASE = Path(__file__).resolve().parent

def sha256_file(p):
    h = hashlib.sha256()
    with open(p, 'rb') as f:
        while True:
            chunk = f.read(65536)
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest()

def is_safe_path(p):
    s = str(p)
    if os.path.isabs(s): return False
    if '..' in p.parts: return False
    if re.search(r'[<>:"|?*]', s): return False
    return True

def check_pack(override_base=None):
    base = Path(override_base) if override_base else BASE
    errors = []

    # required files
    required = ['00_INPUT_RECEIPT.md', '01_SCOPE_AND_NON_GOALS.md', 'PACK_STATUS.json', 'README.md',
                'LICENSE_NOTES.md', 'CONTRACT_INDEX.md', 'VERIFY_PACK.py', 'compute_hashes.py',
                'SHA256SUMS.txt', 'MANIFEST.json']
    for r in required:
        if not (base / r).exists():
            errors.append(f"Missing required file: {r}")

    # SHA256SUMS check
    sums_file = base / 'SHA256SUMS.txt'
    if sums_file.exists():
        with open(sums_file) as f:
            for line in f:
                if line.strip():
                    parts = line.strip().split(None, 1)
                    if len(parts) != 2:
                        errors.append("Malformed SHA256SUMS line")
                        continue
                    h, rel = parts
                    p = base / rel
                    if not p.exists():
                        errors.append(f"SHA256SUMS lists missing file: {rel}")
                    elif sha256_file(p) != h:
                        errors.append(f"SHA256 mismatch: {rel}")

    # MANIFEST consistency
    manifest_file = base / 'MANIFEST.json'
    if manifest_file.exists():
        try:
            with open(manifest_file) as f:
                manifest = json.load(f)
        except Exception as e:
            errors.append(f"Invalid MANIFEST.json: {e}")
        else:
            # canonical_manifest_hash check
            if manifest.get('canonical_manifest_hash'):
                mcopy = {k: v for k, v in manifest.items() if k != 'canonical_manifest_hash'}
                computed = hashlib.sha256(json.dumps(mcopy, sort_keys=True, separators=(',', ':')).encode()).hexdigest()
                if computed != manifest['canonical_manifest_hash']:
                    errors.append("MANIFEST canonical_manifest_hash mismatch")
            for finfo in manifest.get('files', []):
                path = finfo['path']
                if not (base / path).exists():
                    errors.append(f"Manifest lists missing file: {path}")
                elif sha256_file(base / path) != finfo['sha256']:
                    errors.append(f"Manifest hash mismatch: {path}")
                if not is_safe_path(Path(path)):
                    errors.append(f"Manifest contains unsafe path: {path}")

    # PACK_STATUS truthfulness
    ps_file = base / 'PACK_STATUS.json'
    if ps_file.exists():
        with open(ps_file) as f:
            ps = json.load(f)
        if ps.get('live_repository_status') != 'NOT_INCLUDED':
            errors.append("live_repository_status must be NOT_INCLUDED")
        if ps.get('integration_status') != 'NOT_EXECUTED':
            errors.append("integration_status must be NOT_EXECUTED")
        if ps.get('safe_to_merge') != False:
            errors.append("safe_to_merge must be false")

    # Schema JSON validity
    schemas_dir = base / 'schemas'
    if schemas_dir.exists():
        for sf in schemas_dir.glob('*.json'):
            try:
                with open(sf) as f:
                    json.load(f)
            except Exception as e:
                errors.append(f"Invalid schema JSON: {sf.name} - {e}")

    # path safety walk
    for root, dirs, files in os.walk(base):
        for f in files:
            p = Path(root) / f
            rel = p.relative_to(base)
            if not is_safe_path(rel):
                errors.append(f"Unsafe path: {rel}")

    return errors

# ── mutation self‑test ──
MUTATIONS = []

def add_mut(desc, mutate):
    MUTATIONS.append((desc, mutate))

add_mut("Missing 00_INPUT_RECEIPT.md", lambda d: (d / '00_INPUT_RECEIPT.md').unlink())
add_mut("SHA256SUMS with wrong hash", lambda d: open(d / 'SHA256SUMS.txt', 'a').write("0000000000000000000000000000000000000000000000000000000000000000  README.md\n"))
add_mut("MANIFEST lists missing file", lambda d: open(d / 'MANIFEST.json', 'w').write(json.dumps({"canonical_manifest_hash":"","files":[{"path":"nonexistent","sha256":"aaaa","size":1,"role":"OTHER"}]})))
add_mut("MANIFEST with .. traversal", lambda d: open(d / 'MANIFEST.json', 'w').write(json.dumps({"canonical_manifest_hash":"","files":[{"path":"../escape","sha256":"aaaa","size":1,"role":"OTHER"}]})))
add_mut("PACK_STATUS safe_to_merge true", lambda d: open(d / 'PACK_STATUS.json', 'w').write(json.dumps({**json.load(open(d/'PACK_STATUS.json')), "safe_to_merge": True})))
add_mut("PACK_STATUS live_repository_status wrong", lambda d: open(d / 'PACK_STATUS.json', 'w').write(json.dumps({**json.load(open(d/'PACK_STATUS.json')), "live_repository_status": "INCLUDED"})))
add_mut("PACK_STATUS integration_status PASS", lambda d: open(d / 'PACK_STATUS.json', 'w').write(json.dumps({**json.load(open(d/'PACK_STATUS.json')), "integration_status": "PASS"})))
add_mut("Corrupt schema JSON", lambda d: open(d / 'schemas/rule-source.schema.json', 'w').write("not json"))
add_mut("Unsafe path in bundle-file example", lambda d: open(d / 'examples/valid/bundle-file.json', 'w').write(json.dumps({"path":"../evil","sha256":"aaaa","size":1,"role":"OTHER"})))
add_mut("Duplicate RuleId in metadata", lambda d: open(d / 'examples/valid/rule-metadata.json', 'w').write(json.dumps({**json.load(open(d/'examples/valid/rule-metadata.json')), "rule_id": "dup"})))
add_mut("Invalid lifecycle in manifest example", lambda d: open(d / 'examples/valid/bundle-manifest.json', 'w').write(json.dumps({**json.load(open(d/'examples/valid/bundle-manifest.json')), "lifecycle": "BROKEN"})))
add_mut("Signature envelope missing signature", lambda d: open(d / 'examples/valid/signature-envelope.json', 'w').write(json.dumps({**json.load(open(d/'examples/valid/signature-envelope.json')), "signature": ""})))
add_mut("Verification receipt with actions_taken non-empty", lambda d: open(d / 'examples/valid/verification-receipt.json', 'w').write(json.dumps({**json.load(open(d/'examples/valid/verification-receipt.json')), "checks": {**json.load(open(d/'examples/valid/verification-receipt.json'))["checks"], "actions_taken_empty": False}})))
add_mut("read_only false in receipt", lambda d: open(d / 'examples/valid/verification-receipt.json', 'w').write(json.dumps({**json.load(open(d/'examples/valid/verification-receipt.json')), "checks": {**json.load(open(d/'examples/valid/verification-receipt.json'))["checks"], "read_only": False}})))
add_mut("Expired bundle active", lambda d: open(d / 'examples/valid/bundle-lifecycle.json', 'w').write(json.dumps({"bundle_id":"aaaa","current_state":"ACTIVE","validity_window":{"not_before":"2020-01-01T00:00:00Z","not_after":"2020-12-31T23:59:59Z"}})))
add_mut("Revoked bundle in loader-status READY", lambda d: open(d / 'examples/valid/loader-status.json', 'w').write(json.dumps({**json.load(open(d/'examples/valid/loader-status.json')), "state": "READY", "bundle_lifecycle": "REVOKED"})))
add_mut("Unknown capability in manifest", lambda d: open(d / 'examples/valid/bundle-manifest.json', 'w').write(json.dumps({**json.load(open(d/'examples/valid/bundle-manifest.json')), "required_capabilities": ["unknown"]})))
add_mut("Manifest hash mismatch", lambda d: open(d / 'MANIFEST.json', 'r+').write("..."))  # will cause invalid JSON
add_mut("Unexpected file present", lambda d: (d / 'UNEXPECTED_FILE').touch())
add_mut("Empty MANIFEST.json", lambda d: open(d / 'MANIFEST.json', 'w').write('{}'))
add_mut("SHA256SUMS missing", lambda d: (d / 'SHA256SUMS.txt').unlink())
add_mut("Path with absolute in manifest", lambda d: open(d / 'MANIFEST.json', 'w').write(json.dumps({"canonical_manifest_hash":"","files":[{"path":"/absolute/path","sha256":"aaaa","size":1,"role":"OTHER"}]})))
add_mut("Duplicate file entries in SHA256SUMS", lambda d: open(d / 'SHA256SUMS.txt', 'a').write("aaaa  README.md\n"))
add_mut("Compiler receipt with FAIL status", lambda d: open(d / 'examples/valid/compiler-receipt.json', 'w').write(json.dumps({**json.load(open(d/'examples/valid/compiler-receipt.json')), "status": "FAIL"})))
add_mut("Loader report with REJECTED but no reason", lambda d: open(d / 'examples/valid/loader-report.json', 'w').write(json.dumps({"status":"REJECTED","details":[]})))
add_mut("Unsigned bundle (missing signature field)", lambda d: open(d / 'examples/valid/signature-envelope.json', 'w').write('{"signed":{}}'))
add_mut("Signature with wrong domain separator", lambda d: open(d / 'examples/valid/signature-envelope.json', 'w').write(json.dumps({**json.load(open(d/'examples/valid/signature-envelope.json')), "signed": {**json.load(open(d/'examples/valid/signature-envelope.json'))["signed"], "domain_separator": "WRONG"}})))
add_mut("Bundle ID mismatch in manifest", lambda d: open(d / 'examples/valid/bundle-manifest.json', 'w').write(json.dumps({**json.load(open(d/'examples/valid/bundle-manifest.json')), "bundle_id": "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"})))
add_mut("Schema version unsupported", lambda d: open(d / 'examples/valid/bundle-manifest.json', 'w').write(json.dumps({**json.load(open(d/'examples/valid/bundle-manifest.json')), "schema_version": "0.9"})))
add_mut("Negative size in manifest file entry", lambda d: open(d / 'examples/valid/bundle-file.json', 'w').write(json.dumps({"path":"x","sha256":"aaaa","size":-1,"role":"OTHER"})))
add_mut("Manifest without files array", lambda d: open(d / 'MANIFEST.json', 'w').write(json.dumps({"canonical_manifest_hash":"","files":[]})))
add_mut("Invalid UTF-8 in README", lambda d: open(d / 'README.md', 'wb').write(b'\xff\xfe invalid'))
add_mut("Corrupt SHA256SUMS line", lambda d: open(d / 'SHA256SUMS.txt', 'a').write("bad line\n"))
add_mut("Extra file in schemas directory not in manifest", lambda d: (d / 'schemas/extra.schema.json').write_text('{}'))
add_mut("Symlink in pack (if possible)", lambda d: None)  # skip
add_mut("Actions taken non-empty in invalid example", lambda d: open(d / 'examples/invalid/actions_taken_nonempty.json', 'w').write('{"actions_taken":["delete"],"read_only":false}'))
add_mut("Read-only false in invalid example", lambda d: open(d / 'examples/invalid/read_only_false.json', 'w').write('{"read_only":false}'))

def self_test():
    import tempfile
    original_base = BASE
    with tempfile.TemporaryDirectory() as tmpdir:
        tmpbase = Path(tmpdir)
        shutil.copytree(original_base, tmpbase, symlinks=False)
        results = []
        for desc, mutate in MUTATIONS:
            # reset
            shutil.rmtree(tmpbase, ignore_errors=True)
            shutil.copytree(original_base, tmpbase, symlinks=False)
            try:
                if mutate: mutate(tmpbase)
            except Exception:
                pass
            errors = check_pack(str(tmpbase))
            caught = len(errors) > 0
            results.append({
                "mutation": desc,
                "expected": "FAIL",
                "actual": "FAIL" if caught else "PASS",
                "caught": caught,
                "errors": errors[:3]
            })
        all_caught = all(r["caught"] for r in results)
        total = len(results)
        caught_count = sum(1 for r in results if r["caught"])
        print(f"Mutation tests: {total} executed, {caught_count} caught")
        if not all_caught:
            print("FAIL: some mutations not caught")
            for r in results:
                if not r["caught"]:
                    print(f"  Missed: {r['mutation']}")
        else:
            print("All mutations caught – PASS")
        # write report
        report_path = original_base / "NEGATIVE_TEST_REPORT.md"
        with open(report_path, 'w') as f:
            f.write("# Negative Test Report\n\n")
            for r in results:
                f.write(f"- {r['mutation']}: {r['actual']} (caught: {r['caught']})\n")
        return all_caught

if __name__ == '__main__':
    if '--self-test' in sys.argv:
        ok = self_test()
        sys.exit(0 if ok else 1)
    else:
        errors = check_pack()
        if errors:
            print("FAIL")
            for e in errors:
                print(e)
            sys.exit(1)
        else:
            print("PASS")
