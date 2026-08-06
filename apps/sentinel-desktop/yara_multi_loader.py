#!/usr/bin/env python3
import hashlib, json, pathlib, sys, time
import yara

registry = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
target = pathlib.Path(sys.argv[2])
pack_results = []
for pack in registry:
    if not pack.get("enabled", True):
        continue
    started = time.monotonic()
    files = [p for p in sorted(pathlib.Path(pack["root_path"]).rglob("*")) if p.is_file() and p.suffix.lower() in {".yar", ".yara", ".rule"}]
    compile_errors = []
    filepaths = {}
    for path in files:
        try:
            yara.compile(filepath=str(path))
            filepaths[f'{pack["pack_id"]}::{path.name}::{path.relative_to(pack["root_path"])}'] = str(path)
        except Exception as exc:
            compile_errors.append({"path": str(path), "error": str(exc)})
    matches = []
    scan_errors = []
    try:
        compiled = yara.compile(filepaths=filepaths)
        matches = [{"rule": m.rule, "namespace": m.namespace, "source_pack_id": pack["pack_id"], "tags": list(m.tags)} for m in compiled.match(str(target))]
        status = "PARTIAL" if compile_errors else "COMPLETE"
    except Exception as exc:
        scan_errors.append({"error": str(exc)})
        status = "FAILED"
    pack_results.append({"pack_id": pack["pack_id"], "display_name": pack.get("display_name", pack["pack_id"]), "corpus_content_id": pack["corpus_content_id"], "source_commit": pack.get("source_commit"), "admitted_rule_count": pack["admitted_rule_count"], "quarantined_rule_count": pack["quarantined_rule_count"], "license_mode": pack.get("license_mode", "EXTERNAL"), "scan_status": status, "match_count": len(matches), "matches": matches, "compile_errors": compile_errors, "scan_errors": scan_errors, "elapsed_ms": round((time.monotonic() - started) * 1000)})
completed = sum(p["scan_status"] in {"COMPLETE", "PARTIAL"} for p in pack_results)
failed = sum(p["scan_status"] == "FAILED" for p in pack_results)
overall = "COMPLETE" if completed == len(pack_results) else "PARTIAL" if completed else "FAILED"
print(json.dumps({"overall_status": overall, "total_match_count": sum(p["match_count"] for p in pack_results), "packs": pack_results, "rule_pack_content_id": hashlib.sha256(json.dumps(registry, sort_keys=True).encode()).hexdigest()}))
