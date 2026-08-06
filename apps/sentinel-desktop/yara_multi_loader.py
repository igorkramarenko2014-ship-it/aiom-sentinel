#!/usr/bin/env python3
import hashlib, json, pathlib, sys, time, datetime, subprocess
import yara

def _manifest_files(pack):
    root = pathlib.Path(pack["root_path"]).resolve()
    manifest_path = pack.get("manifest_path")
    if not manifest_path:
        return [p for p in sorted(root.rglob("*")) if p.is_file() and p.suffix.lower() in {".yar", ".yara", ".rule"}]
    manifest = json.loads(pathlib.Path(manifest_path).read_text(encoding="utf-8"))
    if manifest.get("content_id") != pack.get("corpus_content_id"):
        raise ValueError("manifest content_id does not match configured corpus_content_id")
    records = manifest.get("records", [])
    if len(records) != int(pack.get("admitted_rule_count", -1)):
        raise ValueError("manifest admitted record count does not match configured count")
    paths = []
    seen = set()
    for record in records:
        rel = pathlib.PurePosixPath(record["path"])
        if rel.is_absolute() or ".." in rel.parts or str(rel) in seen:
            raise ValueError(f"invalid or duplicate manifest path: {record.get('path')}")
        seen.add(str(rel))
        path = (root / pathlib.Path(*rel.parts)).resolve()
        if root not in path.parents or not path.is_file():
            raise ValueError(f"manifest path is missing or escapes root: {record.get('path')}")
        expected = record.get("sha256") or record.get("effective_sha256")
        if expected and hashlib.sha256(path.read_bytes()).hexdigest() != expected:
            raise ValueError(f"manifest hash mismatch: {record.get('path')}")
        paths.append(path)
    return paths

def _freshness(pack):
    stamp = pack.get("last_updated_at") or pack.get("source_commit_date")
    if not stamp:
        return {"state": "UNKNOWN", "age_days": None}
    try:
        date = datetime.datetime.fromisoformat(stamp.replace("Z", "+00:00"))
        age = max(0, (datetime.datetime.now(datetime.timezone.utc) - date.astimezone(datetime.timezone.utc)).days)
        return {"state": "CURRENT" if age <= 30 else "AGING" if age <= 90 else "STALE", "age_days": age}
    except ValueError:
        return {"state": "UNKNOWN", "age_days": None}

def _metadata(rule, source):
    meta = getattr(rule, "meta", {}) or {}
    return {"rule": rule.rule, "description": meta.get("description"), "author": meta.get("author"), "reference": meta.get("reference"), "date": meta.get("date"), "modified": meta.get("modified"), "source_path": source}

def _signing(path):
    if sys.platform != "darwin":
        return {"status": "UNAVAILABLE", "signed": None, "notarized": None}
    try:
        result = subprocess.run(["codesign", "-dv", "--verbose=4", str(path)], capture_output=True, text=True, timeout=5)
        text = result.stderr
        return {"status": "SIGNED" if result.returncode == 0 else "UNSIGNED", "signed": result.returncode == 0, "notarized": "Ticket=present" in text, "team_id": next((line.split("=")[1] for line in text.splitlines() if line.startswith("TeamIdentifier=")), None)}
    except (OSError, subprocess.TimeoutExpired):
        return {"status": "UNAVAILABLE", "signed": None, "notarized": None}

registry = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
target = pathlib.Path(sys.argv[2])
pack_results = []
for pack in registry:
    if not pack.get("enabled", True):
        continue
    started = time.monotonic()
    compile_errors = []
    filepaths = {}
    try:
        files = _manifest_files(pack)
    except Exception as exc:
        pack_results.append({"pack_id": pack["pack_id"], "display_name": pack.get("display_name", pack["pack_id"]), "corpus_content_id": pack.get("corpus_content_id"), "scan_status": "FAILED", "match_count": 0, "matches": [], "compile_errors": [], "scan_errors": [{"error": str(exc)}], "elapsed_ms": round((time.monotonic() - started) * 1000)})
        continue
    for path in files:
        try:
            yara.compile(filepath=str(path))
            rel = path.relative_to(pathlib.Path(pack["root_path"]).resolve()).as_posix()
            namespace = hashlib.sha256(f'{pack["pack_id"]}:{rel}'.encode()).hexdigest()[:24]
            filepaths[f'{namespace}::{rel}'] = str(path)
        except Exception as exc:
            compile_errors.append({"path": str(path), "error": str(exc)})
    matches = []
    scan_errors = []
    try:
        compiled = yara.compile(filepaths=filepaths)
        matches = [{"rule": m.rule, "namespace": m.namespace, "source_pack_id": pack["pack_id"], "tags": list(m.tags), "metadata": _metadata(m, filepaths.get(m.namespace, ""))} for m in compiled.match(str(target))]
        status = "PARTIAL" if compile_errors else "COMPLETE"
    except Exception as exc:
        scan_errors.append({"error": str(exc)})
        status = "FAILED"
    goodware_root = pack.get("goodware_root")
    gate = {"status": "NOT_EXECUTED", "files_scanned": 0, "rules_tested": len(filepaths), "matched_goodware_files": [], "offending_rules": [], "match_count": 0, "elapsed_ms": 0}
    if goodware_root and pathlib.Path(goodware_root).is_dir():
        gate_start = time.monotonic(); files = [p for p in pathlib.Path(goodware_root).rglob("*") if p.is_file()]
        gate["files_scanned"] = len(files)
        for sample in files:
            for match in compiled.match(str(sample)):
                gate["match_count"] += 1; gate["offending_rules"].append(match.rule); gate["matched_goodware_files"].append(hashlib.sha256(sample.read_bytes()).hexdigest())
        gate["status"] = "PASS" if gate["match_count"] == 0 else "FAIL"; gate["elapsed_ms"] = round((time.monotonic()-gate_start)*1000)
    pack_results.append({"pack_id": pack["pack_id"], "display_name": pack.get("display_name", pack["pack_id"]), "corpus_content_id": pack["corpus_content_id"], "source_commit": pack.get("source_commit"), "admitted_rule_count": pack["admitted_rule_count"], "quarantined_rule_count": pack["quarantined_rule_count"], "license_mode": pack.get("license_mode", "EXTERNAL"), "freshness": _freshness(pack), "goodware_gate": gate, "signing": _signing(target), "scan_status": status, "match_count": len(matches), "matches": matches, "compile_errors": compile_errors, "scan_errors": scan_errors, "elapsed_ms": round((time.monotonic() - started) * 1000)})
completed = sum(p["scan_status"] in {"COMPLETE", "PARTIAL"} for p in pack_results)
failed = sum(p["scan_status"] == "FAILED" for p in pack_results)
overall = "COMPLETE" if completed == len(pack_results) else "PARTIAL" if completed else "FAILED"
print(json.dumps({"overall_status": overall, "total_match_count": sum(p["match_count"] for p in pack_results), "packs": pack_results, "rule_pack_content_id": hashlib.sha256(json.dumps(registry, sort_keys=True).encode()).hexdigest()}))
