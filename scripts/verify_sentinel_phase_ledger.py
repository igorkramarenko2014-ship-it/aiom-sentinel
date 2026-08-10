#!/usr/bin/env python3
"""Verify the six-phase Sentinel maturity ledger invariants."""
import json
import pathlib
import sys

def fail(code: str, message: str) -> None:
    print("SENTINEL_PHASE_LEDGER: FAIL")
    print(f"CODE: {code}")
    print(f"MESSAGE: {message}")
    raise SystemExit(1)

path = pathlib.Path(sys.argv[1]) if len(sys.argv) > 1 else pathlib.Path("docs/roadmap/SENTINEL_PHASE_LEDGER.json")
try:
    data = json.loads(path.read_text(encoding="utf-8"))
except (OSError, json.JSONDecodeError) as exc:
    fail("INVALID_JSON", str(exc))
for key in ("schema_version", "program_id", "product", "phases", "safe_to_release"):
    if key not in data: fail("MISSING_TOP_LEVEL_FIELD", key)
if not isinstance(data["safe_to_release"], bool): fail("INVALID_SAFE_TO_RELEASE", "must be boolean")
phases = data["phases"]
if not isinstance(phases, list) or len(phases) != 6: fail("PHASE_COUNT", "exactly six phases required")
required = ("phase_id", "title", "status", "entry_gate", "deliverables", "automated_gates", "manual_gates", "stop_conditions", "commit_boundary", "evidence_refs")
allowed = {"IN_PROGRESS", "COMPLETE", "ACCEPTED", *(f"BLOCKED_BY_PHASE_{i}" for i in range(1, 6))}
ids = [p.get("phase_id") for p in phases]
if ids != [f"PHASE_{i}" for i in range(1, 7)] or len(set(ids)) != 6: fail("PHASE_ORDER", "canonical unique phase order required")
for i, phase in enumerate(phases):
    for key in required:
        if key not in phase: fail("MISSING_PHASE_FIELD", f"{phase.get('phase_id')}: {key}")
    for key in ("deliverables", "automated_gates", "manual_gates", "stop_conditions"):
        if not isinstance(phase[key], list) or not phase[key]: fail("INVALID_GATE_LIST", f"{phase['phase_id']}: {key}")
    if not isinstance(phase["evidence_refs"], list): fail("INVALID_EVIDENCE_REFS", phase["phase_id"])
    if phase["status"] not in allowed: fail("INVALID_STATUS", phase["status"])
    if i and phase["status"].startswith("BLOCKED") and phase["status"] != f"BLOCKED_BY_PHASE_{i}": fail("BLOCKED_PREDECESSOR", phase["phase_id"])
active = [p for p in phases if p["status"] == "IN_PROGRESS"]
if len(active) > 1: fail("MULTIPLE_ACTIVE_PHASES", "at most one phase may be in progress")
for i, phase in enumerate(phases):
    if phase["status"] in {"IN_PROGRESS", "COMPLETE", "ACCEPTED"} and any(p["status"] not in {"ACCEPTED"} for p in phases[:i]): fail("SEQUENTIAL_DEPENDENCY", phase["phase_id"])
if data["safe_to_release"]:
    if any(p["status"] != "ACCEPTED" for p in phases): fail("PREMATURE_RELEASE", "all phases must be accepted")
    if not any("release-ratification" in ref.lower() for ref in phases[-1]["evidence_refs"]): fail("MISSING_RELEASE_RATIFICATION", "Phase 6 evidence must name release ratification")
print("SENTINEL_PHASE_LEDGER: PASS")
