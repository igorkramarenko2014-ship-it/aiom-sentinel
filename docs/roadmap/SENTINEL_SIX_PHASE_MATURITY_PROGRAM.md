# AIOM Sentinel — Calm Integrity

Six-phase maturity program for the local-first deterministic evidence and detection desktop system.

## Phase gates

1. **Phase 1 — Desktop Evidence MVP** (`IN_PROGRESS`): close P1-D progress, cancellation, partial receipts, positive fixtures, parity, and manual acceptance. Commit only after measured closure.
2. **Phase 2 — Detection Orchestrator and Verdict Contract** (`BLOCKED_BY_PHASE_1`): versioned subject, applicability, execution, finding, policy, verdict, and receipt contracts.
3. **Phase 3 — MVP Detection Engines** (`BLOCKED_BY_PHASE_2`): hash reputation, real YARA-compatible engine, explicit ClamAV adapter, bounded static analysis.
4. **Phase 4 — Bounded Archive Member Inspection** (`BLOCKED_BY_PHASE_3`): ZIP/TAR/gzip scopes with depth, member, byte, ratio, timeout, traversal, and cancellation limits.
5. **Phase 5 — Quarantine and Signed Updates** (`BLOCKED_BY_PHASE_4`): explicit quarantine/restore and signed staged updates with rollback/LKG.
6. **Phase 6 — Investor Build and Freeze** (`BLOCKED_BY_PHASE_5`): reproducible candidate, measured demo cases, evidence archive, ratified release gate, and feature freeze.

Global truth: `NO_KNOWN_MATCH` is not `SAFE`; `NOT_APPLICABLE`, `NOT_EXERCISED`, `UNAVAILABLE`, and partial execution remain distinct. `SAFE_TO_RELEASE` is false until Phase 6 ratification.

See `SENTINEL_PHASE_LEDGER.json` for machine-readable gates and `scripts/verify_sentinel_phase_ledger.py` for validation.
