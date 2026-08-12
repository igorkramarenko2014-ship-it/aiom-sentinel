# AIOM Sentinel — Post-2026-08-12 Grok Review Pack

ROLE: INDEPENDENT_REVIEWER

Do not implement unless explicitly authorized. Review CS15-CS19, the focused regressions,
false-positive matrix, source governance, static/runtime distinction, and telemetry limitations.

1. Verify the ZIP SHA-256 against the accompanying `.sha256` file.
2. Verify `WORKTREE_MANIFEST.json` and its listed file hashes.
3. Treat this packaged working tree as the post-10-Aug implementation authority.
4. Do not reconstruct the implementation from Git HEAD alone.
5. Confirm `crates/sentinel-core/src/threat_coverage.rs` exists.
6. Confirm `crates/sentinel-scanner/src/macos_analysis.rs` exists.
7. Confirm `crates/sentinel-scanner/src/supply_chain_analysis.rs` exists.
8. Read `VERIFIED_BASELINE_2026-08-10.md` before making claims.
9. Read the 11-Aug delta roadmap supplied with this handoff, if present.
10. Review CS15-CS19 only; do not expand scope into production response wiring.

Verify the pack hash, manifest, source presence, test receipt, diff, coverage claims, and
product-honesty claims. Attempt compilation/tests only if Rust/Cargo >=1.93 is actually observable.
If the runtime is older, perform source/evidence review only and say so explicitly.

## Runtime gate

Source readiness does not imply execution-runtime readiness. Sentinel requires Rust/Cargo
1.93 or newer for causal compile and test claims.
