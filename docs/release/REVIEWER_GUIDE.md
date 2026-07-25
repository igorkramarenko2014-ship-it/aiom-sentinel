# Reviewer Guide

implementation_authority: REVIEW_ONLY

## Start here

1. Read `README.md`, `docs/THREAT-MODEL.md`, and `docs/EVIDENCE-CONTRACT.md` for actual Phase 1 behavior.
2. Run the commands in `docs/release/VERIFICATION_RECEIPT.md` from a clean temporary copy.
3. Inspect `crates/sentinel-scanner/`, `crates/sentinel-evidence/`, and `crates/sentinel-cli/` for the data path.
4. Confirm workspace crates use `#![forbid(unsafe_code)]` and search for owned `unsafe` blocks.
5. Review `docs/research/KIMI_CLAIM_LEDGER.md`; entries are defensive design analysis, never implementation authority.
6. Inspect `docs/release/DEPENDENCY_REVIEW.md` and rerun supply-chain tooling when available.
7. Review path and identity boundaries, malformed format probes, PE limits, AI boundary, support claims,
   Phase 1/design separation, and the high-risk assumption that local macOS evidence does not prove other platforms.

## Review questions

- Does every scan outcome preserve the read-only boundary?
- Are evidence fields and exit codes consistent with the documented contracts?
- Do resource limits and parse failures remain explicit rather than silently ignored?
- Does CI execute only checks that are meaningful without the restricted raw corpus?

## Design-pack boundary

`docs/architecture/`, `docs/contracts/`, `docs/platform/`, `docs/formats/`, and `docs/adr/` describe
future-state contracts. They are not evidence that collectors or response actions exist.
