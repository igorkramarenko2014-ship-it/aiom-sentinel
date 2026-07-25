# Phase 1 Release Notes

release_state: RELEASE_CANDIDATE
implementation_authority: PHASE_1_ONLY

## Delivered

- User-mode, read-only static scanning of explicit files and opt-in recursive directories.
- SHA-256, SHA-1, MD5, entropy, bounded PE metadata, local literal rules, evidence JSON, and timelines.
- Evidence schema 1.1.0 with risk, threat/benign confidence, and evidence-quality fields.
- Unit and integration tests, benchmarks, fuzz targets, documentation, and local verification tools.

## Boundary

There is no runtime Phase 2 functionality. The enterprise documents are design-only and do not
authorize collectors, monitoring, response, quarantine, containment, update, or telemetry code.

## Publication state

No commit, tag, remote push, package publication, or release artifact has been created. The current
candidate is for senior technical review only.
