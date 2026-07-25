# ADR-009: Detection Scoring

implementation_authority: NONE
current_runtime_status: DESIGN_ONLY

## Status
Accepted for contracts; Phase 1 static evidence aligned.

## Context
One confidence value conflates impact, threat likelihood, benign evidence, source quality, and coverage.

## Decision
Separate `risk_score`, `threat_confidence`, `benign_confidence`, `evidence_quality`, and
`telemetry_quality`; preserve contributing and contradicting signals. Entropy alone is never a verdict.

## Alternatives
One “confidence” percentage and signature/entropy-only hard blocking were rejected.

## Consequences
Rules must document calibration, contradiction handling, missing telemetry, and response thresholds.

## Security Impact
Prevents weak evidence from appearing authoritative and supports multi-signal correlation.

## Privacy Impact
Higher confidence cannot justify raw data collection without a separate privacy gate.

## Availability Impact
Response policy can distinguish risk from evidence quality before blocking.

## Verification Requirements
Positive, negative, contradictory, degraded, calibration, replay, and false-positive tests.

## Implementation Phase
Phase 1 evidence schema and Phase 3 detection engine; no Phase 3 authority.

## Unresolved Questions
Calibration corpora and category-specific thresholds remain unmeasured.
