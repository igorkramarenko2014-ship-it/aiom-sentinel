# ADR-010: Response Authority

implementation_authority: NONE
current_runtime_status: DESIGN_ONLY

## Status
Accepted for future policy design.

## Context
Immediate destructive actions can cause data loss, fleet outage, and unrecoverable identity changes.

## Decision
Use `OBSERVE → ENRICH → ALERT → RESTRICT → SUSPEND → CONTAIN → ISOLATE_HOST → QUARANTINE →
ERADICATE`, with explicit automation, approval, reversibility, blast radius, asset criticality,
evidence/confidence threshold, timeout, and rollback for every action.

## Alternatives
Automatic kill/isolate/delete and recommendation-only policy without enforcement gates were rejected.

## Consequences
Actions require owners, policy versions, audit, expiry, and recovery drills.

## Security Impact
Narrow reversible automation remains possible without granting autonomous destructive authority.

## Privacy Impact
Memory, credential, identity, and raw-content actions require separate case/role/privacy authorization.

## Availability Impact
Critical assets and boot paths receive stricter approval and rollback requirements.

## Verification Requirements
False-positive, timeout, expiry, rollback, critical-asset, identity-plane, and blast-radius exercises.

## Implementation Phase
Phase 4+; no current implementation authority.

## Unresolved Questions
Approval roles, emergency authority, asset tiers, and identity-plane ownership remain open.
