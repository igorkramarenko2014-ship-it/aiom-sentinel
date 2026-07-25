# ADR-003: Evidence Integrity

implementation_authority: NONE
current_runtime_status: DESIGN_ONLY

## Status
Accepted for future design.

## Context
Incident decisions require attributable, ordered, tamper-evident evidence without implying truth
from collection alone.

## Decision
Use append-only versioned records, source sequence, payload hashes, chain continuity, explicit gaps,
retention/access policy, and case-linked export. Local HMAC may protect a journal but is not update trust.

## Alternatives
Mutable event tables and unverifiable flat logs were rejected.

## Consequences
Storage, rotation, migration, and verification become explicit operational responsibilities.

## Security Impact
Tampering and loss become detectable; evidence quality remains separate from verdict confidence.

## Privacy Impact
Minimization, redaction, retention, regional policy, and access audit apply before persistence/export.

## Availability Impact
A bounded spool prevents storage outage from immediately blocking host operation.

## Verification Requirements
Chain-break, replay, duplicate, loss, rotation, migration, access, and recovery tests.

## Implementation Phase
Phase 2/3; no current implementation authority.

## Unresolved Questions
Attestation root, retention periods, and regional key ownership remain open.
