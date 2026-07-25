# ADR-006: Quarantine Key Management

implementation_authority: NONE
current_runtime_status: DESIGN_ONLY

## Status
Accepted as a Phase 5 prerequisite.

## Context
DPAPI, keyrings, or platform keystores alone do not define complete recovery and authorization.

## Decision
Use platform root protection where available, wrapped per-object/epoch data keys, authenticated
content-addressed storage, rotation, revocation, zeroization, backup/restore, and audited authorization.

## Alternatives
One machine-wide key and mandatory VSS snapshots were rejected.

## Consequences
Recovery ownership, escrow policy, lifecycle ceremonies, and restore metadata become mandatory.

## Security Impact
Object compromise is bounded and unauthorized restore/read attempts are auditable.

## Privacy Impact
Quarantined content is restricted, minimized, retained by policy, and region-bound.

## Availability Impact
Key loss can make recovery impossible; tested backup and emergency recovery are required.

## Verification Requirements
Rotation, revocation, wrong-role, restore, corruption, backup, zeroization, and disaster-recovery tests.

## Implementation Phase
Phase 5; no current implementation authority.

## Unresolved Questions
Escrow authority, hardware requirements, retention, and cross-device recovery remain open.
