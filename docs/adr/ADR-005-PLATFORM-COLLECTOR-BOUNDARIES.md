# ADR-005: Platform Collector Boundaries

implementation_authority: NONE
current_runtime_status: DESIGN_ONLY

## Status
Accepted for future design.

## Context
Windows, Linux, and macOS expose different privilege, event, loss, signing, and configuration models.

## Decision
Maintain separate collector contracts and normalize only at the versioned event boundary. Documented
APIs are normative; unstable internals and fixed addresses remain research.

## Alternatives
One universal kernel collector and universal registry model were rejected.

## Consequences
Platform teams and compatibility matrices are required, but false equivalence is avoided.

## Security Impact
Privileges, source integrity, event loss, and backpressure are explicit per platform.

## Privacy Impact
Native fields receive platform-specific minimization and redaction before normalization.

## Availability Impact
Each collector can degrade/disable independently without taking down the core service.

## Verification Requirements
Supported-version, fidelity, loss, privilege, signing/entitlement, load, crash, upgrade and rollback tests.

## Implementation Phase
Phase 2 shadow mode; no current implementation authority.

## Unresolved Questions
Exact OS matrices and initial source subset require primary-source review.
