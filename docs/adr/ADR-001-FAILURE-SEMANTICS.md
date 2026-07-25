# ADR-001: Failure Semantics

implementation_authority: NONE
current_runtime_status: DESIGN_ONLY

## Status
Accepted for future design.

## Context
A universal fail-closed policy can turn a security failure into fleet-wide unavailability.

## Decision
Use the failure matrix: block only when bounded and reversible; otherwise preserve availability,
last-known-good state, explicit degraded status, and evidence.

## Alternatives
Global fail-closed was rejected; global fail-open was rejected for silently discarding security intent.

## Consequences
Every critical path needs timeout, fallback, operator visibility, and rollback policy.

## Security Impact
Prevents silent bypass while retaining bounded secure decisions.

## Privacy Impact
Failure evidence remains minimized and classified.

## Availability Impact
Boot-critical and service-outage paths prefer operational safety.

## Verification Requirements
Timeout, crash, storage, invalid-update, LKG, boot-critical, and policy-outage tests.

## Implementation Phase
Phase 2 design prerequisite; implementation authority remains absent.

## Unresolved Questions
Per-asset wait budgets and emergency policy ownership require approval.
