# ADR-002: Worker Isolation

implementation_authority: NONE
current_runtime_status: DESIGN_ONLY

## Status
Accepted for future design.

## Context
Parsers consume attacker-controlled bytes and must not share privileged service authority.

## Decision
Run bounded scan/plugin work in separate low-privilege processes with scoped handles, bounded IPC,
CPU/memory/time limits, crash containment, and controlled respawn.

## Alternatives
In-process privileged parsing was rejected; unrestricted file copies to plugins were rejected.

## Consequences
IPC and lifecycle complexity increase, while parser compromise blast radius decreases.

## Security Impact
Capabilities are explicit; workers cannot mutate targets or grant themselves access.

## Privacy Impact
Raw content is denied by default and needs purpose-bound policy authority.

## Availability Impact
Worker crashes degrade one scan, not the service or host.

## Verification Requirements
Sandbox escape review, resource exhaustion, malformed input, crash/respawn, and capability tests.

## Implementation Phase
Phase 2/3 prerequisite; no current implementation authority.

## Unresolved Questions
Per-platform sandbox technology and brokered-handle semantics remain open.
