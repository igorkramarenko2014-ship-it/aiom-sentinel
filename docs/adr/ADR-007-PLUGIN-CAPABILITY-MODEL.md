# ADR-007: Plugin Capability Model

implementation_authority: NONE
current_runtime_status: DESIGN_ONLY

## Status
Accepted for future design.

## Context
Third-party parsers and detectors must not inherit service privilege or unrestricted raw content.

## Decision
Use signed/versioned plugins in separate sandboxes with deny-by-default capabilities, message passing,
bounded resources, explicit schema compatibility, raw-content grants, revocation, and kill switches.

## Alternatives
In-process dynamic libraries and unrestricted file paths were rejected.

## Consequences
Capability brokering and compatibility migrations add complexity but reduce blast radius.

## Security Impact
Compromised plugins cannot directly access kernel/service authority or unrelated files.

## Privacy Impact
Raw bytes and identity fields require purpose-bound capability and audit.

## Availability Impact
Plugin failure disables only that capability; core detection continues in degraded mode.

## Verification Requirements
Capability denial, schema mismatch, resource exhaustion, crash, revocation, signature, and escape tests.

## Implementation Phase
Phase 3 or later; no current implementation authority.

## Unresolved Questions
Sandbox runtimes, plugin SDK, trust policy, and compatibility horizon remain open.
