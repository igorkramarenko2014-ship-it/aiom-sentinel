# ADR-012 Cross-Platform From Origin

implementation_authority: NONE
current_runtime_status: DESIGN_ONLY

## Status
Accepted.
## Context
Platform-specific assumptions in shared contracts create lock-in.
## Decision
AIOM Sentinel is cross-platform by architecture, platform-specific by telemetry implementation,
and platform-verified only where evidence exists. Shared contracts use explicit capability states.
## Alternatives
Platform-first shared domain logic is rejected.
## Consequences
Not implemented is distinct from unsupported and authorization failure.
## Security Impact
Avoids fabricated support claims.
## Privacy Impact
Native identity is optional and platform-specific.
## Availability Impact
Unsupported formats remain controlled evidence outcomes.
## Verification Requirements
Portability verifier and platform matrix review.
## Implementation Phase
Phase 1 domain contracts only.
## Unresolved Questions
Remote CI evidence is pending.
