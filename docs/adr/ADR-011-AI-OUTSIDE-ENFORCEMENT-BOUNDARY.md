# ADR-011 AI Outside Enforcement Boundary

implementation_authority: NONE
current_runtime_status: DESIGN_ONLY

## Status
Accepted.
## Context
AI output is probabilistic and cannot substitute for verified evidence or deterministic authority.
## Decision
AI and ML may analyze verified evidence. AI and ML may not directly control privileged enforcement.
AI cannot delete, quarantine, mutate firewall policy, command kernel components, terminate processes,
revoke credentials, collect unrestricted memory, override deterministic policy, or override evidence gates.
## Alternatives
Direct autonomous enforcement is rejected.
## Consequences
Recommendations require deterministic policy and authorized human action.
## Security Impact
Prevents model output from becoming privileged control.
## Privacy Impact
AI receives only evidence authorized for analysis.
## Availability Impact
No enforcement action depends on model availability.
## Verification Requirements
`node tools/verify-portability.mjs`.
## Implementation Phase
Design only.
## Unresolved Questions
Authorized review workflows require a separate phase.
