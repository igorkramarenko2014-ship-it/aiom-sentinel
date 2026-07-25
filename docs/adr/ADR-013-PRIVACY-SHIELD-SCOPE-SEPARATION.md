# ADR-013 Privacy Shield Scope Separation

implementation_authority: NONE
current_runtime_status: DESIGN_ONLY

## Status
Accepted.
## Context
Ad and tracker filtering are product policy, not static scanning.
## Decision
Privacy Shield is an optional layer separate from core protection. Rules must be declarative,
reversible, visible, capability-aware, documented, recoverable, and safe for OS upgrades.
## Alternatives
Merging privacy policy into scanner enforcement is rejected.
## Consequences
No OS component is disabled or deleted by core scanning.
## Security Impact
Prevents scope expansion into hidden policy mutation.
## Privacy Impact
Rules require transparent operator authority.
## Availability Impact
Recovery is required for every future rule.
## Verification Requirements
Portability verifier checks scope separation.
## Implementation Phase
Design only.
## Unresolved Questions
Platform policy adapters require separate authority.
