# ADR-017 Personal Device Policy Authority
implementation_authority: NONE
current_runtime_status: DESIGN_ONLY
## Status
Accepted.
## Context
Personal devices are an approval surface, not root control.
## Decision
Only signed, scoped, nonce-protected, expiring typed intents may be approved after local validation; phone is not sole recovery authority.
## Alternatives
Remote shell and bearer authority are rejected.
## Consequences
Recovery, revocation, pairing inventory, and break-glass are required.
## Security Impact
No AI-generated privileged commands.
## Privacy Impact
Evidence summaries are bounded.
## Availability Impact
Local administrator recovery exists.
## Verification Requirements
Intent contract review.
## Implementation Phase
Design only.
## Unresolved Questions
Maximum device count.
