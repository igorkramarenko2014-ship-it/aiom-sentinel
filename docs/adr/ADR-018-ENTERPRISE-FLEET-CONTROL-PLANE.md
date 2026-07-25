# ADR-018 Enterprise Fleet Control Plane
implementation_authority: NONE
current_runtime_status: DESIGN_ONLY
## Status
Accepted.
## Context
Fleet management must not become scanning execution.
## Decision
Control plane manages inventory, policy, approvals, references, audit, and licensing; endpoint keeps last-known-good signed policy during outage.
## Alternatives
Cloud-required scanning is rejected.
## Consequences
No outage fail-open.
## Security Impact
Hard-safety constraints cannot be bypassed.
## Privacy Impact
Bounded evidence summaries only.
## Availability Impact
Local operation continues offline.
## Verification Requirements
Enterprise contract review.
## Implementation Phase
Design only.
## Unresolved Questions
On-prem topology.
