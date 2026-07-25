# ADR-022 Local-First Endpoint Scanning
implementation_authority: NONE
current_runtime_status: DESIGN_ONLY
## Status
Accepted.
## Context
Scanning must work under network loss.
## Decision
Rules, models, policies flow down; bounded evidence summaries flow up; raw files stay local by default. RAW_SAMPLE_UPLOAD_DEFAULT: DISABLED.
## Alternatives
Mandatory cloud scanning is rejected.
## Consequences
Queues are bounded and critical loss is explicit.
## Security Impact
Cloud loss never widens permissions.
## Privacy Impact
Raw upload needs explicit incident authority.
## Availability Impact
Endpoint scans offline.
## Verification Requirements
Telemetry contract review.
## Implementation Phase
Design only.
## Unresolved Questions
Measured resource budgets.
