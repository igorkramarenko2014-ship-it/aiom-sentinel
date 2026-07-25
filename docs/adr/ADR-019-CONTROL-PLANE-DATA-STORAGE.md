# ADR-019 Control Plane Data Storage
implementation_authority: NONE
current_runtime_status: DESIGN_ONLY
## Status
Accepted.
## Context
Authoritative state differs from cache and artifacts.
## Decision
PostgreSQL is authoritative, object storage holds large artifacts, endpoint SQLite holds bounded local state; caches and queues are not authoritative.
## Alternatives
Cache as source of truth is rejected.
## Consequences
Backup, residency, encryption, export, restore, and cost require design review.
## Security Impact
Logical data separation is required.
## Privacy Impact
Retention boundaries apply.
## Availability Impact
Offline queue is bounded.
## Verification Requirements
Storage strategy review.
## Implementation Phase
Design only.
## Unresolved Questions
Measured analytics workload.
