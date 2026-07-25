# ADR-016 C as Canonical Native ABI
implementation_authority: NONE
current_runtime_status: DESIGN_ONLY
## Status
Accepted.
## Context
C++ ABI is compiler-specific.
## Decision
C is the canonical in-process ABI; C++ may be internal behind it. Versioned authenticated IPC is preferred across privilege boundaries.
## Alternatives
Public C++ ABI is rejected.
## Consequences
No STL, templates, exceptions, or Rust-native layouts cross the boundary.
## Security Impact
Ownership and panic containment are explicit.
## Privacy Impact
Bounded encoded payloads only.
## Availability Impact
Major ABI mismatch rejects safely.
## Verification Requirements
ABI contract review.
## Implementation Phase
Design only.
## Unresolved Questions
Fixture adapter conformance.
