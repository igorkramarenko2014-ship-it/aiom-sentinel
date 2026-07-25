# ADR-014 Untrusted Sample Isolation
implementation_authority: NONE
current_runtime_status: DESIGN_ONLY
## Status
Accepted.
## Context
Untrusted samples and privileged experiments have host risk.
## Decision
HOST_DEVELOPMENT and EPHEMERAL_CI use harmless synthetic fixtures only. DISPOSABLE_MALWARE_LAB and PRIVILEGED_PLATFORM_LAB use disposable images, no credentials, mounts, clipboard, drag-and-drop, or shared folders; isolated network and revert/destroy are required. VM isolation is not absolute.
## Alternatives
Primary-workstation execution is rejected.
## Consequences
No malware sample enters repository or public export.
## Security Impact
Reduces exposure to hostile input.
## Privacy Impact
No personal credentials in labs.
## Availability Impact
Snapshots provide recovery.
## Verification Requirements
Portability verifier checks lab boundaries.
## Implementation Phase
Design only.
## Unresolved Questions
Lab provider selection.
