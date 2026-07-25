# ADR-021 Mobile Authentication Is Not SSH
implementation_authority: NONE
current_runtime_status: DESIGN_ONLY
## Status
Accepted.
## Context
Login, device identity, and approval authority differ.
## Decision
Use OIDC/OAuth Authorization Code + PKCE, device-bound asymmetric keys, and signed policy intents. SSH is not mobile authentication or administration.
## Alternatives
SSH shell/server and universal SSH key are rejected.
## Consequences
Hardware-backed claims remain unverified until measured.
## Security Impact
No remote shell.
## Privacy Impact
Authentication data is bounded.
## Availability Impact
Recovery is independent of phone.
## Verification Requirements
Mobile threat model review.
## Implementation Phase
Design only.
## Unresolved Questions
Transport selection.
