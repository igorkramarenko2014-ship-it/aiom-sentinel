# ADR-020 Secrets and Key Management
implementation_authority: NONE
current_runtime_status: DESIGN_ONLY
## Status
Accepted.
## Context
Fleet secrets cannot be universally trusted.
## Decision
Use KMS/HSM/Vault-compatible references, envelope encryption, tenant separation, unique devices, rotation, revocation, expiry, and audit.
## Alternatives
Plaintext database or universal fleet secret is rejected.
## Consequences
Database records references, not secret plaintext.
## Security Impact
Least privilege and recovery required.
## Privacy Impact
Keys separate tenant data.
## Availability Impact
Disaster recovery is mandatory.
## Verification Requirements
Key hierarchy review.
## Implementation Phase
Design only.
## Unresolved Questions
Provider portability.
