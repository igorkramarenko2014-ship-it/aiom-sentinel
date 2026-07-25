# ADR-004: Update Trust

implementation_authority: NONE
current_runtime_status: DESIGN_ONLY

## Status
Accepted for future design.

## Context
Endpoint-held symmetric secrets cannot be the sole vendor-signature trust root.

## Decision
Use an offline vendor signing key, signed manifest, immutable snapshots, chunk/Merkle hashes,
endpoint public-key verification, atomic activation, staged rollout, version pinning, and LKG rollback.

## Alternatives
Per-record HMAC as vendor trust and in-place mutable updates were rejected.

## Consequences
Offline key ceremonies, rotation, revocation, transparency, and recovery processes are required.

## Security Impact
Compromised endpoints cannot mint vendor-valid update manifests with verification material alone.

## Privacy Impact
Update telemetry exposes only version/health metadata unless separately authorized.

## Availability Impact
Invalid updates never replace LKG; rollout health gates limit blast radius.

## Verification Requirements
Invalid signature, rollback, replay, downgrade, partial download, atomicity, revocation, and canary tests.

## Implementation Phase
Phase 5; no current implementation authority.

## Unresolved Questions
Algorithm suite, root rotation, offline ceremony, and transparency service remain open.
