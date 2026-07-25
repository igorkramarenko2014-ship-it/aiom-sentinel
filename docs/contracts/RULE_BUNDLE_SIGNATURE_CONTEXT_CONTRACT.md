# Rule Bundle Signature Context Contract
implementation_authority: PASS_F_FOUNDATION_ONLY
current_runtime_status: IMPLEMENTED_TESTED_LOCAL_FOUNDATION

RFC 8785/JCS, UTF-8, explicit signature domain, key ID, algorithm, and fields
are required; signature bytes are excluded from their own preimage.

The production verifier accepts only Ed25519 public keys from the
repository-pinned registry. The algorithm token is exactly `ED25519`; keys are
32 bytes in strict lowercase hex and are either `ACTIVE` or `REVOKED`.
`TEST_ONLY` keys are rejected by the production registry path.

The verified message is:

```text
AIOM_SENTINEL_RULE_BUNDLE_SIGNATURE_V1\0
||
RFC8785_JCS_CANONICAL_SIGNATURE_CONTEXT_BYTES
```

Verification uses `ed25519_dalek::VerifyingKey::verify_strict`. Production code
does not load, generate, retain, or expose private keys or a signing API.

This foundation verifies caller-supplied canonical signature-context bytes.
Construction and cross-field validation of those canonical bytes remains the
Autoloader Pass A responsibility.
