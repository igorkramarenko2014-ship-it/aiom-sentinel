# Autoloader Pass A — STOP.missing_compiler_semantics
status: BLOCKED_MISSING_COMPILER_SEMANTICS
evidence_tier: AE3
production_status: NOT_PRODUCTION_VALIDATED

## Scope

This report records the pre-mutation stop reached during Sentinel Autoloader
Pass A. Pass F established and locally tested the strict Ed25519 verification
foundation and scanner-owned atomic ruleset replacement. No Autoloader implementation source was mutated during Pass A. Repository mutations during
checkpoint closure were limited to this factual STOP report and mechanical
removal of trailing whitespace from 28 staged Markdown files; the whitespace
normalization introduced no intended semantic change.

The pre-amend local checkpoint identity was
`dd626352423332a6fe2eeea8beb72a777079febc`.

The repaired
`architecture-input/AIOM_SENTINEL_RULE_COMPILER_AUTOLOADER_CANONICAL_BASIS_v1.1`
is a byte-verified schema/design basis. Its packaged verifier passes, but it is
not executable compiler authority and does not define a complete runtime bundle.

## Reproduced compiler mismatch

The physical rule-source schema accepts only `language: "YARA_X"`, and its valid
fixture contains:

```text
rule test { condition: true }
```

The production `LocalRuleEngine` accepts exactly five pipe-delimited literal
fields. Feeding the canonical valid fixture into the real CLI rule-loading path
reproduced the mismatch:

```text
$ cargo run -q --locked -p sentinel-cli -- scan \
    tests/fixtures/harmless-negative.txt \
    --rules architecture-input/AIOM_SENTINEL_RULE_COMPILER_AUTOLOADER_CANONICAL_BASIS_v1.1/examples/valid/rule-source.json
sentinel: rule must contain exactly five pipe-delimited fields
EXIT=3
```

The repository contains no YARA-X parser/compiler dependency. Translating
YARA-X into the literal adapter would invent an unauthorised private rule
language, so the pre-mutation gate correctly stopped.

## Contract conflicts and missing authority

- The basis signature envelope describes a Base64 signature and inner domain
  `AIOM_SENTINEL_RULE_BUNDLE_V1`; the Pass F verifier requires strict lowercase
  64-byte hex and prefixes
  `AIOM_SENTINEL_RULE_BUNDLE_SIGNATURE_V1\0`. No executable contract reconciles
  the domain layering, encoding, duplicated key IDs, or exact JCS preimage.
- The 14 valid fixtures are heterogeneous schema examples, not 14 complete
  compilable bundles. No candidate binds manifest, rule source, metadata and
  signature into one executable input.
- The exact `bundle_content_id` domain, semantic preimage, exclusions and
  relationship to `bundle_id`, `canonical_manifest_hash`, rule IDs and compiled
  artifact identity are not defined.
- There is no canonical approval receipt schema binding decision, actor,
  authority boundary, timestamp, policy version, bundle identity, compiled
  artifact identity and rollback intent.
- There is no canonical durable PREPARED/COMMITTED LKG form, record checksum,
  recovery transition table, downgrade ordering, rollback receipt, or exact
  authenticated rollback authority.
- The portability contract requires Unicode NFC and casefold collision
  controls, but the approved dependency closure contains no complete Unicode
  normalization/casefold primitive.

Because these are enforcement semantics rather than naming details, proceeding
would risk false activation and unverifiable rollback.

## Pre-mutation artifact receipt

```text
baseline_archive:
  /private/tmp/aiom-sentinel-pass-a-baseline.7z3p05/AIOM-Sentinel-pre-pass-a.tar
baseline_archive_sha256:
  242143cf4742562593ba6d6472ea68be0a8087429e79dc74ff459c4bf63a97d0
baseline_manifest_sha256:
  29fcf2bc8a20f36d2a67ebed1d82964b6bc4f770173a3e8e1f3ae42817a3f628
baseline_inventory_sha256:
  ddef60734bffbd6e3502803b0a6c54208eb52f4c3cd77ecf899ee32f090fa23e
baseline_inventory:
  388/388 files verified
cargo_lock_sha256:
  4c438c24ae3dd0bf0f4fff67df2c8527347b9a118bc60304668494f1fa205247
```

`Command Gate: Pasted Text.txt (27).txt` was already absent and was not restored,
deleted, or attributed to Pass A. Baseline archives remain outside the
repository and must not be committed.

## Exact next operator choices

1. Publish a corrected canonical-basis version defining a complete literal-rule
   bundle compatible with `LocalRuleEngine`, exact content/signature preimages,
   approval and LKG schemas, downgrade/rollback ordering, capability registry,
   and fixture-to-schema expected-error mapping.
2. Authorise a separate dependency and architecture review for a real YARA-X
   compiler/scanner plus Unicode NFC and full casefold primitives, while also
   supplying the missing bundle, identity, signature, approval, LKG and rollback
   contracts. Dependency authorisation alone does not close the contract gaps.

Until one choice is completed:

```text
Autoloader: BLOCKED_MISSING_COMPILER_SEMANTICS
safeToFinalizeAutoloader: false
safeToMerge: false
safeToRelease: false
safeToStartCommander: false
```
