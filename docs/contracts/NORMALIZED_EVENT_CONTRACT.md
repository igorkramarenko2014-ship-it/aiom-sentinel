# Normalized Event Contract

implementation_authority: NONE
current_runtime_status: DESIGN_ONLY

Required envelope fields are `schema_version`, `event_id`, `event_type`, `timestamp_observed`,
`timestamp_ingested`, `host_id`, `os_family`, `collector_id`, `collector_version`, `action`, `result`,
`raw_source_reference`, `telemetry_quality`, `privacy_class`, and `correlation_id`. Optional,
event-dependent fields are `process_identity`, `parent_identity`, `user_identity`, `object_identity`,
and `causal_parent_id`.

Platform identities retain native IDs plus normalized stable representations; missing fields are
explicitly `null` with a reason, never synthesized. Raw references point to authorized local evidence,
not embedded content. Privacy classes are `PUBLIC`, `SYSTEM`, `USER_METADATA`, `SENSITIVE`, and
`RESTRICTED_CONTENT`; redaction occurs before durable export.

Ordering uses collector sequence plus observed/ingested time and clock-uncertainty milliseconds.
Duplicates retain a source fingerprint and deduplication disposition. Integrity metadata includes
collector identity, sequence, payload hash, and optional signature/attestation. Partial events declare
missing fields and telemetry quality `DEGRADED` or `PARTIAL`; only complete validated sources use
`COMPLETE`. Schema evolution is additive within a major version and rejects unknown incompatible majors.

Windows, Linux, and macOS mappings live in separate collector contracts; no universal registry or
kernel event is invented.
