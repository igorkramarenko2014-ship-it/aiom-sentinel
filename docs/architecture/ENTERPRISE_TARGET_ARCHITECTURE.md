# Enterprise Target Architecture

implementation_authority: NONE
current_runtime_status: DESIGN_ONLY

## Current state

Phase 1 is the only implemented runtime: a standalone, user-mode, read-only static scanner with
bounded traversal, streaming hashes, bounded PE metadata, harmless local rules, and JSON evidence.

## Future component boundaries

| Component | Privilege | Authority and boundary |
|---|---|---|
| OS-specific sensor | Minimum platform-required privilege | Bounded metadata and stable identities only; never default full-file kernel copies |
| Privileged service | Service account | Authenticates sensors, owns policy, brokered handles, and response authorization |
| Scan worker | Low privilege, isolated | Parses authorized bounded content; no direct target mutation or network |
| Evidence engine | Local service boundary | Append-only records, integrity metadata, retention and chain continuity |
| Correlation engine | User mode | Multi-signal detection and contradicting-evidence evaluation |
| Policy/response engine | Privileged service | Enforces the response authority matrix and rollback requirements |
| Plugin sandbox | Separate constrained process | Versioned capability grants; raw content denied by default |
| Update plane | Separate trust boundary | Public-key verified manifests, immutable snapshots, atomic activation, last-known-good rollback |
| Evidence/quarantine plane | Encrypted storage | Future capability with independent key, recovery, retention, and authorization contracts |
| Central management | Remote management plane | Future fleet policy and evidence exchange; no implicit endpoint authority |
| AI explanation layer | Unprivileged advisory layer | Reads authorized normalized evidence; cannot alter verdicts or authorize response |

## Canonical principles

- Evidence-first, least privilege, bounded blocking, last-known-good recovery, no silent degradation.
- A valid signature is one signal, never unconditional trust or scan bypass.
- Security-critical cache keys include platform and volume identity, change indicator, content hash,
  policy/rule/engine versions, and revalidation.
- Vendor update trust roots in offline asymmetric signing; endpoint-held HMAC is not sufficient.
- Performance values remain `TARGET_OR_HYPOTHESIS` until the full measurement context is recorded.
