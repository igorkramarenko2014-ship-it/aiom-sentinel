# ADR-002: Local Persistence

Status: ACCEPTED FOR P0, implementation deferred to P3
Date: 2026-08-05

## Decision

Use a deterministic local JSON store for the first product milestone. SQLite is deferred until measured history volume, concurrent writes, or query requirements justify its operational cost.

## Stored data

- scan identifier
- timestamp with source disclosure
- user-facing target label
- summary and completion state
- exported receipt identity or embedded receipt
- application, core, rule-pack, and evidence-schema versions

No file contents, silent path expansion, uploaded hashes, telemetry, or secrets are stored.

## Invariants

- `PERSIST-01`: writes are local-only; network is not required for scanning.
- `PERSIST-02`: deleting a history row requires explicit user confirmation and does not delete scan targets or receipts.
- `PERSIST-03`: receipt identity is deterministic for deterministic input.
- `PERSIST-04`: corrupt or partial history is a structured error and cannot crash the UI.

## Migration and rollback

Version the store schema from its first write. A failed write leaves the prior record intact. Before SQLite adoption, measure record volume and query latency; until then JSON is the smallest reversible mechanism.
