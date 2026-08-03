# ADR-023: PostgreSQL fingerprint registry (lane 1)

Status: ACCEPTED_DESIGN_ONLY
Scope: schema and contract decision only; no migration or runtime integration.

## Context

Sentinel computes sha256, sha1, and md5 together in sentinel_hash::HashSet and
emits EvidenceBundle schema 1.1.0. The registry must not change scanner
detection semantics or the evidence contract in lane 1.

## Decision

Use PostgreSQL with versioned immutable SQL migrations and a bounded Rust
repository crate. sqlx is preferred only after physical compatibility with
Rust 1.93, Tokio, time, and uuid is measured. No production database,
automatic update authority, malware corpus, blocking, remediation, or LKG
promotion is included.

Lane 1 has exactly three domain tables:

1. fingerprint_sets — logical source/version metadata.
2. source_artifacts — set membership; uniqueness is
   (fingerprint_set_id, sha256), not global sha256, so one artifact may be
   imported into multiple sets idempotently.
3. fingerprints — algorithm plus digest bytes linked to a source artifact.

The classification assertion carries both `asserted_by` (who made the
assertion) and `assertion_source` (the source feed, document, or provenance
reference). A set has no separate content hash in lane 1; set identity is
established by its artifact memberships and their hashes.

There is no ingestion_runs table, fingerprint_lookup_events table, active
column, or global activation lock in lane 1. Run accounting is file-receipt
only. Lookup takes an explicit fingerprint-set id and returns a non-persistent
receipt.

authority_state is not a second independent revocation source. In lane 1,
revoked_at is the source of truth; authority_state is derived for display and
must be REVOKED exactly when revoked_at IS NOT NULL. A later migration must
enforce that invariant with a CHECK or remove the stored state.

## Lookup contract

The scanner's three digests are queried independently:

- MATCH_STRONG: SHA-256 matches an asserted classification.
- MATCH_WEAK_ONLY: only SHA-1 or MD5 matches; this is lower authority and is
  never the same verdict as MATCH_STRONG.
- DISAGREEMENT: algorithms return conflicting classifications.

Resolution priority is DISAGREEMENT first, then MATCH_STRONG, then
MATCH_WEAK_ONLY, then NO_MATCH. A strong malicious SHA-256 match plus a benign
MD5 match is therefore DISAGREEMENT, never two simultaneous final states.

Weak-only matches are not self-sufficient for any governed action: they cannot
promote, block, release, or override a strong result and require explicit
human/evidence follow-up. A revoked set is excluded by an explicit
revoked_at IS NULL predicate and is reported as SET_REVOKED, not as a normal
miss.

## Canonical digest boundary

All import records and scanner results pass through one function:

    canonical_digest(algorithm, hex) -> Result<fixed-size digest bytes>

It accepts only the algorithm's exact length, canonicalizes case, and rejects
0x prefixes, odd lengths, non-hex characters, and wrong lengths. Both input
paths use it. Tests prove equivalent case produces identical BYTEA. Alias the
existing HashSet type when importing it beside std::collections::HashSet; this
is a type-name concern, not a canonical_digest naming concern.

## Import and failure semantics

Each set import is one transaction. The loader parses streams with bounded
record/byte limits, validates every row, and commits only when all rows are
valid. Any invalid row aborts the complete transaction.

Exact duplicate re-import is IDEMPOTENT_NO_OP. The same artifact in another
set is a new inserted membership. A repeated algorithm+digest within one input
file is REJECTED_DUPLICATE_INPUT with a receipt reason before SQL constraint
handling; it aborts the transaction. Contradictory duplicate metadata is
REJECTED_CONTRADICTORY_METADATA and is never silently merged.

Before touching PostgreSQL, the loader writes an intent receipt with status
STARTED, run_id, set_id, source_digest, and started_at. If the database dies
before commit, an unmatched STARTED receipt is an INCOMPLETE run, not evidence
that the run did not occur. Durable orphan recovery is a later lane.

## Observation versus assertion

Digest bytes are observations. Classification is an authored assertion and
must carry asserted_by and source provenance. A disagreement between vendors
is a conflict between assertions, not data corruption and not an automatic
rollback of a valid set.

## Evidence isolation

EvidenceBundle schema 1.1.0 remains untouched in lane 1. Registry lookup
returns a separate receipt. REGISTRY_UNAVAILABLE means the database could not
be reached; SET_REVOKED means the explicit set is intentionally revoked. They
are distinct states with distinct next actions. REGISTRY_UNAVAILABLE,
MATCH_WEAK_ONLY, and DISAGREEMENT are not inserted into the current evidence bundle. Integration
requires a separate schema bump and acceptance lane.

## Availability and status reporting

PostgreSQL availability is an environmental gate, not an implementation
verdict. NOT_EXERCISED is valid only when the receipt contains reason,
environmentObserved, requiredEnvironment, and rerunCommand. It never
increments PASS.

## Security and boundaries

- No database password, credentialed URL, secret, or private key enters Git.
- Fixtures contain harmless synthetic hashes only.
- Lookup digest telemetry is not persisted by default.
- No production authority, cloud export, privileged scanning, blocking,
  remediation, merge, release, or ACCEPT is provided.

## Later implementation gates

1. Resolve a compatible sqlx version from the physical lockfile/toolchain.
2. Add migrations for the three-table model only.
3. Add bounded streaming import and explicit lookup receipts.
4. Test duplicate/no-op, contradictory metadata, rollback, revocation,
   weak-only/strong/disagreement, canonical hex, and orphan STARTED intent.
5. Run disposable PostgreSQL integration tests; unavailable PostgreSQL is
   reported with the four required NOT_EXERCISED fields.
6. Use the physical tools/run_full_verification.py entry point and resolve the
   three .mjs verifier paths before P15.

SAFE_TO_RELEASE: false
ACCEPT_LOCK: NO
