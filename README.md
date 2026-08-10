# AIOM Sentinel

## Position

Not a production antivirus yet. A verified Rust scanning core, deterministic evidence contract,
and governed path toward endpoint protection. Cross-platform by architecture; platform support is
earned through verification.

## Phase 1 state

Implemented capabilities are recursive opt-in filesystem scanning, SHA-256/SHA-1/MD5, entropy,
bounded PE metadata, local literal-rule matching, a Rust-native YARA-X static engine path, JSON
evidence, timeline records, and documented exit codes. YARA-X is a verified-local production
candidate for bounded static scans; it is not real-time endpoint protection or efficacy evidence.

## Nonclaims

Sentinel is not a complete antivirus or EDR. `CLEAN` only means that configured Phase 1 detectors
did not match. It makes no safety guarantee and has no process monitoring, real-time collection,
memory scanning, network interception, kernel components, persistence, telemetry, cloud service,
automatic update, quarantine, deletion, or remediation.

## Quick start

```bash
cargo build --workspace --all-features
cargo run -p sentinel-cli -- scan tests/fixtures/harmless-negative.txt --output evidence.json
node tools/verify-evidence.mjs evidence.json
```

## Example scan

Directory traversal is explicit:

```bash
cargo run -p sentinel-cli -- scan tests/fixtures --recursive \
  --rules tests/fixtures/harmless.rules --output evidence.json
```

Rust-native YARA-X scanning is explicit and does not invoke Python:

```bash
cargo run -p sentinel-cli -- scan tests/fixtures/harmless-yara-positive.txt \
  --yara-rules tests/fixtures/harmless.yar --yara-namespace fixture --json
```

## Example output

Each detection includes `timestamp`, `path`, `hashes`, `entropy`, `signature`, `confidence`,
`scanner_version`, and `engine_version`. Schema 1.1.0 additionally records `risk_score`,
`threat_confidence`, `benign_confidence`, and `evidence_quality`. The schema contract is
`docs/EVIDENCE-CONTRACT.md`.

## Verification

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-features
cargo build --workspace --all-features
cargo bench --workspace --no-run
node tools/verify-architecture.mjs
```

See `docs/VERIFICATION.md` and `docs/release/VERIFICATION_RECEIPT.md` for the executed release
candidate gate and the unavailable optional tools.

## Cross-platform architecture

The shared domain uses neutral OS, capability, verification, file-format, and file-identity
contracts. The Platform Support Matrix records only locally measured verification. Windows and Linux
CI are configured but not executed; no runtime support is claimed from configuration alone.

## Architecture overview

The executable workspace separates core types, hashing, PE parsing, rule evaluation, evidence,
scanner orchestration, and CLI presentation. `docs/ARCHITECTURE.md` describes the current runtime;
the enterprise architecture pack is design-only and declares `implementation_authority: NONE`.

## Repository map

- `crates/` — Phase 1 Rust workspace crates.
- `tests/` — integration tests and harmless fixtures.
- `fuzz/` and `benches/` — fuzz targets and benchmarks.
- `docs/` — implementation, threat-model, architecture, and release documents.
- `tools/` — evidence and architecture verifiers.
- `architecture-input/` — source-corpus receipt; the verbatim corpus is locally restricted.

## Security boundary

The scanner opens supplied targets for read-only analysis and writes only the explicitly requested
evidence file. It has no remediation authority. Resource limits and failure behavior are defined
in `docs/THREAT-MODEL.md` and `docs/ARCHITECTURE.md`.

## Roadmap

`docs/ROADMAP.md` describes future work as non-authoritative design. Phase 2 is not implemented or
approved by this release candidate.

## Limitations

Read `docs/release/KNOWN_LIMITATIONS.md` before relying on a result for an operational decision.

## Reviewer entry points

Start with `docs/release/REVIEWER_GUIDE.md`, then run the commands in
`docs/release/VERIFICATION_RECEIPT.md`. `docs/release/SOURCE_CORPUS_PUBLICATION_DECISION.md`
explains why the verbatim research corpus is excluded from public release.
