# Verification Receipt

release_state: RELEASE_CANDIDATE
execution_environment: macOS local workspace
evidence_tier: AE3

## Executed release gate

```text
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-features
cargo build --workspace --all-features
cargo bench --workspace --no-run
node --check tools/verify-evidence.mjs
node --check tools/verify-architecture.mjs
cargo run -p sentinel-cli -- scan tests/fixtures/harmless-negative.txt --output evidence.json
node tools/verify-evidence.mjs evidence.json
node tools/verify-architecture.mjs
git diff --check
```

The release gate is rerun from a temporary public-style copy that excludes build output, evidence
output, Git history, and the locally restricted verbatim corpus. Architecture verification therefore
reports `corpus_mode=receipt-only` in that copy.

## Results

- Formatting, clippy with warnings denied, tests, build, benchmark compilation, Node syntax, both
  verifiers, and whitespace checks passed.
- The fresh release-candidate gate passed 12 tests. The generated negative-fixture evidence passed
  schema verification at version 1.1.0.
- `Cargo.lock` is present and must be included in the first authorized commit. It appears untracked
  only because this new repository has no authorized initial commit.

## Not executed

`cargo-audit`, `cargo-deny`, `cargo-fuzz`, and `cargo-llvm-cov` were not installed in the release
candidate environment. No coverage percentage is claimed by this receipt.
