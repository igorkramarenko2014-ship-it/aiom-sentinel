# Verification

Run from the repository root:

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-features
cargo build --workspace --all-features
cargo bench --workspace --no-run
cargo run -p sentinel-cli -- scan tests/fixtures/harmless-positive.txt --rules tests/fixtures/harmless.rules --output evidence.json
node tools/verify-evidence.mjs evidence.json
node tools/verify-architecture.mjs
```

The fixture scan intentionally exits `1` because its harmless marker matches. Optional gates are
`cargo audit`, `cargo deny check`, bounded `cargo fuzz`, and measured coverage when those tools are
already installed. Never infer coverage or performance from compilation.

The architecture verifier checks source-corpus integrity, required documents and ADR headings,
design-only authority, Phase 2 path absence, scoring/response contracts, claim-ledger Sprint coverage,
and rejection of unsafe canonical assertions.
