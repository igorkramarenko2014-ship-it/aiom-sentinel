# S-01 test-count reconciliation

The earlier receipt recorded 142 tests. Fresh Rust 1.93 execution against the remediated tree
observed:

- runtime `cargo test --workspace --all-features --locked`: 145 passed, 0 failed;
- runtime `cargo test --workspace --all-features --locked -- --list`: 145 listed tests;
- discrepancy: resolved (145 listed = 145 executed).

The count increased because the remediation added three governance regressions after the previous
pack: typed catalogue completeness/runtime honesty, typed primitive registration, and canonical
product-honesty set completeness.
