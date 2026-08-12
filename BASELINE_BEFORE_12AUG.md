# Baseline before 12-Aug delta

Repository: `AIOM Sentinel`  
Branch: `feat/sentinel-yara-spike`  
Observed HEAD: `efd1fbcae49ed6dcb2465ba620e38dea42962f26`  
Toolchain: `rustc 1.93.0`, `cargo 1.93.0`

Required source files were present before mutation:

- `crates/sentinel-core/src/threat_coverage.rs`
- `crates/sentinel-scanner/src/macos_analysis.rs`
- `crates/sentinel-scanner/src/supply_chain_analysis.rs`

The prior release proof recorded workspace tests and strict service Clippy as passing. This
delta began with formatting verification and a fresh Cargo verification attempt using an isolated
writable target directory. Any final state is recorded in the implementation receipt, not inferred
from the older release receipt.
