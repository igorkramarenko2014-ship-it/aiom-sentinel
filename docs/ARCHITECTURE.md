# Architecture

The dependency direction is `cli → scanner → {hash, pe, rules} → core`, with `evidence` serializing
core results. Crates do not use global mutable state. The scanner opens targets read-only, refuses a
top-level symlink, does not follow discovered symlinks, canonicalizes entries under the scan root,
and retains traversal failures.

Hashing is streaming in 64 KiB chunks. Parser/rule input is separately bounded by `max_file_size`.
The local literal adapter and pinned Rust-native YARA-X engine use a typed engine result containing
engine/ruleset identity, deterministic normalized matches, and explicit coverage. YARA-X rules are
compiled before scan and held as an immutable `Rules` snapshot. Non-complete engine coverage is
propagated as scan failure rather than a clean verdict. Python YARA remains an experimental legacy
edge and is not called by the production-candidate CLI/Tauri file-scan path.

The future enterprise architecture is a design proposal only. Phase 1 contains no worker service,
collector, kernel component, quarantine, update channel, telemetry, or response action.
