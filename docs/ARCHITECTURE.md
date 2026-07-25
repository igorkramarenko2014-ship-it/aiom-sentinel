# Architecture

The dependency direction is `cli → scanner → {hash, pe, rules} → core`, with `evidence` serializing
core results. Crates do not use global mutable state. The scanner opens targets read-only, refuses a
top-level symlink, does not follow discovered symlinks, canonicalizes entries under the scan root,
and retains traversal failures.

Hashing is streaming in 64 KiB chunks. Parser/rule input is separately bounded by `max_file_size`.
The local rule adapter is intentionally smaller than YARA; its trait boundary permits a future
YARA-compatible engine without coupling scanner policy to a specific parser.

The future enterprise architecture is a design proposal only. Phase 1 contains no worker service,
collector, kernel component, quarantine, update channel, telemetry, or response action.
