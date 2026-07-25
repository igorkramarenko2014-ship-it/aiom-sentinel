# Security policy

Before a public contact is configured, use the repository host's private reporting mechanism or
contact the maintainers through the repository's private channel. Do not disclose vulnerabilities
in public issues. Include the affected version, harmless reproducible input, expected impact, and
whether the report contains sensitive data. Do not attach malware samples.

Publication gate: replace this placeholder with a maintained private disclosure address before any
public release.

Phase 1 never remediates targets. Security fixes must preserve read-only scanning, bounded resource
use, explicit errors, and evidence compatibility. Dependencies may contain internally reviewed
`unsafe` Rust even though every Sentinel workspace crate uses `#![forbid(unsafe_code)]`.
