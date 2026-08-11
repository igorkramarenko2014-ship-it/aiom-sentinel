# Known limitations

AIOM Sentinel is a locally verified defensive endpoint-security prototype, not a production EPP.

- Verification is macOS/Unix local only. Windows response behavior and parity are unverified.
- A clean result is detector-relative, not a safety guarantee. Real-malware efficacy, external
  corpus qualification, and complete threat coverage are not established.
- YARA-X is integrated for bounded local static scanning; live process, memory, network, kernel,
  persistence, and on-access enforcement are not provided.
- Production key authority is not implemented. The verified Slice 3C demo uses `TestKeyProvider`
  and harmless temporary fixtures only.
- Tauri transactional V2 response wiring is not enabled. Automatic production effects are disabled.
- No production installer, service, privileged path, deployment, monitoring, or alert transport has
  been validated.
- Frontend automated tests are absent. The existing frontend typecheck/build lanes provide static
  and build validation only.
- Optional security tooling such as `cargo-audit`, `cargo-deny`, fuzzing, and coverage tooling is
  not part of the measured portfolio release gate.
