# Known Limitations

implementation_authority: PHASE_1_ONLY

- A clean result is detector-relative, not a safety guarantee.
- Static scanning alone does not provide modern endpoint protection; there is no behavioral or fileless detection.
- Rust-native YARA-X is integrated for bounded local static scans. Detection efficacy, production
  rule-feed quality, on-access enforcement and external corpus validation remain unverified.
- PE metadata parsing is bounded and does not provide ELF or Mach-O runtime parsing.
- Scanning is user-mode and on-demand; there is no process, registry, or real-time filesystem monitor.
- The scanner does not inspect memory, intercept network traffic, load drivers, persist state, or escalate privileges.
- Prototype quarantine code exists, but no production response capability is claimed; there is no
  verified remediation, containment or alert transport.
- There is no memory collection, firewall, certificate interception, or production performance evidence.
- Windows and Linux runtime verification are pending; qualified platform claims require external validation.
- Hash and metadata results can change if a target changes during analysis; evidence records the observed result.
- Coverage is measured separately; this receipt does not claim an independently measured 80 percent threshold.
- Optional `cargo-audit`, `cargo-deny`, `cargo-fuzz`, and `cargo-llvm-cov` were unavailable in the release-candidate environment.
