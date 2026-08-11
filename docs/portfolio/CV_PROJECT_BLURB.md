# AIOM Sentinel — CV project blurb

## Short CV version

**AIOM Sentinel — AI-native Endpoint Security Prototype | Rust, Tauri, YARA-X**

- Built a Rust-based macOS/Unix-locally-verified endpoint-security prototype with YARA-X
  detection, typed response policy, AES-256-GCM transactional quarantine, crash-safe recovery,
  authorized restore, and evidence receipts.
- Designed adversarial filesystem verification covering 24 protected-object cases, four
  deterministic object-swap races, 13 transaction failpoints, and a 132-test workspace; strict
  product-service Clippy passes with zero diagnostics.

## LinkedIn / portfolio version

AIOM Sentinel is an AI-native Rust/Tauri defensive endpoint-security prototype. I built a typed
detection-to-response pipeline around YARA-X, canonical artifact identity, explicit policy gates,
encrypted transactional quarantine, recovery, and authorized restore. Adversarial filesystem tests
exposed TOCTOU risks and drove same-handle consumption and `(dev, ino)` restore-temp identity
enforcement. The result is locally verified on macOS/Unix, not presented as production EPP.

## Interview talking points

- The service pipeline is detection → identity → policy → transaction → quarantine → receipt.
- A detection digest is not trusted blindly: the canonical adapter hashes artifact bytes it reads.
- Same-handle operations and identity checks reduce TOCTOU replacement risk at filesystem seams.
- Durable transaction records let recovery converge safely after injected failpoints.
- Audit/disabled policy is a typed no-effect outcome; only explicit enabled quarantine authorizes
  the hardened executor.
- Protected-object and object-swap regressions test failure modes that happy-path scans miss.
- AI agents accelerated bounded implementation, while operator-owned architecture and executable
  evidence gates constrained scope and claims.
- Production key authority, automatic response, Windows parity, and malware-efficacy claims remain
  deliberately out of scope.
