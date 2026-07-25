# Evidence contract

Schema `1.1.0` contains a scan envelope and ordered file records. Paths include a human-readable
display string plus base64 platform bytes so non-UTF-8 paths remain representable. Records carry
file identity, hashes, entropy, bounded PE metadata, rule matches, findings, versions, duration,
errors, verdict, risk score, threat confidence, benign confidence, and evidence quality.

Verdict derivation is deterministic: any record error is `SCAN_ERROR`; any rule match is `MATCH`
with the maximum configured rule contribution as risk score; otherwise the record is `CLEAN` with
risk score 0. Entropy is evidence only and never a verdict by itself. `CLEAN` means only no
configured Phase 1 detector matched. Benign confidence remains `LOW`; absence of a match is not
proof of safety. UUIDv5 evidence IDs derive from scan ID and lossless target bytes.
