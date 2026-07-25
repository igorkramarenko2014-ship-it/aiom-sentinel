# Rule Lifecycle

implementation_authority: NONE
current_runtime_status: DESIGN_ONLY

`DRAFT` requires rationale, schema, test corpus, privacy class, cost hypothesis, and owner. `SHADOW`
collects no-response observations. `TUNING` records false positives, contradicting evidence, and
performance. `ACTIVE` requires reviewed thresholds, rollback, and evidence. `DEGRADED` marks missing
telemetry or breached quality gates. `DISABLED` produces no detections but preserves audit history.
`RETIRED` is immutable historical state.

Transitions are signed/audited configuration changes. Promotion requires positive, negative,
contradicting-signal, degraded-telemetry, privacy, and load tests. Any rollback restores the previous
versioned ruleset; deletion never erases historical evidence.
