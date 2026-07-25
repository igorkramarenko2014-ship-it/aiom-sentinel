# Failure Mode Matrix

implementation_authority: NONE
current_runtime_status: DESIGN_ONLY

Canonical rule: fail secure where blocking is bounded and reversible; fail operationally safe where
blocking threatens host availability; never fail silently; preserve last-known-good state.

| Situation | Default action | Policy override | Maximum wait | Fallback | Operator visibility | Evidence preserved | Reversibility | Availability risk |
|---|---|---|---|---|---|---|---|---|
| Unknown executable before launch | Bounded wait then policy verdict | allow/restrict/block by asset class | Explicit launch budget | last-known-good policy | immediate | request, timeout, identity | yes | medium |
| Scan timeout | cancel worker task | one bounded retry | scan budget | deferred scan or policy verdict | immediate | partial evidence | yes | medium |
| Scan-worker crash | isolate and respawn | disable affected parser | one retry window | degraded static signals | immediate | crash receipt and partial record | yes | low |
| Collector unavailable | allow with degraded telemetry | restrict critical asset | health SLO | alternate source | immediate | outage interval | yes | medium |
| Plugin crash | disable plugin | bounded restart | plugin deadline | core engine only | immediate | plugin/version/crash | yes | low |
| Signature DB unavailable | use last-known-good | disable affected rules | none | hash/parser evidence | immediate | active version | yes | low |
| Invalid update | reject activation | none without signed recovery | none | last-known-good | immediate | manifest verification | yes | low |
| Evidence storage unavailable | bounded local spool | stop optional enrichment | spool budget | alert and degrade | immediate | sequence gap marker | yes | medium |
| Boot-critical operation | operationally safe allow | narrowly signed policy | minimal | post-boot scan | immediate | decision rationale | yes | high |
| Large non-executable file | bounded metadata then defer | explicit deeper scan | file budget | evidence-only record | visible | limits and identity | yes | low |
| Policy service unavailable | last-known-good policy | emergency local policy | health deadline | safe degraded mode | immediate | service-health receipt | yes | high |
