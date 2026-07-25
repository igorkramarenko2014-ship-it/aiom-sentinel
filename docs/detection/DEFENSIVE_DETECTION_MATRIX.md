# Defensive Detection Matrix

implementation_authority: NONE
current_runtime_status: DESIGN_ONLY

All categories use multi-signal correlation, explicit contradicting signals, minimized evidence,
policy-controlled response, and the lifecycle in `RULE_LIFECYCLE.md`.

| Category | Observables and telemetry | Risk/confidence and contradicting signals | Evidence/privacy | Response/authority/recovery | Tests/performance/platform |
|---|---|---|---|---|---|
| Process execution | Process/parent, path, arguments, signer, hash, role baseline | Parent/path/rarity/context contributions; approved admin tooling, maintenance and provenance contradict | Process tree, redacted command line, hashes; sensitive metadata | Observe/enrich/alert; suspend or contain needs policy; resume/reconnect rollback | Clean role baselines plus synthetic anomalous trees; high volume; all OS collectors |
| Memory manipulation | Cross-process access, protection changes, thread starts, image loads | Correlated write/change/execute; debuggers, browsers, accessibility, agents and updaters contradict | Permissions, identities, bounded authorized samples; restricted content | Alert/restrict; suspend/contain approval; resume rollback | Defensive lab simulation; expensive targeted collection; platform-specific sources |
| Persistence | Autostart/config/service/task/file changes and actor | Baseline/change authority/signer/execution; approved deployment contradicts | Before/after, definitions, hashes; user config sensitive | Alert/restrict; disable only authorized; restore known-good config | Clean images and synthetic approved/unapproved changes; low volume; native config surfaces |
| Security-tool tampering | Service/agent stop, collector degradation, log clear, policy/update changes | Sensitive target plus actor/follow-on activity; signed maintenance contradicts | Actor, target, authority, health timeline; system metadata | Rapid alert; narrow containment only; restore last-known-good and restart | Maintenance and tamper simulations; critical latency; all OS health sources |
| Credential/identity abuse | Sensitive-store/process access, sessions, logons, token/ticket metadata | Host+identity anomalies; expected identity/security tooling contradicts | Rights/session/source identity; very high privacy, no default content | Contain only by policy; identity actions require separate authority; reauthenticate/rotate rollback | Legitimate tools plus defensive access tests; focused collection; endpoint+identity planes |
| Lateral/remote execution | Remote services/tasks, SSH/WinRM/SMB and source-target rarity | Actor/asset/time/provenance; approved administration contradicts | Source/user/target/method/hash; medium-high privacy | Alert then source-or-target containment; never isolate both on weak signal; restore config | Legitimate admin plus controlled simulations; centralized cost; cross-host mappings |

`risk_score`, `threat_confidence`, `benign_confidence`, `evidence_quality`, and
`telemetry_quality` remain separate. Attack mappings are taxonomy references only, not attacker
instructions. Raw memory, command lines, identity data, and user content follow explicit privacy gates.
