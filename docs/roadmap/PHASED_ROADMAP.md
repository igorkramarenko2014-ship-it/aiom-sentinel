# Phased Roadmap

implementation_authority: NONE beyond completed Phase 1
current_runtime_status: DESIGN_ONLY for Phases 2–7

| Phase | Entry criteria | Scope and dependencies | Explicit exclusions | Gates and tests | Rollback and evidence | Exit criteria / safeToStartNextPhase |
|---|---|---|---|---|---|---|
| 1 Static scanner | Standalone repo and bounded contract | Hashes, entropy evidence, bounded PE, local rules, JSON verifier | collectors, response, network, cloud | fmt/clippy/test/build/bench/evidence verifier; privacy and malformed-input tests | remove release; evidence AE3 locally | verified handoff; `safeToStartNextPhase: false` pending operator review |
| 2 Shadow collectors | Approved ADRs, primary sources, supported OS matrix, privacy review | normalized events and read-only OS-specific collectors; signing/entitlements | blocking, remediation, cross-host response | event fidelity/loss, backpressure, crash, upgrade/rollback, privacy, resource tests | disable collector and preserve health receipts; AE3 lab evidence | shadow SLOs met; `safeToStartNextPhase: false` pending external gate |
| 3 Correlation | Phase 2 complete telemetry-quality evidence and labeled corpus | scoring dimensions, rule lifecycle, local evidence graph | automated containment | positive/negative/contradicting/degraded/load tests, analyst review | revert ruleset/model and replay immutable evidence; AE3 | quality/privacy budgets met; `safeToStartNextPhase: false` |
| 4 Reversible containment | Response ADR approval, rollback drills, asset policy | restrict/suspend/contain under policy | quarantine/eradication by default | blast-radius, timeout, recovery, boot-critical, false-positive exercises | automatic expiry and tested rollback; AE4 staging | reversible controls proven; `safeToStartNextPhase: false` |
| 5 Quarantine and updates | Key-management/update-trust ADRs, recovery ownership | encrypted content-addressed quarantine, signed updates, central management foundation | autonomous eradication | crypto lifecycle, restore, invalid update, LKG, staged rollout tests | restore object/config and pin LKG; AE4 staging | recovery and update SLOs met; `safeToStartNextPhase: false` |
| 6 Enterprise fleet | Phase 5 operational evidence, privacy governance, SIEM contracts | fleet policy, SIEM, forensics, regional retention | AI response authority | canary, tenancy, export, incident, DR, compliance and load tests | staged rollback, regional recovery, immutable case receipts; AE4 | fleet error budgets healthy; `safeToStartNextPhase: false` |
| 7 Advisory AI | Verified evidence schemas, model/privacy approval, human workflow | explanation, prioritization, clustering, defensive drafts | verdict override, raw content by default, autonomous response | hallucination, missing telemetry, privacy, adversarial prompt, rollback tests | disable model and retain deterministic pipeline; AE4 for production | advisory value proven; next phase undefined and blocked |

Each future phase needs separate operator authority, concrete SLOs, owners, deployment strategy, and
production rollback before implementation. This roadmap itself grants none.
