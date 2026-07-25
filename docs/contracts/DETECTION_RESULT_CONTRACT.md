# Detection Result Contract

implementation_authority: NONE
current_runtime_status: DESIGN_ONLY

Every result contains `detection_id`, `rule_id`, `rule_version`, `category`, `risk_score` (0..100),
`threat_confidence`, `benign_confidence`, `evidence_quality`, `telemetry_quality`,
`contributing_signals`, `contradicting_signals`, `baseline_reference`, `false_positive_notes`,
`recommended_response`, `automatic_response_allowed`, `human_approval_required`, `reversibility`,
`blast_radius`, `asset_criticality`, `evidence_references`, `attack_mapping`, and
`defensive_mapping`.

Threat and benign confidence are independent `LOW|MEDIUM|HIGH` values; known-good confidence is
never mislabeled as threat confidence. Evidence quality is `AE0|AE1|AE2|AE3`; telemetry quality is
`DEGRADED|PARTIAL|COMPLETE`. Risk is impact-weighted priority, not probability. Multi-signal
correlation is default. A narrow single-event high-confidence result requires an integrity-protected
source, deterministic validated rule, contradicting-evidence evaluation, and policy-controlled response.
