use sentinel_core::{ConfidenceLevel, Verdict};
use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum AnalysisAvailability {
    ImplementedTested,
    Partial,
    Experimental,
    BlockedByTelemetry,
    Unavailable,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct CodeSigningMetadata {
    pub codesigned: Option<bool>,
    pub notarized: Option<bool>,
    pub team_id: Option<String>,
    pub signing_identity: Option<String>,
    pub bundle_id: Option<String>,
    pub certificate_information: Vec<String>,
    pub availability: AnalysisAvailability,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BehavioralAssessment {
    pub verdict: Verdict,
    pub confidence: ConfidenceLevel,
    pub evidence: Vec<String>,
    pub availability: AnalysisAvailability,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct TerminalChainEvidence {
    pub interactive_terminal: bool,
    pub shell_execution: bool,
    pub network_retrieval: bool,
    pub new_artifact_materialized: bool,
    pub execution_transition: bool,
}

#[must_use]
pub fn assess_terminal_chain(evidence: &TerminalChainEvidence) -> BehavioralAssessment {
    let complete = evidence.interactive_terminal
        && evidence.shell_execution
        && evidence.network_retrieval
        && evidence.new_artifact_materialized
        && evidence.execution_transition;
    BehavioralAssessment {
        verdict: if complete {
            Verdict::Suspicious
        } else {
            Verdict::Clean
        },
        confidence: if complete {
            ConfidenceLevel::Medium
        } else {
            ConfidenceLevel::Low
        },
        evidence: if complete {
            vec!["CLICKFIX_LIKE_TERMINAL_CHAIN".to_owned()]
        } else {
            Vec::new()
        },
        availability: AnalysisAvailability::BlockedByTelemetry,
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct XcodeBuildEvidence {
    pub baseline_run_scripts: Vec<String>,
    pub current_run_scripts: Vec<String>,
    pub build_triggered_execution: bool,
    pub network_retrieval: bool,
    pub persistence_change: bool,
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct LaunchAgentEvidence {
    pub temporary_execution: bool,
    pub stable_copy_present: bool,
    pub launchagent_registration: bool,
    pub run_at_load: bool,
    pub keep_alive: bool,
    pub legitimate_install_context: bool,
}

/// Static/synthetic only: no LaunchAgent is created or queried by this model.
#[must_use]
pub fn assess_launchagent_persistence(evidence: &LaunchAgentEvidence) -> BehavioralAssessment {
    let correlated = evidence.temporary_execution
        && evidence.stable_copy_present
        && evidence.launchagent_registration
        && (evidence.run_at_load || evidence.keep_alive)
        && !evidence.legitimate_install_context;
    assessment(
        correlated,
        "TEMP_EXECUTION_STABLE_COPY_LAUNCHAGENT",
        AnalysisAvailability::Experimental,
    )
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum CapabilityEvidenceLevel {
    StaticCapabilityHint,
    ImplementedCapabilityEvidence,
    ObservedRuntimeBehavior,
}

#[must_use]
pub fn capability_evidence_level(
    symbol_present: bool,
    implementation_reachable: bool,
    runtime_observed: bool,
) -> Option<CapabilityEvidenceLevel> {
    if runtime_observed {
        Some(CapabilityEvidenceLevel::ObservedRuntimeBehavior)
    } else if implementation_reachable {
        Some(CapabilityEvidenceLevel::ImplementedCapabilityEvidence)
    } else if symbol_present {
        Some(CapabilityEvidenceLevel::StaticCapabilityHint)
    } else {
        None
    }
}

#[must_use]
pub fn assess_xcode_build(evidence: &XcodeBuildEvidence) -> BehavioralAssessment {
    let unexpected = evidence
        .current_run_scripts
        .iter()
        .any(|script| !evidence.baseline_run_scripts.contains(script));
    let correlated = unexpected
        && evidence.build_triggered_execution
        && (evidence.network_retrieval || evidence.persistence_change);
    assessment(
        correlated,
        "XCODE_BUILD_TRIGGERED_EXECUTION",
        AnalysisAvailability::BlockedByTelemetry,
    )
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct PreferencesEvidence {
    pub preference_operation: bool,
    pub opaque_or_encoded_content: bool,
    pub decode_transition: bool,
    pub execution_transition: bool,
}

#[must_use]
pub fn assess_preferences(evidence: &PreferencesEvidence) -> BehavioralAssessment {
    assessment(
        evidence.preference_operation
            && evidence.opaque_or_encoded_content
            && evidence.decode_transition
            && evidence.execution_transition,
        "PREFERENCES_ENCODED_PERSISTENCE",
        AnalysisAvailability::BlockedByTelemetry,
    )
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct SecurityControlEvidence {
    pub ordinary_administration: bool,
    pub update_policy_change: bool,
    pub protection_service_termination: bool,
    pub repeated_tcc_reset: bool,
    pub protective_file_interference: bool,
    pub correlated_suspicious_context: bool,
}

#[must_use]
pub fn assess_security_control(evidence: &SecurityControlEvidence) -> BehavioralAssessment {
    let impairment_count = [
        evidence.update_policy_change,
        evidence.protection_service_termination,
        evidence.repeated_tcc_reset,
        evidence.protective_file_interference,
    ]
    .into_iter()
    .filter(|present| *present)
    .count();
    assessment(
        !evidence.ordinary_administration
            && evidence.correlated_suspicious_context
            && impairment_count >= 2,
        "MACOS_SECURITY_CONTROL_IMPAIRMENT",
        AnalysisAvailability::BlockedByTelemetry,
    )
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct RemoteBridgeEvidence {
    pub webview_present: bool,
    pub remotely_supplied_logic: bool,
    pub native_bridge: bool,
    pub shell_capability: bool,
    pub filesystem_capability: bool,
    pub network_capability: bool,
}

#[must_use]
pub fn assess_remote_bridge(evidence: &RemoteBridgeEvidence) -> BehavioralAssessment {
    assessment(
        evidence.webview_present
            && evidence.remotely_supplied_logic
            && evidence.native_bridge
            && (evidence.shell_capability
                || evidence.filesystem_capability
                || evidence.network_capability),
        "REMOTE_LOGIC_NATIVE_BRIDGE",
        AnalysisAvailability::Experimental,
    )
}

fn assessment(
    correlated: bool,
    primitive: &str,
    availability: AnalysisAvailability,
) -> BehavioralAssessment {
    BehavioralAssessment {
        verdict: if correlated {
            Verdict::Suspicious
        } else {
            Verdict::Clean
        },
        confidence: if correlated {
            ConfidenceLevel::Medium
        } else {
            ConfidenceLevel::Low
        },
        evidence: if correlated {
            vec![primitive.to_owned()]
        } else {
            Vec::new()
        },
        availability,
    }
}

#[must_use]
pub fn parse_codesign_evidence(command_succeeded: bool, output: &str) -> CodeSigningMetadata {
    let value = |prefix: &str| {
        output
            .lines()
            .find_map(|line| line.trim().strip_prefix(prefix))
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(ToOwned::to_owned)
    };
    let certificate_information = output
        .lines()
        .filter_map(|line| line.trim().strip_prefix("Authority="))
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
        .collect();

    CodeSigningMetadata {
        codesigned: Some(command_succeeded),
        notarized: value("Notarized=").and_then(|value| match value.as_str() {
            "yes" | "true" => Some(true),
            "no" | "false" => Some(false),
            _ => None,
        }),
        team_id: value("TeamIdentifier="),
        signing_identity: value("Authority="),
        bundle_id: value("Identifier="),
        certificate_information,
        availability: AnalysisAvailability::Partial,
    }
}

#[must_use]
pub fn assess_signing_provenance(
    metadata: &CodeSigningMetadata,
    correlated_suspicious_behavior: bool,
) -> BehavioralAssessment {
    let mut evidence = Vec::new();
    if metadata.codesigned == Some(true) {
        evidence.push("CODE_SIGNED".to_owned());
    }
    if metadata.notarized == Some(true) {
        evidence.push("NOTARIZED".to_owned());
    }
    if correlated_suspicious_behavior {
        evidence.push("CORRELATED_SUSPICIOUS_BEHAVIOR".to_owned());
    }

    if correlated_suspicious_behavior {
        BehavioralAssessment {
            verdict: Verdict::Suspicious,
            confidence: ConfidenceLevel::Medium,
            evidence,
            availability: metadata.availability,
        }
    } else {
        BehavioralAssessment {
            verdict: Verdict::Clean,
            confidence: ConfidenceLevel::Low,
            evidence,
            availability: metadata.availability,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn signed_fixture(notarized: bool) -> CodeSigningMetadata {
        parse_codesign_evidence(
            true,
            &format!(
                "Identifier=com.example.safe\nTeamIdentifier=TEAM123\nAuthority=Developer ID Application: Example\nNotarized={}\n",
                if notarized { "yes" } else { "no" }
            ),
        )
    }

    #[test]
    fn signed_and_notarized_benign_artifacts_are_not_malicious() {
        // Arrange
        let signed = signed_fixture(false);
        let notarized = signed_fixture(true);

        // Act
        let signed_result = assess_signing_provenance(&signed, false);
        let notarized_result = assess_signing_provenance(&notarized, false);

        // Assert
        assert_eq!(signed_result.verdict, Verdict::Clean);
        assert_eq!(notarized_result.verdict, Verdict::Clean);
        assert_eq!(notarized.notarized, Some(true));
        assert_eq!(notarized.team_id.as_deref(), Some("TEAM123"));
    }

    #[test]
    fn suspicious_behavior_with_trusted_provenance_escalates_evidence() {
        // Arrange
        let notarized = signed_fixture(true);

        // Act
        let result = assess_signing_provenance(&notarized, true);

        // Assert
        assert_eq!(result.verdict, Verdict::Suspicious);
        assert_eq!(result.confidence, ConfidenceLevel::Medium);
        assert!(result.evidence.contains(&"NOTARIZED".to_owned()));
        assert!(
            result
                .evidence
                .contains(&"CORRELATED_SUSPICIOUS_BEHAVIOR".to_owned())
        );
    }

    #[test]
    fn complete_terminal_retrieval_execution_chain_is_suspicious() {
        // Arrange
        let chain = TerminalChainEvidence {
            interactive_terminal: true,
            shell_execution: true,
            network_retrieval: true,
            new_artifact_materialized: true,
            execution_transition: true,
        };

        // Act
        let result = assess_terminal_chain(&chain);

        // Assert
        assert_eq!(result.verdict, Verdict::Suspicious);
        assert_eq!(
            result.availability,
            AnalysisAvailability::BlockedByTelemetry
        );
    }

    #[test]
    fn partial_terminal_or_download_activity_stays_benign_compatible() {
        // Arrange
        let cases = [
            TerminalChainEvidence {
                interactive_terminal: true,
                shell_execution: true,
                network_retrieval: false,
                new_artifact_materialized: false,
                execution_transition: false,
            },
            TerminalChainEvidence {
                interactive_terminal: false,
                shell_execution: false,
                network_retrieval: true,
                new_artifact_materialized: true,
                execution_transition: false,
            },
            TerminalChainEvidence {
                interactive_terminal: true,
                shell_execution: true,
                network_retrieval: true,
                new_artifact_materialized: true,
                execution_transition: false,
            },
        ];

        for case in cases {
            // Act
            let result = assess_terminal_chain(&case);

            // Assert
            assert_eq!(result.verdict, Verdict::Clean);
            assert_eq!(result.confidence, ConfidenceLevel::Low);
        }
    }

    #[test]
    fn xcode_baseline_is_clean_and_correlated_new_script_is_suspicious() {
        // Arrange
        let baseline = XcodeBuildEvidence {
            baseline_run_scripts: vec!["generate-assets".to_owned()],
            current_run_scripts: vec!["generate-assets".to_owned()],
            build_triggered_execution: true,
            ..XcodeBuildEvidence::default()
        };
        let changed = XcodeBuildEvidence {
            baseline_run_scripts: baseline.baseline_run_scripts.clone(),
            current_run_scripts: vec!["generate-assets".to_owned(), "new-fetch-step".to_owned()],
            build_triggered_execution: true,
            network_retrieval: true,
            ..XcodeBuildEvidence::default()
        };

        // Act / Assert
        assert_eq!(assess_xcode_build(&baseline).verdict, Verdict::Clean);
        assert_eq!(assess_xcode_build(&changed).verdict, Verdict::Suspicious);
    }

    #[test]
    fn defaults_alone_is_clean_and_encoded_decode_execution_chain_is_suspicious() {
        // Arrange
        let benign = PreferencesEvidence {
            preference_operation: true,
            ..PreferencesEvidence::default()
        };
        let correlated = PreferencesEvidence {
            preference_operation: true,
            opaque_or_encoded_content: true,
            decode_transition: true,
            execution_transition: true,
        };

        // Act / Assert
        assert_eq!(assess_preferences(&benign).verdict, Verdict::Clean);
        assert_eq!(assess_preferences(&correlated).verdict, Verdict::Suspicious);
    }

    #[test]
    fn ordinary_security_administration_is_clean_but_correlated_impairment_is_suspicious() {
        // Arrange
        let administration = SecurityControlEvidence {
            ordinary_administration: true,
            update_policy_change: true,
            repeated_tcc_reset: true,
            correlated_suspicious_context: true,
            ..SecurityControlEvidence::default()
        };
        let impairment = SecurityControlEvidence {
            protection_service_termination: true,
            protective_file_interference: true,
            correlated_suspicious_context: true,
            ..SecurityControlEvidence::default()
        };

        // Act / Assert
        assert_eq!(
            assess_security_control(&administration).verdict,
            Verdict::Clean
        );
        assert_eq!(
            assess_security_control(&impairment).verdict,
            Verdict::Suspicious
        );
    }

    #[test]
    fn webview_alone_is_clean_but_remote_native_bridge_capability_is_suspicious() {
        // Arrange
        let ordinary = RemoteBridgeEvidence {
            webview_present: true,
            ..RemoteBridgeEvidence::default()
        };
        let bridge = RemoteBridgeEvidence {
            webview_present: true,
            remotely_supplied_logic: true,
            native_bridge: true,
            filesystem_capability: true,
            ..RemoteBridgeEvidence::default()
        };

        // Act / Assert
        assert_eq!(assess_remote_bridge(&ordinary).verdict, Verdict::Clean);
        let result = assess_remote_bridge(&bridge);
        assert_eq!(result.verdict, Verdict::Suspicious);
        assert_eq!(result.availability, AnalysisAvailability::Experimental);
    }

    #[test]
    fn launchagent_alone_is_clean_but_correlated_temp_chain_is_suspicious() {
        let benign = assess_launchagent_persistence(&LaunchAgentEvidence {
            launchagent_registration: true,
            run_at_load: true,
            ..LaunchAgentEvidence::default()
        });
        let suspicious = assess_launchagent_persistence(&LaunchAgentEvidence {
            temporary_execution: true,
            stable_copy_present: true,
            launchagent_registration: true,
            run_at_load: true,
            ..LaunchAgentEvidence::default()
        });
        assert_eq!(benign.verdict, Verdict::Clean);
        assert_eq!(suspicious.verdict, Verdict::Suspicious);
    }

    #[test]
    fn capability_levels_never_promote_symbols_to_runtime_observation() {
        assert_eq!(
            capability_evidence_level(true, false, false),
            Some(CapabilityEvidenceLevel::StaticCapabilityHint)
        );
        assert_eq!(
            capability_evidence_level(true, true, false),
            Some(CapabilityEvidenceLevel::ImplementedCapabilityEvidence)
        );
        assert_eq!(
            capability_evidence_level(true, true, true),
            Some(CapabilityEvidenceLevel::ObservedRuntimeBehavior)
        );
        assert_eq!(capability_evidence_level(false, false, false), None);
    }
}
