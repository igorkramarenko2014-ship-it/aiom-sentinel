use sentinel_core::threat_coverage::CapabilityId;
use sentinel_core::{ConfidenceLevel, Verdict};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum NpmPrimitive {
    LifecycleExecution,
    ImportTimeExecution,
    RuntimeBinaryDownload,
    NewChildProcess,
    ProvenanceDrift,
    CredentialAccess,
    LocalArtifactAfterUpstreamFix,
    BuildTimeDependencyExecution,
    ArchitectureSpecificArtifactSelection,
    PlatformSpecificNativeFetch,
}

impl NpmPrimitive {
    #[must_use]
    pub const fn capability_id(self) -> CapabilityId {
        match self {
            Self::LifecycleExecution | Self::ImportTimeExecution => {
                CapabilityId::NpmSupplyChainModel
            }
            Self::RuntimeBinaryDownload | Self::NewChildProcess => {
                CapabilityId::BuildTimeDependencyExecution
            }
            Self::ProvenanceDrift
            | Self::CredentialAccess
            | Self::LocalArtifactAfterUpstreamFix => {
                CapabilityId::PersistentEffectAfterInitialRemoval
            }
            Self::BuildTimeDependencyExecution => CapabilityId::BuildTimeDependencyExecution,
            Self::ArchitectureSpecificArtifactSelection => {
                CapabilityId::ArchitectureSpecificArtifactSelection
            }
            Self::PlatformSpecificNativeFetch => CapabilityId::PlatformSpecificNativeFetch,
        }
    }
}

#[cfg(test)]
fn primitive_is_catalogued(primitive: NpmPrimitive) -> bool {
    sentinel_core::threat_coverage::capability_coverage()
        .iter()
        .any(|row| row.capability == primitive.capability_id())
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct BuildDependencyEvidence {
    pub source_repository_clean: bool,
    pub dependency_graph_suspicious: bool,
    pub resolved_package_suspicious: bool,
    pub build_time_execution: bool,
    pub install_hooks_disabled: bool,
    pub architecture_selected: bool,
    pub native_artifact_fetched: bool,
    pub ordinary_installer_context: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BuildDependencyAnalysis {
    pub primitives: Vec<NpmPrimitive>,
    pub verdict: Verdict,
    pub confidence: ConfidenceLevel,
}

/// Analyze a dependency/build chain without treating a clean source checkout or
/// disabled install hooks as proof that imported build-time code is safe.
#[must_use]
pub fn analyze_build_dependency(evidence: &BuildDependencyEvidence) -> BuildDependencyAnalysis {
    let mut primitives = Vec::new();
    if evidence.build_time_execution {
        primitives.push(NpmPrimitive::BuildTimeDependencyExecution);
    }
    if evidence.architecture_selected {
        primitives.push(NpmPrimitive::ArchitectureSpecificArtifactSelection);
    }
    if evidence.native_artifact_fetched {
        primitives.push(NpmPrimitive::PlatformSpecificNativeFetch);
    }
    let correlated = evidence.dependency_graph_suspicious
        && (evidence.build_time_execution
            || evidence.native_artifact_fetched
            || evidence.resolved_package_suspicious)
        && !evidence.ordinary_installer_context;
    BuildDependencyAnalysis {
        primitives,
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
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum PersistenceState {
    InitialArtifactPresent,
    InitialArtifactRemoved,
    PersistentCopyPresent,
    PersistenceMechanismPresent,
    PersistentExecutionObserved,
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct PersistenceEvidence {
    pub initial_artifact_present: bool,
    pub initial_artifact_removed: bool,
    pub persistent_copy_present: bool,
    pub persistence_mechanism_present: bool,
    pub persistent_execution_observed: bool,
    pub legitimate_install_context: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PersistenceAnalysis {
    pub states: Vec<PersistenceState>,
    pub remediation_resolved: bool,
    pub verdict: Verdict,
}

#[must_use]
pub fn analyze_persistence(evidence: &PersistenceEvidence) -> PersistenceAnalysis {
    let mut states = Vec::new();
    if evidence.initial_artifact_present {
        states.push(PersistenceState::InitialArtifactPresent);
    }
    if evidence.initial_artifact_removed {
        states.push(PersistenceState::InitialArtifactRemoved);
    }
    if evidence.persistent_copy_present {
        states.push(PersistenceState::PersistentCopyPresent);
    }
    if evidence.persistence_mechanism_present {
        states.push(PersistenceState::PersistenceMechanismPresent);
    }
    if evidence.persistent_execution_observed {
        states.push(PersistenceState::PersistentExecutionObserved);
    }
    let persistent = evidence.persistent_copy_present
        || evidence.persistence_mechanism_present
        || evidence.persistent_execution_observed;
    let suspicious = persistent && !evidence.legitimate_install_context;
    PersistenceAnalysis {
        states,
        remediation_resolved: !persistent,
        verdict: if suspicious {
            Verdict::Suspicious
        } else {
            Verdict::Clean
        },
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum LocalRemediationState {
    NotApplicable,
    UpstreamFixedLocalAbsent,
    UpstreamFixedLocalArtifactPresent,
    UpstreamFixedLocalExecutionObserved,
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct NpmBehaviorEvidence {
    pub import_time_execution: bool,
    pub runtime_binary_download: bool,
    pub new_child_process: bool,
    pub provenance_drift: bool,
    pub credential_access: bool,
    pub upstream_fixed: bool,
    pub local_artifact_present: bool,
    pub local_execution_observed: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NpmAnalysis {
    pub lifecycle_scripts: BTreeMap<String, String>,
    pub primitives: Vec<NpmPrimitive>,
    pub remediation: LocalRemediationState,
    pub verdict: Verdict,
    pub confidence: ConfidenceLevel,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum AgentSkillCapability {
    ShellContent,
    RemoteInstructionFetch,
    SecretAccess,
    RepositoryMutation,
    ExternalUpload,
    HiddenScriptReference,
    RuntimeProcessBehavior,
    AgentConfigPersistence,
    DeveloperToolConfigMutation,
    CiSecretAccess,
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct AgentSkillEvidence {
    pub declared_intent: Vec<String>,
    pub static_shell_content: bool,
    pub remote_instruction_fetch: bool,
    pub secret_access: bool,
    pub repository_mutation: bool,
    pub external_upload: bool,
    pub hidden_script_reference: bool,
    pub runtime_process_capability: bool,
    pub observed_execution: bool,
    pub agent_config_persistence: bool,
    pub developer_tool_config_mutation: bool,
    pub ci_secret_access: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AgentSkillAnalysis {
    pub declared_intent: Vec<String>,
    pub static_capabilities: Vec<AgentSkillCapability>,
    pub runtime_capabilities: Vec<AgentSkillCapability>,
    pub observed_execution: bool,
    pub verdict: Verdict,
    pub confidence: ConfidenceLevel,
}

#[must_use]
pub fn analyze_agent_skill(evidence: &AgentSkillEvidence) -> AgentSkillAnalysis {
    let mut static_capabilities = Vec::new();
    let mut runtime_capabilities = Vec::new();
    for (present, capability) in [
        (
            evidence.static_shell_content,
            AgentSkillCapability::ShellContent,
        ),
        (
            evidence.remote_instruction_fetch,
            AgentSkillCapability::RemoteInstructionFetch,
        ),
        (evidence.secret_access, AgentSkillCapability::SecretAccess),
        (
            evidence.repository_mutation,
            AgentSkillCapability::RepositoryMutation,
        ),
        (
            evidence.external_upload,
            AgentSkillCapability::ExternalUpload,
        ),
        (
            evidence.hidden_script_reference,
            AgentSkillCapability::HiddenScriptReference,
        ),
        (
            evidence.agent_config_persistence,
            AgentSkillCapability::AgentConfigPersistence,
        ),
        (
            evidence.developer_tool_config_mutation,
            AgentSkillCapability::DeveloperToolConfigMutation,
        ),
        (
            evidence.ci_secret_access,
            AgentSkillCapability::CiSecretAccess,
        ),
    ] {
        if present {
            static_capabilities.push(capability);
        }
    }
    if evidence.runtime_process_capability {
        runtime_capabilities.push(AgentSkillCapability::RuntimeProcessBehavior);
    }

    let correlated = evidence.secret_access && evidence.external_upload
        || evidence.remote_instruction_fetch && evidence.hidden_script_reference
        || evidence.remote_instruction_fetch && evidence.agent_config_persistence
        || evidence.observed_execution
            && (evidence.repository_mutation
                || evidence.developer_tool_config_mutation
                || evidence.ci_secret_access);
    AgentSkillAnalysis {
        declared_intent: evidence.declared_intent.clone(),
        static_capabilities,
        runtime_capabilities,
        observed_execution: evidence.observed_execution,
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
    }
}

pub fn analyze_npm_package(
    package_json: &str,
    evidence: &NpmBehaviorEvidence,
) -> Result<NpmAnalysis, String> {
    let document: serde_json::Value =
        serde_json::from_str(package_json).map_err(|error| format!("package.json: {error}"))?;
    let lifecycle_scripts = document
        .get("scripts")
        .and_then(serde_json::Value::as_object)
        .into_iter()
        .flatten()
        .filter(|(name, _)| {
            matches!(
                name.as_str(),
                "preinstall" | "install" | "postinstall" | "prepare" | "prepublish"
            )
        })
        .filter_map(|(name, value)| {
            value
                .as_str()
                .map(|script| (name.clone(), script.to_owned()))
        })
        .collect::<BTreeMap<_, _>>();

    let mut primitives = Vec::new();
    if !lifecycle_scripts.is_empty() {
        primitives.push(NpmPrimitive::LifecycleExecution);
    }
    if evidence.import_time_execution {
        primitives.push(NpmPrimitive::ImportTimeExecution);
    }
    if evidence.runtime_binary_download {
        primitives.push(NpmPrimitive::RuntimeBinaryDownload);
    }
    if evidence.new_child_process {
        primitives.push(NpmPrimitive::NewChildProcess);
    }
    if evidence.provenance_drift {
        primitives.push(NpmPrimitive::ProvenanceDrift);
    }
    if evidence.credential_access {
        primitives.push(NpmPrimitive::CredentialAccess);
    }

    let remediation = if !evidence.upstream_fixed {
        LocalRemediationState::NotApplicable
    } else if evidence.local_execution_observed {
        LocalRemediationState::UpstreamFixedLocalExecutionObserved
    } else if evidence.local_artifact_present {
        LocalRemediationState::UpstreamFixedLocalArtifactPresent
    } else {
        LocalRemediationState::UpstreamFixedLocalAbsent
    };
    if matches!(
        remediation,
        LocalRemediationState::UpstreamFixedLocalArtifactPresent
            | LocalRemediationState::UpstreamFixedLocalExecutionObserved
    ) {
        primitives.push(NpmPrimitive::LocalArtifactAfterUpstreamFix);
    }

    let strong = evidence.credential_access
        || evidence.runtime_binary_download && evidence.new_child_process
        || evidence.import_time_execution && evidence.provenance_drift
        || evidence.local_execution_observed;
    Ok(NpmAnalysis {
        lifecycle_scripts,
        primitives,
        remediation,
        verdict: if strong {
            Verdict::Suspicious
        } else {
            Verdict::Clean
        },
        confidence: if strong {
            ConfidenceLevel::Medium
        } else {
            ConfidenceLevel::Low
        },
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lifecycle_import_and_runtime_download_are_separate_primitives() {
        // Arrange
        let package = r#"{"scripts":{"postinstall":"node setup.js"}}"#;
        let evidence = NpmBehaviorEvidence {
            import_time_execution: true,
            runtime_binary_download: true,
            new_child_process: true,
            ..NpmBehaviorEvidence::default()
        };

        // Act
        let result = analyze_npm_package(package, &evidence).unwrap();

        // Assert
        assert_eq!(result.verdict, Verdict::Suspicious);
        assert!(
            result
                .primitives
                .contains(&NpmPrimitive::LifecycleExecution)
        );
        assert!(
            result
                .primitives
                .contains(&NpmPrimitive::ImportTimeExecution)
        );
        assert!(
            result
                .primitives
                .contains(&NpmPrimitive::RuntimeBinaryDownload)
        );
    }

    #[test]
    fn legitimate_lifecycle_and_safe_update_remain_benign_compatible() {
        // Arrange
        let package = r#"{"scripts":{"install":"node-gyp rebuild"}}"#;
        let evidence = NpmBehaviorEvidence {
            upstream_fixed: true,
            ..NpmBehaviorEvidence::default()
        };

        // Act
        let result = analyze_npm_package(package, &evidence).unwrap();

        // Assert
        assert_eq!(result.verdict, Verdict::Clean);
        assert_eq!(result.confidence, ConfidenceLevel::Low);
        assert_eq!(
            result.remediation,
            LocalRemediationState::UpstreamFixedLocalAbsent
        );
    }

    #[test]
    fn upstream_fix_does_not_erase_local_artifact_or_execution_state() {
        // Arrange
        let package = r#"{"name":"safe-name","version":"2.0.0"}"#;
        let local_artifact = NpmBehaviorEvidence {
            upstream_fixed: true,
            local_artifact_present: true,
            ..NpmBehaviorEvidence::default()
        };
        let local_execution = NpmBehaviorEvidence {
            upstream_fixed: true,
            local_artifact_present: true,
            local_execution_observed: true,
            ..NpmBehaviorEvidence::default()
        };

        // Act
        let artifact_result = analyze_npm_package(package, &local_artifact).unwrap();
        let execution_result = analyze_npm_package(package, &local_execution).unwrap();

        // Assert
        assert_eq!(
            artifact_result.remediation,
            LocalRemediationState::UpstreamFixedLocalArtifactPresent
        );
        assert_eq!(artifact_result.verdict, Verdict::Clean);
        assert_eq!(
            execution_result.remediation,
            LocalRemediationState::UpstreamFixedLocalExecutionObserved
        );
        assert_eq!(execution_result.verdict, Verdict::Suspicious);
    }

    #[test]
    fn ordinary_shell_using_agent_skill_is_not_malicious() {
        // Arrange
        let evidence = AgentSkillEvidence {
            declared_intent: vec!["run local formatter".to_owned()],
            static_shell_content: true,
            ..AgentSkillEvidence::default()
        };

        // Act
        let result = analyze_agent_skill(&evidence);

        // Assert
        assert_eq!(result.verdict, Verdict::Clean);
        assert_eq!(result.confidence, ConfidenceLevel::Low);
        assert_eq!(
            result.static_capabilities,
            vec![AgentSkillCapability::ShellContent]
        );
        assert!(!result.observed_execution);
    }

    #[test]
    fn every_npm_primitive_has_a_registered_typed_capability() {
        let primitives = [
            NpmPrimitive::LifecycleExecution,
            NpmPrimitive::ImportTimeExecution,
            NpmPrimitive::RuntimeBinaryDownload,
            NpmPrimitive::NewChildProcess,
            NpmPrimitive::ProvenanceDrift,
            NpmPrimitive::CredentialAccess,
            NpmPrimitive::LocalArtifactAfterUpstreamFix,
            NpmPrimitive::BuildTimeDependencyExecution,
            NpmPrimitive::ArchitectureSpecificArtifactSelection,
            NpmPrimitive::PlatformSpecificNativeFetch,
        ];
        assert!(primitives.iter().copied().all(primitive_is_catalogued));
    }

    #[test]
    fn correlated_remote_instruction_and_config_persistence_is_suspicious() {
        // Arrange
        let evidence = AgentSkillEvidence {
            declared_intent: vec!["documentation helper".to_owned()],
            remote_instruction_fetch: true,
            hidden_script_reference: true,
            agent_config_persistence: true,
            runtime_process_capability: true,
            ..AgentSkillEvidence::default()
        };

        // Act
        let result = analyze_agent_skill(&evidence);

        // Assert
        assert_eq!(result.verdict, Verdict::Suspicious);
        assert!(
            result
                .static_capabilities
                .contains(&AgentSkillCapability::RemoteInstructionFetch)
        );
        assert_eq!(
            result.runtime_capabilities,
            vec![AgentSkillCapability::RuntimeProcessBehavior]
        );
        assert!(!result.observed_execution);
    }

    #[test]
    fn observed_secret_or_repository_side_effects_raise_confidence() {
        // Arrange
        let exfiltration = AgentSkillEvidence {
            secret_access: true,
            external_upload: true,
            ..AgentSkillEvidence::default()
        };
        let repository_effect = AgentSkillEvidence {
            repository_mutation: true,
            observed_execution: true,
            ..AgentSkillEvidence::default()
        };

        // Act
        let exfiltration_result = analyze_agent_skill(&exfiltration);
        let repository_result = analyze_agent_skill(&repository_effect);

        // Assert
        assert_eq!(exfiltration_result.verdict, Verdict::Suspicious);
        assert_eq!(repository_result.verdict, Verdict::Suspicious);
        assert!(repository_result.observed_execution);
    }

    #[test]
    fn dependency_graph_and_build_execution_remain_actionable_when_source_is_clean() {
        let result = analyze_build_dependency(&BuildDependencyEvidence {
            source_repository_clean: true,
            dependency_graph_suspicious: true,
            build_time_execution: true,
            install_hooks_disabled: true,
            ..BuildDependencyEvidence::default()
        });
        assert_eq!(result.verdict, Verdict::Suspicious);
        assert!(
            result
                .primitives
                .contains(&NpmPrimitive::BuildTimeDependencyExecution)
        );
    }

    #[test]
    fn ordinary_architecture_aware_installer_is_benign_compatible() {
        let result = analyze_build_dependency(&BuildDependencyEvidence {
            architecture_selected: true,
            native_artifact_fetched: true,
            ordinary_installer_context: true,
            ..BuildDependencyEvidence::default()
        });
        assert_eq!(result.verdict, Verdict::Clean);
    }

    #[test]
    fn build_execution_and_native_fetch_correlate_but_architecture_alone_does_not() {
        let benign = analyze_build_dependency(&BuildDependencyEvidence {
            architecture_selected: true,
            ..BuildDependencyEvidence::default()
        });
        let suspicious = analyze_build_dependency(&BuildDependencyEvidence {
            dependency_graph_suspicious: true,
            build_time_execution: true,
            architecture_selected: true,
            native_artifact_fetched: true,
            ..BuildDependencyEvidence::default()
        });
        assert_eq!(benign.verdict, Verdict::Clean);
        assert_eq!(suspicious.verdict, Verdict::Suspicious);
        assert!(
            suspicious
                .primitives
                .contains(&NpmPrimitive::PlatformSpecificNativeFetch)
        );
    }

    #[test]
    fn removed_first_stage_does_not_hide_persistent_effect() {
        let result = analyze_persistence(&PersistenceEvidence {
            initial_artifact_removed: true,
            persistent_copy_present: true,
            persistence_mechanism_present: true,
            ..PersistenceEvidence::default()
        });
        assert_eq!(result.verdict, Verdict::Suspicious);
        assert!(!result.remediation_resolved);
    }

    #[test]
    fn no_persistent_effect_allows_remediation_to_resolve() {
        let result = analyze_persistence(&PersistenceEvidence {
            initial_artifact_removed: true,
            ..PersistenceEvidence::default()
        });
        assert_eq!(result.verdict, Verdict::Clean);
        assert!(result.remediation_resolved);
    }

    #[test]
    fn legitimate_install_persistence_is_benign_compatible() {
        let result = analyze_persistence(&PersistenceEvidence {
            persistent_copy_present: true,
            persistence_mechanism_present: true,
            legitimate_install_context: true,
            ..PersistenceEvidence::default()
        });
        assert_eq!(result.verdict, Verdict::Clean);
    }
}
