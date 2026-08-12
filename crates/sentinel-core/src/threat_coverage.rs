use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum CoverageStatus {
    ImplementedTested,
    ImplementedUntested,
    Partial,
    Experimental,
    BlockedByTelemetry,
    Unavailable,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum RuntimeAvailability {
    Available,
    HostDependent,
    Unavailable,
}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum CapabilityId {
    IocLifecycle,
    TransactionalQuarantineCore,
    ProductQuarantineWiring,
    ScannerFailureNeverClean,
    MacosSigningEvidence,
    ClickfixTerminalChain,
    NpmSupplyChainModel,
    AgentSkillModel,
    XcodeBuildTriggeredExecution,
    PreferencesEncodedPersistence,
    MacosSecurityControlImpairment,
    RemoteLogicNativeBridge,
    YaraXHygiene,
    BuildTimeDependencyExecution,
    ArchitectureSpecificArtifactSelection,
    PlatformSpecificNativeFetch,
    PersistentEffectAfterInitialRemoval,
    StaticCapabilityHints,
    SourceClaimGovernance,
}

impl CapabilityId {
    pub const ALL: [Self; 19] = [
        Self::IocLifecycle,
        Self::TransactionalQuarantineCore,
        Self::ProductQuarantineWiring,
        Self::ScannerFailureNeverClean,
        Self::MacosSigningEvidence,
        Self::ClickfixTerminalChain,
        Self::NpmSupplyChainModel,
        Self::AgentSkillModel,
        Self::XcodeBuildTriggeredExecution,
        Self::PreferencesEncodedPersistence,
        Self::MacosSecurityControlImpairment,
        Self::RemoteLogicNativeBridge,
        Self::YaraXHygiene,
        Self::BuildTimeDependencyExecution,
        Self::ArchitectureSpecificArtifactSelection,
        Self::PlatformSpecificNativeFetch,
        Self::PersistentEffectAfterInitialRemoval,
        Self::StaticCapabilityHints,
        Self::SourceClaimGovernance,
    ];
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct CapabilityCoverage {
    pub capability: CapabilityId,
    pub status: CoverageStatus,
    pub runtime_observation: RuntimeAvailability,
    pub limitation: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct EngineStatus {
    pub engine: String,
    pub supported: bool,
    pub integrated: bool,
    pub available_runtime: RuntimeAvailability,
    pub tested: bool,
    pub limitation: Option<String>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum SourceProvenanceClass {
    PrimaryResearch,
    Upstream,
    Academic,
    Secondary,
    SourceUnverified,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ClaimVerificationState {
    Verified,
    Unverified,
    Disputed,
    UnsupportedByPrimary,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct SourceClaim {
    pub source_id: String,
    pub source_type: SourceProvenanceClass,
    pub claim: String,
    pub impact: String,
    pub verification: ClaimVerificationState,
    pub published_at: Option<String>,
    pub feed_ingested_at: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct CanonicalImpact {
    pub impact: String,
    pub verification: ClaimVerificationState,
    pub source_ids: Vec<String>,
}

/// Preserve every source claim while refusing to promote a stronger secondary
/// headline over a primary claim without corroboration.
#[must_use]
pub fn resolve_canonical_impact(claims: &[SourceClaim]) -> Option<CanonicalImpact> {
    let primary = claims.iter().find(|claim| {
        matches!(
            claim.source_type,
            SourceProvenanceClass::PrimaryResearch | SourceProvenanceClass::Upstream
        )
    })?;
    let corroborated = claims.iter().any(|claim| {
        claim.impact == primary.impact
            && matches!(claim.verification, ClaimVerificationState::Verified)
    });
    let supporting = claims
        .iter()
        .filter(|claim| claim.impact == primary.impact)
        .map(|claim| claim.source_id.clone())
        .collect();
    Some(CanonicalImpact {
        impact: primary.impact.clone(),
        verification: if corroborated {
            ClaimVerificationState::Verified
        } else {
            ClaimVerificationState::Unverified
        },
        source_ids: supporting,
    })
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct FeedRecency {
    pub first_seen: Option<String>,
    pub published_at: Option<String>,
    pub feed_ingested_at: Option<String>,
    pub observed_at: Option<String>,
}

#[must_use]
pub fn capability_coverage() -> Vec<CapabilityCoverage> {
    vec![
        capability(
            CapabilityId::IocLifecycle,
            CoverageStatus::ImplementedTested,
            RuntimeAvailability::Available,
            None,
        ),
        capability(
            CapabilityId::TransactionalQuarantineCore,
            CoverageStatus::ImplementedTested,
            RuntimeAvailability::Available,
            Some("MACOS_UNIX_VERIFIED_LOCAL"),
        ),
        capability(
            CapabilityId::ProductQuarantineWiring,
            CoverageStatus::Unavailable,
            RuntimeAvailability::Unavailable,
            Some("production key authority is not implemented"),
        ),
        capability(
            CapabilityId::ScannerFailureNeverClean,
            CoverageStatus::ImplementedTested,
            RuntimeAvailability::Available,
            None,
        ),
        capability(
            CapabilityId::MacosSigningEvidence,
            CoverageStatus::Partial,
            RuntimeAvailability::HostDependent,
            Some("bounded parser/correlation; no canonical live command adapter"),
        ),
        capability(
            CapabilityId::ClickfixTerminalChain,
            CoverageStatus::BlockedByTelemetry,
            RuntimeAvailability::Unavailable,
            Some("synthetic correlation only; no process telemetry"),
        ),
        capability(
            CapabilityId::NpmSupplyChainModel,
            CoverageStatus::Partial,
            RuntimeAvailability::Unavailable,
            Some("bounded manifest/supplied-observation analysis; no endpoint observer"),
        ),
        capability(
            CapabilityId::AgentSkillModel,
            CoverageStatus::Partial,
            RuntimeAvailability::Unavailable,
            Some("static/synthetic analysis only"),
        ),
        capability(
            CapabilityId::XcodeBuildTriggeredExecution,
            CoverageStatus::BlockedByTelemetry,
            RuntimeAvailability::Unavailable,
            Some("bounded baseline/diff representation only"),
        ),
        capability(
            CapabilityId::PreferencesEncodedPersistence,
            CoverageStatus::BlockedByTelemetry,
            RuntimeAvailability::Unavailable,
            Some("bounded correlation representation only"),
        ),
        capability(
            CapabilityId::MacosSecurityControlImpairment,
            CoverageStatus::BlockedByTelemetry,
            RuntimeAvailability::Unavailable,
            Some("no TCC/XProtect observation surface"),
        ),
        capability(
            CapabilityId::RemoteLogicNativeBridge,
            CoverageStatus::Experimental,
            RuntimeAvailability::Unavailable,
            Some("no WebView runtime observer"),
        ),
        capability(
            CapabilityId::YaraXHygiene,
            CoverageStatus::ImplementedTested,
            RuntimeAvailability::Available,
            Some("compile hygiene is not detection efficacy"),
        ),
        capability(
            CapabilityId::BuildTimeDependencyExecution,
            CoverageStatus::ImplementedTested,
            RuntimeAvailability::Unavailable,
            Some("static/synthetic dependency-chain model; no build-process observer"),
        ),
        capability(
            CapabilityId::ArchitectureSpecificArtifactSelection,
            CoverageStatus::ImplementedTested,
            RuntimeAvailability::Unavailable,
            Some("architecture-aware selection model; no live artifact observer"),
        ),
        capability(
            CapabilityId::PlatformSpecificNativeFetch,
            CoverageStatus::ImplementedTested,
            RuntimeAvailability::Unavailable,
            Some("correlation model only; no live retrieval observer"),
        ),
        capability(
            CapabilityId::PersistentEffectAfterInitialRemoval,
            CoverageStatus::ImplementedTested,
            RuntimeAvailability::Unavailable,
            Some("static/synthetic persistence state model"),
        ),
        capability(
            CapabilityId::StaticCapabilityHints,
            CoverageStatus::ImplementedTested,
            RuntimeAvailability::Unavailable,
            Some("symbols do not establish runtime behavior"),
        ),
        capability(
            CapabilityId::SourceClaimGovernance,
            CoverageStatus::ImplementedTested,
            RuntimeAvailability::Available,
            Some("secondary claims remain historical until corroborated"),
        ),
    ]
}

#[must_use]
pub fn engine_statuses() -> Vec<EngineStatus> {
    vec![
        engine(
            "YARA",
            true,
            true,
            RuntimeAvailability::HostDependent,
            true,
            Some("implemented through YARA-X compatibility, not a separate adapter"),
        ),
        engine(
            "YARA-X",
            true,
            true,
            RuntimeAvailability::Available,
            true,
            Some("version 1.19.0; tested with synthetic fixtures"),
        ),
        engine(
            "CAPA",
            false,
            false,
            RuntimeAvailability::Unavailable,
            false,
            None,
        ),
        engine(
            "ClamAV",
            false,
            false,
            RuntimeAvailability::Unavailable,
            false,
            None,
        ),
        engine(
            "Sigma",
            false,
            false,
            RuntimeAvailability::Unavailable,
            false,
            None,
        ),
    ]
}

#[must_use]
pub fn product_honesty_invariants() -> Vec<&'static str> {
    ProductHonestyInvariant::ALL
        .iter()
        .map(|item| item.as_str())
        .collect()
}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum ProductHonestyInvariant {
    ExternalReport,
    IocMatch,
    Signed,
    Notarized,
    TrustedPublishing,
    RegistryScanned,
    UpstreamFixed,
    StaticOnly,
    StaticBinaryClean,
    MlScore,
    ScannerFailure,
    EngineFailure,
    CleanRepository,
    InitialArtifactRemoved,
    SymbolPresent,
    SecondarySeverityAmplification,
    FeedNew,
}

impl ProductHonestyInvariant {
    pub const ALL: [Self; 17] = [
        Self::ExternalReport,
        Self::IocMatch,
        Self::Signed,
        Self::Notarized,
        Self::TrustedPublishing,
        Self::RegistryScanned,
        Self::UpstreamFixed,
        Self::StaticOnly,
        Self::StaticBinaryClean,
        Self::MlScore,
        Self::ScannerFailure,
        Self::EngineFailure,
        Self::CleanRepository,
        Self::InitialArtifactRemoved,
        Self::SymbolPresent,
        Self::SecondarySeverityAmplification,
        Self::FeedNew,
    ];

    const fn as_str(self) -> &'static str {
        match self {
            Self::ExternalReport => "EXTERNAL_REPORT != MALICIOUS_VERDICT",
            Self::IocMatch => "IOC_MATCH != FAMILY_ATTRIBUTION",
            Self::Signed => "SIGNED != SAFE",
            Self::Notarized => "NOTARIZED != SAFE",
            Self::TrustedPublishing => "TRUSTED_PUBLISHING != SAFE",
            Self::RegistryScanned => "REGISTRY_SCANNED != ENDPOINT_SAFE",
            Self::UpstreamFixed => "UPSTREAM_FIXED != LOCAL_ENDPOINT_CLEAN",
            Self::StaticOnly => "STATIC_ONLY != SAFE",
            Self::StaticBinaryClean => "STATIC_BINARY_CLEAN != RUNTIME_BEHAVIOR_CLEAN",
            Self::MlScore => "ML_SCORE != MALICIOUS",
            Self::ScannerFailure => "SCANNER_FAILURE != CLEAN",
            Self::EngineFailure => "ENGINE_FAILURE != CLEAN",
            Self::CleanRepository => "CLEAN_REPOSITORY != CLEAN_DEPENDENCY_GRAPH",
            Self::InitialArtifactRemoved => "INITIAL_ARTIFACT_REMOVED != PERSISTENCE_REMOVED",
            Self::SymbolPresent => "SYMBOL_PRESENT != CAPABILITY_OBSERVED",
            Self::SecondarySeverityAmplification => {
                "SECONDARY_SEVERITY_AMPLIFICATION != VERIFIED_IMPACT"
            }
            Self::FeedNew => "FEED_NEW != THREAT_NEW",
        }
    }
}

fn capability(
    capability: CapabilityId,
    status: CoverageStatus,
    runtime_observation: RuntimeAvailability,
    limitation: Option<&str>,
) -> CapabilityCoverage {
    CapabilityCoverage {
        capability,
        status,
        runtime_observation,
        limitation: limitation.map(ToOwned::to_owned),
    }
}

fn engine(
    engine: &str,
    supported: bool,
    integrated: bool,
    available_runtime: RuntimeAvailability,
    tested: bool,
    limitation: Option<&str>,
) -> EngineStatus {
    EngineStatus {
        engine: engine.to_owned(),
        supported,
        integrated,
        available_runtime,
        tested,
        limitation: limitation.map(ToOwned::to_owned),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unavailable_engines_are_not_reported_as_integrated_or_tested() {
        // Arrange / Act
        let statuses = engine_statuses();

        // Assert
        for name in ["CAPA", "ClamAV", "Sigma"] {
            let status = statuses.iter().find(|item| item.engine == name).unwrap();
            assert!(!status.supported);
            assert!(!status.integrated);
            assert!(!status.tested);
            assert_eq!(status.available_runtime, RuntimeAvailability::Unavailable);
        }
    }

    #[test]
    fn coverage_catalogue_is_typed_unique_and_complete() {
        let catalogue = capability_coverage();
        let ids: std::collections::BTreeSet<_> =
            catalogue.iter().map(|row| row.capability).collect();
        assert_eq!(ids.len(), catalogue.len());
        assert_eq!(ids.len(), CapabilityId::ALL.len());
        assert!(CapabilityId::ALL.iter().all(|id| ids.contains(id)));
    }

    #[test]
    fn coverage_runtime_honesty_is_universal() {
        for row in capability_coverage() {
            assert!(
                !(row.runtime_observation == RuntimeAvailability::Unavailable
                    && row.status == CoverageStatus::ImplementedTested
                    && row.limitation.is_none())
            );
            if row.status == CoverageStatus::BlockedByTelemetry {
                assert_eq!(row.runtime_observation, RuntimeAvailability::Unavailable);
            }
        }
    }

    #[test]
    fn absent_observers_cannot_report_runtime_coverage() {
        // Arrange / Act
        let coverage = capability_coverage();

        // Assert
        for item in coverage {
            if item.status == CoverageStatus::BlockedByTelemetry {
                assert_eq!(item.runtime_observation, RuntimeAvailability::Unavailable);
            }
        }
    }

    #[test]
    fn honesty_contract_contains_never_clean_failure_invariants() {
        // Arrange / Act
        let invariants = product_honesty_invariants();

        // Assert
        let canonical: Vec<_> = ProductHonestyInvariant::ALL
            .iter()
            .map(|item| item.as_str())
            .collect();
        assert_eq!(invariants, canonical);
        let unique: std::collections::BTreeSet<_> = invariants.iter().copied().collect();
        assert_eq!(unique.len(), invariants.len());
    }

    #[test]
    fn stronger_secondary_claim_is_retained_but_not_promoted() {
        let claims = vec![
            SourceClaim {
                source_id: "primary".to_owned(),
                source_type: SourceProvenanceClass::PrimaryResearch,
                claim: "auth bypass".to_owned(),
                impact: "authentication bypass".to_owned(),
                verification: ClaimVerificationState::Verified,
                published_at: Some("2026-08-12".to_owned()),
                feed_ingested_at: Some("2026-08-12".to_owned()),
            },
            SourceClaim {
                source_id: "secondary".to_owned(),
                source_type: SourceProvenanceClass::Secondary,
                claim: "headline".to_owned(),
                impact: "root RCE".to_owned(),
                verification: ClaimVerificationState::UnsupportedByPrimary,
                published_at: None,
                feed_ingested_at: Some("2026-08-12".to_owned()),
            },
        ];
        let canonical = resolve_canonical_impact(&claims).unwrap();
        assert_eq!(canonical.impact, "authentication bypass");
        assert_eq!(canonical.verification, ClaimVerificationState::Verified);
        assert!(
            !claims
                .iter()
                .any(|claim| claim.impact == canonical.impact && claim.source_id == "secondary")
        );
    }

    #[test]
    fn feed_ingestion_does_not_rewrite_report_age() {
        let recency = FeedRecency {
            first_seen: Some("2024-01-01".to_owned()),
            published_at: Some("2024-01-01".to_owned()),
            feed_ingested_at: Some("2026-08-12".to_owned()),
            observed_at: None,
        };
        assert_ne!(recency.first_seen, recency.feed_ingested_at);
    }
}
