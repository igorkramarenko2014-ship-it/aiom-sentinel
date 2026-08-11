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

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct CapabilityCoverage {
    pub capability: String,
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

#[must_use]
pub fn capability_coverage() -> Vec<CapabilityCoverage> {
    vec![
        capability(
            "IOC_LIFECYCLE",
            CoverageStatus::ImplementedTested,
            RuntimeAvailability::Available,
            None,
        ),
        capability(
            "TRANSACTIONAL_QUARANTINE_CORE",
            CoverageStatus::ImplementedTested,
            RuntimeAvailability::Available,
            Some("MACOS_UNIX_VERIFIED_LOCAL"),
        ),
        capability(
            "PRODUCT_QUARANTINE_WIRING",
            CoverageStatus::Unavailable,
            RuntimeAvailability::Unavailable,
            Some("production key authority is not implemented"),
        ),
        capability(
            "SCANNER_FAILURE_NEVER_CLEAN",
            CoverageStatus::ImplementedTested,
            RuntimeAvailability::Available,
            None,
        ),
        capability(
            "MACOS_SIGNING_EVIDENCE",
            CoverageStatus::Partial,
            RuntimeAvailability::HostDependent,
            Some("bounded parser/correlation; no canonical live command adapter"),
        ),
        capability(
            "CLICKFIX_TERMINAL_CHAIN",
            CoverageStatus::BlockedByTelemetry,
            RuntimeAvailability::Unavailable,
            Some("synthetic correlation only; no process telemetry"),
        ),
        capability(
            "NPM_SUPPLY_CHAIN_MODEL",
            CoverageStatus::Partial,
            RuntimeAvailability::Unavailable,
            Some("bounded manifest/supplied-observation analysis; no endpoint observer"),
        ),
        capability(
            "AGENT_SKILL_MODEL",
            CoverageStatus::Partial,
            RuntimeAvailability::Unavailable,
            Some("static/synthetic analysis only"),
        ),
        capability(
            "XCODE_BUILD_TRIGGERED_EXECUTION",
            CoverageStatus::BlockedByTelemetry,
            RuntimeAvailability::Unavailable,
            Some("bounded baseline/diff representation only"),
        ),
        capability(
            "PREFERENCES_ENCODED_PERSISTENCE",
            CoverageStatus::BlockedByTelemetry,
            RuntimeAvailability::Unavailable,
            Some("bounded correlation representation only"),
        ),
        capability(
            "MACOS_SECURITY_CONTROL_IMPAIRMENT",
            CoverageStatus::BlockedByTelemetry,
            RuntimeAvailability::Unavailable,
            Some("no TCC/XProtect observation surface"),
        ),
        capability(
            "REMOTE_LOGIC_NATIVE_BRIDGE",
            CoverageStatus::Experimental,
            RuntimeAvailability::Unavailable,
            Some("no WebView runtime observer"),
        ),
        capability(
            "YARA_X_HYGIENE",
            CoverageStatus::ImplementedTested,
            RuntimeAvailability::Available,
            Some("compile hygiene is not detection efficacy"),
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
    vec![
        "EXTERNAL_REPORT != MALICIOUS_VERDICT",
        "IOC_MATCH != FAMILY_ATTRIBUTION",
        "SIGNED != SAFE",
        "NOTARIZED != SAFE",
        "TRUSTED_PUBLISHING != SAFE",
        "REGISTRY_SCANNED != ENDPOINT_SAFE",
        "UPSTREAM_FIXED != LOCAL_ENDPOINT_CLEAN",
        "STATIC_ONLY != SAFE",
        "STATIC_BINARY_CLEAN != RUNTIME_BEHAVIOR_CLEAN",
        "ML_SCORE != MALICIOUS",
        "SCANNER_FAILURE != CLEAN",
        "ENGINE_FAILURE != CLEAN",
    ]
}

fn capability(
    capability: &str,
    status: CoverageStatus,
    runtime_observation: RuntimeAvailability,
    limitation: Option<&str>,
) -> CapabilityCoverage {
    CapabilityCoverage {
        capability: capability.to_owned(),
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
    fn absent_observers_cannot_report_runtime_coverage() {
        // Arrange / Act
        let coverage = capability_coverage();

        // Assert
        for capability_name in [
            "CLICKFIX_TERMINAL_CHAIN",
            "XCODE_BUILD_TRIGGERED_EXECUTION",
            "PREFERENCES_ENCODED_PERSISTENCE",
            "MACOS_SECURITY_CONTROL_IMPAIRMENT",
        ] {
            let item = coverage
                .iter()
                .find(|item| item.capability == capability_name)
                .unwrap();
            assert_eq!(item.status, CoverageStatus::BlockedByTelemetry);
            assert_eq!(item.runtime_observation, RuntimeAvailability::Unavailable);
        }
    }

    #[test]
    fn honesty_contract_contains_never_clean_failure_invariants() {
        // Arrange / Act
        let invariants = product_honesty_invariants();

        // Assert
        assert!(invariants.contains(&"SCANNER_FAILURE != CLEAN"));
        assert!(invariants.contains(&"ENGINE_FAILURE != CLEAN"));
        assert!(invariants.contains(&"IOC_MATCH != FAMILY_ATTRIBUTION"));
    }
}
