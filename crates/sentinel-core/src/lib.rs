#![forbid(unsafe_code)]
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used))]
//! Stable domain contracts for Phase 1 static scanning.

pub mod threat_coverage;

use base64::{Engine as _, engine::general_purpose::STANDARD};
use serde::{Deserialize, Serialize};
use std::{ffi::OsStr, path::PathBuf};
use thiserror::Error;
use time::OffsetDateTime;
use uuid::Uuid;

pub const EVIDENCE_SCHEMA_VERSION: &str = "1.2.0";
pub const PREVIOUS_EVIDENCE_SCHEMA_VERSION: &str = "1.1.0";

pub fn is_supported_evidence_schema(version: &str) -> bool {
    matches!(
        version,
        EVIDENCE_SCHEMA_VERSION | PREVIOUS_EVIDENCE_SCHEMA_VERSION
    )
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum OsFamily {
    Windows,
    Linux,
    MacOs,
    Unknown,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum CapabilityState {
    Supported,
    Degraded,
    Unsupported,
    NotAuthorized,
    NotImplemented,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum VerificationLevel {
    ArchitectureReady,
    BuildVerified,
    TestVerified,
    RuntimeVerified,
    PrivilegedIntegrationVerified,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct PlatformCapability {
    pub capability: String,
    pub state: CapabilityState,
    pub verification: VerificationLevel,
    pub evidence_reference: Option<String>,
    pub reason: Option<String>,
}

pub trait PlatformCapabilities {
    fn os_family(&self) -> OsFamily;
    fn capabilities(&self) -> Vec<PlatformCapability>;
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ScanRequest {
    pub scan_id: Uuid,
    pub target: ScanTarget,
    pub recursive: bool,
    pub limits: ScanLimits,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ScanTarget(pub PathBuf);

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ScanLimits {
    pub max_depth: usize,
    pub max_files: usize,
    pub max_file_size: u64,
    pub max_evidence_records: usize,
}

pub const DEFAULT_MAX_FILE_BYTES: u64 = 1024 * 1024 * 1024;
pub const HARD_MAX_FILE_BYTES: u64 = 2 * 1024 * 1024 * 1024;

impl ScanLimits {
    pub fn validate(&self) -> Result<(), String> {
        if self.max_file_size == 0 || self.max_file_size > HARD_MAX_FILE_BYTES {
            return Err(format!(
                "max_file_size must be between 1 and {HARD_MAX_FILE_BYTES} bytes"
            ));
        }
        Ok(())
    }
}

impl Default for ScanLimits {
    fn default() -> Self {
        Self {
            max_depth: 64,
            max_files: 100_000,
            max_file_size: DEFAULT_MAX_FILE_BYTES,
            max_evidence_records: 100_000,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct SafePath {
    pub display: String,
    pub raw_base64: String,
    pub encoding: String,
}

impl SafePath {
    #[must_use]
    pub fn from_path(path: &std::path::Path) -> Self {
        Self {
            display: path.to_string_lossy().into_owned(),
            raw_base64: STANDARD.encode(os_bytes(path.as_os_str())),
            encoding: platform_encoding().to_owned(),
        }
    }
}

#[cfg(unix)]
fn os_bytes(value: &OsStr) -> Vec<u8> {
    use std::os::unix::ffi::OsStrExt;
    value.as_bytes().to_vec()
}

#[cfg(windows)]
fn os_bytes(value: &OsStr) -> Vec<u8> {
    use std::os::windows::ffi::OsStrExt;
    value.encode_wide().flat_map(u16::to_le_bytes).collect()
}

#[cfg(unix)]
const fn platform_encoding() -> &'static str {
    "unix-bytes"
}

#[cfg(windows)]
const fn platform_encoding() -> &'static str {
    "windows-utf16le"
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct FileMetadata {
    pub size: u64,
    pub file_type: FileFormat,
    pub canonical_path_status: CanonicalPathStatus,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct FileIdentity {
    pub os_family: OsFamily,
    pub platform_file_id: Option<String>,
    pub volume_or_device_id: Option<String>,
    pub canonical_path_sha256: String,
    pub size: u64,
    pub change_indicator: Option<String>,
    pub identity_quality: IdentityQuality,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum FileFormat {
    Pe,
    Elf,
    MachO,
    Script,
    Archive,
    Document,
    Other,
    Unknown,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum IdentityQuality {
    Native,
    Partial,
    PathOnly,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum CanonicalPathStatus {
    VerifiedInsideRoot,
    NotCanonicalized,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct HashSet {
    pub sha256: String,
    pub sha1: String,
    pub md5: String,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct EntropyResult {
    pub shannon_bits_per_byte: f64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct RuleMatch {
    pub identifier: String,
    pub namespace: String,
    pub source_hash_sha256: String,
    pub matched_condition: String,
    pub severity: Severity,
    pub confidence_contribution: u8,
    pub evidence_reference: String,
    #[serde(default)]
    pub tags: Vec<String>,
    #[serde(default)]
    pub metadata: Vec<RuleMetadataEntry>,
    #[serde(default)]
    pub spans: Vec<MatchSpan>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct MatchSpan {
    pub pattern: String,
    pub start: u64,
    pub end: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct RuleMetadataEntry {
    pub key: String,
    pub value: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct DetectionEngineIdentityV1 {
    pub engine_id: String,
    pub engine_version: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct RuleSetIdentityV1 {
    pub pack_id: String,
    pub content_sha256: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum EngineCoverageStateV1 {
    Complete,
    Partial,
    Failed,
    Unsupported,
    Cancelled,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct EngineCoverageV1 {
    pub engine: DetectionEngineIdentityV1,
    pub ruleset: RuleSetIdentityV1,
    pub state: EngineCoverageStateV1,
    pub scanned_bytes: u64,
    pub match_count: u64,
    pub reason: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct EngineScanResultV1 {
    pub schema_version: String,
    pub coverage: EngineCoverageV1,
    pub matches: Vec<RuleMatch>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EngineScanBudgetV1 {
    pub max_scan_bytes: usize,
    pub max_matches: usize,
    pub timeout_ms: u64,
    pub cancelled: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum Severity {
    Informational,
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct PeMetadata {
    pub machine: u16,
    pub timestamp: u32,
    pub sections: Vec<PeSection>,
    pub certificate_table_present: bool,
    pub warnings: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct PeSection {
    pub name: String,
    pub raw_size: u32,
    pub virtual_size: u32,
    pub entropy: f64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ScanFinding {
    pub detector: String,
    pub summary: String,
    pub severity: Severity,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct EngineVersion {
    pub scanner: String,
    pub rules: String,
    pub pe_parser: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum IocLifecycle {
    Active,
    Stale,
    Withdrawn,
    Disputed,
    Superseded,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum IocType {
    Sha256,
    Domain,
    Url,
    Ip,
    Certificate,
    TeamId,
    DeveloperId,
    BundleId,
    PackageName,
    PackageVersion,
    NpmNamespace,
    FilePathPattern,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IocDisposition {
    ActiveAlert,
    Review,
    HistoricalOnly,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct IocSource {
    pub source_id: String,
    pub source_type: String,
    pub confidence: u8,
    pub last_updated: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct IocRecord {
    pub ioc_id: String,
    pub ioc_type: IocType,
    pub value: String,
    pub lifecycle: IocLifecycle,
    pub sources: Vec<IocSource>,
    pub superseded_by: Option<String>,
}

impl IocRecord {
    #[must_use]
    pub const fn disposition(&self) -> IocDisposition {
        match self.lifecycle {
            IocLifecycle::Active => IocDisposition::ActiveAlert,
            IocLifecycle::Disputed => IocDisposition::Review,
            IocLifecycle::Stale | IocLifecycle::Withdrawn | IocLifecycle::Superseded => {
                IocDisposition::HistoricalOnly
            }
        }
    }

    #[must_use]
    pub fn exact_match_disposition(
        &self,
        ioc_type: IocType,
        observed_value: &str,
    ) -> Option<IocDisposition> {
        (self.ioc_type == ioc_type && self.value == observed_value).then(|| self.disposition())
    }

    pub fn transition_to(
        &mut self,
        lifecycle: IocLifecycle,
        superseded_by: Option<String>,
    ) -> Result<(), String> {
        if lifecycle == IocLifecycle::Superseded {
            let replacement = superseded_by
                .as_deref()
                .filter(|value| !value.is_empty() && *value != self.ioc_id)
                .ok_or_else(|| "superseded IOC requires a distinct replacement id".to_owned())?;
            self.superseded_by = Some(replacement.to_owned());
        } else if superseded_by.is_some() {
            return Err("superseded_by is only valid for SUPERSEDED lifecycle".to_owned());
        } else {
            self.superseded_by = None;
        }
        self.lifecycle = lifecycle;
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum Verdict {
    Clean,
    Suspicious,
    Match,
    ScanError,
    Unsupported,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ConfidenceLevel {
    Low,
    Medium,
    High,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum EvidenceQuality {
    AE0,
    AE1,
    AE2,
    AE3,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct EvidenceRecord {
    pub schema_version: String,
    pub evidence_id: Uuid,
    pub scan_id: Uuid,
    pub timestamp: OffsetDateTime,
    pub target_path: SafePath,
    pub canonical_path_status: CanonicalPathStatus,
    pub file_identity: FileIdentity,
    pub file_size: u64,
    pub hashes: Option<HashSet>,
    pub entropy: Option<EntropyResult>,
    pub file_type: FileFormat,
    pub format_support: CapabilityState,
    pub pe_metadata: Option<PeMetadata>,
    pub rule_matches: Vec<RuleMatch>,
    #[serde(default)]
    pub engine_reports: Vec<EngineCoverageV1>,
    pub findings: Vec<ScanFinding>,
    pub scanner_version: String,
    pub engine_version: EngineVersion,
    pub duration_ms: u128,
    pub errors: Vec<String>,
    pub verdict: Verdict,
    pub risk_score: u8,
    pub threat_confidence: ConfidenceLevel,
    pub benign_confidence: ConfidenceLevel,
    pub evidence_quality: EvidenceQuality,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ScanResult {
    pub scan_id: Uuid,
    pub records: Vec<EvidenceRecord>,
    pub traversal_errors: Vec<String>,
}

#[derive(Debug, Error)]
pub enum ScannerError {
    #[error("invalid scan target: {0}")]
    InvalidTarget(String),
    #[error("scan limit exceeded: {0}")]
    LimitExceeded(String),
    #[error("I/O error for {path}: {message}")]
    Io { path: String, message: String },
    #[error("evidence serialization failed: {0}")]
    Evidence(String),
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn default_limits_are_bounded() {
        let limits = ScanLimits::default();
        assert!(limits.max_depth > 0);
        assert!(limits.max_files <= 100_000);
        assert_eq!(limits.max_file_size, DEFAULT_MAX_FILE_BYTES);
        assert!(limits.validate().is_ok());
    }

    #[test]
    fn portability_contract_serializes_distinct_states() {
        let capability = PlatformCapability {
            capability: "static_scanning".to_owned(),
            state: CapabilityState::Supported,
            verification: VerificationLevel::TestVerified,
            evidence_reference: Some("local-test".to_owned()),
            reason: None,
        };
        let value = serde_json::to_value(&capability).unwrap();
        assert_eq!(value["state"], "SUPPORTED");
        assert_eq!(value["verification"], "TEST_VERIFIED");
        assert_ne!(
            CapabilityState::Unsupported,
            CapabilityState::NotImplemented
        );
        assert_eq!(serde_json::to_value(OsFamily::MacOs).unwrap(), "MAC_OS");
    }

    #[test]
    fn file_format_serialization_is_explicit() {
        assert_eq!(serde_json::to_value(FileFormat::Pe).unwrap(), "PE");
        assert_eq!(serde_json::to_value(FileFormat::Elf).unwrap(), "ELF");
        assert_eq!(serde_json::to_value(FileFormat::MachO).unwrap(), "MACH_O");
    }

    #[test]
    fn ioc_lifecycle_serialization_is_explicit() {
        // Arrange
        let states = [
            IocLifecycle::Active,
            IocLifecycle::Stale,
            IocLifecycle::Withdrawn,
            IocLifecycle::Disputed,
            IocLifecycle::Superseded,
        ];

        // Act
        let encoded = serde_json::to_value(states).unwrap();
        let decoded: Vec<IocLifecycle> = serde_json::from_value(encoded.clone()).unwrap();

        // Assert
        assert_eq!(
            encoded,
            serde_json::json!(["ACTIVE", "STALE", "WITHDRAWN", "DISPUTED", "SUPERSEDED"])
        );
        assert_eq!(decoded, states);
    }

    fn active_ioc() -> IocRecord {
        IocRecord {
            ioc_id: "sha256:fixture".to_owned(),
            ioc_type: IocType::Sha256,
            value: "00".repeat(32),
            lifecycle: IocLifecycle::Active,
            sources: vec![IocSource {
                source_id: "fixture-source".to_owned(),
                source_type: "UPSTREAM".to_owned(),
                confidence: 80,
                last_updated: "2026-08-10T00:00:00Z".to_owned(),
            }],
            superseded_by: None,
        }
    }

    #[test]
    fn ioc_lifecycle_controls_current_disposition() {
        // Arrange
        let mut record = active_ioc();

        // Act / Assert
        assert_eq!(record.disposition(), IocDisposition::ActiveAlert);
        record.transition_to(IocLifecycle::Disputed, None).unwrap();
        assert_eq!(record.disposition(), IocDisposition::Review);
        record.transition_to(IocLifecycle::Withdrawn, None).unwrap();
        assert_eq!(record.disposition(), IocDisposition::HistoricalOnly);
    }

    #[test]
    fn supersession_requires_a_distinct_replacement() {
        // Arrange
        let mut record = active_ioc();

        // Act
        let missing = record.transition_to(IocLifecycle::Superseded, None);
        let same =
            record.transition_to(IocLifecycle::Superseded, Some("sha256:fixture".to_owned()));
        let valid = record.transition_to(
            IocLifecycle::Superseded,
            Some("sha256:replacement".to_owned()),
        );

        // Assert
        assert!(missing.is_err());
        assert!(same.is_err());
        assert!(valid.is_ok());
        assert_eq!(record.disposition(), IocDisposition::HistoricalOnly);
    }

    #[test]
    fn ioc_matching_is_exact_and_lifecycle_aware() {
        // Arrange
        let mut record = active_ioc();
        let exact_value = record.value.clone();

        // Act / Assert
        assert_eq!(
            record.exact_match_disposition(IocType::Sha256, &exact_value),
            Some(IocDisposition::ActiveAlert)
        );
        assert_eq!(
            record.exact_match_disposition(IocType::Sha256, &format!("{exact_value}0")),
            None
        );
        assert_eq!(
            record.exact_match_disposition(IocType::Domain, &exact_value),
            None
        );

        record.transition_to(IocLifecycle::Stale, None).unwrap();
        assert_eq!(
            record.exact_match_disposition(IocType::Sha256, &exact_value),
            Some(IocDisposition::HistoricalOnly)
        );
    }
}
