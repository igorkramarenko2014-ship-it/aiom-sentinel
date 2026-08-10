#![forbid(unsafe_code)]
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used))]
//! Stable domain contracts for Phase 1 static scanning.

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
}
