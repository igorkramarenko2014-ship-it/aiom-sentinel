#![forbid(unsafe_code)]
#![cfg_attr(test, allow(clippy::expect_used, clippy::unwrap_used))]
//! Versioned product-facing DTOs. Internal scanner structs never cross this boundary.

use sentinel_core::{EngineCoverageV1, FileIdentity, MatchSpan, RuleMetadataEntry};
use serde::{Deserialize, Serialize};

pub const DTO_SCHEMA_VERSION: &str = "sentinel-product/v2";
pub const PREVIOUS_DTO_SCHEMA_VERSION: &str = "sentinel-product/v1";
pub const WATCH_SCHEMA_VERSION: &str = "sentinel-watch/v1";

pub fn validate_dto_schema(version: &str) -> Result<(), String> {
    if version == DTO_SCHEMA_VERSION {
        Ok(())
    } else {
        Err(format!("unsupported DTO schema: {version}"))
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ScanFileRequestV1 {
    pub request_id: String,
    pub target_path: String,
    pub rule_pack: RulePackBindingV1,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct RulePackBindingV1 {
    pub pack_id: String,
    pub expected_bytes_sha256: String,
    pub source_path: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ScanFindingV1 {
    pub path: String,
    pub identity: FileIdentity,
    pub engine_id: String,
    pub rule_id: String,
    pub namespace: String,
    pub matched_condition: String,
    pub evidence_reference: String,
    pub tags: Vec<String>,
    pub metadata: Vec<RuleMetadataEntry>,
    pub spans: Vec<MatchSpan>,
    pub confidence: Option<String>,
    pub severity: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ScanResultV1 {
    pub schema_version: String,
    pub request_id: String,
    pub state: ScanStateV1,
    pub processed_count: u64,
    pub finding_count: u64,
    pub findings: Vec<ScanFindingV1>,
    pub skipped: Vec<String>,
    pub held: Vec<String>,
    pub errors: Vec<ApplicationErrorV1>,
    pub rule_pack: RulePackBindingV1,
    #[serde(default)]
    pub engine_reports: Vec<EngineCoverageV1>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ScanStateV1 {
    Completed,
    Failed,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct CanonicalReceiptV1 {
    pub schema_version: String,
    pub payload: ScanResultV1,
    pub payload_sha256: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ApplicationErrorV1 {
    pub code: String,
    pub message: String,
    pub path: Option<String>,
    pub retryable: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct WatchRequestV1 {
    pub root: String,
    pub rule_pack: RulePackBindingV1,
    pub queue_capacity: usize,
    pub debounce_ms: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum WatchEventTypeV1 {
    Create,
    Modify,
    RenameIn,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum WatchResultStateV1 {
    Match,
    NoMatch,
    Partial,
    Failed,
    Rejected,
    Cancelled,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, Default)]
pub struct WatchCountersV1 {
    pub accepted: u64,
    pub coalesced: u64,
    pub dropped: u64,
    pub rejected: u64,
    pub scanned: u64,
    pub matched: u64,
    pub failed: u64,
    pub cancelled: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct WatchResultV1 {
    pub schema_version: String,
    #[serde(default)]
    pub session_id: String,
    pub event_id: u64,
    #[serde(default)]
    pub generation: u64,
    pub event_type: WatchEventTypeV1,
    pub path: String,
    pub artifact_identity: Option<FileIdentity>,
    #[serde(default)]
    pub pre_scan_identity: Option<FileIdentity>,
    #[serde(default)]
    pub post_scan_identity: Option<FileIdentity>,
    pub observed_at: String,
    pub engine_id: String,
    pub ruleset_id: String,
    pub state: WatchResultStateV1,
    pub findings: Vec<ScanFindingV1>,
    pub coverage: Vec<EngineCoverageV1>,
    pub failure: Option<ApplicationErrorV1>,
    pub latency_ms: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct WatchHealthV1 {
    pub schema_version: String,
    pub active: bool,
    pub root: String,
    pub queue_capacity: usize,
    pub queue_depth: usize,
    pub counters: WatchCountersV1,
    pub last_failure: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct FolderSelectionV1 {
    pub selection_id: String,
    pub display_name: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct FolderProgressV1 {
    pub schema_version: String,
    pub request_id: String,
    pub phase: FolderProgressPhaseV1,
    pub discovered_count: u64,
    pub accepted_count: u64,
    pub processed_count: u64,
    pub finding_count: u64,
    pub skipped_count: u64,
    pub error_count: u64,
    pub current_relative_path: Option<String>,
    pub processed_bytes: u64,
    pub accepted_total_bytes: Option<u64>,
    pub cancellation_requested: bool,
    pub terminal: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum FolderProgressPhaseV1 {
    Discovering,
    Accepting,
    Scanning,
    Cancelling,
    Completed,
    CompletedWithFindings,
    Incomplete,
    Cancelled,
    Failed,
}

impl FolderProgressV1 {
    pub fn discovering(request_id: &str) -> Self {
        Self {
            schema_version: DTO_SCHEMA_VERSION.into(),
            request_id: request_id.into(),
            phase: FolderProgressPhaseV1::Discovering,
            discovered_count: 0,
            accepted_count: 0,
            processed_count: 0,
            finding_count: 0,
            skipped_count: 0,
            error_count: 0,
            current_relative_path: None,
            processed_bytes: 0,
            accepted_total_bytes: None,
            cancellation_requested: false,
            terminal: false,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct FolderFileResultV1 {
    pub relative_path: String,
    pub size_bytes: u64,
    pub content_sha256: Option<String>,
    pub state: FolderFileStateV1,
    pub finding_count: u64,
    pub findings: Vec<ScanFindingV1>,
    pub errors: Vec<ApplicationErrorV1>,
    pub child_evidence_sha256: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum FolderFileStateV1 {
    Processed,
    SkippedSymlink,
    SkippedLimit,
    ReadError,
    FileChangedDuringScan,
    Cancelled,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum FolderScanStateV1 {
    Completed,
    CompletedWithFindings,
    Incomplete,
    Cancelled,
    Failed,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct FolderScanResultV1 {
    pub schema_version: String,
    pub request_id: String,
    pub state: FolderScanStateV1,
    pub root_label: String,
    pub discovered_count: u64,
    pub accepted_count: u64,
    pub processed_count: u64,
    pub finding_count: u64,
    pub skipped_count: u64,
    pub error_count: u64,
    pub processed_bytes: u64,
    pub cancellation_requested: bool,
    pub files: Vec<FolderFileResultV1>,
    pub rule_pack: RulePackBindingV1,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct FolderManifestReceiptV1 {
    pub schema_version: String,
    pub run: FolderScanResultV1,
    pub content_manifest: FolderContentManifestV1,
    pub content_manifest_sha256: String,
    pub runtime_diagnostics: FolderScanRuntimeDiagnosticsV1,
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct FolderScanRuntimeDiagnosticsV1 {
    pub progress_delivery_error_count: u64,
    pub last_progress_delivery_error: Option<String>,
    pub terminal_progress_delivery_failed: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct FolderContentManifestV1 {
    pub manifest_schema_version: String,
    pub terminal_state: FolderScanStateV1,
    pub rule_pack_id: String,
    pub rule_pack_sha256: String,
    pub aggregate_counts: Vec<(String, u64)>,
    pub ordered_children: Vec<FolderManifestChildV1>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct FolderManifestChildV1 {
    pub relative_path: String,
    pub size_bytes: u64,
    pub content_sha256: Option<String>,
    pub child_evidence_sha256: Option<String>,
    pub state: FolderFileStateV1,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_roundtrip_preserves_binding() {
        let request = ScanFileRequestV1 {
            request_id: "req-1".to_owned(),
            target_path: "fixture.txt".to_owned(),
            rule_pack: RulePackBindingV1 {
                pack_id: "fixture-pack".to_owned(),
                expected_bytes_sha256: "a".repeat(64),
                source_path: "rules".to_owned(),
            },
        };
        let encoded = serde_json::to_string(&request).expect("DTO serializes");
        let decoded: ScanFileRequestV1 =
            serde_json::from_str(&encoded).expect("valid DTO must deserialize");
        assert_eq!(decoded, request);
    }

    #[test]
    fn nullable_finding_fields_remain_null() {
        let finding = ScanFindingV1 {
            path: "fixture.txt".to_owned(),
            identity: FileIdentity {
                os_family: sentinel_core::OsFamily::Unknown,
                platform_file_id: None,
                volume_or_device_id: None,
                canonical_path_sha256: "a".repeat(64),
                size: 0,
                change_indicator: None,
                identity_quality: sentinel_core::IdentityQuality::PathOnly,
            },
            engine_id: "test".to_owned(),
            rule_id: "rule".to_owned(),
            namespace: "default".to_owned(),
            matched_condition: "true".to_owned(),
            evidence_reference: "test".to_owned(),
            tags: vec![],
            metadata: vec![],
            spans: vec![],
            confidence: None,
            severity: None,
        };
        let encoded = serde_json::to_value(finding).expect("finding serializes");
        assert!(encoded["confidence"].is_null());
        assert!(encoded["severity"].is_null());
    }

    #[test]
    fn receipt_payload_has_no_export_destination_or_timestamp() {
        let fields = serde_json::to_value(CanonicalReceiptV1 {
            schema_version: DTO_SCHEMA_VERSION.to_owned(),
            payload: ScanResultV1 {
                schema_version: DTO_SCHEMA_VERSION.to_owned(),
                request_id: "req".to_owned(),
                state: ScanStateV1::Completed,
                processed_count: 0,
                finding_count: 0,
                findings: vec![],
                skipped: vec![],
                held: vec![],
                errors: vec![],
                rule_pack: RulePackBindingV1 {
                    pack_id: "pack".to_owned(),
                    expected_bytes_sha256: "b".repeat(64),
                    source_path: "rules".to_owned(),
                },
                engine_reports: vec![],
            },
            payload_sha256: "c".repeat(64),
        })
        .expect("receipt serializes");
        assert!(fields.get("destination").is_none());
        assert!(fields.get("exported_at").is_none());
    }
}
