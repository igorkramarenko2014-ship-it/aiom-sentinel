#![forbid(unsafe_code)]
#![cfg_attr(test, allow(clippy::expect_used, clippy::unwrap_used))]
//! Versioned product-facing DTOs. Internal scanner structs never cross this boundary.

use serde::{Deserialize, Serialize};
use serde_json::Value;

pub const DTO_SCHEMA_VERSION: &str = "sentinel-product/v1";

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
    pub identity: Value,
    pub rule_id: Option<String>,
    pub matched_evidence: Option<Value>,
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
            identity: Value::Null,
            rule_id: None,
            matched_evidence: None,
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
            },
            payload_sha256: "c".repeat(64),
        })
        .expect("receipt serializes");
        assert!(fields.get("destination").is_none());
        assert!(fields.get("exported_at").is_none());
    }
}
