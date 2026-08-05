#![forbid(unsafe_code)]
#![cfg_attr(test, allow(clippy::expect_used, clippy::unwrap_used))]
//! Shell-independent application service for the first product vertical slice.

use sentinel_core::{ScanLimits, ScanRequest, ScanTarget};
use sentinel_product_dto::{
    ApplicationErrorV1, CanonicalReceiptV1, DTO_SCHEMA_VERSION, RulePackBindingV1,
    ScanFileRequestV1, ScanFindingV1, ScanResultV1, ScanStateV1,
};
use sentinel_rules::LocalRuleEngine;
use sentinel_scanner::scan;
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::{path::Path, sync::Arc};
use thiserror::Error;
use uuid::Uuid;

#[derive(Debug, Error)]
pub enum ProductServiceError {
    #[error("invalid request id: {0}")]
    InvalidRequestId(String),
    #[error("rule pack identity mismatch: expected {expected}, actual {actual}")]
    RulePackIdentityMismatch { expected: String, actual: String },
    #[error("rule pack cannot be read: {0}")]
    RulePackRead(String),
    #[error("rule pack cannot be parsed: {0}")]
    RulePackParse(String),
    #[error("scan failed: {0}")]
    Scan(String),
    #[error("receipt serialization failed: {0}")]
    ReceiptSerialization(String),
}

impl ProductServiceError {
    fn application_error(&self, path: Option<String>) -> ApplicationErrorV1 {
        let code = match self {
            Self::InvalidRequestId(_) => "INVALID_REQUEST_ID",
            Self::RulePackIdentityMismatch { .. } => "RULE_PACK_IDENTITY_MISMATCH",
            Self::RulePackRead(_) => "RULE_PACK_UNAVAILABLE",
            Self::RulePackParse(_) => "RULE_PACK_INVALID",
            Self::Scan(_) => "SCAN_FAILED",
            Self::ReceiptSerialization(_) => "RECEIPT_SERIALIZATION_FAILED",
        };
        ApplicationErrorV1 {
            code: code.to_owned(),
            message: self.to_string(),
            path,
            retryable: matches!(self, Self::RulePackRead(_) | Self::Scan(_)),
        }
    }
}

/// Recompute rule-pack bytes immediately before the scan and refuse stale identity.
pub async fn scan_file_v1(request: ScanFileRequestV1) -> Result<ScanResultV1, ApplicationErrorV1> {
    let request_id = Uuid::parse_str(&request.request_id)
        .map_err(|error| ProductServiceError::InvalidRequestId(error.to_string()))
        .map_err(|error| error.application_error(Some(request.target_path.clone())))?;
    let source = tokio::fs::read(&request.rule_pack.source_path)
        .await
        .map_err(|error| ProductServiceError::RulePackRead(error.to_string()))
        .map_err(|error| error.application_error(Some(request.rule_pack.source_path.clone())))?;
    let actual_digest = hex::encode(Sha256::digest(&source));
    if actual_digest != request.rule_pack.expected_bytes_sha256 {
        return Err(ProductServiceError::RulePackIdentityMismatch {
            expected: request.rule_pack.expected_bytes_sha256,
            actual: actual_digest,
        }
        .application_error(Some(request.rule_pack.source_path)));
    }
    let source_text = String::from_utf8(source)
        .map_err(|error| ProductServiceError::RulePackParse(error.to_string()))
        .map_err(|error| error.application_error(Some(request.rule_pack.source_path.clone())))?;
    let rules = LocalRuleEngine::parse(&source_text)
        .map_err(|error| ProductServiceError::RulePackParse(error.to_string()))
        .map_err(|error| error.application_error(Some(request.rule_pack.source_path.clone())))?;
    let core_request = ScanRequest {
        scan_id: request_id,
        target: ScanTarget(request.target_path.clone().into()),
        recursive: false,
        limits: ScanLimits::default(),
    };
    let result = scan(&core_request, Some(Arc::new(rules)))
        .await
        .map_err(|error| ProductServiceError::Scan(error.to_string()))
        .map_err(|error| error.application_error(Some(request.target_path.clone())))?;
    let mut findings = Vec::new();
    let mut held = Vec::new();
    let mut errors = result.traversal_errors;
    let mut processed_count = 0_u64;
    for record in result.records {
        processed_count = processed_count.saturating_add(1);
        if record.verdict == sentinel_core::Verdict::ScanError {
            errors.extend(record.errors.clone());
        }
        if record.errors.iter().any(|error| error.contains("size")) {
            held.push(record.target_path.display.clone());
        }
        for rule_match in record.rule_matches {
            findings.push(ScanFindingV1 {
                path: record.target_path.display.clone(),
                identity: serde_json::to_value(&record.file_identity).unwrap_or(Value::Null),
                rule_id: Some(rule_match.identifier),
                matched_evidence: Some(serde_json::json!({
                    "condition": rule_match.matched_condition,
                    "reference": rule_match.evidence_reference,
                })),
                confidence: None,
                severity: Some(format!("{:?}", rule_match.severity)),
            });
        }
    }
    Ok(ScanResultV1 {
        schema_version: DTO_SCHEMA_VERSION.to_owned(),
        request_id: request.request_id,
        state: if errors.is_empty() {
            ScanStateV1::Completed
        } else {
            ScanStateV1::Failed
        },
        processed_count,
        finding_count: findings.len() as u64,
        findings,
        skipped: vec![],
        held,
        errors: errors
            .into_iter()
            .map(|message| ApplicationErrorV1 {
                code: "SCAN_RECORD_ERROR".to_owned(),
                message,
                path: None,
                retryable: false,
            })
            .collect(),
        rule_pack: RulePackBindingV1 {
            pack_id: request.rule_pack.pack_id,
            expected_bytes_sha256: actual_digest,
            source_path: request.rule_pack.source_path,
        },
    })
}

pub fn build_receipt_v1(result: ScanResultV1) -> Result<CanonicalReceiptV1, ProductServiceError> {
    let payload = serde_json::to_vec(&result)
        .map_err(|error| ProductServiceError::ReceiptSerialization(error.to_string()))?;
    let payload_sha256 = hex::encode(Sha256::digest(&payload));
    Ok(CanonicalReceiptV1 {
        schema_version: DTO_SCHEMA_VERSION.to_owned(),
        payload: result,
        payload_sha256,
    })
}

pub fn receipt_bytes(receipt: &CanonicalReceiptV1) -> Result<Vec<u8>, ProductServiceError> {
    serde_json::to_vec(receipt)
        .map_err(|error| ProductServiceError::ReceiptSerialization(error.to_string()))
}

pub fn write_receipt(
    receipt: &CanonicalReceiptV1,
    destination: &Path,
) -> Result<usize, ProductServiceError> {
    let bytes = receipt_bytes(receipt)?;
    std::fs::write(destination, &bytes)
        .map_err(|error| ProductServiceError::ReceiptSerialization(error.to_string()))?;
    Ok(bytes.len())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::tempdir;

    fn fixture_request(dir: &Path, content: &[u8]) -> ScanFileRequestV1 {
        let file = dir.join("fixture.txt");
        fs::write(&file, content).expect("fixture write");
        let rules = dir.join("rules.txt");
        fs::write(&rules, "marker|synthetic|HARMLESS_MARKER|LOW|20\n").expect("rules write");
        let digest = hex::encode(Sha256::digest(fs::read(&rules).expect("rules read")));
        ScanFileRequestV1 {
            request_id: Uuid::new_v4().to_string(),
            target_path: file.to_string_lossy().into_owned(),
            rule_pack: RulePackBindingV1 {
                pack_id: "fixture-pack".to_owned(),
                expected_bytes_sha256: digest,
                source_path: rules.to_string_lossy().into_owned(),
            },
        }
    }

    #[tokio::test]
    async fn scans_harmless_file_and_normalizes_result() {
        let dir = tempdir().expect("tempdir");
        let result = scan_file_v1(fixture_request(dir.path(), b"hello world"))
            .await
            .expect("scan");
        assert_eq!(result.state, ScanStateV1::Completed);
        assert_eq!(result.processed_count, 1);
        assert_eq!(result.finding_count, 0);
    }

    #[tokio::test]
    async fn binds_live_rule_pack_digest_and_refuses_mismatch() {
        let dir = tempdir().expect("tempdir");
        let mut request = fixture_request(dir.path(), b"HARMLESS_MARKER");
        request.rule_pack.expected_bytes_sha256 = "0".repeat(64);
        let error = scan_file_v1(request).await.expect_err("mismatch refused");
        assert_eq!(error.code, "RULE_PACK_IDENTITY_MISMATCH");
    }

    #[tokio::test]
    async fn receipt_is_deterministic_for_same_request_and_bytes() {
        let dir = tempdir().expect("tempdir");
        let mut first = fixture_request(dir.path(), b"HARMLESS_MARKER");
        first.request_id = "00000000-0000-0000-0000-000000000001".to_owned();
        let second = first.clone();
        let left = build_receipt_v1(scan_file_v1(first).await.expect("scan")).expect("receipt");
        let right = build_receipt_v1(scan_file_v1(second).await.expect("scan")).expect("receipt");
        assert_eq!(
            receipt_bytes(&left).expect("bytes"),
            receipt_bytes(&right).expect("bytes")
        );
        assert_eq!(
            left.payload_sha256,
            hex::encode(Sha256::digest(
                serde_json::to_vec(&left.payload).expect("payload")
            ))
        );
    }

    #[tokio::test]
    async fn scan_does_not_mutate_fixture() {
        let dir = tempdir().expect("tempdir");
        let request = fixture_request(dir.path(), b"HARMLESS_MARKER");
        let before = sha256_file(Path::new(&request.target_path));
        let target_path = request.target_path.clone();
        let _ = scan_file_v1(request).await.expect("scan");
        assert_eq!(before, sha256_file(Path::new(&target_path)));
    }

    fn sha256_file(path: &Path) -> String {
        hex::encode(Sha256::digest(fs::read(path).expect("file read")))
    }
}
