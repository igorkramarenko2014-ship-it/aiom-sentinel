#![allow(clippy::expect_used, clippy::unwrap_used)]
use sentinel_core::{ScanLimits, ScanRequest, ScanTarget, Verdict};
use sentinel_evidence::EvidenceBundle;
use sentinel_rules::LocalRuleEngine;
use sentinel_scanner::scan;
use std::sync::Arc;
use uuid::Uuid;

#[tokio::test]
async fn harmless_positive_and_negative_rules_produce_normalized_evidence() {
    let directory = tempfile::tempdir().unwrap();
    let positive = directory.path().join("positive.txt");
    let negative = directory.path().join("negative.txt");
    std::fs::write(
        &positive,
        include_bytes!("../fixtures/harmless-positive.txt"),
    )
    .unwrap();
    std::fs::write(
        &negative,
        include_bytes!("../fixtures/harmless-negative.txt"),
    )
    .unwrap();
    let rules =
        Arc::new(LocalRuleEngine::parse(include_str!("../fixtures/harmless.rules")).unwrap());
    let request = ScanRequest {
        scan_id: Uuid::nil(),
        target: ScanTarget(directory.path().to_path_buf()),
        recursive: true,
        limits: ScanLimits::default(),
    };
    let result = scan(&request, Some(rules)).await.unwrap();
    assert_eq!(result.records.len(), 2);
    assert!(
        result
            .records
            .iter()
            .any(|record| record.verdict == Verdict::Match)
    );
    assert!(
        result
            .records
            .iter()
            .any(|record| record.verdict == Verdict::Clean)
    );
    let json = EvidenceBundle::from(result).to_json().unwrap();
    let value: serde_json::Value = serde_json::from_str(&json).unwrap();
    for field in ["schema_version", "scan_id", "records", "traversal_errors"] {
        assert!(value.get(field).is_some(), "missing {field}");
    }
}

#[tokio::test]
async fn oversized_file_becomes_explicit_scan_error() {
    let file = tempfile::NamedTempFile::new().unwrap();
    std::fs::write(file.path(), b"12345").unwrap();
    let request = ScanRequest {
        scan_id: Uuid::nil(),
        target: ScanTarget(file.path().to_path_buf()),
        recursive: false,
        limits: ScanLimits {
            max_file_size: 4,
            ..ScanLimits::default()
        },
    };
    let result = scan(&request, None).await.unwrap();
    assert_eq!(result.records[0].verdict, Verdict::ScanError);
    assert!(!result.records[0].errors.is_empty());
}
