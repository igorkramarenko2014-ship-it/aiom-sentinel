#![forbid(unsafe_code)]
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used))]
//! Deterministic JSON evidence envelope and serialization.

use sentinel_core::{EVIDENCE_SCHEMA_VERSION, IocRecord, ScanResult, ScannerError};
use serde::{Deserialize, Serialize};
use std::{io::Write, path::Path};
use uuid::Uuid;

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct EvidenceBundle {
    pub schema_version: String,
    pub scan_id: Uuid,
    pub records: Vec<sentinel_core::EvidenceRecord>,
    pub traversal_errors: Vec<String>,
    #[serde(default)]
    pub ioc_matches: Vec<IocRecord>,
}

impl From<ScanResult> for EvidenceBundle {
    fn from(result: ScanResult) -> Self {
        Self {
            schema_version: EVIDENCE_SCHEMA_VERSION.to_owned(),
            scan_id: result.scan_id,
            records: result.records,
            traversal_errors: result.traversal_errors,
            ioc_matches: Vec::new(),
        }
    }
}

impl EvidenceBundle {
    pub fn to_json(&self) -> Result<String, ScannerError> {
        serde_json::to_string_pretty(self)
            .map_err(|error| ScannerError::Evidence(error.to_string()))
    }

    pub fn write(&self, path: &Path) -> Result<(), ScannerError> {
        let json = self.to_json()?;
        let parent = path.parent().unwrap_or_else(|| Path::new("."));
        let mut temporary = tempfile_path(parent, path);
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temporary)
            .map_err(|error| ScannerError::Evidence(error.to_string()))?;
        if let Err(error) = file
            .write_all(json.as_bytes())
            .and_then(|()| file.sync_all())
        {
            let _ = std::fs::remove_file(&temporary);
            return Err(ScannerError::Evidence(error.to_string()));
        }
        if let Err(error) = std::fs::rename(&temporary, path) {
            let _ = std::fs::remove_file(&temporary);
            return Err(ScannerError::Evidence(error.to_string()));
        }
        temporary.clear();
        Ok(())
    }
}

fn tempfile_path(parent: &Path, destination: &Path) -> std::path::PathBuf {
    let name = destination
        .file_name()
        .unwrap_or_default()
        .to_string_lossy();
    parent.join(format!(".{name}.{}.tmp", std::process::id()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use sentinel_core::{IocDisposition, IocLifecycle, IocSource, IocType};
    #[test]
    fn bundle_serializes_with_schema() {
        let bundle = EvidenceBundle {
            schema_version: EVIDENCE_SCHEMA_VERSION.to_owned(),
            scan_id: Uuid::nil(),
            records: vec![],
            traversal_errors: vec![],
            ioc_matches: vec![],
        };
        let value: serde_json::Value = serde_json::from_str(&bundle.to_json().unwrap()).unwrap();
        assert_eq!(value["schema_version"], EVIDENCE_SCHEMA_VERSION);
    }

    #[test]
    fn bundle_without_ioc_matches_remains_backward_compatible() {
        // Arrange
        let legacy = serde_json::json!({
            "schema_version": EVIDENCE_SCHEMA_VERSION,
            "scan_id": Uuid::nil(),
            "records": [],
            "traversal_errors": []
        });

        // Act
        let bundle: EvidenceBundle = serde_json::from_value(legacy).unwrap();

        // Assert
        assert!(bundle.ioc_matches.is_empty());
    }

    #[test]
    fn historical_ioc_evidence_is_immutable_when_current_knowledge_changes() {
        // Arrange
        let historical = IocRecord {
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
        };
        let bundle = EvidenceBundle {
            schema_version: EVIDENCE_SCHEMA_VERSION.to_owned(),
            scan_id: Uuid::nil(),
            records: vec![],
            traversal_errors: vec![],
            ioc_matches: vec![historical.clone()],
        };
        let serialized_receipt = bundle.to_json().unwrap();
        let mut current_knowledge = historical;

        // Act
        current_knowledge
            .transition_to(IocLifecycle::Withdrawn, None)
            .unwrap();

        // Assert
        assert_eq!(
            current_knowledge.disposition(),
            IocDisposition::HistoricalOnly
        );
        assert_eq!(bundle.ioc_matches[0].lifecycle, IocLifecycle::Active);
        assert_eq!(bundle.to_json().unwrap(), serialized_receipt);
    }
}
