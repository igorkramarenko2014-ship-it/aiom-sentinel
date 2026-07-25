#![forbid(unsafe_code)]
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used))]
//! Deterministic JSON evidence envelope and serialization.

use sentinel_core::{EVIDENCE_SCHEMA_VERSION, ScanResult, ScannerError};
use serde::{Deserialize, Serialize};
use std::{io::Write, path::Path};
use uuid::Uuid;

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct EvidenceBundle {
    pub schema_version: String,
    pub scan_id: Uuid,
    pub records: Vec<sentinel_core::EvidenceRecord>,
    pub traversal_errors: Vec<String>,
}

impl From<ScanResult> for EvidenceBundle {
    fn from(result: ScanResult) -> Self {
        Self {
            schema_version: EVIDENCE_SCHEMA_VERSION.to_owned(),
            scan_id: result.scan_id,
            records: result.records,
            traversal_errors: result.traversal_errors,
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
    #[test]
    fn bundle_serializes_with_schema() {
        let bundle = EvidenceBundle {
            schema_version: EVIDENCE_SCHEMA_VERSION.to_owned(),
            scan_id: Uuid::nil(),
            records: vec![],
            traversal_errors: vec![],
        };
        let value: serde_json::Value = serde_json::from_str(&bundle.to_json().unwrap()).unwrap();
        assert_eq!(value["schema_version"], "1.1.0");
    }
}
