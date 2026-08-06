#![forbid(unsafe_code)]
#![cfg_attr(test, allow(clippy::expect_used, clippy::unwrap_used))]
//! Shell-independent application service for the first product vertical slice.

use sentinel_core::{ScanLimits, ScanRequest, ScanTarget};
use sentinel_product_dto::{
    ApplicationErrorV1, CanonicalReceiptV1, DTO_SCHEMA_VERSION, FolderContentManifestV1,
    FolderFileResultV1, FolderFileStateV1, FolderManifestChildV1, FolderManifestReceiptV1,
    FolderScanResultV1, FolderScanRuntimeDiagnosticsV1, FolderScanStateV1, RulePackBindingV1,
    ScanFileRequestV1, ScanFindingV1, ScanResultV1, ScanStateV1,
};
use sentinel_rules::LocalRuleEngine;
use sentinel_scanner::scan;
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::{
    path::{Path, PathBuf},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
};
use thiserror::Error;
use uuid::Uuid;

pub mod container;

pub trait FolderProgressSink: Send + Sync {
    fn emit(&self, progress: sentinel_product_dto::FolderProgressV1) -> Result<(), String>;
}

pub trait CancellationProbe: Send + Sync {
    fn is_cancelled(&self) -> bool;
}

impl CancellationProbe for AtomicBool {
    fn is_cancelled(&self) -> bool {
        self.load(Ordering::SeqCst)
    }
}

pub struct NoopProgressSink;
impl FolderProgressSink for NoopProgressSink {
    fn emit(&self, _progress: sentinel_product_dto::FolderProgressV1) -> Result<(), String> {
        Ok(())
    }
}

struct FolderProgressController {
    current: sentinel_product_dto::FolderProgressV1,
    terminal_emitted: bool,
    sink: Arc<dyn FolderProgressSink>,
    delivery_error_count: u64,
    last_delivery_error: Option<String>,
    terminal_delivery_failed: bool,
}

impl FolderProgressController {
    fn new(request_id: &str, sink: Arc<dyn FolderProgressSink>) -> Self {
        Self {
            current: sentinel_product_dto::FolderProgressV1::discovering(request_id),
            terminal_emitted: false,
            sink,
            delivery_error_count: 0,
            last_delivery_error: None,
            terminal_delivery_failed: false,
        }
    }
    fn emit(&mut self, phase: sentinel_product_dto::FolderProgressPhaseV1, terminal: bool) {
        if self.terminal_emitted {
            return;
        }
        self.current.phase = phase;
        self.current.terminal = terminal;
        if terminal {
            self.terminal_emitted = true;
        }
        if let Err(error) = self.sink.emit(self.current.clone()) {
            self.delivery_error_count += 1;
            self.last_delivery_error = Some(error);
            if terminal {
                self.terminal_delivery_failed = true;
            }
        }
    }
    fn discovering(&mut self) {
        self.emit(
            sentinel_product_dto::FolderProgressPhaseV1::Discovering,
            false,
        );
    }
    fn scanning(&mut self, path: String) {
        self.current.current_relative_path = Some(path);
        self.emit(sentinel_product_dto::FolderProgressPhaseV1::Scanning, false);
    }
    fn cancelling(&mut self) {
        self.current.cancellation_requested = true;
        self.emit(
            sentinel_product_dto::FolderProgressPhaseV1::Cancelling,
            false,
        );
    }
    #[allow(clippy::too_many_arguments)]
    fn counters(
        &mut self,
        discovered: u64,
        accepted: u64,
        processed: u64,
        findings: u64,
        skipped: u64,
        errors: u64,
        bytes: u64,
        total: u64,
    ) {
        self.current.discovered_count = discovered;
        self.current.accepted_count = accepted;
        self.current.processed_count = processed;
        self.current.finding_count = findings;
        self.current.skipped_count = skipped;
        self.current.error_count = errors;
        self.current.processed_bytes = bytes;
        self.current.accepted_total_bytes = Some(total);
    }
    fn terminal(&mut self, state: FolderScanStateV1) {
        let phase = match state {
            FolderScanStateV1::Completed => sentinel_product_dto::FolderProgressPhaseV1::Completed,
            FolderScanStateV1::CompletedWithFindings => {
                sentinel_product_dto::FolderProgressPhaseV1::CompletedWithFindings
            }
            FolderScanStateV1::Incomplete => {
                sentinel_product_dto::FolderProgressPhaseV1::Incomplete
            }
            FolderScanStateV1::Cancelled => sentinel_product_dto::FolderProgressPhaseV1::Cancelled,
            FolderScanStateV1::Failed => sentinel_product_dto::FolderProgressPhaseV1::Failed,
        };
        self.current.current_relative_path = None;
        self.emit(phase, true);
    }
}

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
        yara: None,
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

pub async fn scan_folder_v1(
    root: PathBuf,
    request_id: String,
    binding: RulePackBindingV1,
) -> Result<FolderManifestReceiptV1, ApplicationErrorV1> {
    scan_folder_with_control(
        root,
        request_id,
        binding,
        Arc::new(NoopProgressSink),
        Arc::new(AtomicBool::new(false)),
    )
    .await
}

pub async fn scan_folder_with_control(
    root: PathBuf,
    request_id: String,
    binding: RulePackBindingV1,
    progress: Arc<dyn FolderProgressSink>,
    cancellation: Arc<dyn CancellationProbe>,
) -> Result<FolderManifestReceiptV1, ApplicationErrorV1> {
    Uuid::parse_str(&request_id).map_err(|e| {
        ProductServiceError::InvalidRequestId(e.to_string()).application_error(None)
    })?;
    let canonical = tokio::task::spawn_blocking(move || root.canonicalize())
        .await
        .map_err(|e| ProductServiceError::Scan(e.to_string()).application_error(None))?
        .map_err(|e| ProductServiceError::Scan(e.to_string()).application_error(None))?;
    let meta = std::fs::symlink_metadata(&canonical)
        .map_err(|e| ProductServiceError::Scan(e.to_string()).application_error(None))?;
    if !meta.is_dir() || meta.file_type().is_symlink() {
        return Err(
            ProductServiceError::Scan("folder is not a regular directory".into())
                .application_error(None),
        );
    }
    let mut paths = Vec::new();
    let mut skipped = 0_u64;
    let mut stack = vec![canonical.clone()];
    let mut controller = FolderProgressController::new(&request_id, progress);
    controller.discovering();
    while let Some(dir) = stack.pop() {
        if cancellation.is_cancelled() {
            break;
        }
        let entries = std::fs::read_dir(&dir).map_err(|e| {
            ProductServiceError::Scan(e.to_string())
                .application_error(Some(dir.to_string_lossy().into_owned()))
        })?;
        for entry in entries.flatten() {
            if cancellation.is_cancelled() {
                break;
            }
            let path = entry.path();
            let m = match std::fs::symlink_metadata(&path) {
                Ok(m) => m,
                Err(_) => {
                    skipped += 1;
                    continue;
                }
            };
            if m.file_type().is_symlink() {
                skipped += 1;
                continue;
            }
            if m.is_dir() {
                stack.push(path);
                continue;
            }
            if m.is_file()
                && path
                    .canonicalize()
                    .map(|p| p.starts_with(&canonical))
                    .unwrap_or(false)
            {
                paths.push(path);
            } else {
                skipped += 1;
            }
        }
    }
    paths.sort_by_key(|p| {
        p.strip_prefix(&canonical)
            .unwrap_or(p)
            .to_string_lossy()
            .replace('\\', "/")
    });
    let discovered_count = paths.len() as u64 + skipped;
    let accepted_total_bytes = paths
        .iter()
        .filter_map(|p| std::fs::metadata(p).ok().map(|m| m.len()))
        .sum::<u64>();
    let mut files: Vec<FolderFileResultV1> = Vec::new();
    for path in paths {
        if cancellation.is_cancelled() {
            controller.cancelling();
            break;
        }
        let relative = path
            .strip_prefix(&canonical)
            .unwrap_or(&path)
            .to_string_lossy()
            .replace('\\', "/");
        let size = std::fs::metadata(&path).map(|m| m.len()).unwrap_or(0);
        controller.counters(
            discovered_count,
            files.len() as u64 + 1,
            files
                .iter()
                .filter(|f| f.state == FolderFileStateV1::Processed)
                .count() as u64,
            files.iter().map(|f| f.finding_count).sum(),
            skipped,
            files.iter().filter(|f| !f.errors.is_empty()).count() as u64,
            files
                .iter()
                .filter(|f| f.state == FolderFileStateV1::Processed)
                .map(|f| f.size_bytes)
                .sum(),
            accepted_total_bytes,
        );
        controller.scanning(relative.clone());
        let bytes = match std::fs::read(&path) {
            Ok(b) => b,
            Err(e) => {
                files.push(FolderFileResultV1 {
                    relative_path: relative,
                    size_bytes: size,
                    content_sha256: None,
                    state: FolderFileStateV1::ReadError,
                    finding_count: 0,
                    findings: vec![],
                    errors: vec![ApplicationErrorV1 {
                        code: "FILE_READ_ERROR".into(),
                        message: e.to_string(),
                        path: None,
                        retryable: false,
                    }],
                    child_evidence_sha256: None,
                });
                controller.counters(
                    discovered_count,
                    files.len() as u64,
                    files
                        .iter()
                        .filter(|f| f.state == FolderFileStateV1::Processed)
                        .count() as u64,
                    files.iter().map(|f| f.finding_count).sum(),
                    skipped,
                    files.iter().filter(|f| !f.errors.is_empty()).count() as u64,
                    files
                        .iter()
                        .filter(|f| f.state == FolderFileStateV1::Processed)
                        .map(|f| f.size_bytes)
                        .sum(),
                    accepted_total_bytes,
                );
                continue;
            }
        };
        let digest = hex::encode(Sha256::digest(&bytes));
        let result = match scan_file_v1(ScanFileRequestV1 {
            request_id: Uuid::new_v4().to_string(),
            target_path: path.to_string_lossy().into_owned(),
            rule_pack: binding.clone(),
        })
        .await
        {
            Ok(result) => result,
            Err(error) => {
                files.push(FolderFileResultV1 {
                    relative_path: relative,
                    size_bytes: size,
                    content_sha256: Some(digest),
                    state: FolderFileStateV1::ReadError,
                    finding_count: 0,
                    findings: vec![],
                    errors: vec![error],
                    child_evidence_sha256: None,
                });
                controller.counters(
                    discovered_count,
                    files.len() as u64,
                    files
                        .iter()
                        .filter(|f| f.state == FolderFileStateV1::Processed)
                        .count() as u64,
                    files.iter().map(|f| f.finding_count).sum(),
                    skipped,
                    files.iter().filter(|f| !f.errors.is_empty()).count() as u64,
                    files
                        .iter()
                        .filter(|f| f.state == FolderFileStateV1::Processed)
                        .map(|f| f.size_bytes)
                        .sum(),
                    accepted_total_bytes,
                );
                continue;
            }
        };
        let child_payload = serde_json::json!({ "relative_path": relative, "size_bytes": size, "content_sha256": digest, "state": if result.state == ScanStateV1::Completed { "PROCESSED" } else { "SCAN_ERROR" }, "findings": result.findings, "errors": result.errors, "rule_pack_id": binding.pack_id, "rule_pack_sha256": binding.expected_bytes_sha256 });
        let child_payload = serde_json::to_vec(&child_payload).map_err(|e| {
            ProductServiceError::ReceiptSerialization(e.to_string()).application_error(None)
        })?;
        let child_digest = hex::encode(Sha256::digest(&child_payload));
        let state = if result.state == ScanStateV1::Completed {
            FolderFileStateV1::Processed
        } else {
            FolderFileStateV1::ReadError
        };
        files.push(FolderFileResultV1 {
            relative_path: relative,
            size_bytes: size,
            content_sha256: Some(digest),
            state,
            finding_count: result.finding_count,
            findings: result.findings,
            errors: result.errors,
            child_evidence_sha256: Some(child_digest),
        });
        controller.counters(
            discovered_count,
            files.len() as u64,
            files
                .iter()
                .filter(|f| f.state == FolderFileStateV1::Processed)
                .count() as u64,
            files.iter().map(|f| f.finding_count).sum(),
            skipped,
            files.iter().filter(|f| !f.errors.is_empty()).count() as u64,
            files
                .iter()
                .filter(|f| f.state == FolderFileStateV1::Processed)
                .map(|f| f.size_bytes)
                .sum(),
            accepted_total_bytes,
        );
        if cancellation.is_cancelled() {
            controller.cancelling();
        }
    }
    let processed_count = files
        .iter()
        .filter(|f| f.state == FolderFileStateV1::Processed)
        .count() as u64;
    let finding_count = files.iter().map(|f| f.finding_count).sum();
    let error_count = files.iter().filter(|f| !f.errors.is_empty()).count() as u64;
    let processed_bytes = files
        .iter()
        .filter(|f| f.state == FolderFileStateV1::Processed)
        .map(|f| f.size_bytes)
        .sum();
    let state = if cancellation.is_cancelled() {
        FolderScanStateV1::Cancelled
    } else if error_count > 0 || skipped > 0 {
        FolderScanStateV1::Incomplete
    } else if finding_count > 0 {
        FolderScanStateV1::CompletedWithFindings
    } else {
        FolderScanStateV1::Completed
    };
    let run = FolderScanResultV1 {
        schema_version: DTO_SCHEMA_VERSION.into(),
        request_id,
        state,
        root_label: canonical
            .file_name()
            .unwrap_or_default()
            .to_string_lossy()
            .into_owned(),
        discovered_count,
        accepted_count: files.len() as u64,
        processed_count,
        finding_count,
        skipped_count: skipped,
        error_count,
        processed_bytes,
        cancellation_requested: cancellation.is_cancelled(),
        files,
        rule_pack: binding,
    };
    controller.counters(
        run.discovered_count,
        run.accepted_count,
        run.processed_count,
        run.finding_count,
        run.skipped_count,
        run.error_count,
        run.processed_bytes,
        accepted_total_bytes,
    );
    controller.terminal(run.state.clone());
    let content_manifest = FolderContentManifestV1 {
        manifest_schema_version: format!("{DTO_SCHEMA_VERSION}/folder-manifest"),
        terminal_state: run.state.clone(),
        rule_pack_id: run.rule_pack.pack_id.clone(),
        rule_pack_sha256: run.rule_pack.expected_bytes_sha256.clone(),
        aggregate_counts: vec![
            ("discovered".into(), run.discovered_count),
            ("accepted".into(), run.accepted_count),
            ("processed".into(), run.processed_count),
            ("findings".into(), run.finding_count),
            ("skipped".into(), run.skipped_count),
            ("errors".into(), run.error_count),
            ("processed_bytes".into(), run.processed_bytes),
        ],
        ordered_children: run
            .files
            .iter()
            .map(|file| FolderManifestChildV1 {
                relative_path: file.relative_path.clone(),
                size_bytes: file.size_bytes,
                content_sha256: file.content_sha256.clone(),
                child_evidence_sha256: file.child_evidence_sha256.clone(),
                state: file.state.clone(),
            })
            .collect(),
    };
    let manifest = serde_json::to_vec(&content_manifest).map_err(|e| {
        ProductServiceError::ReceiptSerialization(e.to_string()).application_error(None)
    })?;
    Ok(FolderManifestReceiptV1 {
        schema_version: DTO_SCHEMA_VERSION.into(),
        run,
        content_manifest,
        content_manifest_sha256: hex::encode(Sha256::digest(manifest)),
        runtime_diagnostics: FolderScanRuntimeDiagnosticsV1 {
            progress_delivery_error_count: controller.delivery_error_count,
            last_progress_delivery_error: controller.last_delivery_error,
            terminal_progress_delivery_failed: controller.terminal_delivery_failed,
        },
    })
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
    use std::sync::Mutex as StdMutex;
    use tempfile::tempdir;

    struct CaptureProgress(StdMutex<Vec<sentinel_product_dto::FolderProgressV1>>);
    impl FolderProgressSink for CaptureProgress {
        fn emit(&self, progress: sentinel_product_dto::FolderProgressV1) -> Result<(), String> {
            self.0.lock().unwrap().push(progress);
            Ok(())
        }
    }

    struct CancelOnFirstScan {
        events: StdMutex<Vec<sentinel_product_dto::FolderProgressV1>>,
        token: Arc<AtomicBool>,
    }
    impl FolderProgressSink for CancelOnFirstScan {
        fn emit(&self, progress: sentinel_product_dto::FolderProgressV1) -> Result<(), String> {
            if progress.phase == sentinel_product_dto::FolderProgressPhaseV1::Scanning {
                self.token.store(true, Ordering::SeqCst);
            }
            self.events.lock().unwrap().push(progress);
            Ok(())
        }
    }

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

    #[tokio::test]
    async fn cancelled_before_discovery_returns_cancelled_receipt() {
        let dir = tempdir().expect("tempdir");
        fs::write(dir.path().join("one.txt"), b"one").expect("fixture");
        let rules_dir = tempdir().expect("rules tempdir");
        let rules = rules_dir.path().join("rules.txt");
        fs::write(&rules, "marker|synthetic|ONE|LOW|20\n").expect("rules");
        let binding = RulePackBindingV1 {
            pack_id: "fixture".into(),
            expected_bytes_sha256: hex::encode(Sha256::digest(fs::read(&rules).expect("rules"))),
            source_path: rules.to_string_lossy().into_owned(),
        };
        let cancel = Arc::new(std::sync::atomic::AtomicBool::new(true));
        let progress = Arc::new(CaptureProgress(StdMutex::new(Vec::new())));
        let receipt = scan_folder_with_control(
            dir.path().to_path_buf(),
            Uuid::new_v4().to_string(),
            binding,
            progress.clone(),
            cancel,
        )
        .await
        .expect("cancelled receipt");
        assert_eq!(receipt.run.state, FolderScanStateV1::Cancelled);
        assert!(receipt.run.cancellation_requested);
        assert_eq!(receipt.run.processed_count, 0);
        assert!(receipt.run.files.is_empty());
        let events = progress.0.lock().unwrap();
        assert_eq!(events.iter().filter(|event| event.terminal).count(), 1);
        let terminal_index = events.iter().position(|event| event.terminal).unwrap();
        assert_eq!(events.len(), terminal_index + 1);
        assert!(
            events.iter().any(
                |event| event.phase == sentinel_product_dto::FolderProgressPhaseV1::Discovering
            )
        );
    }

    #[tokio::test]
    async fn mid_scan_cancel_preserves_first_child_and_does_not_start_next() {
        let root = tempdir().expect("root tempdir");
        for (name, body) in [
            ("01-first.txt", b"one".as_slice()),
            ("02-second.txt", b"two"),
            ("03-third.txt", b"three"),
        ] {
            fs::write(root.path().join(name), body).expect("fixture");
        }
        let rules_dir = tempdir().expect("rules tempdir");
        let rules = rules_dir.path().join("rules.txt");
        fs::write(&rules, "marker|synthetic|one|LOW|20\n").expect("rules");
        let binding = RulePackBindingV1 {
            pack_id: "fixture".into(),
            expected_bytes_sha256: hex::encode(Sha256::digest(
                fs::read(&rules).expect("rules read"),
            )),
            source_path: rules.to_string_lossy().into_owned(),
        };
        let token = Arc::new(AtomicBool::new(false));
        let sink = Arc::new(CancelOnFirstScan {
            events: StdMutex::new(Vec::new()),
            token: token.clone(),
        });
        let receipt = scan_folder_with_control(
            root.path().to_path_buf(),
            Uuid::new_v4().to_string(),
            binding,
            sink.clone(),
            token,
        )
        .await
        .expect("receipt");
        assert_eq!(receipt.run.state, FolderScanStateV1::Cancelled);
        assert_eq!(receipt.run.processed_count, 1);
        assert_eq!(receipt.run.files.len(), 1);
        assert_eq!(receipt.run.files[0].relative_path, "01-first.txt");
        assert!(receipt.run.cancellation_requested);
        let events = sink.events.lock().unwrap();
        let started: Vec<_> = events
            .iter()
            .filter(|event| event.phase == sentinel_product_dto::FolderProgressPhaseV1::Scanning)
            .filter_map(|event| event.current_relative_path.clone())
            .collect();
        assert_eq!(started, vec!["01-first.txt"]);
        assert_eq!(events.iter().filter(|event| event.terminal).count(), 1);
        let terminal_index = events.iter().position(|event| event.terminal).unwrap();
        assert_eq!(events.len(), terminal_index + 1);
        let manifest = serde_json::to_vec(&receipt.content_manifest).expect("manifest bytes");
        assert_eq!(
            receipt.content_manifest_sha256,
            hex::encode(Sha256::digest(manifest))
        );
        for name in ["01-first.txt", "02-second.txt", "03-third.txt"] {
            assert_eq!(
                sha256_file(&root.path().join(name)),
                hex::encode(Sha256::digest(
                    fs::read(root.path().join(name)).expect("read")
                ))
            );
        }
    }
}
