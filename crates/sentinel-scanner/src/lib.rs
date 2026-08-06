#![forbid(unsafe_code)]
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used))]
//! Bounded read-only file and directory scanning orchestration.

use arc_swap::ArcSwap;
use sentinel_core::{
    CanonicalPathStatus, CapabilityState, ConfidenceLevel, EVIDENCE_SCHEMA_VERSION, EngineVersion,
    EvidenceQuality, EvidenceRecord, FileFormat, FileIdentity, IdentityQuality, OsFamily, SafePath,
    ScanFinding, ScanRequest, ScanResult, ScannerError, Verdict,
};
use sentinel_hash::analyze;
use sentinel_pe::{PeError, parse};
use sentinel_rules::RuleEngine;
use sha2::{Digest, Sha256};
#[cfg(test)]
use std::sync::atomic::{AtomicBool, Ordering};
use std::{
    collections::VecDeque,
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
    time::Instant,
};
use thiserror::Error;
use time::OffsetDateTime;
use tokio::io::AsyncReadExt;
use uuid::Uuid;

pub const SCANNER_VERSION: &str = env!("CARGO_PKG_VERSION");
pub const PE_PARSER_VERSION: &str = "sentinel-pe/1";

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RuleSetActivationMetadata {
    pub key_id: String,
    pub verification_receipt_sha256: String,
    pub accepted_at_utc: String,
}

#[derive(Clone)]
pub struct RuleSetSnapshot {
    pub bundle_content_id: Option<String>,
    pub generation: u64,
    pub activation: Option<RuleSetActivationMetadata>,
    rules: Option<Arc<dyn RuleEngine>>,
}

impl RuleSetSnapshot {
    fn empty() -> Self {
        Self {
            bundle_content_id: None,
            generation: 0,
            activation: None,
            rules: None,
        }
    }

    pub fn rules(&self) -> Option<Arc<dyn RuleEngine>> {
        self.rules.clone()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RuleSetReplacementReceipt {
    pub replaced: bool,
    pub old_bundle_content_id: Option<String>,
    pub new_bundle_content_id: String,
    pub old_generation: u64,
    pub new_generation: u64,
}

#[derive(Debug, Error, Eq, PartialEq)]
pub enum ActiveRuleSetError {
    #[error("bundle_content_id must be strict lowercase SHA-256")]
    InvalidBundleContentId,
    #[error("activation key_id must not be empty")]
    EmptyKeyId,
    #[error("verification receipt identity must be strict lowercase SHA-256")]
    InvalidVerificationReceipt,
    #[error("accepted_at_utc must not be empty")]
    MissingAcceptedAt,
    #[error("active-ruleset generation is exhausted")]
    GenerationExhausted,
    #[error("active-ruleset writer lock is poisoned")]
    WriterLockPoisoned,
    #[cfg(test)]
    #[error("injected active-ruleset replacement failure")]
    InjectedReplacementFailure,
}

pub struct ActiveRuleSet {
    active: ArcSwap<RuleSetSnapshot>,
    writer: Mutex<()>,
    #[cfg(test)]
    fail_next_replace: AtomicBool,
}

impl Default for ActiveRuleSet {
    fn default() -> Self {
        Self::new()
    }
}

impl ActiveRuleSet {
    pub fn new() -> Self {
        Self {
            active: ArcSwap::from_pointee(RuleSetSnapshot::empty()),
            writer: Mutex::new(()),
            #[cfg(test)]
            fail_next_replace: AtomicBool::new(false),
        }
    }

    /// Obtain one immutable scanner-owned snapshot. Readers never observe a
    /// partially replaced ruleset.
    pub fn snapshot(&self) -> Arc<RuleSetSnapshot> {
        self.active.load_full()
    }

    /// Atomically activate a complete verified ruleset.
    ///
    /// Writer serialization makes generation increments exact. Reader access
    /// remains lock-free through ArcSwap. Persistence/LKG belongs to the
    /// Autoloader and is deliberately not performed here.
    pub fn replace(
        &self,
        bundle_content_id: String,
        rules: Arc<dyn RuleEngine>,
        activation: RuleSetActivationMetadata,
    ) -> Result<RuleSetReplacementReceipt, ActiveRuleSetError> {
        validate_activation(&bundle_content_id, &activation)?;
        let _writer = self
            .writer
            .lock()
            .map_err(|_| ActiveRuleSetError::WriterLockPoisoned)?;
        let old = self.active.load_full();
        if old.bundle_content_id.as_deref() == Some(bundle_content_id.as_str()) {
            return Ok(RuleSetReplacementReceipt {
                replaced: false,
                old_bundle_content_id: old.bundle_content_id.clone(),
                new_bundle_content_id: bundle_content_id,
                old_generation: old.generation,
                new_generation: old.generation,
            });
        }

        #[cfg(test)]
        if self.fail_next_replace.swap(false, Ordering::SeqCst) {
            return Err(ActiveRuleSetError::InjectedReplacementFailure);
        }

        let new_generation = old
            .generation
            .checked_add(1)
            .ok_or(ActiveRuleSetError::GenerationExhausted)?;
        let next = Arc::new(RuleSetSnapshot {
            bundle_content_id: Some(bundle_content_id.clone()),
            generation: new_generation,
            activation: Some(activation),
            rules: Some(rules),
        });
        self.active.store(next);
        Ok(RuleSetReplacementReceipt {
            replaced: true,
            old_bundle_content_id: old.bundle_content_id.clone(),
            new_bundle_content_id: bundle_content_id,
            old_generation: old.generation,
            new_generation,
        })
    }

    #[cfg(test)]
    fn inject_next_replacement_failure(&self) {
        self.fail_next_replace.store(true, Ordering::SeqCst);
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct ActiveScanResult {
    pub bundle_content_id: Option<String>,
    pub generation: u64,
    pub result: ScanResult,
}

/// Scan through exactly one immutable active snapshot.
pub async fn scan_with_active(
    request: &ScanRequest,
    active: &ActiveRuleSet,
) -> Result<ActiveScanResult, ScannerError> {
    let snapshot = active.snapshot();
    let result = scan(request, snapshot.rules()).await?;
    Ok(ActiveScanResult {
        bundle_content_id: snapshot.bundle_content_id.clone(),
        generation: snapshot.generation,
        result,
    })
}

fn validate_activation(
    bundle_content_id: &str,
    activation: &RuleSetActivationMetadata,
) -> Result<(), ActiveRuleSetError> {
    if !is_lowercase_sha256(bundle_content_id) {
        return Err(ActiveRuleSetError::InvalidBundleContentId);
    }
    if activation.key_id.is_empty() {
        return Err(ActiveRuleSetError::EmptyKeyId);
    }
    if !is_lowercase_sha256(&activation.verification_receipt_sha256) {
        return Err(ActiveRuleSetError::InvalidVerificationReceipt);
    }
    if activation.accepted_at_utc.is_empty() {
        return Err(ActiveRuleSetError::MissingAcceptedAt);
    }
    Ok(())
}

fn is_lowercase_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

struct RecordContext {
    scan_id: Uuid,
    evidence_id: Uuid,
    timestamp: OffsetDateTime,
    target_path: SafePath,
    file_identity: FileIdentity,
    file_size: u64,
    engine_version: EngineVersion,
    started: Instant,
}

pub async fn scan(
    request: &ScanRequest,
    rules: Option<Arc<dyn RuleEngine>>,
) -> Result<ScanResult, ScannerError> {
    request
        .limits
        .validate()
        .map_err(ScannerError::LimitExceeded)?;
    let root = request.target.0.clone();
    let metadata = std::fs::symlink_metadata(&root).map_err(|error| {
        ScannerError::InvalidTarget(format!("{}: {error}", root.to_string_lossy()))
    })?;
    if metadata.file_type().is_symlink() {
        return Err(ScannerError::InvalidTarget(
            "top-level symlink targets are not followed".to_owned(),
        ));
    }
    let canonical_root = std::fs::canonicalize(&root)
        .map_err(|error| ScannerError::InvalidTarget(error.to_string()))?;
    let (paths, traversal_errors) = if metadata.is_file() {
        (vec![canonical_root.clone()], Vec::new())
    } else if metadata.is_dir() && request.recursive {
        discover(
            &canonical_root,
            request.limits.max_depth,
            request.limits.max_files,
        )
    } else if metadata.is_dir() {
        return Err(ScannerError::InvalidTarget(
            "directory scans require --recursive".to_owned(),
        ));
    } else {
        return Err(ScannerError::InvalidTarget(
            "target is not a regular file or directory".to_owned(),
        ));
    };
    if paths.len() > request.limits.max_evidence_records {
        return Err(ScannerError::LimitExceeded(
            "evidence record limit exceeded".to_owned(),
        ));
    }
    let mut records = Vec::with_capacity(paths.len());
    for path in paths {
        records.push(
            scan_file(
                request.scan_id,
                &canonical_root,
                &path,
                request.limits.max_file_size,
                rules.as_deref(),
            )
            .await,
        );
    }
    records.sort_by(|left, right| {
        left.target_path
            .raw_base64
            .cmp(&right.target_path.raw_base64)
    });
    Ok(ScanResult {
        scan_id: request.scan_id,
        records,
        traversal_errors,
    })
}

fn discover(root: &Path, max_depth: usize, max_files: usize) -> (Vec<PathBuf>, Vec<String>) {
    let mut queue = VecDeque::from([(root.to_path_buf(), 0_usize)]);
    let mut files = Vec::new();
    let mut errors = Vec::new();
    while let Some((directory, depth)) = queue.pop_front() {
        if depth > max_depth {
            errors.push(format!(
                "depth limit reached at {}",
                directory.to_string_lossy()
            ));
            continue;
        }
        let entries = match std::fs::read_dir(&directory) {
            Ok(entries) => entries,
            Err(error) => {
                errors.push(format!("{}: {error}", directory.to_string_lossy()));
                continue;
            }
        };
        for entry in entries {
            let entry = match entry {
                Ok(entry) => entry,
                Err(error) => {
                    errors.push(error.to_string());
                    continue;
                }
            };
            let path = entry.path();
            let metadata = match std::fs::symlink_metadata(&path) {
                Ok(metadata) => metadata,
                Err(error) => {
                    errors.push(format!("{}: {error}", path.to_string_lossy()));
                    continue;
                }
            };
            if metadata.file_type().is_symlink() {
                errors.push(format!("symlink skipped: {}", path.to_string_lossy()));
                continue;
            }
            if metadata.is_dir() {
                queue.push_back((path, depth.saturating_add(1)));
                continue;
            }
            if !metadata.is_file() {
                errors.push(format!(
                    "unsupported filesystem entry: {}",
                    path.to_string_lossy()
                ));
                continue;
            }
            match std::fs::canonicalize(&path) {
                Ok(canonical) if canonical.starts_with(root) => files.push(canonical),
                Ok(_) => errors.push(format!(
                    "path escaped scan root: {}",
                    path.to_string_lossy()
                )),
                Err(error) => errors.push(format!("{}: {error}", path.to_string_lossy())),
            }
            if files.len() >= max_files {
                errors.push(format!("file limit reached: {max_files}"));
                return (files, errors);
            }
        }
    }
    (files, errors)
}

async fn scan_file(
    scan_id: Uuid,
    root: &Path,
    path: &Path,
    max_file_size: u64,
    rules: Option<&dyn RuleEngine>,
) -> EvidenceRecord {
    let started = Instant::now();
    let timestamp = OffsetDateTime::now_utc();
    let safe_path = SafePath::from_path(path);
    let evidence_id = Uuid::new_v5(&scan_id, safe_path.raw_base64.as_bytes());
    let metadata = std::fs::metadata(path);
    let file_size = metadata.as_ref().map_or(0, std::fs::Metadata::len);
    let file_identity = build_file_identity(&safe_path, metadata.as_ref().ok());
    let engine_version = EngineVersion {
        scanner: SCANNER_VERSION.to_owned(),
        rules: rules.map_or_else(
            || "disabled".to_owned(),
            |engine| engine.version().to_owned(),
        ),
        pe_parser: PE_PARSER_VERSION.to_owned(),
    };
    let context = RecordContext {
        scan_id,
        evidence_id,
        timestamp,
        target_path: safe_path,
        file_identity,
        file_size,
        engine_version,
        started,
    };
    if let Err(error) = metadata {
        return error_record(context, error.to_string());
    }
    if file_size > max_file_size {
        return error_record(context, format!("file exceeds {max_file_size} byte limit"));
    }
    let (hashes, entropy) = match analyze(path, max_file_size).await {
        Ok(result) => result,
        Err(error) => {
            return error_record(context, error.to_string());
        }
    };
    let bytes = match read_bounded(path, max_file_size).await {
        Ok(bytes) => bytes,
        Err(error) => {
            return error_record(context, error.to_string());
        }
    };
    let (file_type, format_support, pe_metadata, mut errors) = if bytes.get(..2) != Some(b"MZ") {
        classify_non_pe(&bytes)
    } else {
        match parse(&bytes) {
            Ok(metadata) => (
                FileFormat::Pe,
                CapabilityState::Supported,
                Some(metadata),
                Vec::new(),
            ),
            Err(PeError::NotPe) => classify_non_pe(&bytes),
            Err(error) => (
                FileFormat::Other,
                CapabilityState::Unsupported,
                None,
                vec![format!("PE parser: {error}")],
            ),
        }
    };
    let rule_matches = rules.map_or_else(Vec::new, |engine| engine.evaluate(&bytes));
    let findings = Vec::new();
    let (verdict, risk_score, threat_confidence) =
        derive_verdict(&rule_matches, &findings, &errors);
    errors.shrink_to_fit();
    EvidenceRecord {
        schema_version: EVIDENCE_SCHEMA_VERSION.to_owned(),
        evidence_id: context.evidence_id,
        scan_id: context.scan_id,
        timestamp: context.timestamp,
        target_path: context.target_path,
        canonical_path_status: if path.starts_with(root) {
            CanonicalPathStatus::VerifiedInsideRoot
        } else {
            CanonicalPathStatus::NotCanonicalized
        },
        file_identity: context.file_identity,
        file_size,
        hashes: Some(hashes),
        entropy: Some(entropy),
        file_type,
        format_support,
        pe_metadata,
        rule_matches,
        findings,
        scanner_version: SCANNER_VERSION.to_owned(),
        engine_version: context.engine_version,
        duration_ms: context.started.elapsed().as_millis(),
        errors,
        verdict,
        risk_score,
        threat_confidence,
        benign_confidence: ConfidenceLevel::Low,
        evidence_quality: EvidenceQuality::AE2,
    }
}

async fn read_bounded(path: &Path, limit: u64) -> Result<Vec<u8>, ScannerError> {
    let capacity = usize::try_from(limit.min(8 * 1024 * 1024))
        .map_err(|_| ScannerError::LimitExceeded("platform allocation limit".to_owned()))?;
    let mut bytes = Vec::with_capacity(capacity);
    let file = tokio::fs::File::open(path)
        .await
        .map_err(|error| ScannerError::Io {
            path: path.to_string_lossy().into_owned(),
            message: error.to_string(),
        })?;
    file.take(limit.saturating_add(1))
        .read_to_end(&mut bytes)
        .await
        .map_err(|error| ScannerError::Io {
            path: path.to_string_lossy().into_owned(),
            message: error.to_string(),
        })?;
    if bytes.len() as u64 > limit {
        return Err(ScannerError::LimitExceeded(format!(
            "file exceeds {limit} bytes"
        )));
    }
    Ok(bytes)
}

fn derive_verdict(
    matches: &[sentinel_core::RuleMatch],
    findings: &[ScanFinding],
    errors: &[String],
) -> (Verdict, u8, ConfidenceLevel) {
    if !errors.is_empty() {
        return (Verdict::ScanError, 0, ConfidenceLevel::Low);
    }
    if !matches.is_empty() {
        let score = matches
            .iter()
            .map(|item| item.confidence_contribution)
            .max()
            .unwrap_or(0);
        let confidence = if score >= 70 {
            ConfidenceLevel::High
        } else if score >= 30 {
            ConfidenceLevel::Medium
        } else {
            ConfidenceLevel::Low
        };
        return (Verdict::Match, score, confidence);
    }
    if !findings.is_empty() {
        return (Verdict::Suspicious, 10, ConfidenceLevel::Low);
    }
    (Verdict::Clean, 0, ConfidenceLevel::Low)
}

fn build_file_identity(path: &SafePath, metadata: Option<&std::fs::Metadata>) -> FileIdentity {
    let (platform_file_id, volume_or_device_id, identity_quality) = platform_identity(metadata);
    let change_indicator = metadata
        .and_then(|value| value.modified().ok())
        .and_then(|value| value.duration_since(std::time::UNIX_EPOCH).ok())
        .map(|value| value.as_nanos());
    FileIdentity {
        os_family: current_os_family(),
        platform_file_id,
        volume_or_device_id,
        canonical_path_sha256: hex::encode(Sha256::digest(path.raw_base64.as_bytes())),
        size: metadata.map_or(0, std::fs::Metadata::len),
        change_indicator: change_indicator.map(|value| value.to_string()),
        identity_quality,
    }
}

#[cfg(unix)]
fn platform_identity(
    metadata: Option<&std::fs::Metadata>,
) -> (Option<String>, Option<String>, IdentityQuality) {
    use std::os::unix::fs::MetadataExt;
    (
        metadata.map(|value| value.ino().to_string()),
        metadata.map(|value| value.dev().to_string()),
        if metadata.is_some() {
            IdentityQuality::Native
        } else {
            IdentityQuality::PathOnly
        },
    )
}

#[cfg(windows)]
fn platform_identity(
    _metadata: Option<&std::fs::Metadata>,
) -> (Option<String>, Option<String>, IdentityQuality) {
    (None, None, IdentityQuality::PathOnly)
}

#[cfg(target_os = "linux")]
const fn current_os_family() -> OsFamily {
    OsFamily::Linux
}
#[cfg(target_os = "macos")]
const fn current_os_family() -> OsFamily {
    OsFamily::MacOs
}
#[cfg(windows)]
const fn current_os_family() -> OsFamily {
    OsFamily::Windows
}
#[cfg(not(any(target_os = "linux", target_os = "macos", windows)))]
const fn current_os_family() -> OsFamily {
    OsFamily::Unknown
}

fn classify_non_pe(
    bytes: &[u8],
) -> (
    FileFormat,
    CapabilityState,
    Option<sentinel_core::PeMetadata>,
    Vec<String>,
) {
    if bytes.starts_with(b"\x7fELF") {
        return (
            FileFormat::Elf,
            CapabilityState::NotImplemented,
            None,
            Vec::new(),
        );
    }
    if bytes.starts_with(&[0xfe, 0xed, 0xfa, 0xce])
        || bytes.starts_with(&[0xfe, 0xed, 0xfa, 0xcf])
        || bytes.starts_with(&[0xcf, 0xfa, 0xed, 0xfe])
        || bytes.starts_with(&[0xce, 0xfa, 0xed, 0xfe])
    {
        return (
            FileFormat::MachO,
            CapabilityState::NotImplemented,
            None,
            Vec::new(),
        );
    }
    if bytes.starts_with(b"#!") {
        return (
            FileFormat::Script,
            CapabilityState::Unsupported,
            None,
            Vec::new(),
        );
    }
    if bytes.starts_with(b"PK\x03\x04") {
        return (
            FileFormat::Archive,
            CapabilityState::Unsupported,
            None,
            Vec::new(),
        );
    }
    (
        FileFormat::Other,
        CapabilityState::Unsupported,
        None,
        Vec::new(),
    )
}

fn error_record(context: RecordContext, error: String) -> EvidenceRecord {
    EvidenceRecord {
        schema_version: EVIDENCE_SCHEMA_VERSION.to_owned(),
        evidence_id: context.evidence_id,
        scan_id: context.scan_id,
        timestamp: context.timestamp,
        target_path: context.target_path,
        canonical_path_status: CanonicalPathStatus::NotCanonicalized,
        file_identity: context.file_identity,
        file_size: context.file_size,
        hashes: None,
        entropy: None,
        file_type: FileFormat::Unknown,
        format_support: CapabilityState::Unsupported,
        pe_metadata: None,
        rule_matches: Vec::new(),
        findings: Vec::new(),
        scanner_version: SCANNER_VERSION.to_owned(),
        engine_version: context.engine_version,
        duration_ms: context.started.elapsed().as_millis(),
        errors: vec![error],
        verdict: Verdict::ScanError,
        risk_score: 0,
        threat_confidence: ConfidenceLevel::Low,
        benign_confidence: ConfidenceLevel::Low,
        evidence_quality: EvidenceQuality::AE1,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sentinel_core::{ScanLimits, ScanTarget};
    use sentinel_rules::LocalRuleEngine;

    fn activation() -> RuleSetActivationMetadata {
        RuleSetActivationMetadata {
            key_id: "operator-key-1".to_owned(),
            verification_receipt_sha256: "b".repeat(64),
            accepted_at_utc: "2026-07-25T00:00:00Z".to_owned(),
        }
    }

    fn rules(literal: &str) -> Arc<dyn RuleEngine> {
        Arc::new(LocalRuleEngine::parse(&format!("marker|synthetic|{literal}|LOW|20")).unwrap())
    }

    #[test]
    fn distinct_replacement_increments_generation_exactly_once() {
        let active = ActiveRuleSet::new();
        let receipt = active
            .replace("a".repeat(64), rules("FIRST"), activation())
            .unwrap();
        assert!(receipt.replaced);
        assert_eq!(receipt.old_generation, 0);
        assert_eq!(receipt.new_generation, 1);
        let snapshot = active.snapshot();
        assert_eq!(snapshot.bundle_content_id, Some("a".repeat(64)));
        assert_eq!(snapshot.generation, 1);
    }

    #[test]
    fn identical_bundle_content_id_is_a_no_op() {
        let active = ActiveRuleSet::new();
        active
            .replace("a".repeat(64), rules("FIRST"), activation())
            .unwrap();
        let before = active.snapshot();
        let receipt = active
            .replace("a".repeat(64), rules("SECOND"), activation())
            .unwrap();
        let after = active.snapshot();
        assert!(!receipt.replaced);
        assert_eq!(receipt.old_generation, 1);
        assert_eq!(receipt.new_generation, 1);
        assert!(Arc::ptr_eq(&before, &after));
    }

    #[test]
    fn old_snapshot_remains_immutable_after_replacement() {
        let active = ActiveRuleSet::new();
        active
            .replace("a".repeat(64), rules("FIRST"), activation())
            .unwrap();
        let old = active.snapshot();
        active
            .replace("c".repeat(64), rules("SECOND"), activation())
            .unwrap();
        let current = active.snapshot();
        assert_eq!(old.bundle_content_id, Some("a".repeat(64)));
        assert_eq!(old.generation, 1);
        assert_eq!(current.bundle_content_id, Some("c".repeat(64)));
        assert_eq!(current.generation, 2);
    }

    #[test]
    fn injected_swap_failure_preserves_snapshot_and_generation() {
        let active = ActiveRuleSet::new();
        active
            .replace("a".repeat(64), rules("FIRST"), activation())
            .unwrap();
        let before = active.snapshot();
        active.inject_next_replacement_failure();
        assert_eq!(
            active
                .replace("c".repeat(64), rules("SECOND"), activation())
                .unwrap_err(),
            ActiveRuleSetError::InjectedReplacementFailure
        );
        let after = active.snapshot();
        assert!(Arc::ptr_eq(&before, &after));
        assert_eq!(after.bundle_content_id, Some("a".repeat(64)));
        assert_eq!(after.generation, 1);
    }

    #[test]
    fn generation_exhaustion_preserves_snapshot() {
        let initial = RuleSetSnapshot {
            bundle_content_id: Some("a".repeat(64)),
            generation: u64::MAX,
            activation: Some(activation()),
            rules: Some(rules("FIRST")),
        };
        let active = ActiveRuleSet {
            active: ArcSwap::from_pointee(initial),
            writer: Mutex::new(()),
            fail_next_replace: AtomicBool::new(false),
        };
        let before = active.snapshot();
        assert_eq!(
            active
                .replace("c".repeat(64), rules("SECOND"), activation())
                .unwrap_err(),
            ActiveRuleSetError::GenerationExhausted
        );
        let after = active.snapshot();
        assert!(Arc::ptr_eq(&before, &after));
        assert_eq!(after.generation, u64::MAX);
    }

    #[tokio::test]
    async fn scan_through_active_handle_observes_one_snapshot() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("sample.txt");
        std::fs::write(&path, b"FIRST").unwrap();
        let request = ScanRequest {
            scan_id: Uuid::nil(),
            target: ScanTarget(path),
            recursive: false,
            limits: ScanLimits::default(),
        };
        let active = ActiveRuleSet::new();
        active
            .replace("a".repeat(64), rules("FIRST"), activation())
            .unwrap();
        let result = scan_with_active(&request, &active).await.unwrap();
        assert_eq!(result.bundle_content_id, Some("a".repeat(64)));
        assert_eq!(result.generation, 1);
        assert_eq!(result.result.records[0].verdict, Verdict::Match);
    }

    #[tokio::test]
    async fn scans_one_file_without_mutating_it() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("sample.txt");
        std::fs::write(&path, b"harmless").unwrap();
        let before = std::fs::read(&path).unwrap();
        let request = ScanRequest {
            scan_id: Uuid::nil(),
            target: ScanTarget(path.clone()),
            recursive: false,
            limits: ScanLimits::default(),
        };
        let result = scan(&request, None).await.unwrap();
        assert_eq!(result.records.len(), 1);
        assert_eq!(result.records[0].verdict, Verdict::Clean);
        assert_eq!(std::fs::read(path).unwrap(), before);
    }
    #[cfg(unix)]
    #[tokio::test]
    async fn recursive_scan_skips_symlinks() {
        use std::os::unix::fs::symlink;
        let directory = tempfile::tempdir().unwrap();
        std::fs::write(directory.path().join("file"), b"ok").unwrap();
        symlink("file", directory.path().join("link")).unwrap();
        let request = ScanRequest {
            scan_id: Uuid::nil(),
            target: ScanTarget(directory.path().to_path_buf()),
            recursive: true,
            limits: ScanLimits::default(),
        };
        let result = scan(&request, None).await.unwrap();
        assert_eq!(result.records.len(), 1);
        assert!(
            result
                .traversal_errors
                .iter()
                .any(|error| error.contains("symlink skipped"))
        );
    }
}
