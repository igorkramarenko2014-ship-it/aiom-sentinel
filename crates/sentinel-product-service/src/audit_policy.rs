use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{fs::File, io::Read, path::Path};

use sentinel_product_dto::{ScanResultV1, ScanStateV1};

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct AuditPolicyV1 {
    pub policy_id: String,
    pub policy_version: String,
    pub enabled: bool,
    pub effect: AuditEffectV1,
    pub allowed_root: String,
    pub engine_id: String,
    pub ruleset_id: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum AuditEffectV1 {
    AuditOnly,
    QuarantineDisabled,
    Quarantine,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum ResponseActionV1 {
    Audit,
    Notify,
    Quarantine,
    NoAction,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum PolicyReasonCodeV1 {
    PolicyDisabled,
    AuditOnly,
    EffectDisabled,
    ExplicitQuarantine,
    InvalidScope,
    IncompatibleEngine,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ArtifactIdentityV1 {
    pub normalized_path: String,
    pub content_digest: String,
    pub size: u64,
    pub platform_file_id: Option<String>,
    pub generation: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ObservationIdentityV1 {
    pub event_id: u64,
    pub generation: u64,
    pub source: String,
    pub observed_at: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ResponseArtifactIdentityV1 {
    pub normalized_path: String,
    pub content_digest: String,
    pub size: u64,
    pub platform_file_id: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ResponsePlanV1 {
    pub transaction_id: String,
    pub artifact: ArtifactIdentityV1,
    pub action: ResponseActionV1,
    pub effect_enabled: bool,
    pub reason: PolicyReasonCodeV1,
    pub detail: Option<String>,
}

/// Derive the response identity from the bytes behind a positive live scan result.
/// Detection-supplied digest/size metadata is deliberately not authoritative here.
pub fn canonical_identity_from_detection(
    path: &Path,
    detection: &ScanResultV1,
    generation: u64,
) -> Result<ArtifactIdentityV1, String> {
    if detection.state != ScanStateV1::Completed || detection.finding_count == 0 {
        return Err("DETECTION_NOT_POSITIVE".into());
    }
    let canonical = path
        .canonicalize()
        .map_err(|error| format!("ARTIFACT_CANONICALIZE_FAILED: {error}"))?;
    let supplied_path = path.to_string_lossy();
    let canonical_path = canonical.to_string_lossy();
    if !detection
        .findings
        .iter()
        .any(|finding| finding.path == supplied_path || finding.path == canonical_path)
    {
        return Err("DETECTION_ARTIFACT_MISMATCH".into());
    }

    let mut file =
        File::open(&canonical).map_err(|error| format!("ARTIFACT_OPEN_FAILED: {error}"))?;
    let before = file
        .metadata()
        .map_err(|error| format!("ARTIFACT_METADATA_FAILED: {error}"))?;
    if !before.is_file() {
        return Err("ARTIFACT_NOT_REGULAR_FILE".into());
    }
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes)
        .map_err(|error| format!("ARTIFACT_READ_FAILED: {error}"))?;
    let after = file
        .metadata()
        .map_err(|error| format!("ARTIFACT_METADATA_FAILED: {error}"))?;
    if before.len() != after.len() || after.len() != bytes.len() as u64 {
        return Err("ARTIFACT_CHANGED_DURING_IDENTITY_CAPTURE".into());
    }

    #[cfg(unix)]
    let platform_file_id = {
        use std::os::unix::fs::MetadataExt;
        if before.dev() != after.dev() || before.ino() != after.ino() {
            return Err("ARTIFACT_CHANGED_DURING_IDENTITY_CAPTURE".into());
        }
        Some(format!("{}:{}", after.dev(), after.ino()))
    };
    #[cfg(not(unix))]
    let platform_file_id = None;

    Ok(ArtifactIdentityV1 {
        normalized_path: canonical_path.into_owned(),
        content_digest: hex::encode(Sha256::digest(&bytes)),
        size: bytes.len() as u64,
        platform_file_id,
        generation,
    })
}

pub fn plan_for_artifact(
    identity: &ArtifactIdentityV1,
    policy: &AuditPolicyV1,
) -> Result<ResponsePlanV1, String> {
    let policy_bytes =
        serde_json::to_vec(policy).map_err(|e| format!("policy serialization: {e}"))?;
    let policy_digest = Sha256::digest(policy_bytes);
    let action = if !policy.enabled {
        ResponseActionV1::NoAction
    } else {
        match policy.effect {
            AuditEffectV1::AuditOnly => ResponseActionV1::Audit,
            AuditEffectV1::QuarantineDisabled => ResponseActionV1::NoAction,
            AuditEffectV1::Quarantine => ResponseActionV1::Quarantine,
        }
    };
    let canonical = serde_json::to_vec(&(
        identity.normalized_path.as_bytes(),
        identity.content_digest.as_bytes(),
        identity.size,
        &identity.platform_file_id,
        &policy.policy_id,
        &policy.policy_version,
        policy_digest.as_slice(),
        &policy.engine_id,
        &policy.ruleset_id,
        &action,
    ))
    .map_err(|e| format!("idempotency serialization: {e}"))?;
    let transaction_id = hex::encode(Sha256::digest(canonical));
    Ok(if !policy.enabled {
        ResponsePlanV1 {
            transaction_id,
            artifact: identity.clone(),
            action,
            effect_enabled: false,
            reason: PolicyReasonCodeV1::PolicyDisabled,
            detail: None,
        }
    } else {
        match policy.effect {
            AuditEffectV1::AuditOnly => ResponsePlanV1 {
                transaction_id,
                artifact: identity.clone(),
                action,
                effect_enabled: false,
                reason: PolicyReasonCodeV1::AuditOnly,
                detail: None,
            },
            AuditEffectV1::QuarantineDisabled => ResponsePlanV1 {
                transaction_id,
                artifact: identity.clone(),
                action,
                effect_enabled: false,
                reason: PolicyReasonCodeV1::EffectDisabled,
                detail: None,
            },
            AuditEffectV1::Quarantine => ResponsePlanV1 {
                transaction_id,
                artifact: identity.clone(),
                action,
                effect_enabled: true,
                reason: PolicyReasonCodeV1::ExplicitQuarantine,
                detail: Some("explicit service-level quarantine authorization".into()),
            },
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use sentinel_core::{FileIdentity, IdentityQuality, OsFamily};
    use sentinel_product_dto::{RulePackBindingV1, ScanFindingV1};

    fn positive_detection(path: &Path, claimed_size: u64) -> ScanResultV1 {
        ScanResultV1 {
            schema_version: "sentinel-product/v2".into(),
            request_id: "slice3c-detection".into(),
            state: ScanStateV1::Completed,
            processed_count: 1,
            finding_count: 1,
            findings: vec![ScanFindingV1 {
                path: path.display().to_string(),
                identity: FileIdentity {
                    os_family: OsFamily::MacOs,
                    platform_file_id: Some("stale-caller-file-id".into()),
                    volume_or_device_id: None,
                    canonical_path_sha256: "stale-caller-path".into(),
                    size: claimed_size,
                    change_indicator: None,
                    identity_quality: IdentityQuality::PathOnly,
                },
                engine_id: "yara-x".into(),
                rule_id: "harmless-slice3c-fixture".into(),
                namespace: "slice3c".into(),
                matched_condition: "fixture marker".into(),
                evidence_reference: "local-test".into(),
                tags: vec![],
                metadata: vec![],
                spans: vec![],
                confidence: Some("test".into()),
                severity: Some("test".into()),
            }],
            skipped: vec![],
            held: vec![],
            errors: vec![],
            rule_pack: RulePackBindingV1 {
                pack_id: "slice3c".into(),
                expected_bytes_sha256: "test-only".into(),
                source_path: "embedded-test".into(),
            },
            engine_reports: vec![],
        }
    }

    #[test]
    fn s3c_t01_detection_artifact_produces_canonical_digest_and_size() {
        // Arrange
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("harmless.txt");
        let bytes = b"harmless Slice 3C detection fixture";
        std::fs::write(&path, bytes).unwrap();
        let detection = positive_detection(&path, bytes.len() as u64);

        // Act
        let identity = canonical_identity_from_detection(&path, &detection, 41).unwrap();

        // Assert — S3C-ID-01
        assert_eq!(identity.content_digest, hex::encode(Sha256::digest(bytes)));
        assert_eq!(identity.size, bytes.len() as u64);
        assert_eq!(identity.generation, 41);
        assert_eq!(
            identity.normalized_path,
            path.canonicalize().unwrap().display().to_string()
        );
    }

    #[test]
    fn s3c_t02_stale_detection_metadata_is_not_authoritative() {
        // Arrange
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("harmless.txt");
        let bytes = b"actual harmless bytes";
        std::fs::write(&path, bytes).unwrap();
        let detection = positive_detection(&path, 999_999);

        // Act
        let identity = canonical_identity_from_detection(&path, &detection, 7).unwrap();

        // Assert — S3C-ID-01
        assert_eq!(identity.size, bytes.len() as u64);
        assert_ne!(identity.size, detection.findings[0].identity.size);
        assert_ne!(
            identity.platform_file_id,
            detection.findings[0].identity.platform_file_id
        );
    }

    #[test]
    fn idempotency_key_is_deterministic_and_effect_disabled() {
        let policy = AuditPolicyV1 {
            policy_id: "p".into(),
            policy_version: "v1".into(),
            enabled: true,
            effect: AuditEffectV1::AuditOnly,
            allowed_root: "/tmp".into(),
            engine_id: "yara-x".into(),
            ruleset_id: "r".into(),
        };
        let identity = ArtifactIdentityV1 {
            normalized_path: "/tmp/a".into(),
            content_digest: "d".into(),
            size: 1,
            platform_file_id: None,
            generation: 7,
        };
        let a = plan_for_artifact(&identity, &policy).unwrap();
        let b = plan_for_artifact(&identity, &policy).unwrap();
        assert_eq!(a.transaction_id, b.transaction_id);
        assert!(!a.effect_enabled);
        assert_eq!(a.action, ResponseActionV1::Audit);
    }

    #[test]
    fn explicit_quarantine_policy_enables_only_the_service_effect_gate() {
        // Arrange
        let identity = ArtifactIdentityV1 {
            normalized_path: "/tmp/harmless".into(),
            content_digest: "digest".into(),
            size: 8,
            platform_file_id: None,
            generation: 1,
        };
        let policy = AuditPolicyV1 {
            policy_id: "slice3c".into(),
            policy_version: "v1".into(),
            enabled: true,
            effect: AuditEffectV1::Quarantine,
            allowed_root: "/tmp".into(),
            engine_id: "yara-x".into(),
            ruleset_id: "slice3c".into(),
        };

        // Act
        let plan = plan_for_artifact(&identity, &policy).unwrap();

        // Assert — S3C-ID-02 / S3C-ID-03
        assert_eq!(plan.artifact, identity);
        assert_eq!(plan.action, ResponseActionV1::Quarantine);
        assert!(plan.effect_enabled);
    }
}
