use sentinel_core::{FileIdentity, IdentityQuality, OsFamily};
use sentinel_product_dto::{RulePackBindingV1, ScanFindingV1, ScanResultV1, ScanStateV1};
use sentinel_product_service::audit_policy::{
    AuditEffectV1, AuditPolicyV1, ResponseActionV1, canonical_identity_from_detection,
    plan_for_artifact,
};
use sentinel_product_service::quarantine::QuarantineStoreV2;
use sentinel_product_service::transactional::{
    TestKeyProvider, TransactionStateV1, execute_quarantine_v2, plan_transaction_from_plan,
};
use std::{fs, path::Path};
use uuid::Uuid;

struct DemoWorkspace(std::path::PathBuf);

impl Drop for DemoWorkspace {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn detection_for(path: &Path) -> ScanResultV1 {
    ScanResultV1 {
        schema_version: "sentinel-product/v2".into(),
        request_id: "slice3c-demo".into(),
        state: ScanStateV1::Completed,
        processed_count: 1,
        finding_count: 1,
        findings: vec![ScanFindingV1 {
            path: path.display().to_string(),
            identity: FileIdentity {
                os_family: OsFamily::MacOs,
                platform_file_id: None,
                volume_or_device_id: None,
                canonical_path_sha256: "detection-metadata-is-not-authoritative".into(),
                size: 0,
                change_indicator: None,
                identity_quality: IdentityQuality::PathOnly,
            },
            engine_id: "yara-x".into(),
            rule_id: "harmless-slice3c-fixture".into(),
            namespace: "slice3c-demo".into(),
            matched_condition: "harmless fixture marker".into(),
            evidence_reference: "local-demo".into(),
            tags: vec![],
            metadata: vec![],
            spans: vec![],
            confidence: Some("demo".into()),
            severity: Some("demo".into()),
        }],
        skipped: vec![],
        held: vec![],
        errors: vec![],
        rule_pack: RulePackBindingV1 {
            pack_id: "slice3c-demo".into(),
            expected_bytes_sha256: "embedded-harmless-fixture".into(),
            source_path: "embedded-demo".into(),
        },
        engine_reports: vec![],
    }
}

fn policy(effect: AuditEffectV1) -> AuditPolicyV1 {
    AuditPolicyV1 {
        policy_id: "slice3c-demo".into(),
        policy_version: "v1".into(),
        enabled: true,
        effect,
        allowed_root: std::env::temp_dir().display().to_string(),
        engine_id: "yara-x".into(),
        ruleset_id: "harmless-slice3c-fixture".into(),
    }
}

fn run() -> Result<(), String> {
    let root = std::env::temp_dir().join(format!("aiom-sentinel-slice3c-{}", Uuid::new_v4()));
    fs::create_dir(&root).map_err(|error| error.to_string())?;
    let _workspace = DemoWorkspace(root.clone());
    let source = root.join("harmless-suspicious-fixture.txt");
    fs::write(&source, b"harmless suspicious Slice 3C fixture")
        .map_err(|error| error.to_string())?;
    let detection = detection_for(&source);
    println!("DETECTION: MATCH");

    let identity = canonical_identity_from_detection(&source, &detection, 1)?;
    println!(
        "IDENTITY: digest={} size={} path={}",
        identity.content_digest, identity.size, identity.normalized_path
    );

    let audit_plan = plan_for_artifact(&identity, &policy(AuditEffectV1::AuditOnly))?;
    if audit_plan.effect_enabled
        || plan_transaction_from_plan(identity.clone(), &audit_plan).is_ok()
    {
        return Err("AUDIT_CONTROL_EFFECT_GATE_FAILED".into());
    }
    println!("CONTROL_POLICY: action=Audit effect_enabled=false");
    println!("CONTROL_EFFECT: NOT_EXECUTED");

    let plan = plan_for_artifact(&identity, &policy(AuditEffectV1::Quarantine))?;
    if plan.action != ResponseActionV1::Quarantine || !plan.effect_enabled {
        return Err("QUARANTINE_POLICY_NOT_AUTHORIZED".into());
    }
    println!("POLICY: action=Quarantine effect_enabled=true");

    let mut transaction = plan_transaction_from_plan(identity, &plan)?;
    println!("TRANSACTION: planned id={}", transaction.transaction_id);
    let store =
        QuarantineStoreV2::open(root.join("quarantine")).map_err(|error| error.to_string())?;
    let receipt = execute_quarantine_v2(&mut transaction, &store, &TestKeyProvider([3; 32]))?;
    if receipt.state != TransactionStateV1::Committed {
        return Err("QUARANTINE_NOT_COMMITTED".into());
    }
    println!("QUARANTINE: committed");
    println!(
        "RECEIPT: emitted transaction_id={} digest={} size={}",
        receipt.transaction_id, receipt.digest, receipt.size
    );
    println!("SOURCE_POST_STATE: absent={}", !source.exists());
    println!("KEY_AUTHORITY: TestKeyProvider");
    println!("SLICE_3C_EVIDENCE_BRIDGE: NOT_APPLICABLE_CURRENT_SCHEMA");
    println!("TAURI_TRANSACTIONAL_RESPONSE_WIRING: NOT_ENABLED");
    println!("PRODUCTION_KEY_AUTHORITY: NOT_IMPLEMENTED");
    println!("AUTOMATIC_PRODUCTION_EFFECTS: DISABLED");
    Ok(())
}

fn main() {
    if let Err(error) = run() {
        eprintln!("SLICE_3C_DEMO_ERROR: {error}");
        std::process::exit(1);
    }
}
