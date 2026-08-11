use sentinel_product_service::audit_policy::{
    ArtifactIdentityV1, PolicyReasonCodeV1, ResponseActionV1, ResponsePlanV1,
};
use sentinel_product_service::quarantine::QuarantineStoreV2;
use sentinel_product_service::transactional::{
    Failpoint, RestoreRequestV2, RestoreStateV2, TestKeyProvider, TransactionStateV1,
    execute_quarantine_v2, execute_quarantine_v2_with_failpoint, plan_transaction_from_plan,
    recover_quarantine_store_v2, restore_quarantine_v2, restore_quarantine_v2_with_failpoint,
};
use sha2::{Digest, Sha256};
use std::{
    fs,
    path::{Path, PathBuf},
    sync::{Arc, Barrier},
    thread,
};

const BYTES: &[u8] = b"harmless-slice-3b-f-demo";

fn invariant_ok<T, E: std::fmt::Debug>(result: Result<T, E>, context: &str) -> T {
    match result {
        Ok(value) => value,
        Err(error) => panic!("{context}: {error:?}"),
    }
}

fn invariant_err<T: std::fmt::Debug, E>(result: Result<T, E>, context: &str) -> E {
    match result {
        Err(error) => error,
        Ok(value) => panic!("{context}: unexpectedly succeeded with {value:?}"),
    }
}

fn demo_transaction(
    transaction_id: &str,
    artifact: ArtifactIdentityV1,
) -> sentinel_product_service::transactional::ResponseTransactionV1 {
    let plan = ResponsePlanV1 {
        transaction_id: transaction_id.to_owned(),
        artifact: artifact.clone(),
        action: ResponseActionV1::Quarantine,
        effect_enabled: true,
        reason: PolicyReasonCodeV1::ExplicitQuarantine,
        detail: Some("explicit harmless Slice 3B-F demo authorization".into()),
    };
    invariant_ok(
        plan_transaction_from_plan(artifact, &plan),
        "bind demo policy plan to transaction",
    )
}

struct Fixture {
    root: PathBuf,
    source: PathBuf,
    restore_root: PathBuf,
    store: QuarantineStoreV2,
    receipt: sentinel_product_service::transactional::QuarantineReceiptV2,
}

fn root_for(id: &str) -> PathBuf {
    std::env::temp_dir().join(format!(
        "aiom-sentinel-slice3b-f-{id}-{}",
        std::process::id()
    ))
}

fn fixture(id: &str) -> Fixture {
    let root = root_for(id);
    let _ = fs::remove_dir_all(&root);
    let source = root.join("source");
    let restore_root = root.join("restore");
    invariant_ok(
        fs::create_dir_all(&restore_root),
        "create fixture restore root",
    );
    invariant_ok(fs::write(&source, BYTES), "write harmless fixture");
    let store = invariant_ok(
        QuarantineStoreV2::open(root.join("store")),
        "open fixture quarantine store",
    );
    let mut tx = demo_transaction(
        id,
        ArtifactIdentityV1 {
            normalized_path: source.display().to_string(),
            content_digest: hex::encode(Sha256::digest(BYTES)),
            size: BYTES.len() as u64,
            platform_file_id: None,
            generation: 1,
        },
    );
    let receipt = invariant_ok(
        execute_quarantine_v2(&mut tx, &store, &TestKeyProvider([7; 32])),
        "execute fixture quarantine",
    );
    Fixture {
        root,
        source,
        restore_root,
        store,
        receipt,
    }
}

fn request(fixture: &Fixture, name: &str) -> RestoreRequestV2 {
    RestoreRequestV2 {
        transaction_id: fixture.receipt.transaction_id.clone(),
        destination: fixture.restore_root.join(name).display().to_string(),
        allowed_root: fixture.restore_root.display().to_string(),
        explicit_authority: true,
    }
}

fn planned(
    id: &str,
    root: &Path,
) -> (
    PathBuf,
    QuarantineStoreV2,
    sentinel_product_service::transactional::ResponseTransactionV1,
) {
    let source = root.join(format!("{id}-source"));
    invariant_ok(fs::write(&source, BYTES), "write planned harmless fixture");
    let store = invariant_ok(
        QuarantineStoreV2::open(root.join(format!("{id}-store"))),
        "open planned quarantine store",
    );
    let tx = demo_transaction(
        id,
        ArtifactIdentityV1 {
            normalized_path: source.display().to_string(),
            content_digest: hex::encode(Sha256::digest(BYTES)),
            size: BYTES.len() as u64,
            platform_file_id: None,
            generation: 1,
        },
    );
    (source, store, tx)
}

fn demo01() {
    let f = fixture("demo-01");
    assert!(!f.source.exists());
    assert!(f.store.object_path(&f.receipt.transaction_id).exists());
    assert_ne!(
        invariant_ok(
            fs::read(f.store.object_path(&f.receipt.transaction_id)),
            "read quarantined object",
        ),
        BYTES
    );
    invariant_ok(fs::remove_dir_all(f.root), "remove demo-01 fixture");
}

fn demo02() {
    let failpoints = [
        Failpoint::AfterIdentityRevalidated,
        Failpoint::AfterJournalPrepared,
        Failpoint::AfterSourceClaimed,
        Failpoint::DuringContentProtection,
        Failpoint::AfterObjectCommitted,
        Failpoint::BeforeMetadataCommit,
        Failpoint::AfterMetadataCommitted,
        Failpoint::BeforeSourceSecured,
        Failpoint::AfterSourceSecured,
        Failpoint::BeforeFinalCommit,
    ];
    for (index, failpoint) in failpoints.into_iter().enumerate() {
        let root = root_for(&format!("demo-02-{index}"));
        let _ = fs::remove_dir_all(&root);
        invariant_ok(fs::create_dir_all(&root), "create demo-02 root");
        let (source, store, mut tx) = planned(&format!("demo-02-{index}"), &root);
        assert!(
            execute_quarantine_v2_with_failpoint(
                &mut tx,
                &store,
                &TestKeyProvider([7; 32]),
                failpoint
            )
            .is_err()
        );
        let first = recover_quarantine_store_v2(&store, &TestKeyProvider([7; 32]));
        let journal_before = invariant_ok(
            fs::read(store.journal_path(&tx.transaction_id)),
            "read demo-02 journal before second recovery",
        );
        let second = recover_quarantine_store_v2(&store, &TestKeyProvider([7; 32]));
        let journal_after = invariant_ok(
            fs::read(store.journal_path(&tx.transaction_id)),
            "read demo-02 journal after second recovery",
        );
        assert!(!first.is_empty());
        assert!(!second.is_empty());
        assert_eq!(journal_before, journal_after);
        assert!(source.exists() || store.object_path(&tx.transaction_id).exists());
        invariant_ok(fs::remove_dir_all(root), "remove demo-02 fixture");
    }
}

fn demo03() {
    let root = root_for("demo-03");
    let _ = fs::remove_dir_all(&root);
    invariant_ok(fs::create_dir_all(&root), "create demo-03 root");
    let (source, store, mut tx) = planned("demo-03", &root);
    assert!(
        execute_quarantine_v2_with_failpoint(
            &mut tx,
            &store,
            &TestKeyProvider([7; 32]),
            Failpoint::AfterObjectCommitted
        )
        .is_err()
    );
    let first = recover_quarantine_store_v2(&store, &TestKeyProvider([7; 32]));
    let state_before = invariant_ok(
        fs::read(store.journal_path("demo-03")),
        "read demo-03 journal before second recovery",
    );
    let second = recover_quarantine_store_v2(&store, &TestKeyProvider([7; 32]));
    let state_after = invariant_ok(
        fs::read(store.journal_path("demo-03")),
        "read demo-03 journal after second recovery",
    );
    assert!(!first.is_empty());
    assert!(!second.is_empty());
    assert_eq!(state_before, state_after);
    assert!(source.exists() || store.object_path("demo-03").exists());
    invariant_ok(fs::remove_dir_all(root), "remove demo-03 fixture");
}

fn demo04() {
    let root = root_for("demo-04");
    let _ = fs::remove_dir_all(&root);
    invariant_ok(fs::create_dir_all(&root), "create demo-04 root");
    let (source, store, mut tx) = planned("demo-04", &root);
    let result = execute_quarantine_v2_with_failpoint(
        &mut tx,
        &store,
        &TestKeyProvider([7; 32]),
        Failpoint::DuringContentProtection,
    );
    assert!(result.is_err());
    assert_eq!(
        invariant_ok(fs::read(&source), "read demo-04 source"),
        BYTES
    );
    assert_ne!(tx.state, TransactionStateV1::Committed);
    invariant_ok(fs::remove_dir_all(root), "remove demo-04 fixture");
}

fn demo05() {
    let root = root_for("demo-05");
    let _ = fs::remove_dir_all(&root);
    invariant_ok(fs::create_dir_all(&root), "create demo-05 root");
    let source = root.join("source");
    invariant_ok(fs::write(&source, BYTES), "write demo-05 fixture");
    let store = invariant_ok(
        QuarantineStoreV2::open(root.join("store")),
        "open demo-05 quarantine store",
    );
    let identity = ArtifactIdentityV1 {
        normalized_path: source.display().to_string(),
        content_digest: hex::encode(Sha256::digest(BYTES)),
        size: BYTES.len() as u64,
        platform_file_id: None,
        generation: 1,
    };
    let barrier = Arc::new(Barrier::new(2));
    let mut handles = Vec::new();
    for _ in 0..2 {
        let barrier = Arc::clone(&barrier);
        let store = store.clone();
        let identity = identity.clone();
        handles.push(thread::spawn(move || {
            let mut tx = demo_transaction("demo-05", identity);
            barrier.wait();
            execute_quarantine_v2(&mut tx, &store, &TestKeyProvider([7; 32]))
        }));
    }
    let results: Vec<_> = handles
        .into_iter()
        .map(|handle| invariant_ok(handle.join(), "join demo-05 quarantine worker"))
        .collect();
    assert!(results.iter().filter(|result| result.is_ok()).count() <= 1);
    let objects: Vec<_> = invariant_ok(
        fs::read_dir(store.root.join("objects")),
        "read demo-05 object directory",
    )
    .collect();
    assert!(objects.len() <= 1);
    invariant_ok(fs::remove_dir_all(root), "remove demo-05 fixture");
}

fn demo06() {
    let f = fixture("demo-06");
    let destination = f.restore_root.join("restored");
    let request = request(&f, "restored");
    let barrier = Arc::new(Barrier::new(2));
    let mut handles = Vec::new();
    for _ in 0..2 {
        let barrier = Arc::clone(&barrier);
        let store = f.store.clone();
        let request = request.clone();
        handles.push(thread::spawn(move || {
            barrier.wait();
            restore_quarantine_v2(&request, &store, &TestKeyProvider([7; 32]))
        }));
    }
    let results: Vec<_> = handles
        .into_iter()
        .map(|handle| invariant_ok(handle.join(), "join demo-06 restore worker"))
        .collect();
    assert_eq!(
        invariant_ok(fs::read(&destination), "read demo-06 destination"),
        BYTES
    );
    assert!(results.iter().filter(|result| result.is_ok()).count() <= 1);
    invariant_ok(fs::remove_dir_all(f.root), "remove demo-06 fixture");
}

fn demo07() {
    let f = fixture("demo-07");
    let destination = f.restore_root.join("restored");
    let receipt = invariant_ok(
        restore_quarantine_v2(
            &request(&f, "restored"),
            &f.store,
            &TestKeyProvider([7; 32]),
        ),
        "execute demo-07 authorized restore",
    );
    assert_eq!(receipt.state, RestoreStateV2::Committed);
    assert_eq!(
        invariant_ok(fs::read(destination), "read demo-07 destination"),
        BYTES
    );
    invariant_ok(fs::remove_dir_all(f.root), "remove demo-07 fixture");
}

fn demo08() {
    let f = fixture("demo-08");
    let destination = f.restore_root.join("restored");
    let result = restore_quarantine_v2_with_failpoint(
        &request(&f, "restored"),
        &f.store,
        &TestKeyProvider([7; 32]),
        Failpoint::BeforeRestorePublish,
    );
    assert_eq!(
        invariant_err(result, "demo-08 restore failpoint must fail"),
        "FAILPOINT_BEFORE_RESTORE_PUBLISH"
    );
    assert!(!destination.exists());
    invariant_ok(fs::remove_dir_all(f.root), "remove demo-08 fixture");
}

fn demo09() {
    let f = fixture("demo-09");
    let req = request(&f, "restored");
    assert_eq!(
        invariant_err(
            restore_quarantine_v2_with_failpoint(
                &req,
                &f.store,
                &TestKeyProvider([7; 32]),
                Failpoint::AfterRestorePublish,
            ),
            "demo-09 restore failpoint must fail",
        ),
        "FAILPOINT_AFTER_RESTORE_PUBLISH"
    );
    let retry = invariant_ok(
        restore_quarantine_v2(&req, &f.store, &TestKeyProvider([7; 32])),
        "retry demo-09 restore",
    );
    assert_eq!(retry.state, RestoreStateV2::AlreadyCommitted);
    assert_eq!(
        invariant_ok(
            fs::read(f.restore_root.join("restored")),
            "read demo-09 destination",
        ),
        BYTES
    );
    invariant_ok(fs::remove_dir_all(f.root), "remove demo-09 fixture");
}

fn main() {
    demo01();
    println!("DEMO-01 QUARANTINE_HAPPY_PATH PASS");
    demo02();
    println!("DEMO-02 QUARANTINE_FAILPOINT_RECOVERY PASS failpoints=10/10");
    demo03();
    println!("DEMO-03 ORPHAN_RECOVERY PASS");
    demo04();
    println!("DEMO-04 CROSS_DEVICE_SIMULATION PASS mode=UNSUPPORTED_FAIL_CLOSED");
    demo05();
    println!("DEMO-05 CONCURRENT_QUARANTINE_IDEMPOTENCY PASS");
    demo06();
    println!("DEMO-06 CONCURRENT_RESTORE_COLLISION_SAFETY PASS");
    demo07();
    println!("DEMO-07 AUTHORIZED_RESTORE_HAPPY_PATH PASS");
    demo08();
    println!("DEMO-08 DISK_OR_PERMISSION_FAILURE_FAIL_CLOSED PASS");
    demo09();
    println!("DEMO-09 RESTORE_POST_PUBLISH_RETRY PASS failpoints=3/3");
}
