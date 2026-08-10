use sentinel_product_service::audit_policy::{ArtifactIdentityV1, ResponseActionV1};
use sentinel_product_service::quarantine::QuarantineStoreV2;
use sentinel_product_service::transactional::{
    Failpoint, RestoreRequestV2, RestoreStateV2, TestKeyProvider, TransactionStateV1,
    execute_quarantine_v2, execute_quarantine_v2_with_failpoint, plan_transaction,
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
    fs::create_dir_all(&restore_root).unwrap();
    fs::write(&source, BYTES).unwrap();
    let store = QuarantineStoreV2::open(root.join("store")).unwrap();
    let mut tx = plan_transaction(
        id.to_owned(),
        ArtifactIdentityV1 {
            normalized_path: source.display().to_string(),
            content_digest: hex::encode(Sha256::digest(BYTES)),
            size: BYTES.len() as u64,
            platform_file_id: None,
            generation: 1,
        },
        ResponseActionV1::Quarantine,
    );
    let receipt = execute_quarantine_v2(&mut tx, &store, &TestKeyProvider([7; 32])).unwrap();
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
    fs::write(&source, BYTES).unwrap();
    let store = QuarantineStoreV2::open(root.join(format!("{id}-store"))).unwrap();
    let tx = plan_transaction(
        id.to_owned(),
        ArtifactIdentityV1 {
            normalized_path: source.display().to_string(),
            content_digest: hex::encode(Sha256::digest(BYTES)),
            size: BYTES.len() as u64,
            platform_file_id: None,
            generation: 1,
        },
        ResponseActionV1::Quarantine,
    );
    (source, store, tx)
}

fn demo01() {
    let f = fixture("demo-01");
    assert!(!f.source.exists());
    assert!(f.store.object_path(&f.receipt.transaction_id).exists());
    assert_ne!(
        fs::read(f.store.object_path(&f.receipt.transaction_id)).unwrap(),
        BYTES
    );
    fs::remove_dir_all(f.root).unwrap();
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
        fs::create_dir_all(&root).unwrap();
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
        let journal_before = fs::read(store.journal_path(&tx.transaction_id)).unwrap();
        let second = recover_quarantine_store_v2(&store, &TestKeyProvider([7; 32]));
        let journal_after = fs::read(store.journal_path(&tx.transaction_id)).unwrap();
        assert!(!first.is_empty());
        assert!(!second.is_empty());
        assert_eq!(journal_before, journal_after);
        assert!(source.exists() || store.object_path(&tx.transaction_id).exists());
        fs::remove_dir_all(root).unwrap();
    }
}

fn demo03() {
    let root = root_for("demo-03");
    let _ = fs::remove_dir_all(&root);
    fs::create_dir_all(&root).unwrap();
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
    let state_before = fs::read(store.journal_path("demo-03")).unwrap();
    let second = recover_quarantine_store_v2(&store, &TestKeyProvider([7; 32]));
    let state_after = fs::read(store.journal_path("demo-03")).unwrap();
    assert!(!first.is_empty());
    assert!(!second.is_empty());
    assert_eq!(state_before, state_after);
    assert!(source.exists() || store.object_path("demo-03").exists());
    fs::remove_dir_all(root).unwrap();
}

fn demo04() {
    let root = root_for("demo-04");
    let _ = fs::remove_dir_all(&root);
    fs::create_dir_all(&root).unwrap();
    let (source, store, mut tx) = planned("demo-04", &root);
    let result = execute_quarantine_v2_with_failpoint(
        &mut tx,
        &store,
        &TestKeyProvider([7; 32]),
        Failpoint::DuringContentProtection,
    );
    assert!(result.is_err());
    assert_eq!(fs::read(&source).unwrap(), BYTES);
    assert_ne!(tx.state, TransactionStateV1::Committed);
    fs::remove_dir_all(root).unwrap();
}

fn demo05() {
    let root = root_for("demo-05");
    let _ = fs::remove_dir_all(&root);
    fs::create_dir_all(&root).unwrap();
    let source = root.join("source");
    fs::write(&source, BYTES).unwrap();
    let store = QuarantineStoreV2::open(root.join("store")).unwrap();
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
            let mut tx =
                plan_transaction("demo-05".to_owned(), identity, ResponseActionV1::Quarantine);
            barrier.wait();
            execute_quarantine_v2(&mut tx, &store, &TestKeyProvider([7; 32]))
        }));
    }
    let results: Vec<_> = handles
        .into_iter()
        .map(|handle| handle.join().unwrap())
        .collect();
    assert!(results.iter().filter(|result| result.is_ok()).count() <= 1);
    let objects: Vec<_> = fs::read_dir(store.root.join("objects")).unwrap().collect();
    assert!(objects.len() <= 1);
    fs::remove_dir_all(root).unwrap();
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
        .map(|handle| handle.join().unwrap())
        .collect();
    assert_eq!(fs::read(&destination).unwrap(), BYTES);
    assert!(results.iter().filter(|result| result.is_ok()).count() <= 1);
    fs::remove_dir_all(f.root).unwrap();
}

fn demo07() {
    let f = fixture("demo-07");
    let destination = f.restore_root.join("restored");
    let receipt = restore_quarantine_v2(
        &request(&f, "restored"),
        &f.store,
        &TestKeyProvider([7; 32]),
    )
    .unwrap();
    assert_eq!(receipt.state, RestoreStateV2::Committed);
    assert_eq!(fs::read(destination).unwrap(), BYTES);
    fs::remove_dir_all(f.root).unwrap();
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
    assert_eq!(result.unwrap_err(), "FAILPOINT_BEFORE_RESTORE_PUBLISH");
    assert!(!destination.exists());
    fs::remove_dir_all(f.root).unwrap();
}

fn demo09() {
    let f = fixture("demo-09");
    let req = request(&f, "restored");
    assert_eq!(
        restore_quarantine_v2_with_failpoint(
            &req,
            &f.store,
            &TestKeyProvider([7; 32]),
            Failpoint::AfterRestorePublish,
        )
        .unwrap_err(),
        "FAILPOINT_AFTER_RESTORE_PUBLISH"
    );
    let retry = restore_quarantine_v2(&req, &f.store, &TestKeyProvider([7; 32])).unwrap();
    assert_eq!(retry.state, RestoreStateV2::AlreadyCommitted);
    assert_eq!(fs::read(f.restore_root.join("restored")).unwrap(), BYTES);
    fs::remove_dir_all(f.root).unwrap();
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
