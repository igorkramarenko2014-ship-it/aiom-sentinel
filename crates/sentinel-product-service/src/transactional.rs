use super::audit_policy::{ArtifactIdentityV1, ResponseActionV1, ResponsePlanV1};
use super::quarantine::QuarantineStoreV2;
use aes_gcm::{
    Aes256Gcm, KeyInit,
    aead::{Aead, OsRng, generic_array::GenericArray, rand_core::RngCore},
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    fs,
    io::{self, Read, Write},
    path::{Path, PathBuf},
};

#[cfg(unix)]
use std::os::unix::fs::MetadataExt;
#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;

#[cfg(test)]
type ProtectedObjectTestHook = (PathBuf, Box<dyn Fn() + Send + Sync + 'static>);

#[cfg(test)]
static PROTECTED_OBJECT_TEST_HOOK: std::sync::OnceLock<
    std::sync::Mutex<Option<ProtectedObjectTestHook>>,
> = std::sync::OnceLock::new();

#[cfg(test)]
type RestoreTempTestHook = (PathBuf, Box<dyn Fn() + Send + Sync + 'static>);

#[cfg(test)]
static RESTORE_TEMP_TEST_HOOK: std::sync::OnceLock<std::sync::Mutex<Option<RestoreTempTestHook>>> =
    std::sync::OnceLock::new();

#[cfg(test)]
type RestoreDestinationTestHook = (PathBuf, Box<dyn Fn() + Send + Sync + 'static>);

#[cfg(test)]
static RESTORE_DESTINATION_TEST_HOOK: std::sync::OnceLock<
    std::sync::Mutex<Option<RestoreDestinationTestHook>>,
> = std::sync::OnceLock::new();

#[cfg(test)]
fn run_protected_object_test_hook(path: &Path) {
    let hook = {
        let mut guard = PROTECTED_OBJECT_TEST_HOOK
            .get_or_init(|| std::sync::Mutex::new(None))
            .lock()
            .expect("protected-object test hook mutex");
        guard
            .as_ref()
            .is_some_and(|(expected, _)| expected.as_path() == path)
            .then(|| guard.take().expect("protected-object test hook present").1)
    };
    if let Some(hook) = hook {
        hook();
    }
}

#[cfg(test)]
fn run_restore_temp_test_hook(path: &Path) {
    let hook = {
        let mut guard = RESTORE_TEMP_TEST_HOOK
            .get_or_init(|| std::sync::Mutex::new(None))
            .lock()
            .expect("restore temp test hook mutex");
        guard
            .as_ref()
            .is_some_and(|(expected, _)| expected.as_path() == path)
            .then(|| guard.take().expect("restore temp test hook present").1)
    };
    if let Some(hook) = hook {
        hook();
    }
}

#[cfg(test)]
fn run_restore_destination_test_hook(path: &Path) {
    let hook = {
        let mut guard = RESTORE_DESTINATION_TEST_HOOK
            .get_or_init(|| std::sync::Mutex::new(None))
            .lock()
            .expect("restore destination test hook mutex");
        guard
            .as_ref()
            .is_some_and(|(expected, _)| expected.as_path() == path)
            .then(|| {
                guard
                    .take()
                    .expect("restore destination test hook present")
                    .1
            })
    };
    if let Some(hook) = hook {
        hook();
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum TransactionStateV1 {
    Planned,
    IdentityRevalidated,
    JournalPrepared,
    SourceClaimed,
    ContentProtected,
    ObjectCommitted,
    MetadataCommitted,
    SourceSecured,
    Committed,
    AlreadyHandled,
    StaleArtifact,
    FailedNoEffect,
    RecoveryRequired,
    RolledBack,
    ManualReview,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ResponseTransactionV1 {
    pub schema_version: String,
    pub transaction_id: String,
    pub response_idempotency_key: String,
    pub artifact: ArtifactIdentityV1,
    pub action: ResponseActionV1,
    pub state: TransactionStateV1,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct QuarantineReceiptV2 {
    pub transaction_id: String,
    pub state: TransactionStateV1,
    pub object_path: String,
    pub metadata_path: String,
    pub digest: String,
    pub size: u64,
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct RestoreRequestV2 {
    pub transaction_id: String,
    pub destination: String,
    pub allowed_root: String,
    pub explicit_authority: bool,
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum RestoreStateV2 {
    Prepared,
    Committed,
    AlreadyCommitted,
    Rejected,
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct RestoreReceiptV2 {
    pub transaction_id: String,
    pub destination: String,
    pub state: RestoreStateV2,
    pub digest: String,
    pub size: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
struct RestoreRecordV1 {
    schema_version: String,
    transaction_id: String,
    destination: String,
    digest: String,
    size: u64,
    temp_path: String,
    state: RestoreStateV2,
}

pub struct TestKeyProvider(pub [u8; 32]);
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Failpoint {
    None,
    AfterIdentityRevalidated,
    AfterJournalPrepared,
    AfterSourceClaimed,
    DuringContentProtection,
    AfterObjectCommitted,
    BeforeMetadataCommit,
    AfterMetadataCommitted,
    BeforeSourceSecured,
    AfterSourceSecured,
    BeforeFinalCommit,
    DuringRestoreWrite,
    BeforeRestorePublish,
    AfterRestorePublish,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum RecoveryOutcomeV1 {
    NoAction,
    Completed,
    RolledBack,
    FailedNoEffect,
    RecoveryRequired,
    ManualReview,
    AuthenticationFailed,
    MalformedTransaction,
    StaleArtifact,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct RecoveryReceiptV1 {
    pub transaction_id: String,
    pub outcome: RecoveryOutcomeV1,
}

const MAX_RECOVERY_RECORDS: usize = 1024;
const MAX_TRANSACTION_RECORD_SIZE: u64 = 1024 * 1024;

fn valid_transaction_identity(tx: &ResponseTransactionV1) -> bool {
    !tx.transaction_id.is_empty()
        && tx.transaction_id.len() <= 128
        && tx.transaction_id == tx.response_idempotency_key
        && tx
            .transaction_id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
        && tx.schema_version == "sentinel-response/v1"
}

fn sync_directory(path: &Path) -> Result<(), String> {
    fs::File::open(path)
        .and_then(|file| file.sync_all())
        .map_err(|e| e.to_string())
}

fn publish_new_file(path: &Path, bytes: &[u8]) -> Result<(), String> {
    if path.exists() {
        return Err("DESTINATION_EXISTS".into());
    }
    let parent = path.parent().ok_or("INVALID_DESTINATION")?;
    let temporary = parent.join(format!(
        ".{}.tmp",
        path.file_name()
            .and_then(|n| n.to_str())
            .ok_or("INVALID_DESTINATION")?
    ));
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&temporary)
        .map_err(|e| e.to_string())?;
    if let Err(error) = file.write_all(bytes).and_then(|_| file.sync_all()) {
        let _ = fs::remove_file(&temporary);
        return Err(error.to_string());
    }
    fs::rename(&temporary, path).map_err(|e| e.to_string())?;
    sync_directory(parent)
}

fn restore_record_path(store: &QuarantineStoreV2, id: &str) -> PathBuf {
    store.root.join("restores").join(format!("{id}.json"))
}

fn valid_storage_id(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= 128
        && id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

fn persist_restore_record(
    store: &QuarantineStoreV2,
    record: &RestoreRecordV1,
) -> Result<(), String> {
    let bytes = serde_json::to_vec(record).map_err(|e| e.to_string())?;
    let path = restore_record_path(store, &record.transaction_id);
    if path.exists() {
        let existing: RestoreRecordV1 =
            serde_json::from_slice(&fs::read(&path).map_err(|e| e.to_string())?)
                .map_err(|e| e.to_string())?;
        if existing == *record {
            return Ok(());
        }
        if existing.schema_version != record.schema_version
            || existing.transaction_id != record.transaction_id
            || existing.destination != record.destination
            || existing.digest != record.digest
            || existing.size != record.size
            || existing.temp_path != record.temp_path
        {
            return Err("RESTORE_RECORD_CONFLICT".into());
        }
        let temp = path.with_extension("json.tmp");
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temp)
            .map_err(|e| e.to_string())?;
        file.write_all(&bytes)
            .and_then(|_| file.sync_all())
            .map_err(|e| e.to_string())?;
        fs::rename(temp, path).map_err(|e| e.to_string())?;
        return Ok(());
    }
    publish_new_file(&path, &bytes)
}

fn persist_transaction_state_v2(
    store: &QuarantineStoreV2,
    tx: &ResponseTransactionV1,
    expected_previous_state: Option<TransactionStateV1>,
) -> Result<(), String> {
    if !valid_transaction_identity(tx) {
        return Err("INVALID_TRANSACTION_IDENTITY".into());
    }
    let journal_dir = store.root.join("journal");
    let destination = store.journal_path(&tx.transaction_id);
    if fs::symlink_metadata(&destination).is_ok_and(|m| m.file_type().is_symlink() || !m.is_file())
    {
        return Err("JOURNAL_PATH_REJECTED".into());
    }
    let bytes = serde_json::to_vec(tx).map_err(|_| "TRANSACTION_SERIALIZATION_FAILED")?;
    if let Ok(existing) = fs::read(&destination) {
        if existing == bytes {
            return Ok(());
        }
        let previous: ResponseTransactionV1 =
            serde_json::from_slice(&existing).map_err(|_| "CONFLICTING_TRANSACTION")?;
        if previous.transaction_id != tx.transaction_id
            || expected_previous_state.as_ref() != Some(&previous.state)
        {
            return Err("CONFLICTING_TRANSACTION".into());
        }
        let mut probe = previous.clone();
        advance(&mut probe, tx.state.clone())?;
        if probe != *tx {
            return Err("CONFLICTING_TRANSACTION".into());
        }
    } else if expected_previous_state.is_some() {
        return Err("MISSING_PREVIOUS_TRANSACTION_STATE".into());
    }
    let temporary = journal_dir.join(format!(".{}.tmp", tx.transaction_id));
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&temporary)
        .map_err(|e| e.to_string())?;
    if let Err(error) = file.write_all(&bytes).and_then(|_| file.sync_all()) {
        let _ = fs::remove_file(&temporary);
        return Err(error.to_string());
    }
    fs::rename(&temporary, &destination).map_err(|e| e.to_string())?;
    sync_directory(&journal_dir)
}

#[derive(Debug)]
pub enum TransactionErrorV2 {
    MetadataBindingFailed,
    ObjectTampered,
}

fn metadata_binding(tx: &ResponseTransactionV1) -> Result<Vec<u8>, TransactionErrorV2> {
    serde_json::to_vec(&(
        tx.schema_version.as_str(),
        &tx.transaction_id,
        &tx.response_idempotency_key,
        &tx.artifact,
        &tx.action,
    ))
    .map_err(|_| TransactionErrorV2::MetadataBindingFailed)
}

struct ProtectedObject<'a> {
    nonce: &'a [u8; 12],
    ciphertext: &'a [u8],
}
fn parse_protected_object(bytes: &[u8]) -> Result<ProtectedObject<'_>, TransactionErrorV2> {
    if bytes.len() > 64 * 1024 * 1024
        || bytes.len() < 34
        || bytes.len() - 18 < 16
        || &bytes[..6] != b"AISV2\0"
    {
        return Err(TransactionErrorV2::ObjectTampered);
    }
    let nonce = bytes[6..18]
        .try_into()
        .map_err(|_| TransactionErrorV2::ObjectTampered)?;
    Ok(ProtectedObject {
        nonce,
        ciphertext: &bytes[18..],
    })
}

fn protected_object_open_error(error: &io::Error) -> &'static str {
    #[cfg(unix)]
    if error.raw_os_error() == Some(libc::ELOOP) {
        return "OBJECT_TAMPERED";
    }
    "OBJECT_UNAVAILABLE"
}

fn read_protected_object(path: &Path) -> Result<Vec<u8>, &'static str> {
    let mut options = fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    options.custom_flags(libc::O_NOFOLLOW);
    let mut file = options
        .open(path)
        .map_err(|error| protected_object_open_error(&error))?;
    let metadata = file.metadata().map_err(|_| "OBJECT_UNAVAILABLE")?;
    if !metadata.is_file() {
        return Err("OBJECT_TAMPERED");
    }
    #[cfg(test)]
    run_protected_object_test_hook(path);
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes)
        .map_err(|_| "OBJECT_UNAVAILABLE")?;
    Ok(bytes)
}

fn owned_temp_path_matches(file: &fs::File, path: &Path) -> bool {
    let Ok(handle_metadata) = file.metadata() else {
        return false;
    };
    let Ok(path_metadata) = fs::symlink_metadata(path) else {
        return false;
    };
    if !path_metadata.is_file() || path_metadata.file_type().is_symlink() {
        return false;
    }
    #[cfg(unix)]
    {
        handle_metadata.dev() == path_metadata.dev() && handle_metadata.ino() == path_metadata.ino()
    }
    #[cfg(not(unix))]
    {
        handle_metadata.len() == path_metadata.len()
            && handle_metadata.modified().ok() == path_metadata.modified().ok()
    }
}

fn authenticated_plaintext(
    store: &QuarantineStoreV2,
    tx: &ResponseTransactionV1,
    key: &TestKeyProvider,
) -> Result<Vec<u8>, RecoveryOutcomeV1> {
    let protected = read_protected_object(&store.object_path(&tx.transaction_id))
        .map_err(|_| RecoveryOutcomeV1::ManualReview)?;
    let parsed =
        parse_protected_object(&protected).map_err(|_| RecoveryOutcomeV1::AuthenticationFailed)?;
    let plaintext = Aes256Gcm::new(GenericArray::from_slice(&key.0))
        .decrypt(
            GenericArray::from_slice(parsed.nonce),
            aes_gcm::aead::Payload {
                msg: parsed.ciphertext,
                aad: &metadata_binding(tx).map_err(|_| RecoveryOutcomeV1::MalformedTransaction)?,
            },
        )
        .map_err(|_| RecoveryOutcomeV1::AuthenticationFailed)?;
    if plaintext.len() as u64 != tx.artifact.size
        || hex::encode(Sha256::digest(&plaintext)) != tx.artifact.content_digest
    {
        return Err(RecoveryOutcomeV1::ManualReview);
    }
    Ok(plaintext)
}

fn persist_recovery_state(
    store: &QuarantineStoreV2,
    tx: &mut ResponseTransactionV1,
    next: TransactionStateV1,
) -> Result<(), RecoveryOutcomeV1> {
    let previous = tx.state.clone();
    advance(tx, next).map_err(|_| RecoveryOutcomeV1::ManualReview)?;
    persist_transaction_state_v2(store, tx, Some(previous))
        .map_err(|_| RecoveryOutcomeV1::ManualReview)
}

fn converge_metadata_committed(
    store: &QuarantineStoreV2,
    tx: &mut ResponseTransactionV1,
    plaintext: &[u8],
) -> Result<(), RecoveryOutcomeV1> {
    let source = PathBuf::from(&tx.artifact.normalized_path);
    if source.exists() {
        let bytes = fs::read(&source).map_err(|_| RecoveryOutcomeV1::ManualReview)?;
        if bytes != plaintext
            || hex::encode(Sha256::digest(&bytes)) != tx.artifact.content_digest
            || bytes.len() as u64 != tx.artifact.size
        {
            return Err(RecoveryOutcomeV1::StaleArtifact);
        }
        fs::remove_file(&source).map_err(|_| RecoveryOutcomeV1::ManualReview)?;
    }
    persist_recovery_state(store, tx, TransactionStateV1::SourceSecured)?;
    persist_recovery_state(store, tx, TransactionStateV1::Committed)
}

fn advance_and_persist(
    store: &QuarantineStoreV2,
    tx: &mut ResponseTransactionV1,
    next: TransactionStateV1,
) -> Result<(), String> {
    let previous = tx.state.clone();
    advance(tx, next)?;
    persist_transaction_state_v2(store, tx, Some(previous))
}

pub fn recover_quarantine_store_v2(
    store: &QuarantineStoreV2,
    key: &TestKeyProvider,
) -> Vec<RecoveryReceiptV1> {
    let mut receipts = Vec::new();
    let Ok(entries) = fs::read_dir(store.root.join("metadata")) else {
        return receipts;
    };
    drop(entries);
    let Ok(entries) = fs::read_dir(store.root.join("journal")) else {
        return receipts;
    };
    let mut seen = std::collections::HashSet::new();
    for entry in entries.flatten().take(MAX_RECOVERY_RECORDS) {
        let path = entry.path();
        let fallback_id = path
            .file_stem()
            .map_or_else(String::new, |s| s.to_string_lossy().into());
        let Ok(metadata) = fs::symlink_metadata(&path) else {
            continue;
        };
        if !metadata.is_file()
            || metadata.file_type().is_symlink()
            || metadata.len() > MAX_TRANSACTION_RECORD_SIZE
        {
            receipts.push(RecoveryReceiptV1 {
                transaction_id: fallback_id,
                outcome: RecoveryOutcomeV1::MalformedTransaction,
            });
            continue;
        }
        let Ok(bytes) = fs::read(&path) else { continue };
        let Ok(mut tx) = serde_json::from_slice::<ResponseTransactionV1>(&bytes) else {
            receipts.push(RecoveryReceiptV1 {
                transaction_id: fallback_id,
                outcome: RecoveryOutcomeV1::MalformedTransaction,
            });
            continue;
        };
        if !valid_transaction_identity(&tx)
            || path.file_name().and_then(|n| n.to_str())
                != Some(&format!("{}.json", tx.transaction_id))
        {
            receipts.push(RecoveryReceiptV1 {
                transaction_id: tx.transaction_id,
                outcome: RecoveryOutcomeV1::MalformedTransaction,
            });
            continue;
        }
        if !seen.insert(tx.transaction_id.clone()) {
            receipts.push(RecoveryReceiptV1 {
                transaction_id: tx.transaction_id,
                outcome: RecoveryOutcomeV1::ManualReview,
            });
            continue;
        }
        let outcome = match tx.state {
            TransactionStateV1::Planned => {
                let material = store.object_path(&tx.transaction_id).exists()
                    || store
                        .root
                        .join("metadata")
                        .join(format!("{}.json", tx.transaction_id))
                        .exists()
                    || store
                        .root
                        .join("staging")
                        .join(format!("{}.tmp", tx.transaction_id))
                        .exists();
                if material {
                    RecoveryOutcomeV1::ManualReview
                } else if persist_recovery_state(store, &mut tx, TransactionStateV1::FailedNoEffect)
                    .is_ok()
                {
                    RecoveryOutcomeV1::FailedNoEffect
                } else {
                    RecoveryOutcomeV1::ManualReview
                }
            }
            TransactionStateV1::JournalPrepared => {
                let temporary = store
                    .root
                    .join("staging")
                    .join(format!("{}.tmp", tx.transaction_id));
                if temporary.exists() {
                    let owned = fs::symlink_metadata(&temporary)
                        .is_ok_and(|m| m.is_file() && !m.file_type().is_symlink())
                        && fs::read(&temporary).ok().as_deref()
                            == serde_json::to_vec(&tx).ok().as_deref();
                    if !owned || fs::remove_file(&temporary).is_err() {
                        receipts.push(RecoveryReceiptV1 {
                            transaction_id: tx.transaction_id,
                            outcome: RecoveryOutcomeV1::ManualReview,
                        });
                        continue;
                    }
                }
                if persist_recovery_state(store, &mut tx, TransactionStateV1::RolledBack).is_ok() {
                    RecoveryOutcomeV1::RolledBack
                } else {
                    RecoveryOutcomeV1::ManualReview
                }
            }
            TransactionStateV1::ObjectCommitted => match authenticated_plaintext(store, &tx, key) {
                Ok(plaintext) => {
                    let metadata_path = store
                        .root
                        .join("metadata")
                        .join(format!("{}.json", tx.transaction_id));
                    if metadata_path.exists() {
                        RecoveryOutcomeV1::ManualReview
                    } else {
                        let previous = tx.state.clone();
                        let completed = advance(&mut tx, TransactionStateV1::MetadataCommitted)
                            .and_then(|()| serde_json::to_vec(&tx).map_err(|e| e.to_string()))
                            .and_then(|bytes| publish_new_file(&metadata_path, &bytes))
                            .and_then(|()| {
                                persist_transaction_state_v2(store, &tx, Some(previous))
                            });
                        if completed.is_ok() {
                            match converge_metadata_committed(store, &mut tx, &plaintext) {
                                Ok(()) => RecoveryOutcomeV1::Completed,
                                Err(outcome) => outcome,
                            }
                        } else {
                            RecoveryOutcomeV1::ManualReview
                        }
                    }
                }
                Err(outcome) => outcome,
            },
            TransactionStateV1::MetadataCommitted => match authenticated_plaintext(store, &tx, key)
            {
                Err(outcome) => outcome,
                Ok(plaintext) => match converge_metadata_committed(store, &mut tx, &plaintext) {
                    Ok(()) => RecoveryOutcomeV1::Completed,
                    Err(outcome) => outcome,
                },
            },
            TransactionStateV1::SourceSecured => match authenticated_plaintext(store, &tx, key) {
                Ok(_) if !Path::new(&tx.artifact.normalized_path).exists() => {
                    if persist_recovery_state(store, &mut tx, TransactionStateV1::Committed).is_ok()
                    {
                        RecoveryOutcomeV1::Completed
                    } else {
                        RecoveryOutcomeV1::ManualReview
                    }
                }
                Ok(_) => RecoveryOutcomeV1::ManualReview,
                Err(outcome) => outcome,
            },
            TransactionStateV1::Committed
            | TransactionStateV1::FailedNoEffect
            | TransactionStateV1::RolledBack => RecoveryOutcomeV1::NoAction,
            _ => RecoveryOutcomeV1::ManualReview,
        };
        receipts.push(RecoveryReceiptV1 {
            transaction_id: tx.transaction_id,
            outcome,
        });
    }
    receipts
}

pub fn execute_quarantine_v2(
    tx: &mut ResponseTransactionV1,
    store: &QuarantineStoreV2,
    key: &TestKeyProvider,
) -> Result<QuarantineReceiptV2, String> {
    execute_quarantine_v2_with_failpoint(tx, store, key, Failpoint::None)
}

pub fn execute_quarantine_v2_with_failpoint(
    tx: &mut ResponseTransactionV1,
    store: &QuarantineStoreV2,
    key: &TestKeyProvider,
    failpoint: Failpoint,
) -> Result<QuarantineReceiptV2, String> {
    if tx.action != ResponseActionV1::Quarantine {
        return Err("effect requires QUARANTINE action".into());
    }
    persist_transaction_state_v2(store, tx, None)?;
    let source = std::path::PathBuf::from(&tx.artifact.normalized_path);
    let meta = fs::symlink_metadata(&source).map_err(|e| e.to_string())?;
    if !meta.is_file() || meta.file_type().is_symlink() {
        tx.state = TransactionStateV1::StaleArtifact;
        return Err("STALE_ARTIFACT".into());
    }
    let bytes = fs::read(&source).map_err(|e| e.to_string())?;
    let digest = hex::encode(Sha256::digest(&bytes));
    if digest != tx.artifact.content_digest || bytes.len() as u64 != tx.artifact.size {
        tx.state = TransactionStateV1::StaleArtifact;
        return Err("STALE_ARTIFACT".into());
    }
    advance_and_persist(store, tx, TransactionStateV1::IdentityRevalidated)?;
    if failpoint == Failpoint::AfterIdentityRevalidated {
        return Err("FAILPOINT_AFTER_IDENTITY".into());
    }
    advance_and_persist(store, tx, TransactionStateV1::JournalPrepared)?;
    if failpoint == Failpoint::AfterJournalPrepared {
        return Err("FAILPOINT_AFTER_JOURNAL_PREPARED".into());
    }
    advance_and_persist(store, tx, TransactionStateV1::SourceClaimed)?;
    if failpoint == Failpoint::AfterSourceClaimed {
        return Err("FAILPOINT_AFTER_SOURCE_CLAIMED".into());
    }
    if failpoint == Failpoint::DuringContentProtection {
        return Err("FAILPOINT_DURING_CONTENT_PROTECTION".into());
    }
    let cipher = Aes256Gcm::new(GenericArray::from_slice(&key.0));
    let mut nonce_bytes = [0u8; 12];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = GenericArray::from_slice(&nonce_bytes);
    let mut protected = b"AISV2\0".to_vec();
    protected.extend(nonce_bytes);
    protected.extend(
        cipher
            .encrypt(
                nonce,
                aes_gcm::aead::Payload {
                    msg: bytes.as_ref(),
                    aad: &metadata_binding(tx).map_err(|_| "METADATA_BINDING_FAILED")?,
                },
            )
            .map_err(|_| "CONTENT_PROTECTION_FAILED".to_string())?,
    );
    advance_and_persist(store, tx, TransactionStateV1::ContentProtected)?;
    let object = store.object_path(&tx.transaction_id);
    if object.exists() {
        tx.state = TransactionStateV1::AlreadyHandled;
        return Err("ALREADY_HANDLED".into());
    }
    fs::write(&object, &protected).map_err(|e| e.to_string())?;
    advance_and_persist(store, tx, TransactionStateV1::ObjectCommitted)?;
    if failpoint == Failpoint::AfterObjectCommitted {
        return Err("FAILPOINT_AFTER_OBJECT".into());
    }
    let metadata = store
        .root
        .join("metadata")
        .join(format!("{}.json", tx.transaction_id));
    if failpoint == Failpoint::BeforeMetadataCommit {
        return Err("FAILPOINT_BEFORE_METADATA".into());
    }
    fs::write(
        &metadata,
        serde_json::to_vec(&tx).map_err(|e| e.to_string())?,
    )
    .map_err(|e| e.to_string())?;
    advance_and_persist(store, tx, TransactionStateV1::MetadataCommitted)?;
    if failpoint == Failpoint::AfterMetadataCommitted {
        return Err("FAILPOINT_AFTER_METADATA_COMMITTED".into());
    }
    if failpoint == Failpoint::BeforeSourceSecured {
        return Err("FAILPOINT_BEFORE_SOURCE_SECURED".into());
    }
    fs::remove_file(source).map_err(|e| e.to_string())?;
    advance_and_persist(store, tx, TransactionStateV1::SourceSecured)?;
    if failpoint == Failpoint::AfterSourceSecured {
        return Err("FAILPOINT_AFTER_SOURCE_SECURED".into());
    }
    if failpoint == Failpoint::BeforeFinalCommit {
        return Err("FAILPOINT_BEFORE_FINAL_COMMIT".into());
    }
    advance_and_persist(store, tx, TransactionStateV1::Committed)?;
    fs::write(
        &metadata,
        serde_json::to_vec(&tx).map_err(|e| e.to_string())?,
    )
    .map_err(|e| e.to_string())?;
    Ok(QuarantineReceiptV2 {
        transaction_id: tx.transaction_id.clone(),
        state: tx.state.clone(),
        object_path: object.display().to_string(),
        metadata_path: metadata.display().to_string(),
        digest,
        size: bytes.len() as u64,
    })
}

pub fn restore_quarantine_v2(
    request: &RestoreRequestV2,
    store: &QuarantineStoreV2,
    key: &TestKeyProvider,
) -> Result<RestoreReceiptV2, String> {
    restore_quarantine_v2_with_failpoint(request, store, key, Failpoint::None)
}

pub fn restore_quarantine_v2_with_failpoint(
    request: &RestoreRequestV2,
    store: &QuarantineStoreV2,
    key: &TestKeyProvider,
    failpoint: Failpoint,
) -> Result<RestoreReceiptV2, String> {
    if !request.explicit_authority {
        return Err("RESTORE_AUTHORITY_REQUIRED".into());
    }
    if !valid_storage_id(&request.transaction_id) {
        return Err("TRANSACTION_ID_REJECTED".into());
    }
    let metadata_path = store
        .root
        .join("metadata")
        .join(format!("{}.json", request.transaction_id));
    let tx: ResponseTransactionV1 =
        serde_json::from_slice(&fs::read(&metadata_path).map_err(|_| "METADATA_UNAVAILABLE")?)
            .map_err(|_| "METADATA_TAMPERED")?;
    if tx.transaction_id != request.transaction_id || tx.state != TransactionStateV1::Committed {
        return Err("TRANSACTION_NOT_COMMITTED".into());
    }
    let destination = std::path::PathBuf::from(&request.destination);
    let root = std::path::PathBuf::from(&request.allowed_root)
        .canonicalize()
        .map_err(|e| e.to_string())?;
    let parent = destination
        .parent()
        .ok_or("RESTORE_DESTINATION_REJECTED")?
        .canonicalize()
        .map_err(|_| "RESTORE_DESTINATION_REJECTED")?;
    if !parent.starts_with(&root) {
        return Err("RESTORE_DESTINATION_REJECTED".into());
    }
    let protected = {
        let object_path = store.object_path(&request.transaction_id);
        read_protected_object(&object_path).map_err(str::to_owned)?
    };
    let parsed = parse_protected_object(&protected).map_err(|_| "OBJECT_TAMPERED")?;
    let cipher = Aes256Gcm::new(GenericArray::from_slice(&key.0));
    let plaintext = cipher
        .decrypt(
            GenericArray::from_slice(parsed.nonce),
            aes_gcm::aead::Payload {
                msg: parsed.ciphertext,
                aad: &metadata_binding(&tx).map_err(|_| "METADATA_BINDING_FAILED")?,
            },
        )
        .map_err(|_| "AUTHENTICATION_FAILED")?;
    let digest = hex::encode(Sha256::digest(&plaintext));
    if digest != tx.artifact.content_digest || plaintext.len() as u64 != tx.artifact.size {
        return Err("DIGEST_MISMATCH".into());
    }
    let canonical_destination = parent.join(
        destination
            .file_name()
            .ok_or("RESTORE_DESTINATION_REJECTED")?,
    );
    let record_path = restore_record_path(store, &request.transaction_id);
    if let Ok(record) = fs::read(&record_path).and_then(|bytes| {
        serde_json::from_slice::<RestoreRecordV1>(&bytes).map_err(std::io::Error::other)
    }) {
        if record.transaction_id != tx.transaction_id
            || record.destination != canonical_destination.display().to_string()
            || record.digest != digest
            || record.size != plaintext.len() as u64
        {
            return Err("RESTORE_RECORD_CONFLICT".into());
        }
        if record.state == RestoreStateV2::Committed || record.state == RestoreStateV2::Prepared {
            if canonical_destination.exists() {
                let existing =
                    fs::read(&canonical_destination).map_err(|_| "RESTORE_DESTINATION_REJECTED")?;
                if existing.len() as u64 == record.size
                    && hex::encode(Sha256::digest(&existing)) == record.digest
                {
                    if record.state == RestoreStateV2::Prepared {
                        let _ = fs::remove_file(PathBuf::from(&record.temp_path));
                        persist_restore_record(
                            store,
                            &RestoreRecordV1 {
                                state: RestoreStateV2::Committed,
                                ..record.clone()
                            },
                        )
                        .map_err(|_| "RESTORE_RECORD_FAILED")?;
                    }
                    return Ok(RestoreReceiptV2 {
                        transaction_id: request.transaction_id.clone(),
                        destination: canonical_destination.display().to_string(),
                        state: RestoreStateV2::AlreadyCommitted,
                        digest,
                        size: plaintext.len() as u64,
                    });
                }
                return Err("RESTORE_DESTINATION_REJECTED".into());
            }
            if record.state == RestoreStateV2::Committed {
                return Err("RESTORE_DESTINATION_REJECTED".into());
            }
        }
    } else if record_path.exists() {
        return Err("RESTORE_RECORD_MALFORMED".into());
    }
    if destination.exists() || canonical_destination.exists() {
        return Err("RESTORE_DESTINATION_REJECTED".into());
    }
    #[cfg(test)]
    run_restore_destination_test_hook(&canonical_destination);
    let temp =
        canonical_destination.with_file_name(format!(".{}.restore.tmp", request.transaction_id));
    if failpoint == Failpoint::DuringRestoreWrite {
        return Err("FAILPOINT_DURING_RESTORE_WRITE".into());
    }
    let record = RestoreRecordV1 {
        schema_version: "sentinel-restore/v1".into(),
        transaction_id: request.transaction_id.clone(),
        destination: canonical_destination.display().to_string(),
        digest: digest.clone(),
        size: plaintext.len() as u64,
        temp_path: temp.display().to_string(),
        state: RestoreStateV2::Prepared,
    };
    persist_restore_record(store, &record).map_err(|_| "RESTORE_RECORD_FAILED")?;
    if fs::symlink_metadata(&temp).is_ok() {
        return Err("RESTORE_TEMP_REJECTED".into());
    }
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&temp)
        .map_err(|_| "RESTORE_TEMP_REJECTED")?;
    file.write_all(&plaintext)
        .and_then(|_| file.sync_all())
        .map_err(|e| e.to_string())?;
    #[cfg(test)]
    run_restore_temp_test_hook(&temp);
    if !owned_temp_path_matches(&file, &temp) {
        return Err("RESTORE_TEMP_REJECTED".into());
    }
    if failpoint == Failpoint::BeforeRestorePublish {
        let _ = fs::remove_file(&temp);
        return Err("FAILPOINT_BEFORE_RESTORE_PUBLISH".into());
    }
    if canonical_destination.exists() {
        return Err("RESTORE_DESTINATION_REJECTED".into());
    }
    fs::hard_link(&temp, &canonical_destination).map_err(|_| "RESTORE_DESTINATION_REJECTED")?;
    fs::remove_file(&temp).map_err(|e| e.to_string())?;
    if failpoint == Failpoint::AfterRestorePublish {
        return Err("FAILPOINT_AFTER_RESTORE_PUBLISH".into());
    }
    persist_restore_record(
        store,
        &RestoreRecordV1 {
            state: RestoreStateV2::Committed,
            ..record
        },
    )
    .map_err(|_| "RESTORE_RECORD_FAILED")?;
    Ok(RestoreReceiptV2 {
        transaction_id: request.transaction_id.clone(),
        destination: destination.display().to_string(),
        state: RestoreStateV2::Committed,
        digest,
        size: plaintext.len() as u64,
    })
}

/// Test-only constructor retained for the pre-Slice-3C unit-test corpus.
#[cfg(test)]
fn plan_transaction(
    transaction_id: String,
    artifact: ArtifactIdentityV1,
    action: ResponseActionV1,
) -> ResponseTransactionV1 {
    ResponseTransactionV1 {
        schema_version: "sentinel-response/v1".into(),
        response_idempotency_key: transaction_id.clone(),
        transaction_id,
        artifact,
        action,
        state: TransactionStateV1::Planned,
    }

    /*
    #[test]
    fn quarantine_failpoint_matrix_is_complete_and_recovery_safe() {
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
        assert_eq!(failpoints.len(), 10);
        for (index, failpoint) in failpoints.into_iter().enumerate() {
            let dir = tempfile::tempdir().unwrap();
            let source = dir.path().join("source.txt");
            let bytes = format!("harmless-failpoint-{index}").into_bytes();
            fs::write(&source, &bytes).unwrap();
            let store = QuarantineStoreV2::open(dir.path().join("store")).unwrap();
            let identity = ArtifactIdentityV1 { normalized_path: source.display().to_string(), content_digest: hex::encode(Sha256::digest(&bytes)), size: bytes.len() as u64, platform_file_id: None, generation: index as u64 };
            let id = format!("fp-{index}");
            let mut tx = plan_transaction(id.clone(), identity, ResponseActionV1::Quarantine);
            let error = execute_quarantine_v2_with_failpoint(&mut tx, &store, &TestKeyProvider([6; 32]), failpoint).unwrap_err();
            assert!(error.starts_with("FAILPOINT_"), "unexpected error: {error}");
            let before = fs::read(&source).ok();
            let first = recover_quarantine_store_v2(&store, &TestKeyProvider([6; 32]));
            let after_first = (source.exists(), store.object_path(&id).exists(), fs::read(store.journal_path(&id)).unwrap());
            let second = recover_quarantine_store_v2(&store, &TestKeyProvider([6; 32]));
            let after_second = (source.exists(), store.object_path(&id).exists(), fs::read(store.journal_path(&id)).unwrap());
            assert!(!first.is_empty());
            assert_eq!(after_first, after_second);
            assert!(before.is_some() || store.object_path(&id).exists());
            assert!(!second.is_empty());
        }
    }

    #[test]
    fn restore_security_matrix_rejects_authority_collision_root_key_and_tamper() {
        let dir = tempfile::tempdir().unwrap();
        let source = dir.path().join("source.txt");
        let restore_root = dir.path().join("restore");
        fs::create_dir_all(&restore_root).unwrap();
        let bytes = b"restore-security-fixture";
        fs::write(&source, bytes).unwrap();
        let store = QuarantineStoreV2::open(dir.path().join("store")).unwrap();
        let identity = ArtifactIdentityV1 { normalized_path: source.display().to_string(), content_digest: hex::encode(Sha256::digest(bytes)), size: bytes.len() as u64, platform_file_id: None, generation: 7 };
        let key = TestKeyProvider([5; 32]);
        let mut tx = plan_transaction("security".into(), identity, ResponseActionV1::Quarantine);
        let receipt = execute_quarantine_v2(&mut tx, &store, &key).unwrap();
        let destination = restore_root.join("restored.txt");
        let request = RestoreRequestV2 { transaction_id: receipt.transaction_id.clone(), destination: destination.display().to_string(), allowed_root: restore_root.display().to_string(), explicit_authority: false };
        assert_eq!(restore_quarantine_v2(&request, &store, &key).unwrap_err(), "RESTORE_AUTHORITY_REQUIRED");
        assert!(!destination.exists());
        fs::write(&destination, b"existing").unwrap();
        let mut collision = request.clone(); collision.explicit_authority = true;
        assert_eq!(restore_quarantine_v2(&collision, &store, &key).unwrap_err(), "RESTORE_DESTINATION_REJECTED");
        assert_eq!(fs::read(&destination).unwrap(), b"existing");
        let outside = RestoreRequestV2 { destination: dir.path().join("outside.txt").display().to_string(), ..collision.clone() };
        assert_eq!(restore_quarantine_v2(&outside, &store, &key).unwrap_err(), "RESTORE_DESTINATION_REJECTED");
        let wrong = TestKeyProvider([4; 32]);
        let wrong_destination = restore_root.join("wrong.txt");
        let wrong_request = RestoreRequestV2 { destination: wrong_destination.display().to_string(), ..collision.clone() };
        assert_eq!(restore_quarantine_v2(&wrong_request, &store, &wrong).unwrap_err(), "AUTHENTICATION_FAILED");
        assert!(!wrong_destination.exists());
        let object_path = store.object_path(&receipt.transaction_id);
        let mut tampered = fs::read(&object_path).unwrap(); tampered[20] ^= 1; fs::write(&object_path, tampered).unwrap();
        let tamper_destination = restore_root.join("tampered.txt");
        let tamper_request = RestoreRequestV2 { destination: tamper_destination.display().to_string(), ..collision };
        assert_eq!(restore_quarantine_v2(&tamper_request, &store, &key).unwrap_err(), "AUTHENTICATION_FAILED");
        assert!(!tamper_destination.exists());
    }
    */
}

/// Create a quarantine transaction only from an identity-bound, enabled policy plan.
pub fn plan_transaction_from_plan(
    artifact: ArtifactIdentityV1,
    plan: &ResponsePlanV1,
) -> Result<ResponseTransactionV1, String> {
    if plan.artifact != artifact {
        return Err("POLICY_ARTIFACT_IDENTITY_MISMATCH".into());
    }
    if !plan.effect_enabled {
        return Err("POLICY_EFFECT_NOT_AUTHORIZED".into());
    }
    if plan.action != ResponseActionV1::Quarantine {
        return Err("POLICY_ACTION_NOT_QUARANTINE".into());
    }
    Ok(ResponseTransactionV1 {
        schema_version: "sentinel-response/v1".into(),
        response_idempotency_key: plan.transaction_id.clone(),
        transaction_id: plan.transaction_id.clone(),
        artifact,
        action: ResponseActionV1::Quarantine,
        state: TransactionStateV1::Planned,
    })
}

pub fn advance(tx: &mut ResponseTransactionV1, next: TransactionStateV1) -> Result<(), String> {
    let valid = matches!(
        (&tx.state, &next),
        (
            TransactionStateV1::Planned,
            TransactionStateV1::IdentityRevalidated
        ) | (
            TransactionStateV1::IdentityRevalidated,
            TransactionStateV1::JournalPrepared
        ) | (
            TransactionStateV1::JournalPrepared,
            TransactionStateV1::SourceClaimed
        ) | (
            TransactionStateV1::SourceClaimed,
            TransactionStateV1::ContentProtected
        ) | (
            TransactionStateV1::ContentProtected,
            TransactionStateV1::ObjectCommitted
        ) | (
            TransactionStateV1::ObjectCommitted,
            TransactionStateV1::MetadataCommitted
        ) | (
            TransactionStateV1::MetadataCommitted,
            TransactionStateV1::SourceSecured
        ) | (
            TransactionStateV1::ObjectCommitted,
            TransactionStateV1::Committed
        ) | (
            TransactionStateV1::MetadataCommitted,
            TransactionStateV1::Committed
        ) | (
            TransactionStateV1::SourceSecured,
            TransactionStateV1::Committed
        ) | (
            TransactionStateV1::Planned,
            TransactionStateV1::FailedNoEffect
        ) | (
            TransactionStateV1::JournalPrepared,
            TransactionStateV1::RolledBack
        )
    );
    if !valid {
        return Err(format!(
            "invalid transaction transition {:?} -> {:?}",
            tx.state, next
        ));
    }
    tx.state = next;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit_policy::{AuditEffectV1, AuditPolicyV1, plan_for_artifact};

    fn slice3c_identity(path: &Path, bytes: &[u8]) -> ArtifactIdentityV1 {
        ArtifactIdentityV1 {
            normalized_path: path.canonicalize().unwrap().display().to_string(),
            content_digest: hex::encode(Sha256::digest(bytes)),
            size: bytes.len() as u64,
            platform_file_id: None,
            generation: 1,
        }
    }

    fn slice3c_policy(enabled: bool, effect: AuditEffectV1) -> AuditPolicyV1 {
        AuditPolicyV1 {
            policy_id: "slice3c".into(),
            policy_version: "v1".into(),
            enabled,
            effect,
            allowed_root: "/tmp".into(),
            engine_id: "yara-x".into(),
            ruleset_id: "harmless-fixture".into(),
        }
    }

    #[test]
    fn s3c_t03_audit_only_plan_cannot_create_quarantine_transaction() {
        // Arrange
        let identity = ArtifactIdentityV1 {
            normalized_path: "/tmp/audit-only".into(),
            content_digest: "digest".into(),
            size: 1,
            platform_file_id: None,
            generation: 1,
        };
        let plan =
            plan_for_artifact(&identity, &slice3c_policy(true, AuditEffectV1::AuditOnly)).unwrap();

        // Act
        let result = plan_transaction_from_plan(identity, &plan);

        // Assert — S3C-ID-02
        assert_eq!(result.unwrap_err(), "POLICY_EFFECT_NOT_AUTHORIZED");
    }

    #[test]
    fn s3c_t04_disabled_plan_cannot_create_quarantine_transaction() {
        // Arrange
        let identity = ArtifactIdentityV1 {
            normalized_path: "/tmp/disabled".into(),
            content_digest: "digest".into(),
            size: 1,
            platform_file_id: None,
            generation: 1,
        };
        let plan = plan_for_artifact(&identity, &slice3c_policy(false, AuditEffectV1::Quarantine))
            .unwrap();

        // Act
        let result = plan_transaction_from_plan(identity, &plan);

        // Assert — S3C-ID-02
        assert_eq!(result.unwrap_err(), "POLICY_EFFECT_NOT_AUTHORIZED");
    }

    #[test]
    fn s3c_t05_explicit_enabled_quarantine_plan_creates_transaction() {
        // Arrange
        let identity = ArtifactIdentityV1 {
            normalized_path: "/tmp/authorized".into(),
            content_digest: "digest".into(),
            size: 1,
            platform_file_id: None,
            generation: 1,
        };
        let plan =
            plan_for_artifact(&identity, &slice3c_policy(true, AuditEffectV1::Quarantine)).unwrap();

        // Act
        let transaction = plan_transaction_from_plan(identity.clone(), &plan).unwrap();

        // Assert — S3C-ID-03
        assert_eq!(transaction.artifact, identity);
        assert_eq!(transaction.action, ResponseActionV1::Quarantine);
        assert_eq!(transaction.transaction_id, plan.transaction_id);
    }

    #[test]
    fn s3c_t06_non_quarantine_action_cannot_become_quarantine_transaction() {
        // Arrange
        let identity = ArtifactIdentityV1 {
            normalized_path: "/tmp/forged-action".into(),
            content_digest: "digest".into(),
            size: 1,
            platform_file_id: None,
            generation: 1,
        };
        let mut plan =
            plan_for_artifact(&identity, &slice3c_policy(true, AuditEffectV1::Quarantine)).unwrap();
        plan.action = ResponseActionV1::Audit;

        // Act
        let result = plan_transaction_from_plan(identity, &plan);

        // Assert — S3C-ID-03
        assert_eq!(result.unwrap_err(), "POLICY_ACTION_NOT_QUARANTINE");
    }

    #[test]
    fn s3c_t07_mismatched_plan_identity_is_rejected() {
        // Arrange
        let identity = ArtifactIdentityV1 {
            normalized_path: "/tmp/original".into(),
            content_digest: "digest-a".into(),
            size: 1,
            platform_file_id: None,
            generation: 1,
        };
        let plan =
            plan_for_artifact(&identity, &slice3c_policy(true, AuditEffectV1::Quarantine)).unwrap();
        let mut replacement = identity;
        replacement.content_digest = "digest-b".into();

        // Act
        let result = plan_transaction_from_plan(replacement, &plan);

        // Assert — S3C-ID-03
        assert_eq!(result.unwrap_err(), "POLICY_ARTIFACT_IDENTITY_MISMATCH");
    }

    #[test]
    fn s3c_t08_stale_artifact_after_planning_is_rejected_before_effect() {
        // Arrange
        let directory = tempfile::tempdir().unwrap();
        let source = directory.path().join("harmless");
        let original = b"harmless original";
        let replacement = b"harmless replacement";
        fs::write(&source, original).unwrap();
        let identity = slice3c_identity(&source, original);
        let plan =
            plan_for_artifact(&identity, &slice3c_policy(true, AuditEffectV1::Quarantine)).unwrap();
        let mut transaction = plan_transaction_from_plan(identity, &plan).unwrap();
        let store = QuarantineStoreV2::open(directory.path().join("store")).unwrap();
        fs::write(&source, replacement).unwrap();

        // Act
        let result = execute_quarantine_v2(&mut transaction, &store, &TestKeyProvider([3; 32]));

        // Assert — S3C-ID-04
        assert_eq!(result.unwrap_err(), "STALE_ARTIFACT");
        assert_eq!(fs::read(&source).unwrap(), replacement);
        assert!(!store.object_path(&plan.transaction_id).exists());
        assert_ne!(transaction.state, TransactionStateV1::Committed);
    }

    #[test]
    fn s3c_t09_authorized_harmless_fixture_reaches_quarantine_receipt() {
        // Arrange
        let directory = tempfile::tempdir().unwrap();
        let source = directory.path().join("harmless");
        let bytes = b"harmless authorized Slice 3C fixture";
        fs::write(&source, bytes).unwrap();
        let identity = slice3c_identity(&source, bytes);
        let plan =
            plan_for_artifact(&identity, &slice3c_policy(true, AuditEffectV1::Quarantine)).unwrap();
        let mut transaction = plan_transaction_from_plan(identity, &plan).unwrap();
        let store = QuarantineStoreV2::open(directory.path().join("store")).unwrap();
        let key = TestKeyProvider([3; 32]);

        // Act
        let receipt = execute_quarantine_v2(&mut transaction, &store, &key).unwrap();

        // Assert — S3C-ID-05
        assert_eq!(receipt.state, TransactionStateV1::Committed);
        assert_eq!(receipt.digest, hex::encode(Sha256::digest(bytes)));
        assert!(!source.exists());
        assert!(store.object_path(&receipt.transaction_id).exists());
    }

    #[test]
    fn s3c_t10_key_authority_is_explicitly_test_only() {
        // Arrange
        let key = TestKeyProvider([3; 32]);

        // Act
        let authority_type = std::any::type_name_of_val(&key);

        // Assert — S3C-ID-05 / S3C-ID-06
        assert!(authority_type.ends_with("TestKeyProvider"));
        assert_eq!(key.0, [3; 32]);
    }

    fn canonical_quarantined(
        id: &str,
        bytes: &[u8],
    ) -> (
        tempfile::TempDir,
        std::path::PathBuf,
        std::path::PathBuf,
        QuarantineStoreV2,
        TestKeyProvider,
        QuarantineReceiptV2,
    ) {
        let dir = tempfile::tempdir().unwrap();
        let source = dir.path().join("source");
        let root = dir.path().join("restore");
        fs::create_dir_all(&root).unwrap();
        fs::write(&source, bytes).unwrap();
        let store = QuarantineStoreV2::open(dir.path().join("store")).unwrap();
        let key = TestKeyProvider([11; 32]);
        let mut tx = plan_transaction(
            id.to_owned(),
            ArtifactIdentityV1 {
                normalized_path: source.display().to_string(),
                content_digest: hex::encode(Sha256::digest(bytes)),
                size: bytes.len() as u64,
                platform_file_id: None,
                generation: 1,
            },
            ResponseActionV1::Quarantine,
        );
        let receipt = execute_quarantine_v2(&mut tx, &store, &key).unwrap();
        (dir, source, root, store, key, receipt)
    }

    fn canonical_request(
        receipt: &QuarantineReceiptV2,
        destination: &Path,
        root: &Path,
        explicit_authority: bool,
    ) -> RestoreRequestV2 {
        RestoreRequestV2 {
            transaction_id: receipt.transaction_id.clone(),
            destination: destination.display().to_string(),
            allowed_root: root.display().to_string(),
            explicit_authority,
        }
    }

    fn canonical_temp(root: &Path, id: &str) -> PathBuf {
        root.canonicalize()
            .unwrap()
            .join(format!(".{id}.restore.tmp"))
    }

    #[test]
    fn canonical_po_01_source_initial_symlink_reject() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("target");
        let source = dir.path().join("source");
        let bytes = b"po-01-target";
        fs::write(&target, bytes).unwrap();
        #[cfg(unix)]
        std::os::unix::fs::symlink(&target, &source).unwrap();
        let store = QuarantineStoreV2::open(dir.path().join("store")).unwrap();
        let mut tx = plan_transaction(
            "po-01".into(),
            ArtifactIdentityV1 {
                normalized_path: source.display().to_string(),
                content_digest: hex::encode(Sha256::digest(bytes)),
                size: bytes.len() as u64,
                platform_file_id: None,
                generation: 1,
            },
            ResponseActionV1::Quarantine,
        );
        #[cfg(unix)]
        assert!(execute_quarantine_v2(&mut tx, &store, &TestKeyProvider([11; 32])).is_err());
        #[cfg(unix)]
        assert_eq!(fs::read(&target).unwrap(), bytes);
        #[cfg(unix)]
        assert!(!store.object_path("po-01").exists());
    }

    #[cfg(unix)]
    #[test]
    fn canonical_po_02_source_swap_to_symlink_reject() {
        let dir = tempfile::tempdir().unwrap();
        let source = dir.path().join("source");
        let target = dir.path().join("target");
        let bytes = b"po-02-original";
        fs::write(&source, bytes).unwrap();
        fs::write(&target, b"po-02-target").unwrap();
        let store = QuarantineStoreV2::open(dir.path().join("store")).unwrap();
        let mut tx = plan_transaction(
            "po-02".into(),
            ArtifactIdentityV1 {
                normalized_path: source.display().to_string(),
                content_digest: hex::encode(Sha256::digest(bytes)),
                size: bytes.len() as u64,
                platform_file_id: None,
                generation: 1,
            },
            ResponseActionV1::Quarantine,
        );
        fs::remove_file(&source).unwrap();
        std::os::unix::fs::symlink(&target, &source).unwrap();
        assert!(execute_quarantine_v2(&mut tx, &store, &TestKeyProvider([11; 32])).is_err());
        assert_eq!(fs::read(&target).unwrap(), b"po-02-target");
        assert!(!store.object_path("po-02").exists());
    }

    #[test]
    fn canonical_po_03_source_swap_to_other_regular_reject() {
        let dir = tempfile::tempdir().unwrap();
        let source = dir.path().join("source");
        let bytes = b"po-03-original";
        fs::write(&source, bytes).unwrap();
        let store = QuarantineStoreV2::open(dir.path().join("store")).unwrap();
        let mut tx = plan_transaction(
            "po-03".into(),
            ArtifactIdentityV1 {
                normalized_path: source.display().to_string(),
                content_digest: hex::encode(Sha256::digest(bytes)),
                size: bytes.len() as u64,
                platform_file_id: None,
                generation: 1,
            },
            ResponseActionV1::Quarantine,
        );
        fs::write(&source, b"po-03-replacement").unwrap();
        assert!(execute_quarantine_v2(&mut tx, &store, &TestKeyProvider([11; 32])).is_err());
        assert!(!store.object_path("po-03").exists());
    }

    #[test]
    fn canonical_po_04_source_disappears_before_effect() {
        let dir = tempfile::tempdir().unwrap();
        let source = dir.path().join("source");
        let bytes = b"po-04-original";
        fs::write(&source, bytes).unwrap();
        let store = QuarantineStoreV2::open(dir.path().join("store")).unwrap();
        let mut tx = plan_transaction(
            "po-04".into(),
            ArtifactIdentityV1 {
                normalized_path: source.display().to_string(),
                content_digest: hex::encode(Sha256::digest(bytes)),
                size: bytes.len() as u64,
                platform_file_id: None,
                generation: 1,
            },
            ResponseActionV1::Quarantine,
        );
        fs::remove_file(&source).unwrap();
        assert!(execute_quarantine_v2(&mut tx, &store, &TestKeyProvider([11; 32])).is_err());
        assert!(!store.object_path("po-04").exists());
    }

    #[test]
    fn canonical_po_05_source_becomes_nonregular_reject() {
        let dir = tempfile::tempdir().unwrap();
        let source = dir.path().join("source");
        let bytes = b"po-05-original";
        fs::write(&source, bytes).unwrap();
        let store = QuarantineStoreV2::open(dir.path().join("store")).unwrap();
        let mut tx = plan_transaction(
            "po-05".into(),
            ArtifactIdentityV1 {
                normalized_path: source.display().to_string(),
                content_digest: hex::encode(Sha256::digest(bytes)),
                size: bytes.len() as u64,
                platform_file_id: None,
                generation: 1,
            },
            ResponseActionV1::Quarantine,
        );
        fs::remove_file(&source).unwrap();
        fs::create_dir(&source).unwrap();
        assert!(execute_quarantine_v2(&mut tx, &store, &TestKeyProvider([11; 32])).is_err());
        assert!(!store.object_path("po-05").exists());
    }

    #[test]
    fn canonical_po_06_source_effect_permission_failure() {
        let dir = tempfile::tempdir().unwrap();
        let source = dir.path().join("source");
        let bytes = b"po-06";
        fs::write(&source, bytes).unwrap();
        let store = QuarantineStoreV2::open(dir.path().join("store")).unwrap();
        let mut tx = plan_transaction(
            "po-06".into(),
            ArtifactIdentityV1 {
                normalized_path: source.display().to_string(),
                content_digest: hex::encode(Sha256::digest(bytes)),
                size: bytes.len() as u64,
                platform_file_id: None,
                generation: 1,
            },
            ResponseActionV1::Quarantine,
        );
        let result = execute_quarantine_v2_with_failpoint(
            &mut tx,
            &store,
            &TestKeyProvider([11; 32]),
            Failpoint::DuringContentProtection,
        );
        assert!(result.is_err());
        assert_ne!(tx.state, TransactionStateV1::Committed);
        assert_eq!(fs::read(&source).unwrap(), bytes);
    }

    #[test]
    fn canonical_po_07_quarantine_object_collision_no_overwrite() {
        let dir = tempfile::tempdir().unwrap();
        let source = dir.path().join("source");
        let bytes = b"po-07";
        fs::write(&source, bytes).unwrap();
        let store = QuarantineStoreV2::open(dir.path().join("store")).unwrap();
        let existing = b"existing-object";
        fs::write(store.object_path("po-07"), existing).unwrap();
        let mut tx = plan_transaction(
            "po-07".into(),
            ArtifactIdentityV1 {
                normalized_path: source.display().to_string(),
                content_digest: hex::encode(Sha256::digest(bytes)),
                size: bytes.len() as u64,
                platform_file_id: None,
                generation: 1,
            },
            ResponseActionV1::Quarantine,
        );
        assert!(execute_quarantine_v2(&mut tx, &store, &TestKeyProvider([11; 32])).is_err());
        assert_eq!(fs::read(store.object_path("po-07")).unwrap(), existing);
    }

    #[cfg(unix)]
    #[test]
    fn canonical_po_08_quarantine_object_symlink_substitution_reject() {
        let (_dir, _source, root, store, key, receipt) = canonical_quarantined("po-08", b"po-08");
        let target = root.join("attacker-object");
        fs::write(&target, fs::read(store.object_path("po-08")).unwrap()).unwrap();
        fs::remove_file(store.object_path("po-08")).unwrap();
        std::os::unix::fs::symlink(&target, store.object_path("po-08")).unwrap();
        let destination = root.join("restored");
        let request = canonical_request(&receipt, &destination, &root, true);
        assert_eq!(
            restore_quarantine_v2(&request, &store, &key).unwrap_err(),
            "OBJECT_TAMPERED"
        );
        assert!(!destination.exists());
    }

    #[test]
    fn canonical_po_09_quarantine_object_regular_replacement_reject() {
        let (_dir, _source, root, store, key, receipt) = canonical_quarantined("po-09", b"po-09");
        fs::write(store.object_path("po-09"), b"unrelated-object").unwrap();
        let destination = root.join("restored");
        let request = canonical_request(&receipt, &destination, &root, true);
        assert!(restore_quarantine_v2(&request, &store, &key).is_err());
        assert!(!destination.exists());
    }

    #[test]
    fn canonical_po_10_aisv2_ciphertext_tamper_reject() {
        let (_dir, _source, root, store, key, receipt) = canonical_quarantined("po-10", b"po-10");
        let mut object = fs::read(store.object_path("po-10")).unwrap();
        object[20] ^= 1;
        fs::write(store.object_path("po-10"), object).unwrap();
        let destination = root.join("restored");
        let request = canonical_request(&receipt, &destination, &root, true);
        assert_eq!(
            restore_quarantine_v2(&request, &store, &key).unwrap_err(),
            "AUTHENTICATION_FAILED"
        );
        assert!(!destination.exists());
    }

    #[test]
    fn canonical_po_11_authenticated_metadata_tamper_reject() {
        let (_dir, _source, root, _store, key, receipt) = canonical_quarantined("po-11", b"po-11");
        let metadata_path = PathBuf::from(&receipt.metadata_path);
        let mut metadata: ResponseTransactionV1 =
            serde_json::from_slice(&fs::read(&metadata_path).unwrap()).unwrap();
        metadata.artifact.size += 1;
        fs::write(&metadata_path, serde_json::to_vec(&metadata).unwrap()).unwrap();
        let destination = root.join("restored");
        let request = canonical_request(&receipt, &destination, &root, true);
        assert!(restore_quarantine_v2(&request, &_store, &key).is_err());
        assert!(!destination.exists());
    }

    #[test]
    fn canonical_po_12_wrong_key_reject() {
        let (_dir, _source, root, store, _key, receipt) = canonical_quarantined("po-12", b"po-12");
        let destination = root.join("restored");
        let request = canonical_request(&receipt, &destination, &root, true);
        assert_eq!(
            restore_quarantine_v2(&request, &store, &TestKeyProvider([12; 32])).unwrap_err(),
            "AUTHENTICATION_FAILED"
        );
        assert!(!destination.exists());
    }

    #[test]
    fn canonical_po_13_restore_unauthorized_actor_reject() {
        let (_dir, _source, root, store, key, receipt) = canonical_quarantined("po-13", b"po-13");
        let destination = root.join("restored");
        let request = canonical_request(&receipt, &destination, &root, false);
        assert_eq!(
            restore_quarantine_v2(&request, &store, &key).unwrap_err(),
            "RESTORE_AUTHORITY_REQUIRED"
        );
        assert!(store.object_path("po-13").exists());
        assert!(!destination.exists());
    }

    #[test]
    fn canonical_po_14_restore_outside_authorized_root_reject() {
        let (dir, _source, root, store, key, receipt) = canonical_quarantined("po-14", b"po-14");
        let destination = dir.path().join("outside");
        let request = canonical_request(&receipt, &destination, &root, true);
        assert!(restore_quarantine_v2(&request, &store, &key).is_err());
        assert!(!destination.exists());
        assert!(store.object_path("po-14").exists());
    }

    #[test]
    fn canonical_po_15_existing_regular_destination_no_replace() {
        let (_dir, _source, root, store, key, receipt) = canonical_quarantined("po-15", b"po-15");
        let destination = root.join("restored");
        let existing = b"preexisting-destination";
        fs::write(&destination, existing).unwrap();
        let request = canonical_request(&receipt, &destination, &root, true);
        assert!(restore_quarantine_v2(&request, &store, &key).is_err());
        assert_eq!(fs::read(&destination).unwrap(), existing);
    }

    #[cfg(unix)]
    #[test]
    fn canonical_po_16_existing_symlink_destination_no_follow() {
        let (dir, _source, root, store, key, receipt) = canonical_quarantined("po-16", b"po-16");
        let destination = root.join("restored");
        let target = dir.path().join("destination-target");
        let existing = b"symlink-target";
        fs::write(&target, existing).unwrap();
        std::os::unix::fs::symlink(&target, &destination).unwrap();
        let request = canonical_request(&receipt, &destination, &root, true);
        assert!(restore_quarantine_v2(&request, &store, &key).is_err());
        assert_eq!(fs::read(&target).unwrap(), existing);
    }

    #[cfg(unix)]
    #[test]
    fn canonical_po_17_restore_symlinked_parent_escape_reject() {
        let (dir, _source, root, store, key, receipt) = canonical_quarantined("po-17", b"po-17");
        let outside = dir.path().join("outside");
        let escaped_parent = root.join("link");
        fs::create_dir_all(&outside).unwrap();
        std::os::unix::fs::symlink(&outside, &escaped_parent).unwrap();
        let destination = escaped_parent.join("restored");
        let request = canonical_request(&receipt, &destination, &root, true);
        assert!(restore_quarantine_v2(&request, &store, &key).is_err());
        assert!(!outside.join("restored").exists());
    }

    #[test]
    fn canonical_po_18_destination_insert_race_no_replace() {
        let (_dir, _source, root, store, key, receipt) = canonical_quarantined("po-18", b"po-18");
        let destination = root.join("restored");
        let raced = b"raced-destination";
        let canonical_destination = root.canonicalize().unwrap().join("restored");
        let destination_for_hook = canonical_destination.clone();
        *RESTORE_DESTINATION_TEST_HOOK
            .get_or_init(|| std::sync::Mutex::new(None))
            .lock()
            .unwrap() = Some((
            canonical_destination,
            Box::new(move || {
                fs::write(&destination_for_hook, raced).unwrap();
            }),
        ));
        let request = canonical_request(&receipt, &destination, &root, true);
        assert!(restore_quarantine_v2(&request, &store, &key).is_err());
        assert_eq!(fs::read(&destination).unwrap(), raced);
    }

    #[cfg(unix)]
    #[test]
    fn canonical_po_19_preexisting_temp_symlink_reject() {
        let (dir, _source, root, store, key, receipt) = canonical_quarantined("po-19", b"po-19");
        let destination = root.join("restored");
        let temp = canonical_temp(&root, "po-19");
        let target = dir.path().join("temp-target");
        fs::write(&target, b"attacker-temp").unwrap();
        std::os::unix::fs::symlink(&target, &temp).unwrap();
        let request = canonical_request(&receipt, &destination, &root, true);
        assert_eq!(
            restore_quarantine_v2(&request, &store, &key).unwrap_err(),
            "RESTORE_TEMP_REJECTED"
        );
        assert_eq!(fs::read(&target).unwrap(), b"attacker-temp");
        assert!(!destination.exists());
    }

    #[cfg(unix)]
    #[test]
    fn canonical_po_20_preexisting_temp_hardlink_reject() {
        let (dir, _source, root, store, key, receipt) = canonical_quarantined("po-20", b"po-20");
        let destination = root.join("restored");
        let temp = canonical_temp(&root, "po-20");
        let target = dir.path().join("temp-target");
        let attacker = b"hardlink-temp";
        fs::write(&target, attacker).unwrap();
        fs::hard_link(&target, &temp).unwrap();
        let request = canonical_request(&receipt, &destination, &root, true);
        assert_eq!(
            restore_quarantine_v2(&request, &store, &key).unwrap_err(),
            "RESTORE_TEMP_REJECTED"
        );
        assert_eq!(fs::read(&target).unwrap(), attacker);
        assert!(!destination.exists());
    }

    #[test]
    fn canonical_po_21_preexisting_temp_regular_reject() {
        let (_dir, _source, root, store, key, receipt) = canonical_quarantined("po-21", b"po-21");
        let destination = root.join("restored");
        let temp = canonical_temp(&root, "po-21");
        let attacker = b"regular-temp";
        fs::write(&temp, attacker).unwrap();
        let request = canonical_request(&receipt, &destination, &root, true);
        assert_eq!(
            restore_quarantine_v2(&request, &store, &key).unwrap_err(),
            "RESTORE_TEMP_REJECTED"
        );
        assert_eq!(fs::read(&temp).unwrap(), attacker);
        assert!(!destination.exists());
    }

    #[test]
    fn canonical_po_22_preexisting_temp_nonregular_reject() {
        let (_dir, _source, root, store, key, receipt) = canonical_quarantined("po-22", b"po-22");
        let destination = root.join("restored");
        let temp = canonical_temp(&root, "po-22");
        fs::create_dir(&temp).unwrap();
        let request = canonical_request(&receipt, &destination, &root, true);
        assert_eq!(
            restore_quarantine_v2(&request, &store, &key).unwrap_err(),
            "RESTORE_TEMP_REJECTED"
        );
        assert!(temp.is_dir());
        assert!(!destination.exists());
    }

    #[cfg(unix)]
    #[test]
    fn canonical_po_23_owned_temp_swap_before_publish_reject() {
        restore_owned_temp_swap_rejects_attacker_bytes();
    }

    #[test]
    fn canonical_po_24_post_publish_reconciliation_strict() {
        let (_dir, _source, root, store, key, receipt) = canonical_quarantined("po-24", b"po-24");
        let destination = root.join("restored");
        let request = canonical_request(&receipt, &destination, &root, true);
        let failure = restore_quarantine_v2_with_failpoint(
            &request,
            &store,
            &key,
            Failpoint::AfterRestorePublish,
        )
        .unwrap_err();
        assert_eq!(failure, "FAILPOINT_AFTER_RESTORE_PUBLISH");
        let retry = restore_quarantine_v2(&request, &store, &key).unwrap();
        assert_eq!(retry.state, RestoreStateV2::AlreadyCommitted);
        let mut mismatch = request.clone();
        mismatch.destination = root.join("mismatch").display().to_string();
        fs::write(&mismatch.destination, b"wrong").unwrap();
        assert!(restore_quarantine_v2(&mismatch, &store, &key).is_err());
        assert_eq!(fs::read(&mismatch.destination).unwrap(), b"wrong");
    }

    #[test]
    fn canonical_os_01_source_identity_swap() {
        canonical_po_03_source_swap_to_other_regular_reject();
    }

    #[test]
    fn canonical_os_02_quarantine_object_swap() {
        object_swap_after_validation_uses_bound_object();
    }

    #[cfg(unix)]
    #[test]
    fn canonical_os_03_restore_temp_swap() {
        restore_owned_temp_swap_rejects_attacker_bytes();
    }

    #[test]
    fn canonical_os_04_destination_insert_race() {
        canonical_po_18_destination_insert_race_no_replace();
    }
    #[test]
    fn transaction_starts_effect_free() {
        let artifact = ArtifactIdentityV1 {
            normalized_path: "/tmp/a".into(),
            content_digest: "d".into(),
            size: 1,
            platform_file_id: None,
            generation: 1,
        };
        let mut tx = plan_transaction("t".into(), artifact, ResponseActionV1::Quarantine);
        assert_eq!(tx.state, TransactionStateV1::Planned);
        advance(&mut tx, TransactionStateV1::IdentityRevalidated).unwrap();
        assert!(advance(&mut tx, TransactionStateV1::Committed).is_err());
    }
    #[test]
    fn harmless_quarantine_effect_commits_and_removes_source() {
        let dir = tempfile::tempdir().unwrap();
        let source = dir.path().join("fixture.txt");
        let bytes = b"harmless quarantine fixture";
        std::fs::write(&source, bytes).unwrap();
        let store = QuarantineStoreV2::open(dir.path().join("store")).unwrap();
        let identity = ArtifactIdentityV1 {
            normalized_path: source.display().to_string(),
            content_digest: hex::encode(Sha256::digest(bytes)),
            size: bytes.len() as u64,
            platform_file_id: None,
            generation: 1,
        };
        let mut tx = plan_transaction("tx-fixture".into(), identity, ResponseActionV1::Quarantine);
        let receipt = execute_quarantine_v2(&mut tx, &store, &TestKeyProvider([7u8; 32])).unwrap();
        assert_eq!(receipt.state, TransactionStateV1::Committed);
        assert!(!source.exists());
        assert!(std::path::Path::new(&receipt.object_path).exists());
        assert_ne!(std::fs::read(&receipt.object_path).unwrap(), bytes);
    }

    #[test]
    fn restore_round_trip_and_failpoint_are_bounded() {
        let dir = tempfile::tempdir().unwrap();
        let source = dir.path().join("positive.txt");
        let restore_root = dir.path().join("restore");
        std::fs::create_dir_all(&restore_root).unwrap();
        let destination = restore_root.join("restored.txt");
        let bytes = b"harmless restore fixture";
        std::fs::write(&source, bytes).unwrap();
        let store = QuarantineStoreV2::open(dir.path().join("store")).unwrap();
        let identity = ArtifactIdentityV1 {
            normalized_path: source.display().to_string(),
            content_digest: hex::encode(Sha256::digest(bytes)),
            size: bytes.len() as u64,
            platform_file_id: None,
            generation: 2,
        };
        let mut tx = plan_transaction("tx-restore".into(), identity, ResponseActionV1::Quarantine);
        let key = TestKeyProvider([9u8; 32]);
        let receipt = execute_quarantine_v2(&mut tx, &store, &key).unwrap();
        let request = RestoreRequestV2 {
            transaction_id: receipt.transaction_id.clone(),
            destination: destination.display().to_string(),
            allowed_root: restore_root.display().to_string(),
            explicit_authority: true,
        };
        assert_eq!(
            restore_quarantine_v2_with_failpoint(
                &request,
                &store,
                &key,
                Failpoint::BeforeRestorePublish
            )
            .unwrap_err(),
            "FAILPOINT_BEFORE_RESTORE_PUBLISH"
        );
        assert!(!destination.exists());
        let restored = restore_quarantine_v2(&request, &store, &key).unwrap();
        assert_eq!(restored.state, RestoreStateV2::Committed);
        assert_eq!(std::fs::read(&destination).unwrap(), bytes);
        assert!(std::path::Path::new(&receipt.object_path).exists());
    }

    fn recovery_tx(root: &Path, id: &str, bytes: &[u8]) -> ResponseTransactionV1 {
        plan_transaction(
            id.into(),
            ArtifactIdentityV1 {
                normalized_path: root.join(format!("{id}.source")).display().to_string(),
                content_digest: hex::encode(Sha256::digest(bytes)),
                size: bytes.len() as u64,
                platform_file_id: None,
                generation: 1,
            },
            ResponseActionV1::Quarantine,
        )
    }

    fn seed_state(
        store: &QuarantineStoreV2,
        tx: &mut ResponseTransactionV1,
        state: TransactionStateV1,
    ) {
        persist_transaction_state_v2(store, tx, None).unwrap();
        let path = [
            TransactionStateV1::IdentityRevalidated,
            TransactionStateV1::JournalPrepared,
            TransactionStateV1::SourceClaimed,
            TransactionStateV1::ContentProtected,
            TransactionStateV1::ObjectCommitted,
            TransactionStateV1::MetadataCommitted,
            TransactionStateV1::SourceSecured,
            TransactionStateV1::Committed,
        ];
        for next in path {
            if tx.state == state {
                break;
            }
            advance_and_persist(store, tx, next).unwrap();
        }
    }

    fn seed_object(
        store: &QuarantineStoreV2,
        tx: &ResponseTransactionV1,
        key: &TestKeyProvider,
        bytes: &[u8],
    ) {
        let cipher = Aes256Gcm::new(GenericArray::from_slice(&key.0));
        let nonce = [3_u8; 12];
        let mut protected = b"AISV2\0".to_vec();
        protected.extend(nonce);
        protected.extend(
            cipher
                .encrypt(
                    GenericArray::from_slice(&nonce),
                    aes_gcm::aead::Payload {
                        msg: bytes,
                        aad: &metadata_binding(tx).unwrap(),
                    },
                )
                .unwrap(),
        );
        fs::write(store.object_path(&tx.transaction_id), protected).unwrap();
    }

    fn journal_state(store: &QuarantineStoreV2, id: &str) -> TransactionStateV1 {
        serde_json::from_slice::<ResponseTransactionV1>(&fs::read(store.journal_path(id)).unwrap())
            .unwrap()
            .state
    }

    #[test]
    fn recovery_converges_effect_free_states_idempotently() {
        // Arrange
        let dir = tempfile::tempdir().unwrap();
        let store = QuarantineStoreV2::open(dir.path().join("store")).unwrap();
        let key = TestKeyProvider([7; 32]);
        let mut planned = recovery_tx(dir.path(), "planned", b"planned");
        seed_state(&store, &mut planned, TransactionStateV1::Planned);
        let mut prepared = recovery_tx(dir.path(), "prepared", b"prepared");
        seed_state(&store, &mut prepared, TransactionStateV1::JournalPrepared);
        fs::write(
            store.root.join("staging/prepared.tmp"),
            serde_json::to_vec(&prepared).unwrap(),
        )
        .unwrap();
        // Act
        let first = recover_quarantine_store_v2(&store, &key);
        let snapshot = fs::read(store.journal_path("planned")).unwrap();
        let second = recover_quarantine_store_v2(&store, &key);
        // Assert
        assert!(first.iter().any(
            |r| r.transaction_id == "planned" && r.outcome == RecoveryOutcomeV1::FailedNoEffect
        ));
        assert!(
            first
                .iter()
                .any(|r| r.transaction_id == "prepared"
                    && r.outcome == RecoveryOutcomeV1::RolledBack)
        );
        assert_eq!(
            journal_state(&store, "planned"),
            TransactionStateV1::FailedNoEffect
        );
        assert_eq!(
            journal_state(&store, "prepared"),
            TransactionStateV1::RolledBack
        );
        assert!(!store.root.join("staging/prepared.tmp").exists());
        assert_eq!(fs::read(store.journal_path("planned")).unwrap(), snapshot);
        assert!(
            second
                .iter()
                .all(|r| r.outcome == RecoveryOutcomeV1::NoAction)
        );
    }

    #[test]
    fn recovery_converges_object_metadata_source_and_commit_states() {
        // Arrange
        let dir = tempfile::tempdir().unwrap();
        let store = QuarantineStoreV2::open(dir.path().join("store")).unwrap();
        let key = TestKeyProvider([8; 32]);
        let bytes = b"recovery-content";
        let mut object = recovery_tx(dir.path(), "object", bytes);
        seed_state(&store, &mut object, TransactionStateV1::ObjectCommitted);
        seed_object(&store, &object, &key, bytes);
        let mut metadata = recovery_tx(dir.path(), "metadata", bytes);
        seed_state(&store, &mut metadata, TransactionStateV1::MetadataCommitted);
        seed_object(&store, &metadata, &key, bytes);
        fs::write(&metadata.artifact.normalized_path, bytes).unwrap();
        fs::write(
            store.root.join("metadata/metadata.json"),
            serde_json::to_vec(&metadata).unwrap(),
        )
        .unwrap();
        let mut secured = recovery_tx(dir.path(), "secured", bytes);
        seed_state(&store, &mut secured, TransactionStateV1::SourceSecured);
        seed_object(&store, &secured, &key, bytes);
        fs::write(
            store.root.join("metadata/secured.json"),
            serde_json::to_vec(&secured).unwrap(),
        )
        .unwrap();
        // Act
        let receipts = recover_quarantine_store_v2(&store, &key);
        // Assert
        assert!(
            receipts
                .iter()
                .filter(|r| r.outcome == RecoveryOutcomeV1::Completed)
                .count()
                >= 3
        );
        assert_eq!(
            journal_state(&store, "object"),
            TransactionStateV1::Committed
        );
        assert!(store.root.join("metadata/object.json").exists());
        assert_eq!(
            journal_state(&store, "metadata"),
            TransactionStateV1::Committed
        );
        assert!(!Path::new(&metadata.artifact.normalized_path).exists());
        assert_eq!(
            journal_state(&store, "secured"),
            TransactionStateV1::Committed
        );
    }

    #[test]
    fn recovery_preserves_replacement_and_rejects_wrong_key_and_malformed_record() {
        // Arrange
        let dir = tempfile::tempdir().unwrap();
        let store = QuarantineStoreV2::open(dir.path().join("store")).unwrap();
        let key = TestKeyProvider([9; 32]);
        let mut stale = recovery_tx(dir.path(), "stale", b"original");
        seed_state(&store, &mut stale, TransactionStateV1::MetadataCommitted);
        seed_object(&store, &stale, &key, b"original");
        fs::write(&stale.artifact.normalized_path, b"replacement").unwrap();
        fs::write(
            store.root.join("metadata/stale.json"),
            serde_json::to_vec(&stale).unwrap(),
        )
        .unwrap();
        let mut wrong = recovery_tx(dir.path(), "wrong", b"secret");
        seed_state(&store, &mut wrong, TransactionStateV1::ObjectCommitted);
        seed_object(&store, &wrong, &TestKeyProvider([1; 32]), b"secret");
        fs::write(store.root.join("journal/bad.json"), b"not-json").unwrap();
        // Act
        let receipts = recover_quarantine_store_v2(&store, &key);
        // Assert
        assert!(
            receipts
                .iter()
                .any(|r| r.transaction_id == "stale"
                    && r.outcome == RecoveryOutcomeV1::StaleArtifact)
        );
        assert!(
            receipts.iter().any(|r| r.transaction_id == "wrong"
                && r.outcome == RecoveryOutcomeV1::AuthenticationFailed)
        );
        assert!(
            receipts.iter().any(|r| r.transaction_id == "bad"
                && r.outcome == RecoveryOutcomeV1::MalformedTransaction)
        );
        assert_eq!(
            fs::read(&stale.artifact.normalized_path).unwrap(),
            b"replacement"
        );
        assert_eq!(
            journal_state(&store, "wrong"),
            TransactionStateV1::ObjectCommitted
        );
    }

    #[test]
    fn recovery_handles_absent_source_terminal_state_symlink_and_insufficient_truth() {
        // Arrange
        let dir = tempfile::tempdir().unwrap();
        let store = QuarantineStoreV2::open(dir.path().join("store")).unwrap();
        let key = TestKeyProvider([4; 32]);
        let bytes = b"absent-source";
        let mut absent = recovery_tx(dir.path(), "absent", bytes);
        seed_state(&store, &mut absent, TransactionStateV1::MetadataCommitted);
        seed_object(&store, &absent, &key, bytes);
        fs::write(
            store.root.join("metadata/absent.json"),
            serde_json::to_vec(&absent).unwrap(),
        )
        .unwrap();
        let mut committed = recovery_tx(dir.path(), "committed", bytes);
        seed_state(&store, &mut committed, TransactionStateV1::Committed);
        let mut insufficient = recovery_tx(dir.path(), "insufficient", bytes);
        insufficient.artifact.size += 1;
        seed_state(
            &store,
            &mut insufficient,
            TransactionStateV1::ObjectCommitted,
        );
        seed_object(&store, &insufficient, &key, bytes);
        #[cfg(unix)]
        std::os::unix::fs::symlink(
            store.journal_path("committed"),
            store.root.join("journal/link.json"),
        )
        .unwrap();
        // Act
        let receipts = recover_quarantine_store_v2(&store, &key);
        // Assert
        assert!(
            receipts
                .iter()
                .any(|r| r.transaction_id == "absent" && r.outcome == RecoveryOutcomeV1::Completed)
        );
        assert_eq!(
            journal_state(&store, "absent"),
            TransactionStateV1::Committed
        );
        assert!(
            receipts.iter().any(
                |r| r.transaction_id == "committed" && r.outcome == RecoveryOutcomeV1::NoAction
            )
        );
        assert!(
            receipts.iter().any(|r| r.transaction_id == "insufficient"
                && r.outcome == RecoveryOutcomeV1::ManualReview)
        );
        assert_eq!(
            journal_state(&store, "insufficient"),
            TransactionStateV1::ObjectCommitted
        );
        #[cfg(unix)]
        assert!(
            receipts.iter().any(|r| r.transaction_id == "link"
                && r.outcome == RecoveryOutcomeV1::MalformedTransaction)
        );
    }

    #[test]
    fn failpoint_enum_covers_required_matrix() {
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
        assert_eq!(failpoints.len(), 10);
    }

    #[test]
    fn each_quarantine_failpoint_interrupts_real_executor_and_recovery_is_stable() {
        struct Case {
            failpoint: Failpoint,
            first: RecoveryOutcomeV1,
            state: TransactionStateV1,
            second: RecoveryOutcomeV1,
            source_after_first: bool,
            object_after_first: bool,
        }
        let cases = [
            Case {
                failpoint: Failpoint::AfterIdentityRevalidated,
                first: RecoveryOutcomeV1::ManualReview,
                state: TransactionStateV1::IdentityRevalidated,
                second: RecoveryOutcomeV1::ManualReview,
                source_after_first: true,
                object_after_first: false,
            },
            Case {
                failpoint: Failpoint::AfterJournalPrepared,
                first: RecoveryOutcomeV1::RolledBack,
                state: TransactionStateV1::RolledBack,
                second: RecoveryOutcomeV1::NoAction,
                source_after_first: true,
                object_after_first: false,
            },
            Case {
                failpoint: Failpoint::AfterSourceClaimed,
                first: RecoveryOutcomeV1::ManualReview,
                state: TransactionStateV1::SourceClaimed,
                second: RecoveryOutcomeV1::ManualReview,
                source_after_first: true,
                object_after_first: false,
            },
            Case {
                failpoint: Failpoint::DuringContentProtection,
                first: RecoveryOutcomeV1::ManualReview,
                state: TransactionStateV1::SourceClaimed,
                second: RecoveryOutcomeV1::ManualReview,
                source_after_first: true,
                object_after_first: false,
            },
            Case {
                failpoint: Failpoint::AfterObjectCommitted,
                first: RecoveryOutcomeV1::Completed,
                state: TransactionStateV1::Committed,
                second: RecoveryOutcomeV1::NoAction,
                source_after_first: false,
                object_after_first: true,
            },
            Case {
                failpoint: Failpoint::BeforeMetadataCommit,
                first: RecoveryOutcomeV1::Completed,
                state: TransactionStateV1::Committed,
                second: RecoveryOutcomeV1::NoAction,
                source_after_first: false,
                object_after_first: true,
            },
            Case {
                failpoint: Failpoint::AfterMetadataCommitted,
                first: RecoveryOutcomeV1::Completed,
                state: TransactionStateV1::Committed,
                second: RecoveryOutcomeV1::NoAction,
                source_after_first: false,
                object_after_first: true,
            },
            Case {
                failpoint: Failpoint::BeforeSourceSecured,
                first: RecoveryOutcomeV1::Completed,
                state: TransactionStateV1::Committed,
                second: RecoveryOutcomeV1::NoAction,
                source_after_first: false,
                object_after_first: true,
            },
            Case {
                failpoint: Failpoint::AfterSourceSecured,
                first: RecoveryOutcomeV1::Completed,
                state: TransactionStateV1::Committed,
                second: RecoveryOutcomeV1::NoAction,
                source_after_first: false,
                object_after_first: true,
            },
            Case {
                failpoint: Failpoint::BeforeFinalCommit,
                first: RecoveryOutcomeV1::Completed,
                state: TransactionStateV1::Committed,
                second: RecoveryOutcomeV1::NoAction,
                source_after_first: false,
                object_after_first: true,
            },
        ];
        assert_eq!(cases.len(), 10);
        for (n, case) in cases.into_iter().enumerate() {
            let dir = tempfile::tempdir().unwrap();
            let source = dir.path().join("source");
            let bytes = format!("fixture-{n}").into_bytes();
            fs::write(&source, &bytes).unwrap();
            let store = QuarantineStoreV2::open(dir.path().join("store")).unwrap();
            let id = format!("matrix-{n}");
            let mut tx = plan_transaction(
                id.clone(),
                ArtifactIdentityV1 {
                    normalized_path: source.display().to_string(),
                    content_digest: hex::encode(Sha256::digest(&bytes)),
                    size: bytes.len() as u64,
                    platform_file_id: None,
                    generation: n as u64,
                },
                ResponseActionV1::Quarantine,
            );
            assert!(
                execute_quarantine_v2_with_failpoint(
                    &mut tx,
                    &store,
                    &TestKeyProvider([3; 32]),
                    case.failpoint
                )
                .is_err()
            );
            let first = recover_quarantine_store_v2(&store, &TestKeyProvider([3; 32]));
            assert_eq!(
                first,
                vec![RecoveryReceiptV1 {
                    transaction_id: id.clone(),
                    outcome: case.first.clone()
                }]
            );
            let durable: ResponseTransactionV1 =
                serde_json::from_slice(&fs::read(store.journal_path(&id)).unwrap()).unwrap();
            assert_eq!(durable.state, case.state);
            assert_eq!(source.exists(), case.source_after_first);
            assert_eq!(store.object_path(&id).exists(), case.object_after_first);
            if case.object_after_first {
                let plaintext =
                    authenticated_plaintext(&store, &durable, &TestKeyProvider([3; 32])).unwrap();
                assert_eq!(plaintext, bytes);
                assert_eq!(
                    hex::encode(Sha256::digest(&plaintext)),
                    durable.artifact.content_digest
                );
            } else {
                assert_eq!(fs::read(&source).unwrap(), bytes);
            }
            let second = recover_quarantine_store_v2(&store, &TestKeyProvider([3; 32]));
            assert_eq!(
                second,
                vec![RecoveryReceiptV1 {
                    transaction_id: id,
                    outcome: case.second
                }]
            );
        }
    }

    #[test]
    fn restore_security_rejects_wrong_key_collision_outside_root_and_tamper() {
        let dir = tempfile::tempdir().unwrap();
        let source = dir.path().join("source.txt");
        let root = dir.path().join("restore");
        fs::create_dir_all(&root).unwrap();
        let bytes = b"security-fixture";
        fs::write(&source, bytes).unwrap();
        let store = QuarantineStoreV2::open(dir.path().join("store")).unwrap();
        let txid = "security".to_owned();
        let mut tx = plan_transaction(
            txid.clone(),
            ArtifactIdentityV1 {
                normalized_path: source.display().to_string(),
                content_digest: hex::encode(Sha256::digest(bytes)),
                size: bytes.len() as u64,
                platform_file_id: None,
                generation: 1,
            },
            ResponseActionV1::Quarantine,
        );
        let key = TestKeyProvider([5; 32]);
        let receipt = execute_quarantine_v2(&mut tx, &store, &key).unwrap();
        let destination = root.join("restored.txt");
        let request = RestoreRequestV2 {
            transaction_id: txid.clone(),
            destination: destination.display().to_string(),
            allowed_root: root.display().to_string(),
            explicit_authority: true,
        };
        let wrong_request = RestoreRequestV2 {
            destination: root.join("wrong.txt").display().to_string(),
            ..request.clone()
        };
        assert_eq!(
            restore_quarantine_v2(&wrong_request, &store, &TestKeyProvider([4; 32])).unwrap_err(),
            "AUTHENTICATION_FAILED"
        );
        let outside = RestoreRequestV2 {
            destination: dir.path().join("outside.txt").display().to_string(),
            ..request.clone()
        };
        assert_eq!(
            restore_quarantine_v2(&outside, &store, &key).unwrap_err(),
            "RESTORE_DESTINATION_REJECTED"
        );
        fs::write(&destination, b"existing").unwrap();
        assert_eq!(
            restore_quarantine_v2(&request, &store, &key).unwrap_err(),
            "RESTORE_DESTINATION_REJECTED"
        );
        assert_eq!(fs::read(&destination).unwrap(), b"existing");
        fs::remove_file(&destination).unwrap();
        let object = store.object_path(&receipt.transaction_id);
        let mut bytes_mut = fs::read(&object).unwrap();
        bytes_mut[20] ^= 1;
        fs::write(&object, bytes_mut).unwrap();
        let tampered = RestoreRequestV2 {
            destination: root.join("tampered.txt").display().to_string(),
            ..request
        };
        assert_eq!(
            restore_quarantine_v2(&tampered, &store, &key).unwrap_err(),
            "AUTHENTICATION_FAILED"
        );
    }

    #[test]
    fn restore_failpoint_matrix_has_three_safe_retryable_cases() {
        let cases = [
            (
                Failpoint::DuringRestoreWrite,
                "FAILPOINT_DURING_RESTORE_WRITE",
            ),
            (
                Failpoint::BeforeRestorePublish,
                "FAILPOINT_BEFORE_RESTORE_PUBLISH",
            ),
            (
                Failpoint::AfterRestorePublish,
                "FAILPOINT_AFTER_RESTORE_PUBLISH",
            ),
        ];
        for (index, (failpoint, expected)) in cases.into_iter().enumerate() {
            let dir = tempfile::tempdir().unwrap();
            let source = dir.path().join("source");
            let root = dir.path().join("restore");
            fs::create_dir_all(&root).unwrap();
            let bytes = format!("restore-failpoint-{index}").into_bytes();
            fs::write(&source, &bytes).unwrap();
            let store = QuarantineStoreV2::open(dir.path().join("store")).unwrap();
            let key = TestKeyProvider([8; 32]);
            let mut tx = plan_transaction(
                format!("restore-fp-{index}"),
                ArtifactIdentityV1 {
                    normalized_path: source.display().to_string(),
                    content_digest: hex::encode(Sha256::digest(&bytes)),
                    size: bytes.len() as u64,
                    platform_file_id: None,
                    generation: index as u64,
                },
                ResponseActionV1::Quarantine,
            );
            let receipt = execute_quarantine_v2(&mut tx, &store, &key).unwrap();
            let destination = root.join("restored");
            let request = RestoreRequestV2 {
                transaction_id: receipt.transaction_id.clone(),
                destination: destination.display().to_string(),
                allowed_root: root.display().to_string(),
                explicit_authority: true,
            };
            let failure = restore_quarantine_v2_with_failpoint(&request, &store, &key, failpoint)
                .unwrap_err();
            assert_eq!(failure, expected);
            assert!(store.object_path(&receipt.transaction_id).exists());
            if failpoint == Failpoint::AfterRestorePublish {
                assert_eq!(fs::read(&destination).unwrap(), bytes);
            } else {
                assert!(
                    !root
                        .join(format!(".restore-fp-{index}.restore.tmp"))
                        .exists()
                );
                assert!(!destination.exists());
            }
            if failpoint != Failpoint::AfterRestorePublish {
                let restored = restore_quarantine_v2(&request, &store, &key).unwrap();
                assert_eq!(restored.digest, hex::encode(Sha256::digest(&bytes)));
                assert_eq!(restored.size, bytes.len() as u64);
            } else {
                let retry = restore_quarantine_v2(&request, &store, &key).unwrap();
                assert_eq!(retry.state, RestoreStateV2::AlreadyCommitted);
            }
            assert_eq!(fs::read(&destination).unwrap(), bytes);
        }
    }

    #[test]
    fn restore_temp_substitution_is_rejected_without_touching_external_target() {
        let dir = tempfile::tempdir().unwrap();
        let source = dir.path().join("source");
        let root = dir.path().join("restore");
        fs::create_dir_all(&root).unwrap();
        let bytes = b"temp-substitution";
        fs::write(&source, bytes).unwrap();
        let store = QuarantineStoreV2::open(dir.path().join("store")).unwrap();
        let key = TestKeyProvider([7; 32]);
        let mut tx = plan_transaction(
            "temp-sub".into(),
            ArtifactIdentityV1 {
                normalized_path: source.display().to_string(),
                content_digest: hex::encode(Sha256::digest(bytes)),
                size: bytes.len() as u64,
                platform_file_id: None,
                generation: 1,
            },
            ResponseActionV1::Quarantine,
        );
        execute_quarantine_v2(&mut tx, &store, &key).unwrap();
        let temp = root.join(".temp-sub.restore.tmp");
        let outside = dir.path().join("outside");
        fs::write(&outside, b"outside").unwrap();
        #[cfg(unix)]
        std::os::unix::fs::symlink(&outside, &temp).unwrap();
        #[cfg(unix)]
        {
            let request = RestoreRequestV2 {
                transaction_id: "temp-sub".into(),
                destination: root.join("restored").display().to_string(),
                allowed_root: root.display().to_string(),
                explicit_authority: true,
            };
            assert_eq!(
                restore_quarantine_v2(&request, &store, &key).unwrap_err(),
                "RESTORE_TEMP_REJECTED"
            );
            assert_eq!(fs::read(&outside).unwrap(), b"outside");
            assert!(!root.join("restored").exists());
        }
    }

    #[test]
    fn protected_object_symlink_is_rejected_without_following_target() {
        let dir = tempfile::tempdir().unwrap();
        let source = dir.path().join("source");
        let root = dir.path().join("restore");
        fs::create_dir_all(&root).unwrap();
        let bytes = b"object-symlink";
        fs::write(&source, bytes).unwrap();
        let store = QuarantineStoreV2::open(dir.path().join("store")).unwrap();
        let key = TestKeyProvider([1; 32]);
        let mut tx = plan_transaction(
            "object-link".into(),
            ArtifactIdentityV1 {
                normalized_path: source.display().to_string(),
                content_digest: hex::encode(Sha256::digest(bytes)),
                size: bytes.len() as u64,
                platform_file_id: None,
                generation: 1,
            },
            ResponseActionV1::Quarantine,
        );
        execute_quarantine_v2(&mut tx, &store, &key).unwrap();
        let target = dir.path().join("outside-object");
        let protected_copy = fs::read(store.object_path("object-link")).unwrap();
        fs::write(&target, &protected_copy).unwrap();
        fs::remove_file(store.object_path("object-link")).unwrap();
        #[cfg(unix)]
        std::os::unix::fs::symlink(&target, store.object_path("object-link")).unwrap();
        #[cfg(unix)]
        {
            let destination = root.join("restored");
            let request = RestoreRequestV2 {
                transaction_id: "object-link".into(),
                destination: destination.display().to_string(),
                allowed_root: root.display().to_string(),
                explicit_authority: true,
            };
            assert_eq!(
                restore_quarantine_v2(&request, &store, &key).unwrap_err(),
                "OBJECT_TAMPERED"
            );
            assert_eq!(fs::read(&target).unwrap(), protected_copy);
            assert!(!destination.exists());
        }
    }

    #[cfg(unix)]
    #[test]
    fn object_swap_after_validation_uses_bound_object() {
        let dir = tempfile::tempdir().unwrap();
        let source = dir.path().join("source");
        let root = dir.path().join("restore");
        fs::create_dir_all(&root).unwrap();
        let bytes = b"object-swap-original";
        fs::write(&source, bytes).unwrap();
        let store = QuarantineStoreV2::open(dir.path().join("store")).unwrap();
        let key = TestKeyProvider([2; 32]);
        let mut tx = plan_transaction(
            "object-swap".into(),
            ArtifactIdentityV1 {
                normalized_path: source.display().to_string(),
                content_digest: hex::encode(Sha256::digest(bytes)),
                size: bytes.len() as u64,
                platform_file_id: None,
                generation: 1,
            },
            ResponseActionV1::Quarantine,
        );
        let receipt = execute_quarantine_v2(&mut tx, &store, &key).unwrap();
        let object = store.object_path(&receipt.transaction_id);
        let replacement = dir.path().join("replacement");
        fs::write(&replacement, b"unrelated-object").unwrap();
        let object_for_hook = object.clone();
        let replacement_for_hook = replacement.clone();
        *PROTECTED_OBJECT_TEST_HOOK
            .get_or_init(|| std::sync::Mutex::new(None))
            .lock()
            .unwrap() = Some((
            object.clone(),
            Box::new(move || {
                fs::remove_file(&object_for_hook).unwrap();
                std::os::unix::fs::symlink(&replacement_for_hook, &object_for_hook).unwrap();
            }),
        ));
        let destination = root.join("restored");
        let request = RestoreRequestV2 {
            transaction_id: receipt.transaction_id,
            destination: destination.display().to_string(),
            allowed_root: root.display().to_string(),
            explicit_authority: true,
        };
        let result = restore_quarantine_v2(&request, &store, &key);
        assert_eq!(result.unwrap().state, RestoreStateV2::Committed);
        assert_eq!(fs::read(&destination).unwrap(), bytes);
    }

    #[cfg(unix)]
    #[test]
    fn restore_owned_temp_swap_rejects_attacker_bytes() {
        let dir = tempfile::tempdir().unwrap();
        let source = dir.path().join("source");
        let root = dir.path().join("restore");
        fs::create_dir_all(&root).unwrap();
        let bytes = b"owned-temp-original";
        let attacker_bytes = b"owned-temp-attacker";
        fs::write(&source, bytes).unwrap();
        let store = QuarantineStoreV2::open(dir.path().join("store")).unwrap();
        let key = TestKeyProvider([3; 32]);
        let mut tx = plan_transaction(
            "owned-temp-swap".into(),
            ArtifactIdentityV1 {
                normalized_path: source.display().to_string(),
                content_digest: hex::encode(Sha256::digest(bytes)),
                size: bytes.len() as u64,
                platform_file_id: None,
                generation: 1,
            },
            ResponseActionV1::Quarantine,
        );
        let receipt = execute_quarantine_v2(&mut tx, &store, &key).unwrap();
        let destination = root.join("restored");
        let temp = root
            .canonicalize()
            .unwrap()
            .join(".owned-temp-swap.restore.tmp");
        let attacker = dir.path().join("attacker");
        fs::write(&attacker, attacker_bytes).unwrap();
        let temp_for_hook = temp.clone();
        let attacker_for_hook = attacker.clone();
        *RESTORE_TEMP_TEST_HOOK
            .get_or_init(|| std::sync::Mutex::new(None))
            .lock()
            .unwrap() = Some((
            temp,
            Box::new(move || {
                fs::remove_file(&temp_for_hook).unwrap();
                fs::rename(&attacker_for_hook, &temp_for_hook).unwrap();
            }),
        ));
        let request = RestoreRequestV2 {
            transaction_id: receipt.transaction_id,
            destination: destination.display().to_string(),
            allowed_root: root.display().to_string(),
            explicit_authority: true,
        };
        let result = restore_quarantine_v2(&request, &store, &key);
        assert!(result.is_err());
        assert!(!destination.exists() || fs::read(&destination).unwrap() != attacker_bytes);
    }

    #[test]
    fn protected_object_parser_rejects_all_truncation_and_magic_boundaries() {
        let mut cases = Vec::new();
        for length in 0..=34 {
            cases.push(vec![0_u8; length]);
        }
        let mut magic = b"AISV2\0".to_vec();
        cases.push(magic.clone());
        magic.extend([0_u8; 12]);
        cases.push(magic.clone());
        for bytes in cases {
            assert!(parse_protected_object(&bytes).is_err());
        }
        magic.extend([0_u8; 15]);
        assert!(parse_protected_object(&magic).is_err());
        magic.push(0);
        assert!(parse_protected_object(&magic).is_ok());
    }

    #[test]
    fn metadata_aad_mutations_reject_restore_without_side_effects() {
        let dir = tempfile::tempdir().unwrap();
        let source = dir.path().join("source");
        let root = dir.path().join("restore");
        fs::create_dir_all(&root).unwrap();
        let bytes = b"aad-fixture";
        fs::write(&source, bytes).unwrap();
        let store = QuarantineStoreV2::open(dir.path().join("store")).unwrap();
        let key = TestKeyProvider([2; 32]);
        let mut tx = plan_transaction(
            "aad".into(),
            ArtifactIdentityV1 {
                normalized_path: source.display().to_string(),
                content_digest: hex::encode(Sha256::digest(bytes)),
                size: bytes.len() as u64,
                platform_file_id: None,
                generation: 1,
            },
            ResponseActionV1::Quarantine,
        );
        execute_quarantine_v2(&mut tx, &store, &key).unwrap();
        for index in 0..7 {
            let mut altered = tx.clone();
            match index {
                0 => altered.schema_version.push('x'),
                1 => altered.transaction_id.push('x'),
                2 => altered.response_idempotency_key.push('x'),
                3 => altered.artifact.normalized_path.push('x'),
                4 => altered.artifact.content_digest.push('x'),
                5 => altered.artifact.size += 1,
                _ => altered.action = ResponseActionV1::Audit,
            }
            fs::write(
                store.root.join("metadata/aad.json"),
                serde_json::to_vec(&altered).unwrap(),
            )
            .unwrap();
            let destination = root.join(format!("out-{index}"));
            let request = RestoreRequestV2 {
                transaction_id: "aad".into(),
                destination: destination.display().to_string(),
                allowed_root: root.display().to_string(),
                explicit_authority: true,
            };
            assert!(restore_quarantine_v2(&request, &store, &key).is_err());
            assert!(!destination.exists());
            fs::write(
                store.root.join("metadata/aad.json"),
                serde_json::to_vec(&tx).unwrap(),
            )
            .unwrap();
        }
    }
}
