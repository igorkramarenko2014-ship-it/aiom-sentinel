use sentinel_product_dto::DTO_SCHEMA_VERSION;
use sentinel_core::{DEFAULT_MAX_FILE_BYTES, HARD_MAX_FILE_BYTES};
use sentinel_product_dto::{ApplicationErrorV1, CanonicalReceiptV1, FolderManifestReceiptV1, FolderProgressV1, FolderScanRuntimeDiagnosticsV1, RulePackBindingV1, ScanFileRequestV1, ScanResultV1};
use sentinel_product_service::{build_receipt_v1, receipt_bytes, scan_file_v1, scan_folder_with_control, FolderProgressSink};
use sentinel_product_service::container::{inspect_tar, inspect_zip, ContainerLimits};
use sentinel_product_service::quarantine::{default_root, load_records, persist_records, quarantine_file, restore_file, QuarantineRecord};
use serde::Serialize;
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::{path::PathBuf, sync::{Arc, Mutex, atomic::{AtomicBool, Ordering}}};
use tauri_plugin_dialog::DialogExt;
use tauri::{Manager, Emitter};

struct SelectedFile { id: String, canonical_path: PathBuf, size_bytes: u64, digest: String }
struct ActiveFolderScan { request_id: String, cancellation_token: Arc<AtomicBool>, latest_progress: Option<FolderProgressV1>, cancellation_requested: bool, terminal_emitted: bool, diagnostics: FolderScanRuntimeDiagnosticsV1 }
struct AppState { selected: Mutex<Option<SelectedFile>>, selected_folder: Mutex<Option<(String, PathBuf)>>, receipt: Mutex<Option<CanonicalReceiptV1>>, folder_receipt: Mutex<Option<FolderManifestReceiptV1>>, active_scan: Arc<Mutex<Option<ActiveFolderScan>>>, quarantine: Mutex<Vec<QuarantineRecord>> }
struct TauriProgressSink(tauri::AppHandle, Arc<Mutex<Option<ActiveFolderScan>>>);
impl FolderProgressSink for TauriProgressSink { fn emit(&self, progress: FolderProgressV1) -> Result<(), String> { let result = self.0.emit("sentinel://folder-progress-v1", progress.clone()).map_err(|e| e.to_string()); if let Ok(mut active) = self.1.lock() { if let Some(scan) = active.as_mut() { if scan.request_id == progress.request_id && !scan.terminal_emitted { scan.latest_progress = Some(progress.clone()); scan.cancellation_requested = progress.cancellation_requested; scan.terminal_emitted = progress.terminal; if let Err(error) = &result { scan.diagnostics.progress_delivery_error_count += 1; scan.diagnostics.last_progress_delivery_error = Some(error.clone()); scan.diagnostics.terminal_progress_delivery_failed |= progress.terminal; } } } } result } }

#[derive(Serialize)]
struct ProductStatus {
    application_version: &'static str,
    dto_schema_version: &'static str,
    core_available: bool,
    service_available: bool,
    release_status: &'static str,
    max_file_bytes: u64,
    hard_max_file_bytes: u64,
}

#[tauri::command]
fn get_product_status_v1() -> ProductStatus {
    ProductStatus {
        application_version: env!("CARGO_PKG_VERSION"),
        dto_schema_version: DTO_SCHEMA_VERSION,
        core_available: true,
        service_available: true,
        release_status: "development",
        max_file_bytes: DEFAULT_MAX_FILE_BYTES,
        hard_max_file_bytes: HARD_MAX_FILE_BYTES,
    }
}

#[derive(Serialize)]
struct Selection { selection_id: String, display_name: String, size_bytes: u64 }

#[tauri::command]
async fn select_folder_v1(app: tauri::AppHandle, state: tauri::State<'_, AppState>) -> Result<Option<Selection>, ApplicationErrorV1> {
    let (sender, receiver) = tokio::sync::oneshot::channel();
    app.dialog().file().pick_folder(move |path| { let _ = sender.send(path); });
    let Some(path) = receiver.await.map_err(|_| ApplicationErrorV1 { code: "FOLDER_SELECTION_FAILED".into(), message: "Folder picker closed unexpectedly".into(), path: None, retryable: false })? else { return Ok(None); };
    let path = path.into_path().map_err(|e| ApplicationErrorV1 { code: "FOLDER_SELECTION_FAILED".into(), message: e.to_string(), path: None, retryable: false })?;
    let canonical = tokio::task::spawn_blocking(move || path.canonicalize()).await.map_err(|e| ApplicationErrorV1 { code: "FOLDER_SELECTION_FAILED".into(), message: e.to_string(), path: None, retryable: false })?.map_err(|e| ApplicationErrorV1 { code: "FOLDER_SELECTION_FAILED".into(), message: e.to_string(), path: None, retryable: false })?;
    let metadata = std::fs::symlink_metadata(&canonical).map_err(|e| ApplicationErrorV1 { code: "FOLDER_SELECTION_FAILED".into(), message: e.to_string(), path: None, retryable: false })?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() { return Err(ApplicationErrorV1 { code: "FOLDER_NOT_REGULAR".into(), message: "Only regular non-symlink folders are accepted".into(), path: None, retryable: false }); }
    let id = uuid::Uuid::new_v4().to_string();
    let display_name = canonical.file_name().unwrap_or_default().to_string_lossy().into_owned();
    *state.selected_folder.lock().unwrap() = Some((id.clone(), canonical));
    Ok(Some(Selection { selection_id: id, display_name, size_bytes: 0 }))
}

#[tauri::command]
async fn select_file_v1(app: tauri::AppHandle, state: tauri::State<'_, AppState>) -> Result<Option<Selection>, ApplicationErrorV1> {
    let (sender, receiver) = tokio::sync::oneshot::channel();
    app.dialog().file().pick_file(move |path| { let _ = sender.send(path); });
    let Some(path) = receiver.await.map_err(|_| ApplicationErrorV1 { code: "FILE_SELECTION_FAILED".into(), message: "File picker closed unexpectedly".into(), path: None, retryable: false })? else { return Ok(None); };
    let path = path.into_path().map_err(|e| ApplicationErrorV1 { code: "FILE_SELECTION_FAILED".into(), message: e.to_string(), path: None, retryable: false })?;
    if let Ok(metadata) = std::fs::metadata(&path) { let _ = app.emit("sentinel://file-preparation-v1", serde_json::json!({"phase":"PREPARING","display_name":path.file_name().unwrap_or_default().to_string_lossy(),"size_bytes":metadata.len(),"bytes_processed":null,"total_bytes":metadata.len(),"message":"Reading bytes and calculating SHA-256…"})); }
    let prepared = tokio::task::spawn_blocking(move || -> Result<(PathBuf, u64, String, String), ApplicationErrorV1> {
    let metadata = std::fs::symlink_metadata(&path).map_err(|e| ApplicationErrorV1 { code: "FILE_SELECTION_FAILED".into(), message: e.to_string(), path: None, retryable: false })?;
    if !metadata.is_file() || metadata.file_type().is_symlink() { return Err(ApplicationErrorV1 { code: "FILE_NOT_REGULAR".into(), message: "Only regular non-symlink files are accepted".into(), path: None, retryable: false }); }
    let canonical_path = path.canonicalize().map_err(|e| ApplicationErrorV1 { code: "FILE_SELECTION_FAILED".into(), message: e.to_string(), path: None, retryable: false })?;
    let digest = hex::encode(Sha256::digest(std::fs::read(&canonical_path).map_err(|e| ApplicationErrorV1 { code: "FILE_SELECTION_FAILED".into(), message: e.to_string(), path: None, retryable: false })?));
    Ok((canonical_path, metadata.len(), digest, path.file_name().unwrap_or_default().to_string_lossy().into_owned()))
    }).await.map_err(|e| ApplicationErrorV1 { code: "FILE_SELECTION_FAILED".into(), message: e.to_string(), path: None, retryable: false })??;
    let (canonical_path, size_bytes, digest, display_name) = prepared;
    let id = uuid::Uuid::new_v4().to_string();
    let selection = Selection { selection_id: id.clone(), display_name, size_bytes };
    *state.selected.lock().unwrap() = Some(SelectedFile { id, canonical_path, size_bytes, digest });
    Ok(Some(selection))
}

fn default_rule_binding(app: &tauri::AppHandle) -> Result<RulePackBindingV1, ApplicationErrorV1> {
    let resource_dir = app.path().resource_dir().map_err(|e| ApplicationErrorV1 { code: "RULE_PACK_UNAVAILABLE".into(), message: e.to_string(), path: None, retryable: false })?;
    let source = resource_dir.join("rules/sentinel-default.rules");
    let sidecar = resource_dir.join("rules/sentinel-default.rules.sha256");
    let bytes = std::fs::read(&source).map_err(|e| ApplicationErrorV1 { code: "RULE_PACK_UNAVAILABLE".into(), message: e.to_string(), path: None, retryable: false })?;
    let digest = hex::encode(Sha256::digest(&bytes));
    let declared = std::fs::read_to_string(&sidecar).map_err(|e| ApplicationErrorV1 { code: "RULE_PACK_UNAVAILABLE".into(), message: e.to_string(), path: None, retryable: false })?.trim().to_owned();
    if declared.len() != 64 || !declared.chars().all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()) { return Err(ApplicationErrorV1 { code: "RULE_PACK_DIGEST_INVALID".into(), message: "Rule-pack sidecar digest is not lowercase SHA-256".into(), path: None, retryable: false }); }
    if declared != digest { return Err(ApplicationErrorV1 { code: "RULE_PACK_IDENTITY_MISMATCH".into(), message: "Bundled rule-pack digest mismatch".into(), path: None, retryable: false }); }
    Ok(RulePackBindingV1 { pack_id: "sentinel-default".into(), expected_bytes_sha256: digest, source_path: source.to_string_lossy().into_owned() })
}

async fn experimental_yara(path: PathBuf) -> Option<Value> {
    if let (Some(script), Some(registry)) = (std::env::var_os("AIOM_SENTINEL_YARA_MULTI_SCRIPT"), std::env::var_os("AIOM_SENTINEL_YARA_PACKS_JSON")) {
        let python = std::env::var_os("AIOM_SENTINEL_YARA_PYTHON")?;
        return tokio::task::spawn_blocking(move || {
            let output = std::process::Command::new(python).args([script.to_string_lossy().as_ref(), registry.to_string_lossy().as_ref(), path.to_string_lossy().as_ref()]).output().ok()?;
            serde_json::from_slice(&output.stdout).ok()
        }).await.ok().flatten();
    }
    let python = std::env::var_os("AIOM_SENTINEL_YARA_PYTHON")?;
    let pack = std::env::var_os("AIOM_SENTINEL_YARA_PACK")?;
    if std::env::var("AIOM_SENTINEL_YARA_ENABLED").ok().as_deref() != Some("1") { return None; }
    tokio::task::spawn_blocking(move || {
        let loader = PathBuf::from(pack).join("loader/yara_loader.py");
        let output = std::process::Command::new(python).args([loader.to_string_lossy().as_ref(), "--categories", "capabilities", "--path", path.to_string_lossy().as_ref(), "--json"]).output().ok()?;
        serde_json::from_slice(&output.stdout).ok()
    }).await.ok().flatten()
}

#[tauri::command]
async fn scan_selected_file_v1(app: tauri::AppHandle, selection_id: String, state: tauri::State<'_, AppState>) -> Result<CanonicalReceiptV1, ApplicationErrorV1> {
    let selected = state.selected.lock().unwrap().as_ref().filter(|s| s.id == selection_id).map(|s| (s.canonical_path.clone(), s.size_bytes, s.digest.clone())).ok_or_else(|| ApplicationErrorV1 { code: "SELECTION_NOT_FOUND".into(), message: "Unknown selection id".into(), path: None, retryable: false })?;
    let metadata = std::fs::metadata(&selected.0).map_err(|e| ApplicationErrorV1 { code: "FILE_CHANGED_SINCE_SELECTION".into(), message: e.to_string(), path: None, retryable: false })?;
    let current = hex::encode(Sha256::digest(std::fs::read(&selected.0).map_err(|e| ApplicationErrorV1 { code: "FILE_CHANGED_SINCE_SELECTION".into(), message: e.to_string(), path: None, retryable: false })?));
    if metadata.len() != selected.1 || current != selected.2 { return Err(ApplicationErrorV1 { code: "FILE_CHANGED_SINCE_SELECTION".into(), message: "Selected file changed before scan".into(), path: None, retryable: false }); }
    let binding = default_rule_binding(&app)?;
    let request = ScanFileRequestV1 { request_id: uuid::Uuid::new_v4().to_string(), target_path: selected.0.to_string_lossy().into_owned(), rule_pack: binding };
    let mut result: ScanResultV1 = scan_file_v1(request).await?;
    result.yara = experimental_yara(selected.0.clone()).await;
    let receipt = build_receipt_v1(result).map_err(|e| ApplicationErrorV1 { code: "RECEIPT_SERIALIZATION_FAILED".into(), message: e.to_string(), path: None, retryable: false })?;
    *state.receipt.lock().unwrap() = Some(receipt.clone());
    Ok(receipt)
}

#[tauri::command]
async fn scan_selected_file_yara_v1(selection_id: String, state: tauri::State<'_, AppState>) -> Result<Value, ApplicationErrorV1> {
    if std::env::var("AIOM_SENTINEL_YARA_ENABLED").ok().as_deref() != Some("1") {
        return Ok(serde_json::json!({"status":"UNAVAILABLE","errors":[{"code":"YARA_DISABLED","message":"Experimental YARA is disabled"}]}));
    }
    let path = state.selected.lock().unwrap().as_ref().filter(|selected| selected.id == selection_id).map(|selected| selected.canonical_path.clone()).ok_or_else(|| ApplicationErrorV1 { code: "SELECTION_NOT_FOUND".into(), message: "Unknown selection id".into(), path: None, retryable: false })?;
    Ok(experimental_yara(path).await.unwrap_or_else(|| serde_json::json!({"status":"UNAVAILABLE","errors":[{"code":"YARA_UNAVAILABLE","message":"YARA sidecar did not return a receipt"}]})))
}

#[tauri::command]
async fn inspect_selected_container_v1(selection_id: String, state: tauri::State<'_, AppState>) -> Result<Value, ApplicationErrorV1> {
    let path = state.selected.lock().unwrap().as_ref().filter(|selected| selected.id == selection_id).map(|selected| selected.canonical_path.clone()).ok_or_else(|| ApplicationErrorV1 { code: "SELECTION_NOT_FOUND".into(), message: "Unknown selection id".into(), path: None, retryable: false })?;
    let limits = ContainerLimits::default();
    let result = tokio::task::spawn_blocking(move || {
        let kind = std::fs::read(&path).ok().map(|b| if b.starts_with(b"PK\x03\x04") { "ZIP" } else { "TAR" });
        match kind { Some("ZIP") => inspect_zip(&path, &limits).map(|r| serde_json::to_value(r).unwrap_or(Value::Null)), Some("TAR") => inspect_tar(&path, &limits).map(|r| serde_json::to_value(r).unwrap_or(Value::Null)), _ => Ok(serde_json::json!({"state":"UNSUPPORTED","container_type":"UNKNOWN","errors":["unsupported container format"]})) }
    }).await.map_err(|e| ApplicationErrorV1 { code: "CONTAINER_INSPECTION_FAILED".into(), message: e.to_string(), path: None, retryable: false })?.map_err(|e| ApplicationErrorV1 { code: "CONTAINER_INSPECTION_FAILED".into(), message: e.to_string(), path: None, retryable: false })?;
    Ok(result)
}

#[tauri::command]
fn quarantine_selected_v1(selection_id: String, confirm: bool, state: tauri::State<'_, AppState>) -> Result<Value, ApplicationErrorV1> {
    if !confirm { return Err(ApplicationErrorV1 { code: "QUARANTINE_CONFIRMATION_REQUIRED".into(), message: "Explicit confirmation is required".into(), path: None, retryable: false }); }
    let selected = state.selected.lock().unwrap().as_ref().filter(|s| s.id == selection_id).map(|s| s.canonical_path.clone()).ok_or_else(|| ApplicationErrorV1 { code: "SELECTION_NOT_FOUND".into(), message: "Unknown selection id".into(), path: None, retryable: false })?;
    let root = default_root();
    let id = uuid::Uuid::new_v4().to_string();
    let record = quarantine_file(&selected, &root, &id).map_err(|e| ApplicationErrorV1 { code: "QUARANTINE_FAILED".into(), message: e.to_string(), path: None, retryable: false })?;
    let value = serde_json::to_value(&record).map_err(|e| ApplicationErrorV1 { code: "QUARANTINE_SERIALIZATION_FAILED".into(), message: e.to_string(), path: None, retryable: false })?;
    state.quarantine.lock().unwrap().push(record);
    let records = state.quarantine.lock().unwrap().clone();
    persist_records(&root, &records).map_err(|e| ApplicationErrorV1 { code: "QUARANTINE_INDEX_WRITE_FAILED".into(), message: e.to_string(), path: None, retryable: true })?;
    Ok(value)
}

#[tauri::command]
fn restore_quarantine_v1(id: String, state: tauri::State<'_, AppState>) -> Result<(), ApplicationErrorV1> {
    let mut records = state.quarantine.lock().unwrap();
    let index = records.iter().position(|r| r.id == id).ok_or_else(|| ApplicationErrorV1 { code: "QUARANTINE_RECORD_NOT_FOUND".into(), message: "Unknown quarantine record".into(), path: None, retryable: false })?;
    restore_file(&records[index]).map_err(|e| ApplicationErrorV1 { code: "QUARANTINE_RESTORE_FAILED".into(), message: e.to_string(), path: None, retryable: false })?;
    records.remove(index);
    persist_records(&default_root(), &records).map_err(|e| ApplicationErrorV1 { code: "QUARANTINE_INDEX_WRITE_FAILED".into(), message: e.to_string(), path: None, retryable: true })?;
    Ok(())
}

#[tauri::command]
async fn scan_selected_folder_v1(app: tauri::AppHandle, request_id: String, selection_id: String, state: tauri::State<'_, AppState>) -> Result<FolderManifestReceiptV1, ApplicationErrorV1> {
    let root = state.selected_folder.lock().unwrap().as_ref().filter(|(id, _)| id == &selection_id).map(|(_, path)| path.clone()).ok_or_else(|| ApplicationErrorV1 { code: "FOLDER_SELECTION_NOT_FOUND".into(), message: "Unknown folder selection id".into(), path: None, retryable: false })?;
    if request_id.trim().is_empty() || request_id.len() > 128 { return Err(ApplicationErrorV1 { code: "INVALID_REQUEST_ID".into(), message: "Folder request id must be bounded and non-empty".into(), path: None, retryable: false }); }
    let cancel = Arc::new(AtomicBool::new(false));
    { let mut active = state.active_scan.lock().unwrap(); if active.is_some() { return Err(ApplicationErrorV1 { code: "FOLDER_SCAN_ALREADY_ACTIVE".into(), message: "A folder scan is already active".into(), path: None, retryable: true }); } *active = Some(ActiveFolderScan { request_id: request_id.clone(), cancellation_token: cancel.clone(), latest_progress: None, cancellation_requested: false, terminal_emitted: false, diagnostics: FolderScanRuntimeDiagnosticsV1::default() }); }
    let receipt = scan_folder_with_control(root, request_id.clone(), default_rule_binding(&app)?, Arc::new(TauriProgressSink(app.clone(), state.active_scan.clone())), cancel).await;
    state.active_scan.lock().unwrap().take();
    let receipt = receipt?;
    *state.folder_receipt.lock().unwrap() = Some(receipt.clone());
    Ok(receipt)
}

#[tauri::command]
fn cancel_folder_scan_v1(request_id: String, app: tauri::AppHandle, state: tauri::State<'_, AppState>) -> Result<(), ApplicationErrorV1> {
    let mut active = state.active_scan.lock().unwrap();
    let Some(scan) = active.as_mut() else { return Err(ApplicationErrorV1 { code: "NO_ACTIVE_FOLDER_SCAN".into(), message: "No active folder scan".into(), path: None, retryable: false }); };
    if scan.request_id != request_id { return Err(ApplicationErrorV1 { code: "CANCEL_REQUEST_ID_MISMATCH".into(), message: "Cancellation request does not match the active scan".into(), path: None, retryable: false }); }
    if !scan.cancellation_requested { scan.cancellation_token.store(true, Ordering::SeqCst); }
    drop(active);
    let _ = app;
    Ok(())
}

#[tauri::command]
fn reset_active_case_v1(state: tauri::State<'_, AppState>) -> Result<(), ApplicationErrorV1> {
    if state.active_scan.lock().unwrap().is_some() { return Err(ApplicationErrorV1 { code: "ACTIVE_SCAN_IN_PROGRESS".into(), message: "Cancel the active folder scan before resetting the case".into(), path: None, retryable: true }); }
    *state.selected.lock().unwrap() = None;
    *state.selected_folder.lock().unwrap() = None;
    *state.receipt.lock().unwrap() = None;
    *state.folder_receipt.lock().unwrap() = None;
    Ok(())
}

#[derive(Serialize)]
struct ExportedReceipt { written_path: String, bytes: usize, sha256: String }

#[tauri::command]
async fn export_receipt_v1(app: tauri::AppHandle, state: tauri::State<'_, AppState>) -> Result<Option<ExportedReceipt>, ApplicationErrorV1> {
    let bytes = if let Some(receipt) = state.receipt.lock().unwrap().clone() { receipt_bytes(&receipt).map_err(|e| ApplicationErrorV1 { code: "RECEIPT_SERIALIZATION_FAILED".into(), message: e.to_string(), path: None, retryable: false })? } else if let Some(receipt) = state.folder_receipt.lock().unwrap().clone() { serde_json::to_vec(&receipt).map_err(|e| ApplicationErrorV1 { code: "RECEIPT_SERIALIZATION_FAILED".into(), message: e.to_string(), path: None, retryable: false })? } else { return Err(ApplicationErrorV1 { code: "RECEIPT_NOT_FOUND".into(), message: "Build evidence before exporting".into(), path: None, retryable: false }); };
    let (sender, receiver) = tokio::sync::oneshot::channel();
    app.dialog().file().set_file_name("aiom-sentinel-receipt.json").save_file(move |path| { let _ = sender.send(path); });
    let Some(path) = receiver.await.map_err(|_| ApplicationErrorV1 { code: "RECEIPT_EXPORT_FAILED".into(), message: "Save dialog closed unexpectedly".into(), path: None, retryable: false })? else { return Ok(None); };
    let path = path.into_path().map_err(|e| ApplicationErrorV1 { code: "RECEIPT_EXPORT_FAILED".into(), message: e.to_string(), path: None, retryable: false })?;
    let path_for_write = path.clone();
    let bytes_for_write = bytes.clone();
    tokio::task::spawn_blocking(move || std::fs::write(&path_for_write, &bytes_for_write)).await.map_err(|e| ApplicationErrorV1 { code: "RECEIPT_EXPORT_FAILED".into(), message: e.to_string(), path: None, retryable: false })?.map_err(|e| ApplicationErrorV1 { code: "RECEIPT_EXPORT_FAILED".into(), message: e.to_string(), path: None, retryable: false })?;
    Ok(Some(ExportedReceipt { written_path: path.to_string_lossy().into_owned(), bytes: bytes.len(), sha256: hex::encode(Sha256::digest(&bytes)) }))
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .manage(AppState { selected: Mutex::new(None), selected_folder: Mutex::new(None), receipt: Mutex::new(None), folder_receipt: Mutex::new(None), active_scan: Arc::new(Mutex::new(None)), quarantine: Mutex::new(load_records(&default_root())) })
        .invoke_handler(tauri::generate_handler![get_product_status_v1, select_file_v1, select_folder_v1, scan_selected_file_v1, scan_selected_file_yara_v1, inspect_selected_container_v1, quarantine_selected_v1, restore_quarantine_v1, scan_selected_folder_v1, cancel_folder_scan_v1, reset_active_case_v1, export_receipt_v1])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
