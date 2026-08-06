use sentinel_product_dto::DTO_SCHEMA_VERSION;
use sentinel_core::{DEFAULT_MAX_FILE_BYTES, HARD_MAX_FILE_BYTES};
use sentinel_product_dto::{ApplicationErrorV1, CanonicalReceiptV1, FolderManifestReceiptV1, FolderProgressV1, FolderScanRuntimeDiagnosticsV1, RulePackBindingV1, ScanFileRequestV1, ScanResultV1};
use sentinel_product_service::{build_receipt_v1, receipt_bytes, scan_file_v1, scan_folder_with_control, FolderProgressSink};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::{path::PathBuf, sync::{Arc, Mutex, atomic::{AtomicBool, Ordering}}};
use tauri_plugin_dialog::DialogExt;
use tauri::{Manager, Emitter};

struct SelectedFile { id: String, canonical_path: PathBuf, size_bytes: u64, digest: String }
struct ActiveFolderScan { request_id: String, cancellation_token: Arc<AtomicBool>, latest_progress: Option<FolderProgressV1>, cancellation_requested: bool, terminal_emitted: bool, diagnostics: FolderScanRuntimeDiagnosticsV1 }
struct AppState { selected: Mutex<Option<SelectedFile>>, selected_folder: Mutex<Option<(String, PathBuf)>>, receipt: Mutex<Option<CanonicalReceiptV1>>, folder_receipt: Mutex<Option<FolderManifestReceiptV1>>, active_scan: Arc<Mutex<Option<ActiveFolderScan>>> }
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

#[tauri::command]
async fn scan_selected_file_v1(app: tauri::AppHandle, selection_id: String, state: tauri::State<'_, AppState>) -> Result<CanonicalReceiptV1, ApplicationErrorV1> {
    let selected = state.selected.lock().unwrap().as_ref().filter(|s| s.id == selection_id).map(|s| (s.canonical_path.clone(), s.size_bytes, s.digest.clone())).ok_or_else(|| ApplicationErrorV1 { code: "SELECTION_NOT_FOUND".into(), message: "Unknown selection id".into(), path: None, retryable: false })?;
    let metadata = std::fs::metadata(&selected.0).map_err(|e| ApplicationErrorV1 { code: "FILE_CHANGED_SINCE_SELECTION".into(), message: e.to_string(), path: None, retryable: false })?;
    let current = hex::encode(Sha256::digest(std::fs::read(&selected.0).map_err(|e| ApplicationErrorV1 { code: "FILE_CHANGED_SINCE_SELECTION".into(), message: e.to_string(), path: None, retryable: false })?));
    if metadata.len() != selected.1 || current != selected.2 { return Err(ApplicationErrorV1 { code: "FILE_CHANGED_SINCE_SELECTION".into(), message: "Selected file changed before scan".into(), path: None, retryable: false }); }
    let binding = default_rule_binding(&app)?;
    let request = ScanFileRequestV1 { request_id: uuid::Uuid::new_v4().to_string(), target_path: selected.0.to_string_lossy().into_owned(), rule_pack: binding };
    let result: ScanResultV1 = scan_file_v1(request).await?;
    let receipt = build_receipt_v1(result).map_err(|e| ApplicationErrorV1 { code: "RECEIPT_SERIALIZATION_FAILED".into(), message: e.to_string(), path: None, retryable: false })?;
    *state.receipt.lock().unwrap() = Some(receipt.clone());
    Ok(receipt)
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
        .manage(AppState { selected: Mutex::new(None), selected_folder: Mutex::new(None), receipt: Mutex::new(None), folder_receipt: Mutex::new(None), active_scan: Arc::new(Mutex::new(None)) })
        .invoke_handler(tauri::generate_handler![get_product_status_v1, select_file_v1, select_folder_v1, scan_selected_file_v1, scan_selected_folder_v1, cancel_folder_scan_v1, reset_active_case_v1, export_receipt_v1])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
