import { invoke } from "@tauri-apps/api/core";
import { listen, type UnlistenFn } from "@tauri-apps/api/event";
import "./style.css";

type State = "READY" | "SELECTED" | "SCANNING" | "RESULT" | "ERROR" | "EXPORT_COMPLETE";
type Selection = { selection_id: string; display_name: string; size_bytes: number };
type Finding = { engine_id: string; rule_id: string; namespace: string; matched_condition: string; evidence_reference: string; tags: string[]; metadata: Array<{ key: string; value: string }>; spans: Array<{ pattern: string; start: number; end: number }>; severity: string | null; confidence: string | null };
type EngineReport = { engine: { engine_id: string; engine_version: string }; ruleset: { pack_id: string; content_sha256: string }; state: "COMPLETE" | "PARTIAL" | "FAILED" | "UNSUPPORTED" | "CANCELLED"; scanned_bytes: number; match_count: number; reason: string | null };
type Receipt = { payload: { state: "COMPLETED" | "FAILED"; processed_count: number; finding_count: number; findings: Finding[]; errors: AppError[]; rule_pack: { pack_id: string; expected_bytes_sha256: string }; engine_reports: EngineReport[] }; payload_sha256: string };
type FolderReceipt = { run: { state: string; root_label: string; discovered_count: number; accepted_count: number; processed_count: number; finding_count: number; skipped_count: number; error_count: number; processed_bytes: number; files: Array<{ relative_path: string; state: string; finding_count: number; errors: AppError[] }>; rule_pack: { pack_id: string; expected_bytes_sha256: string } }; content_manifest_sha256: string };
type AppError = { code: string; message: string; path?: string | null };

const root = document.querySelector<HTMLDivElement>("#app");
if (!root) throw new Error("app root missing");
const appRoot = root;
let state: State = "READY";
let selection: Selection | null = null;
let receipt: Receipt | null = null;
let containerReceipt: any = null;
let folderSelection: Selection | null = null;
let folderReceipt: FolderReceipt | null = null;
let exportResult: { written_path: string; bytes: number; sha256: string } | null = null;
let error: AppError | null = null;
let coreAvailable = false;
let activeFolderRequestId: string | null = null;
let preparationMessage = "";
let preparationUnlisten: UnlistenFn | null = null;
let folderProgressUnlisten: UnlistenFn | null = null;
let folderProgress: any = null;
let cancellationRequested = false;
let showFiles = false;
let filePage = 0;
let fileFilter = "ALL";
let fileSearch = "";

const el = <K extends keyof HTMLElementTagNameMap>(tag: K, text?: string): HTMLElementTagNameMap[K] => {
  const node = document.createElement(tag); if (text !== undefined) node.textContent = text; return node;
};
const button = (label: string, disabled: boolean, action: () => void) => { const b = el("button", label); b.disabled = disabled; b.onclick = action; return b; };
const evidenceStream = (): HTMLDivElement => { const node = document.createElement("div"); node.className = "evidence-stream"; node.setAttribute("aria-hidden", "true"); return node; };

function render(): void {
  appRoot.replaceChildren();
  window.scrollTo(0, 0);
  const header = el("header"); const brand = el("div"); brand.append(el("strong", "AIOM Sentinel"), el("small", "Deterministic Evidence Engine")); if (state !== "READY") header.append(button("Home", activeFolderRequestId !== null, resetToHome));
  const core = el("div", "Core  •  "); core.append(el("span", coreAvailable ? "Available" : "Unavailable")); header.append(brand, core);
  const rail = el("nav", "FILE     →     DIGEST     →     EVIDENCE     →     RECEIPT"); rail.className = `rail rail-${state.toLowerCase()} ${(state === "SCANNING" || Boolean(preparationMessage)) ? "evidence-thinking" : ""}`;
  const workspace = el("main");
  const active = state === "SCANNING" || Boolean(preparationMessage);
  if (active) workspace.setAttribute("aria-busy", "true");
  if (state === "READY") { const heading = el("h1", preparationMessage ? "PREPARING FILE" : "ACTIVE CASE"); if (preparationMessage) heading.className = "thinking-title"; workspace.append(heading, el("p", preparationMessage || "Choose a file or folder to build evidence."), preparationMessage ? el("p", "Calculating file identity…") : el("p", "Sentinel reads selected bytes without modifying them."), preparationMessage ? evidenceStream() : el("span"), button("Choose File", Boolean(preparationMessage), chooseFile), button("Choose Folder", Boolean(preparationMessage), chooseFolder)); }
  if (state === "SELECTED" && selection) { workspace.append(el("h1", "SELECTED FILE"), el("h2", selection.display_name), el("p", `${selection.size_bytes} bytes`), el("p", "Read-only selection"), button("Build Evidence", false, scanFile), button("Inspect Container", false, inspectContainer), button("Choose Another", false, chooseFile), button("Choose Folder", false, chooseFolder)); }
  if (state === "SELECTED" && folderSelection && !selection) { workspace.append(el("h1", "SELECTED FOLDER"), el("h2", folderSelection.display_name), el("p", "Recursive · Read-only"), button("Build Folder Evidence", false, scanFolder), button("Choose Another", false, chooseFolder), button("Choose File", false, chooseFile)); }
  if (state === "SCANNING") { const heading = el("h1", folderSelection ? (cancellationRequested ? "CANCELLING…" : "BUILDING FOLDER EVIDENCE…") : "BUILDING EVIDENCE…"); heading.className = "thinking-title"; workspace.append(heading, evidenceStream(), el("p", folderSelection ? `Discovered ${folderProgress?.discovered_count ?? 0} · Accepted ${folderProgress?.accepted_count ?? 0} · Processed ${folderProgress?.processed_count ?? 0}` : "Building deterministic evidence…"), folderSelection ? el("p", `Findings ${folderProgress?.finding_count ?? 0} · Skipped ${folderProgress?.skipped_count ?? 0} · Errors ${folderProgress?.error_count ?? 0}`) : el("p", "The selected file remains unchanged.")); if (folderSelection) workspace.append(el("p", folderProgress?.current_relative_path ?? "Waiting for first file…"), button(cancellationRequested ? "Cancelling…" : "Cancel", cancellationRequested, cancelFolderScan)); }
  if (state === "RESULT" && receipt) renderResult(workspace);
  if (state === "RESULT" && containerReceipt) renderContainerResult(workspace);
  if (state === "RESULT" && folderReceipt) renderFolderResult(workspace);
  if (state === "EXPORT_COMPLETE" && exportResult) { workspace.append(el("h1", "RECEIPT EXPORTED"), el("p", exportResult.written_path), el("p", `${exportResult.bytes} bytes`), el("p", `SHA-256 ${exportResult.sha256}`), button("Done", false, () => { state = "RESULT"; render(); })); }
  if (state === "ERROR" && error) { workspace.append(el("h1", "UNABLE TO COMPLETE"), el("p", error.code), el("p", error.message), button("Try Again", false, () => { state = selection ? "SELECTED" : "READY"; error = null; render(); })); }
  const footer = el("footer", "Read-only · Local · Deterministic evidence · Development build · Receipt may contain local file paths"); appRoot.append(header, rail, workspace, footer);
}
function renderContainerResult(workspace: HTMLElement): void { if (!containerReceipt) return; workspace.append(el("h1", containerReceipt.state === "Complete" ? "CONTAINER INSPECTED" : "CONTAINER EVIDENCE INCOMPLETE"), el("p", `Type  ${containerReceipt.container_type}`), el("p", `Entries  ${containerReceipt.entries?.length ?? 0}`), el("p", `Expanded bytes  ${containerReceipt.expanded_bytes ?? 0}`)); for (const entry of containerReceipt.entries ?? []) { const row = el("section"); row.append(el("p", entry.relative_path), el("p", `SHA-256  ${entry.subject_sha256 ?? "—"}`)); workspace.append(row); } for (const message of containerReceipt.errors ?? []) workspace.append(el("p", `Error  ${message}`)); workspace.append(el("p", "No known rule matched in the inspected eligible files."), el("p", "This does not prove that the container or its contents are safe."), button("Inspect Another", false, chooseFile), button("Home", false, resetToHome)); }
function renderResult(workspace: HTMLElement): void {
  if (!receipt) return;
  const incomplete = receipt.payload.state === "FAILED" || receipt.payload.errors.length > 0;
  workspace.append(el("h1", incomplete ? "EVIDENCE INCOMPLETE" : "EVIDENCE BUILT"), el("p", `File  ${selection?.display_name ?? ""}`), el("p", `Processed  ${receipt.payload.processed_count} file`), el("p", `Findings  ${receipt.payload.finding_count}`), el("p", `Rule pack  ${receipt.payload.rule_pack.pack_id}`), el("p", `Rule-pack digest  ${receipt.payload.rule_pack.expected_bytes_sha256}`), el("p", `Receipt digest  ${receipt.payload_sha256}`));
  if (incomplete) {
    workspace.append(el("p", `Errors  ${receipt.payload.errors.length}`));
    for (const scanError of receipt.payload.errors) { const row = el("section"); row.append(el("p", scanError.code), el("p", scanError.message)); workspace.append(row); }
    workspace.append(el("p", "This file was not fully evaluated."));
  } else if (receipt.payload.finding_count === 0) workspace.append(el("p", "No patterns matched in this file."), el("p", "This does not prove that the file is safe."));
  else { workspace.append(el("h2", "PATTERN MATCHES")); for (const finding of receipt.payload.findings) { const row = el("section"); row.append(el("p", `Engine  ${finding.engine_id}`), el("p", `Rule  ${finding.namespace}:${finding.rule_id}`), el("p", `Tags  ${finding.tags.join(", ") || "—"}`), el("p", `Offsets  ${finding.spans.map(span => `${span.pattern}@${span.start}-${span.end}`).join(", ") || "—"}`)); if (finding.severity) row.append(el("p", `Severity  ${finding.severity}`)); workspace.append(row); } }
  for (const report of receipt.payload.engine_reports) { workspace.append(el("p", `Coverage  ${report.engine.engine_id} ${report.engine.engine_version} · ${report.state} · ${report.match_count} matches · ${report.ruleset.content_sha256}`)); }
  workspace.append(button("Export Receipt", false, exportReceipt), button("Quarantine File", false, quarantineFile), button("Inspect Another File", false, chooseFile));
}
function renderFolderResult(workspace: HTMLElement): void {
  if (!folderReceipt) return;
  const run = folderReceipt.run;
  const cancelled = run.state === "CANCELLED";
  workspace.append(el("h1", cancelled ? "SCAN CANCELLED" : run.state === "INCOMPLETE" ? "EVIDENCE INCOMPLETE" : "FOLDER EVIDENCE BUILT"), el("p", `Folder  ${run.root_label}`), el("p", `Discovered  ${run.discovered_count}`), el("p", `Accepted  ${run.accepted_count}`), el("p", `Processed  ${run.processed_count}`), el("p", `Findings  ${run.finding_count}`), el("p", `Skipped  ${run.skipped_count}`), el("p", `Errors  ${run.error_count}`), el("p", `Processed bytes  ${run.processed_bytes}`), el("p", `Manifest digest  ${folderReceipt.content_manifest_sha256}`), el("p", `Rule pack  ${run.rule_pack.pack_id}`));
  if (cancelled) workspace.append(el("p", "Partial deterministic evidence was preserved."), el("p", "Unprocessed files were not evaluated."));
  const actions = el("nav"); actions.setAttribute("aria-label", "Result actions"); actions.className = "result-actions"; actions.style.position = "sticky"; actions.style.top = "0"; actions.style.zIndex = "2"; actions.style.background = "var(--bg)"; actions.style.border = "1px solid var(--border)"; actions.style.padding = "10px"; actions.append(button("Export Manifest Receipt", false, exportReceipt), button("Inspect Another Folder", false, chooseFolder), button("Home", false, resetToHome)); workspace.append(actions);
  const explorer = el("section"); explorer.append(el("h2", `FILES · ${run.files.length.toLocaleString()}`), button(showFiles ? "Hide Files" : "Show Files", false, () => { showFiles = !showFiles; render(); }));
  if (showFiles) { const query = fileSearch.toLowerCase(); const filters = el("div"); for (const filter of ["ALL", "FINDINGS", "ERRORS", "SKIPPED"]) { const control = button(filter, fileFilter === filter, () => { fileFilter = filter; filePage = 0; render(); }); control.setAttribute("aria-pressed", String(fileFilter === filter)); filters.append(control); } const filtered = run.files.filter(file => (fileFilter === "ALL" || (fileFilter === "FINDINGS" && file.finding_count > 0) || (fileFilter === "ERRORS" && file.errors.length > 0) || (fileFilter === "SKIPPED" && file.state.startsWith("SKIPPED_"))) && file.relative_path.toLowerCase().includes(query)); const pages = Math.max(1, Math.ceil(filtered.length / 100)); filePage = Math.min(filePage, pages - 1); const search = document.createElement("input"); search.type = "search"; search.placeholder = "Search result paths"; search.setAttribute("aria-label", "Search result paths"); search.value = fileSearch; search.oninput = () => { fileSearch = search.value; filePage = 0; render(); }; explorer.append(filters, search, el("p", `Page ${filePage + 1} of ${pages}`)); const start = filePage * 100; for (const file of filtered.slice(start, start + 100)) { const row = el("p", `${file.relative_path} · ${file.state} · findings ${file.finding_count}`); explorer.append(row); } explorer.append(button("Previous", filePage === 0, () => { filePage--; render(); }), button("Next", filePage >= pages - 1, () => { filePage++; render(); })); }
  workspace.append(explorer);
}
async function resetToHome(): Promise<void> { try { await invoke("reset_active_case_v1"); selection = null; folderSelection = null; receipt = null; folderReceipt = null; exportResult = null; error = null; preparationMessage = ""; activeFolderRequestId = null; folderProgress = null; cancellationRequested = false; showFiles = false; filePage = 0; fileFilter = "ALL"; fileSearch = ""; preparationUnlisten?.(); preparationUnlisten = null; folderProgressUnlisten?.(); folderProgressUnlisten = null; state = "READY"; render(); } catch (e) { error = e as AppError; render(); } }
async function chooseFile(): Promise<void> {
  console.info("select_file_v1 invoked");
  preparationMessage = "";
  preparationUnlisten?.();
  preparationUnlisten = await listen<any>("sentinel://file-preparation-v1", (event) => { const p = event.payload; if (p.phase === "PREPARING" || p.phase === "HASHING") { preparationMessage = `${p.display_name}\n${p.message}`; render(); } });
  try {
    const raw = await invoke<Selection | { selectionId?: string; displayName?: string; sizeBytes?: number } | null>("select_file_v1");
    console.info("select_file_v1 resolved", raw ? { displayName: (raw as any).display_name ?? (raw as any).displayName, sizeBytes: (raw as any).size_bytes ?? (raw as any).sizeBytes, hasId: Boolean((raw as any).selection_id ?? (raw as any).selectionId) } : null);
    preparationUnlisten?.(); preparationUnlisten = null;
    if (!raw) { preparationMessage = ""; state = selection ? "SELECTED" : "READY"; render(); return; }
    const value = raw as any;
    const selectionId = value.selection_id ?? value.selectionId;
    const displayName = value.display_name ?? value.displayName;
    const sizeBytes = value.size_bytes ?? value.sizeBytes;
    if (typeof selectionId !== "string" || typeof displayName !== "string" || typeof sizeBytes !== "number") throw new Error("FILE_SELECTION_INVALID_RESPONSE");
    selection = { selection_id: selectionId, display_name: displayName, size_bytes: sizeBytes };
    folderSelection = null; folderReceipt = null; containerReceipt = null; receipt = null; error = null; state = "SELECTED";
    console.info("file selection state transition", { state, displayName });
    render();
  } catch (e) { preparationUnlisten?.(); preparationUnlisten = null; preparationMessage = ""; console.error("select_file_v1 rejected", e); error = e as AppError; state = "ERROR"; render(); }
}
async function chooseFolder(): Promise<void> { try { const folder = await invoke<Selection | null>("select_folder_v1"); if (!folder) { render(); return; } folderSelection = folder; selection = null; folderReceipt = null; receipt = null; state = "SELECTED"; render(); } catch (e) { error = e as AppError; state = "ERROR"; render(); } }
async function scanFolder(): Promise<void> { if (!folderSelection) return; activeFolderRequestId = crypto.randomUUID(); cancellationRequested = false; folderProgress = null; const requestId = activeFolderRequestId; folderProgressUnlisten = await listen<any>("sentinel://folder-progress-v1", (event) => { const payload = event.payload; if (payload.request_id !== activeFolderRequestId || payload.terminal) { if (payload.request_id === activeFolderRequestId && payload.terminal) folderProgress = payload; else return; } folderProgress = payload; if (payload.phase === "CANCELLING") cancellationRequested = true; render(); }); state = "SCANNING"; render(); try { folderReceipt = await invoke<FolderReceipt>("scan_selected_folder_v1", { requestId, selectionId: folderSelection.selection_id }); state = "RESULT"; } catch (e) { error = e as AppError; state = "ERROR"; } finally { activeFolderRequestId = null; folderProgressUnlisten?.(); folderProgressUnlisten = null; render(); } }
async function cancelFolderScan(): Promise<void> { if (!activeFolderRequestId || cancellationRequested) return; cancellationRequested = true; render(); try { await invoke("cancel_folder_scan_v1", { requestId: activeFolderRequestId }); } catch (e) { error = e as AppError; state = "ERROR"; render(); } }
async function scanFile(): Promise<void> { if (!selection) return; state = "SCANNING"; render(); try { receipt = await invoke<Receipt>("scan_selected_file_v1", { selectionId: selection.selection_id }); state = "RESULT"; render(); } catch (e) { error = e as AppError; state = "ERROR"; render(); } }
async function inspectContainer(): Promise<void> { if (!selection) return; state = "SCANNING"; render(); try { containerReceipt = await invoke<any>("inspect_selected_container_v1", { selectionId: selection.selection_id }); state = "RESULT"; render(); } catch (e) { error = e as AppError; state = "ERROR"; render(); } }
async function exportReceipt(): Promise<void> { try { exportResult = await invoke<typeof exportResult>("export_receipt_v1"); if (exportResult) { state = "EXPORT_COMPLETE"; render(); } } catch (e) { error = e as AppError; state = "ERROR"; render(); } }
async function quarantineFile(): Promise<void> { if (!selection || !window.confirm("Move this file to Sentinel quarantine?")) return; try { await invoke("quarantine_selected_v1", { selectionId: selection.selection_id, confirm: true }); state = "READY"; selection = null; receipt = null; render(); } catch (e) { error = e as AppError; state = "ERROR"; render(); } }
async function loadStatus(): Promise<void> { try { const status = await invoke<{ core_available: boolean }>("get_product_status_v1"); coreAvailable = status.core_available; } catch { coreAvailable = false; } render(); }
void loadStatus();
