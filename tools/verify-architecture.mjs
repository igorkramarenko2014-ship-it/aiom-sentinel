#!/usr/bin/env node
import { createHash } from "node:crypto";
import { readFile, readdir, stat } from "node:fs/promises";

const root = new URL("../", import.meta.url);
const required = [
  "docs/architecture/ENTERPRISE_TARGET_ARCHITECTURE.md",
  "docs/architecture/TRUST_BOUNDARIES_AND_DFD.md",
  "docs/architecture/AI_BOUNDARY.md",
  "docs/contracts/FAILURE_MODE_MATRIX.md",
  "docs/contracts/NORMALIZED_EVENT_CONTRACT.md",
  "docs/contracts/DETECTION_RESULT_CONTRACT.md",
  "docs/contracts/RESPONSE_AUTHORITY_MATRIX.md",
  "docs/detection/DEFENSIVE_DETECTION_MATRIX.md",
  "docs/detection/RULE_LIFECYCLE.md",
  "docs/detection/QUALITY_METRICS.md",
  "docs/platform/WINDOWS_COLLECTOR_CONTRACT.md",
  "docs/platform/LINUX_COLLECTOR_CONTRACT.md",
  "docs/platform/MACOS_COLLECTOR_CONTRACT.md",
  "docs/formats/PE_PARSER_CONTRACT.md",
  "docs/formats/ELF_PARSER_CONTRACT.md",
  "docs/formats/MACHO_PARSER_CONTRACT.md",
  "docs/research/KIMI_CLAIM_LEDGER.md",
  "docs/contracts/PLATFORM_CAPABILITY_CONTRACT.md",
  "docs/platform/PLATFORM_SUPPORT_MATRIX.md",
  "docs/platform/PORTABILITY_TEST_PLAN.md",
  "docs/roadmap/PHASED_ROADMAP.md",
  ...Array.from({ length: 13 }, (_, index) => {
    const names = ["FAILURE-SEMANTICS", "WORKER-ISOLATION", "EVIDENCE-INTEGRITY", "UPDATE-TRUST", "PLATFORM-COLLECTOR-BOUNDARIES", "QUARANTINE-KEY-MANAGEMENT", "PLUGIN-CAPABILITY-MODEL", "PERFORMANCE-BUDGETS", "DETECTION-SCORING", "RESPONSE-AUTHORITY", "AI-OUTSIDE-ENFORCEMENT-BOUNDARY", "CROSS-PLATFORM-FROM-ORIGIN", "PRIVACY-SHIELD-SCOPE-SEPARATION"];
    return `docs/adr/ADR-${String(index + 1).padStart(3, "0")}-${names[index]}.md`;
  }),
];

const failures = [];
const contents = new Map();
for (const path of required) {
  try { contents.set(path, await readFile(new URL(path, root), "utf8")); }
  catch { failures.push(`missing required file: ${path}`); }
}

const receipt = JSON.parse(await readFile(new URL("architecture-input/SOURCE_CORPUS_RECEIPT.json", root), "utf8"));
const expectedCorpusHash = "9949a04e4a6cf00ba7009daf6822e657fa9ad4f25b69f340159666fbbaf6ff22";
let corpusMode = "full";
let corpusHash = "not-present";
try {
  const corpus = await readFile(new URL("architecture-input/AIOM_SENTINEL_EXACT_SOURCE_CORPUS_v1.0.md", root));
  corpusHash = createHash("sha256").update(corpus).digest("hex");
  if (corpusHash !== receipt.corpus_sha256 || corpusHash !== expectedCorpusHash) failures.push("source corpus hash mismatch");
} catch (error) {
  if (error?.code !== "ENOENT") throw error;
  corpusMode = "receipt-only";
  if (receipt.publication_status !== "LOCAL_RESTRICTED_NOT_FOR_PUBLIC_RELEASE" || receipt.public_release_corpus_included !== false) {
    failures.push("source corpus is absent without an explicit restricted-publication decision");
  }
}
if (receipt.consolidated_contract_sha256 !== "db9e0f0e7a9d2995245bc91e363c21af338488c095eed2980355ce0627f53a2b" || receipt.source_count !== 3 || receipt.bounded_corpus !== true || receipt.external_claims_allowed !== false) failures.push("invalid source corpus receipt");

const adrHeadings = ["Status", "Context", "Decision", "Alternatives", "Consequences", "Security Impact", "Privacy Impact", "Availability Impact", "Verification Requirements", "Implementation Phase", "Unresolved Questions"];
for (const [path, text] of contents) {
  if (path.includes("/adr/")) for (const heading of adrHeadings) if (!text.includes(`## ${heading}`)) failures.push(`${path}: missing ${heading}`);
  if (!path.includes("PE_PARSER_CONTRACT") && !text.includes("implementation_authority: NONE")) failures.push(`${path}: missing implementation authority NONE`);
  const statusLine = text.split("\n").find((line) => line.startsWith("current_runtime_status:"));
  if (!path.includes("PE_PARSER_CONTRACT") && (!statusLine || !statusLine.includes("DESIGN_ONLY"))) failures.push(`${path}: future runtime status is not DESIGN_ONLY`);
}

const workspace = await readFile(new URL("Cargo.toml", root), "utf8");
if (!/^arc-swap = "=1\.9\.2"$/m.test(workspace)) failures.push("arc-swap foundation dependency is not exactly pinned to 1.9.2");
if (!/^ed25519-dalek = "=3\.0\.0"$/m.test(workspace)) failures.push("ed25519-dalek foundation dependency is not exactly pinned to 3.0.0");
for (const forbidden of ["collector", "behavior", "registry", "network", "quarantine", "containment", "kernel", "driver", "telemetry", "cloud"]) {
  if (new RegExp(`crates/[^"\\n]*${forbidden}`, "i").test(workspace)) failures.push(`forbidden Phase 2 workspace member: ${forbidden}`);
}

const signatureSource = await readFile(new URL("crates/sentinel-rules/src/signature.rs", root), "utf8");
const productionSignatureSource = signatureSource.split("#[cfg(test)]\nmod tests")[0];
for (const requiredSignatureMechanism of [
  "VerifyingKey",
  "verify_strict",
  "AIOM_SENTINEL_RULE_BUNDLE_SIGNATURE_V1\\0",
  "TestOnlyKeyRejected",
]) {
  if (!signatureSource.includes(requiredSignatureMechanism)) failures.push(`signature foundation missing ${requiredSignatureMechanism}`);
}
for (const forbiddenProductionMechanism of ["SigningKey", ".sign("]) {
  if (productionSignatureSource.includes(forbiddenProductionMechanism)) failures.push(`production signature foundation exposes ${forbiddenProductionMechanism}`);
}

const registry = JSON.parse(await readFile(new URL("config/rule-bundle-public-keys.json", root), "utf8"));
if (registry.schema_version !== 1 || !Array.isArray(registry.keys)) failures.push("public-key registry envelope is invalid");
for (const key of registry.keys ?? []) {
  if (key.algorithm !== "ED25519") failures.push(`registry key ${key.key_id ?? "<missing>"} has wrong algorithm`);
  if (!/^[0-9a-f]{64}$/.test(key.public_key_hex ?? "")) failures.push(`registry key ${key.key_id ?? "<missing>"} has malformed public key`);
  if (!["ACTIVE", "REVOKED"].includes(key.status)) failures.push(`registry key ${key.key_id ?? "<missing>"} has invalid status`);
  if (key.scope !== "PRODUCTION") failures.push(`production registry contains non-production key ${key.key_id ?? "<missing>"}`);
}

const scannerSource = await readFile(new URL("crates/sentinel-scanner/src/lib.rs", root), "utf8");
for (const requiredScannerMechanism of [
  "ArcSwap<RuleSetSnapshot>",
  "pub struct ActiveRuleSet",
  "pub fn snapshot",
  "pub fn replace",
  "pub async fn scan_with_active",
]) {
  if (!scannerSource.includes(requiredScannerMechanism)) failures.push(`scanner replacement foundation missing ${requiredScannerMechanism}`);
}
if (/static\s+(mut\s+)?[A-Z_]*ACTIVE_RULE/i.test(scannerSource)) failures.push("scanner replacement foundation uses a global active-ruleset singleton");

const forbiddenRuntimePaths = ["collectors", "behavior", "registry", "network", "quarantine", "containment", "kernel", "drivers", "telemetry", "cloud"];
for (const path of forbiddenRuntimePaths) {
  try { if ((await stat(new URL(`${path}/`, root))).isDirectory()) failures.push(`forbidden Phase 2 runtime path exists: ${path}`); }
  catch { /* Absence is required. */ }
}

for (const platform of ["WINDOWS", "LINUX", "MACOS"]) {
  const text = contents.get(`docs/platform/${platform}_COLLECTOR_CONTRACT.md`) ?? "";
  if (!text.includes("implementation_authority: NONE")) failures.push(`${platform}: collector authority is not NONE`);
}

const detection = contents.get("docs/contracts/DETECTION_RESULT_CONTRACT.md") ?? "";
for (const field of ["risk_score", "threat_confidence", "benign_confidence", "evidence_quality", "telemetry_quality", "contributing_signals", "contradicting_signals", "automatic_response_allowed", "human_approval_required", "reversibility", "blast_radius", "asset_criticality"]) if (!detection.includes(field)) failures.push(`detection result missing ${field}`);

const response = contents.get("docs/contracts/RESPONSE_AUTHORITY_MATRIX.md") ?? "";
for (const action of ["OBSERVE", "ENRICH", "ALERT", "RESTRICT", "SUSPEND", "CONTAIN", "ISOLATE_HOST", "QUARANTINE", "ERADICATE"]) {
  const row = response.split("\n").find((line) => line.startsWith(`| ${action} |`));
  if (!row || row.split("|").length < 11) failures.push(`response action incomplete: ${action}`);
}

const ledger = contents.get("docs/research/KIMI_CLAIM_LEDGER.md") ?? "";
const ledgerRows = ledger.split("\n").filter((line) => /^\| KC-\d+/.test(line));
if (ledgerRows.length < 10) failures.push("claim ledger has fewer than ten material entries");
for (let sprint = 1; sprint <= 10; sprint += 1) if (!ledgerRows.some((row) => row.includes(`Sprint ${sprint},`))) failures.push(`claim ledger missing Sprint ${sprint}`);
const allowedClassifications = ["ACCEPT", "ACCEPT_WITH_QUALIFICATION", "REJECT", "REQUIRES_PRIMARY_SOURCE", "OUT_OF_SCOPE", "DEFENSIVE_REWRITE_REQUIRED"];
for (const row of ledgerRows) {
  if (!allowedClassifications.some((value) => row.includes(`| ${value} |`))) failures.push(`invalid ledger classification: ${row.slice(0, 24)}`);
  if (!row.includes("| NONE |")) failures.push(`claim has implementation authority: ${row.slice(0, 24)}`);
}

const canonical = [...contents.entries()].filter(([path]) => !path.includes("KIMI_CLAIM_LEDGER")).map(([, text]) => text).join("\n");
for (const forbidden of [
  /fail[- ]closed (for|on) every/i,
  /signed .{0,30}(binary|file).{0,20}(skip|unconditional allow)/i,
  /zero[- ]overhead monitoring/i,
  /patch\s+[`'"]?(Amsi|EtwEventWrite)/i,
  /CR0\.WP bypass/i,
  /unlink from [`'"]?PsSetCreateProcessNotifyRoutine/i,
]) if (forbidden.test(canonical)) failures.push(`forbidden canonical assertion matched: ${forbidden}`);

if (!canonical.includes("TARGET_OR_HYPOTHESIS")) failures.push("performance hypothesis label missing");
if (!/Entropy is[\s\S]{0,40}never a (malware )?verdict/i.test(canonical)) failures.push("entropy limitation missing");

const architectureDirs = ["docs/architecture", "docs/contracts", "docs/detection", "docs/platform", "docs/formats", "docs/research", "docs/adr", "docs/roadmap"];
let markdownCount = 0;
for (const directory of architectureDirs) markdownCount += (await readdir(new URL(`${directory}/`, root))).filter((name) => name.endsWith(".md")).length;

if (failures.length > 0) {
  for (const failure of failures) console.error(`architecture: FAIL ${failure}`);
  process.exit(1);
}
console.log(`sentinel-architecture: PASS files=${required.length} markdown=${markdownCount} claims=${ledgerRows.length} adrs=13 corpus_mode=${corpusMode} corpus_sha256=${corpusHash}`);
