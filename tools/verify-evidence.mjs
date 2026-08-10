#!/usr/bin/env node
import { readFile } from "node:fs/promises";

const file = process.argv[2];
if (!file) {
  console.error("usage: node tools/verify-evidence.mjs <evidence.json>");
  process.exit(2);
}

const allowedVerdicts = new Set(["CLEAN", "SUSPICIOUS", "MATCH", "SCAN_ERROR", "UNSUPPORTED"]);
const required = ["schema_version", "evidence_id", "scan_id", "timestamp", "target_path", "canonical_path_status", "file_identity", "file_size", "hashes", "entropy", "file_type", "pe_metadata", "rule_matches", "findings", "scanner_version", "engine_version", "duration_ms", "errors", "verdict", "risk_score", "threat_confidence", "benign_confidence", "evidence_quality"];
const confidenceLevels = new Set(["LOW", "MEDIUM", "HIGH"]);
const evidenceQualities = new Set(["AE0", "AE1", "AE2", "AE3"]);

try {
  const evidence = JSON.parse(await readFile(file, "utf8"));
  if (!(evidence.schema_version === "1.1.0" || evidence.schema_version === "1.2.0") || !Array.isArray(evidence.records) || !Array.isArray(evidence.traversal_errors)) throw new Error("invalid evidence envelope");
  for (const [index, record] of evidence.records.entries()) {
    for (const key of required) if (!(key in record)) throw new Error(`record ${index} missing ${key}`);
    if (!allowedVerdicts.has(record.verdict)) throw new Error(`record ${index} has invalid verdict`);
    if (!Number.isInteger(record.risk_score) || record.risk_score < 0 || record.risk_score > 100) throw new Error(`record ${index} has invalid risk score`);
    if (!confidenceLevels.has(record.threat_confidence) || !confidenceLevels.has(record.benign_confidence)) throw new Error(`record ${index} has invalid confidence dimension`);
    if (!evidenceQualities.has(record.evidence_quality)) throw new Error(`record ${index} has invalid evidence quality`);
    if (record.hashes !== null) {
      if (!/^[0-9a-f]{64}$/.test(record.hashes.sha256) || !/^[0-9a-f]{40}$/.test(record.hashes.sha1) || !/^[0-9a-f]{32}$/.test(record.hashes.md5)) throw new Error(`record ${index} has invalid hashes`);
    }
    if (!record.target_path || typeof record.target_path.display !== "string" || typeof record.target_path.raw_base64 !== "string") throw new Error(`record ${index} has invalid target path`);
  }
  console.log(`sentinel-evidence: PASS records=${evidence.records.length} schema=${evidence.schema_version}`);
} catch (error) {
  console.error(`sentinel-evidence: FAIL ${error.message}`);
  process.exit(1);
}
