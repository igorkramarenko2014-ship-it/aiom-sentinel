#!/usr/bin/env node
import { readFile, readdir, stat } from "node:fs/promises";

const root = new URL("../", import.meta.url);
const required = [
  "docs/adr/ADR-011-AI-OUTSIDE-ENFORCEMENT-BOUNDARY.md",
  "docs/adr/ADR-012-CROSS-PLATFORM-FROM-ORIGIN.md",
  "docs/adr/ADR-013-PRIVACY-SHIELD-SCOPE-SEPARATION.md",
  "docs/contracts/PLATFORM_CAPABILITY_CONTRACT.md",
  "docs/platform/PLATFORM_SUPPORT_MATRIX.md",
  "docs/platform/PORTABILITY_TEST_PLAN.md",
  "docs/future/NETWORK_POLICY_CONTRACT.md",
  "docs/future/MEMORY_OBSERVATION_CONTRACT.md",
  "docs/future/CERTIFICATE_TRUST_CONTRACT.md",
  "docs/future/QUARANTINE_AND_RESTORE_CONTRACT.md",
  "docs/future/PRIVACY_SHIELD_CONTRACT.md",
];
const failures = [];
const texts = [];
for (const path of required) {
  try { texts.push(await readFile(new URL(path, root), "utf8")); }
  catch { failures.push(`missing required file: ${path}`); }
}
const canonical = texts.join("\n");
for (const phrase of ["AI and ML may not directly control privileged enforcement.", "cross-platform by architecture", "Privacy Shield", "NOT_IMPLEMENTED"]) if (!canonical.includes(phrase)) failures.push(`missing canonical claim: ${phrase}`);
for (const forbidden of [/blanket TLS interception (is )?(allowed|enabled|implemented)/i, /automatic full-memory dump (is )?(allowed|enabled|implemented)/i, /AI.{0,80}(firewall|quarantine|kernel).{0,80}(direct|autonomous).{0,80}(allowed|implemented)/i]) if (forbidden.test(canonical)) failures.push(`forbidden assertion: ${forbidden}`);
const matrix = texts.find((text) => text.includes("PLATFORM_SUPPORT_MATRIX")) ?? "";
for (const platform of ["Windows", "Linux", "macOS"]) if (!matrix.includes(platform)) failures.push(`platform matrix missing ${platform}`);
for (const row of matrix.split("\n").filter((line) => line.includes("RUNTIME_VERIFIED"))) if (!row.includes("local Phase 1 release receipt")) failures.push("runtime verification has no evidence reference");
const workspace = await readFile(new URL("Cargo.toml", root), "utf8");
for (const forbidden of ["collector", "behavior", "network", "quarantine", "kernel", "driver", "telemetry"]) if (new RegExp(`crates/[^\"\\n]*${forbidden}`, "i").test(workspace)) failures.push(`forbidden workspace member: ${forbidden}`);
for (const name of ["collectors", "behavior", "network", "quarantine", "kernel", "drivers", "telemetry"]) { try { if ((await stat(new URL(`${name}/`, root))).isDirectory()) failures.push(`forbidden runtime directory: ${name}`); } catch {} }
const publicDocs = await Promise.all(["README.md", ...required].map(async (path) => readFile(new URL(path, root), "utf8")));
if (publicDocs.join("\n").includes("/Users/igorkramarenko/")) failures.push("machine-specific public path");
if (failures.length) { for (const failure of failures) console.error(`portability: FAIL ${failure}`); process.exit(1); }
console.log(`sentinel-portability: PASS files=${required.length}`);
