# macOS Threat Corpus Provenance — 2026-08-10

FILE_ROLE: REPORT

This report records the provenance classes supplied by
`AIOM_SENTINEL_MACOS_THREAT_CORPUS_CODEX_2026-08-10.zip`. It does not promote the
Grok corpus above the live repository and does not independently verify external URLs.

| Signal group | Provenance class | Limitation |
|---|---|---|
| ClickLock / ClickFix | PRIMARY_RESEARCH | Group-IB classification inherited from the corpus |
| CrashStealer | PRIMARY_RESEARCH | Jamf classification inherited from the corpus |
| AsyncAPI / Jscrambler / keyv-cacheable | PRIMARY_RESEARCH | Socket/Datadog classifications inherited from the corpus |
| npm platform changes | UPSTREAM | GitHub/npm classification inherited from the corpus |
| YARA-X 1.19.0 | UPSTREAM | Engine version verified in canonical Cargo configuration |
| OSV withdrawal lesson | UPSTREAM | Lifecycle lesson only; no family attribution |
| SkillGate / adversarial-skill research | ACADEMIC | Research findings are not endpoint telemetry |
| ClamAV TOCTOU and scanner lessons | UPSTREAM | Architectural lessons; no ClamAV adapter is integrated |
| Mach-O feature research | ACADEMIC | Enrichment evidence is not a malicious verdict |
| XCSSET v40 details | SOURCE_UNVERIFIED | Late-window source URLs were not live-verified by the corpus author |
| FlutterBridge / FlutterShell details | SOURCE_UNVERIFIED | Late-window source URLs were not live-verified by the corpus author |
| Public malicious agent-skill cases | SOURCE_UNVERIFIED | Exact campaign and IOC promotion requires source review |

Behavioral models derived from `SOURCE_UNVERIFIED` entries remain generic and synthetic.
No exact family IOC from those entries is promoted by this change.
