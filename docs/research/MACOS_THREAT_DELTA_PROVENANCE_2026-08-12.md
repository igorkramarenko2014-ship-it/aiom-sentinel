# macOS threat delta provenance — 2026-08-12

This delta is a bounded static/synthetic model update. No malware was downloaded or executed,
and no live build-process, persistence, or runtime capability telemetry was available.

| Signal | Source class | Published | Ingested | Verification | Limitation |
|---|---|---|---|---|---|
| SStar dependency-chain case | secondary research signal | not independently verified here | 2026-08-12 | synthetic model | feed-new does not imply threat-new |
| Apple/source impact discrepancy | source-governance fixture | not independently verified here | 2026-08-12 | synthetic conflict case | stronger secondary impact is not canonical without corroboration |
| build-time dependency execution | architecture primitive | n/a | 2026-08-12 | implemented/tested | no live build observer |
| persistence after first-stage removal | architecture primitive | n/a | 2026-08-12 | implemented/tested | no live filesystem persistence observer |

The source claim record preserves primary, upstream, and secondary claims separately. A secondary
claim may remain historically retained while canonical impact stays evidence-backed.
