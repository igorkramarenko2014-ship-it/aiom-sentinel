# Response Authority Matrix

implementation_authority: NONE
current_runtime_status: DESIGN_ONLY

| Action | Automation allowed | Human approval | Reversibility | Blast radius | Asset criticality | Confidence/evidence threshold | Timeout | Rollback action |
|---|---|---|---|---|---|---|---|---|
| OBSERVE | yes | no | discard observation | none | any | AE1+ | none | none |
| ENRICH | yes, metadata-only | raw content requires approval | discard enrichment | low | any | AE1+ | bounded | delete unauthorized derivative |
| ALERT | yes | no | close alert | low | any | AE1+ | none | annotate disposition |
| RESTRICT | policy-specific | critical assets yes | remove restriction | medium | considered | medium threat, AE2 | bounded | restore prior policy |
| SUSPEND | narrow policy only | normally yes | resume process | medium | considered | high threat, AE2 | short | resume and record |
| CONTAIN | narrow reversible controls | yes unless pre-approved | remove containment | high | required | high threat, AE2+ | bounded | restore connectivity/access |
| ISOLATE_HOST | exceptional pre-approved only | yes | reconnect host | fleet/host | mandatory | high threat, AE3 or narrow validated exception | bounded | staged reconnect |
| QUARANTINE | no in current phases | yes | atomic restore | object/host | mandatory | high threat, AE3 | bounded | authenticated restore |
| ERADICATE | never autonomous | mandatory | potentially irreversible | high | mandatory | confirmed case evidence | case-defined | backup/rebuild plan |

No action is implemented in Phase 1. Memory capture, credential revocation, and raw-content export
also require case, role, privacy, retention, regional, access-audit, and export-control gates.
