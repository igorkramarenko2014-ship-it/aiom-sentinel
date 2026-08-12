# 12-Aug signal → coverage delta

| Signal | Old coverage | New coverage | Generic primitive | Tests | Runtime status | Limitation |
|---|---|---|---|---|---|---|
| SStar dependency chain | npm lifecycle/import-time only | dependency graph + build-time execution correlation | `BUILD_TIME_DEPENDENCY_EXECUTION` | focused scanner tests | STATIC/SYNTHETIC | no live build observer |
| platform/architecture routing | not explicit | `ARCHITECTURE_SPECIFIC_ARTIFACT_SELECTION` and native fetch primitives | `PLATFORM_SPECIFIC_NATIVE_FETCH` | focused scanner tests | STATIC/SYNTHETIC | ordinary installers remain benign-compatible |
| persistence after removal | npm-local artifact state | generic persistence state machine | `PERSISTENT_EFFECT_AFTER_INITIAL_REMOVAL` | focused scanner tests | STATIC/SYNTHETIC | no live persistence observer |
| symbols vs capability | agent static/runtime split | three explicit capability levels | `STATIC_CAPABILITY_HINTS` | macOS tests | STATIC/SYNTHETIC | symbols never prove runtime behavior |
| primary/secondary discrepancy | IOC lifecycle only | source claim + canonical impact governance | `SOURCE_CLAIM_GOVERNANCE` | core tests | AVAILABLE | no automatic source corroboration |
| feed recency | IOC `last_updated` | first-seen/published/ingested/observed fields | `FEED_NEW != THREAT_NEW` | core tests | DATA MODEL | unavailable timestamps remain absent |
