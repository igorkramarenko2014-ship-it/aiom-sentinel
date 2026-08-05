# Product Risk Register — P0

| ID | Risk | Consequence | Mitigation | Gate |
|---|---|---|---|---|
| PROD-01 | UI binds to unstable core structs | breaking product API | versioned DTO/service boundary | P1 |
| PROD-02 | path or symlink escape | scans unintended targets | canonical validation; skip symlinks by default | P1 |
| PROD-03 | cancellation leaves work running | resource/UI inconsistency | cancellation token and terminal state test | P2 |
| PROD-04 | UI invents severity/confidence | misleading security claim | preserve nullable core fields | P1 |
| PROD-05 | history leaks paths or content | local privacy loss | labels only; no content; explicit storage policy | P3 |
| PROD-06 | webview command exposure | arbitrary local execution | narrow allowlist; no shell command | P1 |
| PROD-07 | packaging implies antivirus readiness | unsafe user expectation | explicit nonclaims and unsigned-build labeling | P4 |
| PROD-08 | persistence becomes premature database | migration/rollback cost | JSON first; measured SQLite trigger | P3 |
| PROD-09 | baseline verifier weakened | regression hidden | existing 14/14 lane remains mandatory | every phase |
| PROD-10 | untrusted evidence rendered as HTML | injection | escaped text rendering and fixture test | P1 |
