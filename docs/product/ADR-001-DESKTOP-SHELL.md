# ADR-001: Desktop Shell

Status: ACCEPTED FOR P0, implementation deferred to P1
Date: 2026-08-05

## Context

Sentinel is a verified Rust Phase 1 filesystem scanner with deterministic JSON evidence. The repository has no existing UI or desktop shell. The product must remain local-first, non-destructive, and honest about not being antivirus or EDR.

## Options

| Option | Reuse | Packaging | Security boundary | Progress/cancel | Testability | Cost |
|---|---|---|---|---|---|---|
| Tauri 2 + TypeScript UI | High through Rust command boundary | Strong cross-platform path | Explicit webview-to-Rust allowlist | Strong async model | Backend/UI separation | Moderate dependency/tooling |
| egui/eframe | Direct Rust reuse | Good native binary path | Smaller boundary, fewer web risks | Strong Rust control | Rust-focused | Lower stack count, weaker web accessibility |
| Native CLI + local web UI | Maximum core reuse | Requires separate launcher/server packaging | Browser/server boundary and lifecycle complexity | Requires custom job API | Good service testing | Highest operational complexity |

## Decision

Use Tauri 2 with a small TypeScript UI and a Rust application-service layer. The UI may depend only on versioned product DTOs and commands. It must not bind to unstable scanner internals. Tauri is reversible before P1 because the service and DTO boundary are shell-independent.

## Constraints

- Scan execution is local and read-only.
- No arbitrary shell execution from UI input.
- No telemetry, cloud, account, quarantine, remediation, or real-time monitoring.
- File/folder picker and cancellation use explicit backend commands.
- Untrusted evidence is escaped before rendering.

## Rejected alternatives

egui remains viable if Tauri tooling or accessibility requirements fail during P0 toolchain validation. CLI plus local web UI is deferred because it adds a server/lifecycle boundary without current product evidence requiring it.

## Acceptance checks

P0 records this decision. P1 must prove launch, one-file scan, normalized result rendering, deterministic receipt export, and unchanged core baseline.
