# ADR-015 Rust Core and Compatible Native Adapters
implementation_authority: NONE
current_runtime_status: DESIGN_ONLY
## Status
Accepted.
## Context
Native SDKs may require other languages.
## Decision
Rust owns portable core; adapters are language-neutral contracts using authenticated IPC or C ABI. No C/C++ scanner clone.
## Alternatives
Rewriting the core in C++ is rejected.
## Consequences
Native code remains outside trusted portable core.
## Security Impact
Least privilege and isolation are required.
## Privacy Impact
Adapters receive minimum data.
## Availability Impact
IPC isolates adapter crashes.
## Verification Requirements
ABI verifier rules.
## Implementation Phase
Design only.
## Unresolved Questions
Per-platform SDK choices.
