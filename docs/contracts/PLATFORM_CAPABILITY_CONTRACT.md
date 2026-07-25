# Platform Capability Contract

implementation_authority: NONE
current_runtime_status: DESIGN_ONLY

Shared core records `Windows`, `Linux`, `MacOs`, or `Unknown`; platform adapters own native detail.
Allowed capability states are `SUPPORTED`, `DEGRADED`, `UNSUPPORTED`, `NOT_AUTHORIZED`, and
`NOT_IMPLEMENTED`. Verification is `ARCHITECTURE_READY`, `BUILD_VERIFIED`, `TEST_VERIFIED`,
`RUNTIME_VERIFIED`, or `PRIVILEGED_INTEGRATION_VERIFIED`. A runtime claim requires an evidence_reference.

PE is bounded metadata only. ELF and Mach-O are `NOT_IMPLEMENTED`, never parsed by placeholder code.
