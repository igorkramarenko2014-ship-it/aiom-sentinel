# PLATFORM_SUPPORT_MATRIX

implementation_authority: NONE
current_runtime_status: DESIGN_ONLY

| Platform | Static scanner architecture | Local verification | CI state | Runtime claim | evidence_reference |
| --- | --- | --- | --- | --- | --- |
| Windows | ARCHITECTURE_READY | NOT_IMPLEMENTED | CI_CONFIGURED_NOT_EXECUTED | NOT_IMPLEMENTED | none |
| Linux | ARCHITECTURE_READY | NOT_IMPLEMENTED | CI_CONFIGURED_NOT_EXECUTED | NOT_IMPLEMENTED | none |
| macOS | ARCHITECTURE_READY | TEST_VERIFIED | CI_CONFIGURED_NOT_EXECUTED | RUNTIME_VERIFIED | local Phase 1 release receipt |

The macOS claim is limited to the measured user-mode static scanner gate. No privileged integration exists.
