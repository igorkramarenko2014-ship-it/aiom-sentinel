# Windows Collector Contract

implementation_authority: NONE
current_runtime_status: DESIGN_ONLY

Supported Windows versions are unresolved pending primary-source compatibility and test matrices.
Candidate documented sources are process/service APIs, ETW providers, optional Sysmon ingestion,
registry callbacks through an independently reviewed signed component, and Filter Manager minifilter
surfaces. File-system, process, registry, ETW/Sysmon, and service-health streams remain distinct.

Any privileged component requires signing, least privilege, authenticated bounded IPC, no full-file
kernel buffering, explicit event-loss counters, bounded queues, backpressure, health evidence, and
host-availability rollback. Native or undocumented structures and fixed addresses are non-normative.
Normalized events map native file/process/user identities without pretending path alone is identity.
Command lines and user content are sensitive; raw memory is restricted-content and case-authorized.

Validation requires supported-build enumeration, event fidelity/loss tests, ACL/IPC tests, update and
rollback drills, load tests, crash/timeout behavior, and primary-source review. Sysmon is optional
ingestion, not an assumed dependency or integrity root.
