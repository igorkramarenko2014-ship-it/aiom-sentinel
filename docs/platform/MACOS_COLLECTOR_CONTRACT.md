# macOS Collector Contract

implementation_authority: NONE
current_runtime_status: DESIGN_ONLY

Supported macOS versions are unresolved pending Apple entitlement and API compatibility review.
Endpoint Security authorization and notification events, system extensions, Network Extension,
FSEvents, and service health are separate surfaces. Network Extension is outside the initial collector
phase. Kauth/KEXT details are legacy research, not normative implementation guidance.

An Endpoint Security client requires Apple-granted entitlements, signing/notarization, system-extension
approval, explicit auth deadlines, cache invalidation, event-loss handling, bounded queues, and fail-safe
host-availability policy. FSEvents is change notification, not complete security telemetry. Native code
signing remains one signal only. Plists, LaunchAgents/Daemons, Login Items, and user configuration have
distinct privacy and authorization boundaries.

Validation covers supported releases, entitlement failure, dropped events, auth deadline behavior,
extension upgrade/rollback, privacy redaction, crash recovery, and normalized identity mapping.
