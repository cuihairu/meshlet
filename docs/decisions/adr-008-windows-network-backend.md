# ADR-008: Windows Agent Networking Backend

**Status:** Accepted as a platform direction; complete support remains unverified.

## Context

A useful cross-platform client needs more than invoking a tunnel command. It must manage an elevated networking service, routes, cleanup, and recovery after failure or reboot.

## Decision

Keep Windows-specific operations behind a dedicated backend while sharing domain rules and desired-plan semantics with other platforms. Do not claim Windows support until the lifecycle and acceptance matrix is complete.

## Rationale and trade-offs

A backend boundary avoids spreading platform checks through the domain and API layers. Windows privilege and service behavior differ materially from Linux, so sharing low-level command assumptions would be unsafe.

## Revisit when

A supported Windows environment and test plan are available. Acceptance must cover installation, elevation, repeated apply, partial failure, uninstall, route cleanup, and reboot recovery.
