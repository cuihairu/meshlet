# Agent Communication, Platform Backends, and Observability

## Agent communication

The server publishes a desired plan for each authorized device. Agents authenticate, fetch the plan, reconcile local WireGuard and route state, and report health and application evidence. A pending registration receives no desired plan until approval.

## Platform backends

Linux is the first implemented networking backend. Its operations must be attributable to Meshlet and safe to reconcile after interruption. Windows requires a separate backend for tunnel service lifecycle, elevated operations, cleanup, and reboot recovery; command-level prototypes do not count as a complete client.

## Observability

Structured logs and metrics describe API outcomes, revision state, agent reports, and data-plane evidence. No single signal proves connectivity: recent agent reports, WireGuard handshakes, applied revisions, and route checks answer different questions.

## Console

The console presents device, route, revision, and diagnostic state. It should distinguish loading errors and pending application from an empty or successful state, and refresh when device acknowledgements arrive.
