# Network Diagnostics

Diagnostics report observations and do not repair the system. A run captures a timestamped set of checks and persists the result so that an operator can inspect the latest report later.

## What is checked

The checks cover network and device presence, revision state, gateway availability, published LAN routes, Alias consistency, tunnel evidence, data-plane reports, and relevant NAT or MTU signals. Each result identifies its layer and distinguishes healthy, failed, not applicable, and unverified conditions.

## API and console

An authenticated operator starts a run with the diagnostics endpoint and reads the latest result separately. A `404` before any run means that no report exists; it is not an implicit live check. The console presents the recorded findings and should not hide request failures behind an empty report.

## Suggested workflow

Confirm the target network and current revision, inspect device reports and WireGuard handshakes, then examine gateway and route findings. Compare the report timestamp with recent agent activity. Diagnostics narrow the search; they do not replace packet-level checks or a real end-to-end test.
