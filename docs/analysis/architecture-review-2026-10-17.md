# Architecture Review and TODO Assessment · 2026-10-17

## Scope and conclusion

This review distinguishes a passing test from production readiness. It preserves the current WireGuard hub topology and the existing revision model, while identifying gaps that can affect real multi-network deployments, confirmation of device configuration, recovery, and service permissions.

## Findings

- **Network isolation:** a single server instance needs independent data-plane resources for each network. Tests must prove isolation across networks, not only within one network.
- **Apply confirmation:** a successful hub operation does not prove that every device installed the new configuration. Device receipts must participate in the effective-state decision.
- **Recovery:** restoring SQLite state alone does not restore the hub's kernel state. Startup reconciliation and recovery evidence must cover both.
- **Rollback:** cleanup is not equivalent to restoring the last known-good configuration. A failed change must not silently leave the network unusable.
- **Direct LAN routing:** controlled SNAT needs an executable plan and a real data-plane acceptance case.
- **Service permissions:** the production service account and privileged hub operations need a clearly verified boundary.

## How to use the TODO

Items are complete only within their stated acceptance scope. Unit tests, injected failures, network-namespace tests, and a real deployment provide different levels of evidence. A skipped privileged test is not a data-plane pass. Work should proceed from isolation and recovery foundations toward forwarding refinements and real-host acceptance.
