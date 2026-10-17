# ADR-007: Linux Networking Backend

**Status:** Accepted

## Context

Linux is the initial server and agent platform. The agent must apply WireGuard, routes, and NAT while running with a constrained service account.

## Decision

Implement the Linux backend as explicit reconciliation operations with attributable Meshlet-owned resources. Keep desired-plan construction separate from privileged execution and make apply results observable.

## Rationale and operational constraints

The host backend must safely handle repeated application, stale-resource cleanup, partial failure, and process restart. A service unit and runtime privilege model must agree: the production account must be able to perform only the required network operations. Ownership markers must prevent cleanup from deleting unrelated host rules.

## Evidence

Unit and network-namespace tests cover important paths, but they do not equal a clean VPS deployment. Verify the installed service, effective permissions, WireGuard state, forwarding, firewall, and read-back on a real target before claiming deployment acceptance.

## Revisit when

Kernel APIs, distribution support, or privilege requirements change enough to invalidate the current backend.
