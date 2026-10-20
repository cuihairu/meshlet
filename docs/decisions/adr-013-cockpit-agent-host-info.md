# ADR-013: Cockpit Agent as a Local Host-Info Source

Status: Accepted 2026-10-20 (user decision)

## Context

Cockpit keeps an agent on hosts for inventory and operations. Meshlet needs basic node
facts (hostname, addresses, OS, network interfaces) to place devices into networks and
segments. Both projects are user-owned; duplicating host-fact collection in both agents
would drift and waste.

## Decision

- **Mesh networking belongs to Meshlet.** Cockpit does not grow a mesh data plane. Its
  existing frp/WireGuard overlay stays as observation/legacy integration; any new mesh
  capability in Cockpit means integrating with Meshlet, not reimplementing it.
- **Meshlet consumes basic host facts from the local cockpit-agent** (same host,
  read-only local API) instead of collecting them itself. Facts are limited to node
  basics — no secrets, no inventory semantics.
- cockpit-agent is an **optional source**, never a hard dependency: Meshlet must still
  enumerate interfaces and self-describe when cockpit-agent is absent.
- The concrete local read API contract lands with Cockpit's agent capability protocol
  slice (tracked in cockpit `todo.md`, 竞品功能强化 P0).

## Consequences

- No duplicate host-fact collectors; each project keeps its boundary (Cockpit =
  control plane and operations, Meshlet = mesh data plane).
- Per-host, offline-friendly integration (local API, no cloud round trip).
- Meshlet carries an optional edge dependency and must degrade cleanly without it.
- Cockpit must keep the local read API scoped and stable: basic facts only.

## Revisit

If Meshlet needs richer host facts (services, ports, containers), reopen via Cockpit's
capability protocol work rather than widening this API ad hoc.
