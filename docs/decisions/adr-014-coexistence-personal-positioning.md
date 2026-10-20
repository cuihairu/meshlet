# ADR-014: Coexistence with ZeroTier/Tailscale-class Meshes

Status: Accepted 2026-10-20 (user decision)

## Context

ZeroTier and Tailscale already provide mature mesh networking. The question is where
Meshlet stands relative to them: replacement, competitor, or complement.

## Decision

- **Meshlet coexists with ZeroTier/Tailscale-class networks as mutual backup**, not as a
  replacement. A host may run Meshlet alongside one of them; either path failing leaves
  the other usable.
- **Meshlet's positioning is the personal private network.** Its differentiation is not
  protocol completeness but features tailored to an individual's own infrastructure:
  segments as trust boundaries (ADR-012), host facts from the local cockpit-agent
  (ADR-013), enrollment/approval flows (ADR-010/011), and other personal-fit ergonomics.
- Feature priorities follow that positioning: when choosing between "match a
  enterprise VPN feature list" and "fit how one person actually runs their machines",
  pick the latter.

## Consequences

- Interop and coexistence tests matter: Meshlet must not fight another mesh for routes.
- Roadmap pressure from enterprise VPN feature checklists is explicitly out of scope.
- Mutual backup means sane defaults on overlapping address plans — document how Meshlet
  behaves when another mesh occupies part of the LAN.

## Revisit

If a user deployment shows Meshlet and a commercial mesh cannot coexist on one host,
reopen the coexistence contract (address planning, route priority) before adding
protocol features.
