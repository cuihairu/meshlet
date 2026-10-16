<p align="center"><img src="logo-copper.svg" width="64" height="64"></p>

> **English** | [中文](README.zh.md)

<h1 align="center">meshlet</h1>

<p align="center">
  <a href="https://github.com/cuihairu/meshlet/actions/workflows/ci.yml"><img src="https://github.com/cuihairu/meshlet/actions/workflows/ci.yml/badge.svg" alt="Tests"></a>
  <a href="https://github.com/cuihairu/meshlet/actions/workflows/docs.yml"><img src="https://github.com/cuihairu/meshlet/actions/workflows/docs.yml/badge.svg" alt="Docs deploy"></a>
  <a href="https://cuihairu.github.io/meshlet/"><img src="https://img.shields.io/badge/docs-site-brightgreen" alt="Docs"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-Apache--2.0-blue" alt="License"></a>
  <a href="https://cuihairu.github.io/meshlet/design/logo-preview.html"><img src="https://img.shields.io/badge/logo-B%20amber%20copper-C97B2E" alt="Logo variant"></a>
</p>

Self-hosted private networking on your own VPS — Rust + WireGuard.

> [!NOTE]
> Implemented and CI-green: control plane, WireGuard dataplane (hub relay + agent), LAN routing and
> Alias NAT, React console, session auth + API tokens + audit, backup/restore, diagnostics, and
> ZeroTier-style device self-registration with center approval. The 2026-10-17 architecture review
> identifies remaining work in single-instance multi-network isolation, device apply confirmation,
> hub recovery, rollback, Direct LAN SNAT, and deployment permissions, alongside Windows support
> and real-hardware validation. See [TODO](TODO.md) for the current scope and acceptance criteria.

## What it is

Run the meshlet server on a VPS with a public IPv4 address, install agents on your Linux/Windows devices, and get a private virtual network you fully control:

- Stable overlay IPv4 addresses between devices (relayed through your VPS)
- Access to remote LANs behind a gateway device
- Alias prefixes for overlapping LAN subnets (e.g. two `192.168.1.0/24`)
- Web console for networks, devices, routes and diagnostics

Not in scope for v1: public relay networks, P2P/NAT hole punching, L2 bridging, internet exit VPN.

## Documentation

- [Analysis overview](https://cuihairu.github.io/meshlet/analysis/) — structured breakdown by topic
- [Architecture and TODO review](docs/analysis/architecture-review-2026-10-17.md) — verified implementation gaps and proposed priorities (Chinese)
- [Personal networking comparison](docs/analysis/personal-networking-comparison.md) — 61 capabilities compared with ZeroTier and Tailscale, with sources and feasibility (Chinese)
- [External review archive (2026-10-13)](https://cuihairu.github.io/meshlet/review/chatgpt-2026-10-13.html) — verbatim archive of the external conversation; opinions only, verify against code before acting on anything
- [TODO](TODO.md) — tracked items with phase and acceptance criteria
- [Logo color options](https://cuihairu.github.io/meshlet/design/logo-preview.html)

## Status

Control plane (networks, invites, device enrollment, LAN routes, Alias mappings, diagnostics,
backup/restore) and the WireGuard dataplane (hub relay + agent: pull plan → reconcile → apply
tunnel/routes/NAT → heartbeat) are implemented and covered by the workspace test suite, including
privileged netns tests that drive a real kernel WireGuard and real iptables. Session auth, CSRF,
API tokens, audit logging, presence, the config-revision state machine (a DB write never claims
to be effective until applied), and ZeroTier-style device self-registration (bootstrap token →
pending → approve/deny) are in place.

The current implementation is not fully accepted for deployment. The latest review reopens
multi-network isolation, distributed apply confirmation, hub kernel recovery, rollback,
Direct LAN SNAT, and service permissions. The Windows dataplane backend (ADR-008) and real-hardware
walkthroughs are also pending. See the current checklist at the top of [TODO](TODO.md);
historical CI results do not establish end-to-end readiness.

## License

[Apache-2.0](LICENSE)

---

[Chinese version](README.zh.md)

## Local Testing Conventions

CI and local development gate on the surface area that changed — editing one line of docs should not
trigger a full build.

1. **Docs-only changes** (`*.md`, `docs/**`, images): no compile. The main CI workflow's
   `paths-ignore` already skips these paths.
2. **Code changes**: run only the affected subset, never the full suite.
   - `cargo test -p <changed crate>`
3. **Full suite** (`cargo test --workspace`): only for — Cargo.toml / Cargo.lock /
   console/pnpm-lock.yaml, `.github/**`, Docker/Compose config, and pre-release.

