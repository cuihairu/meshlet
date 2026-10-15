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
> ZeroTier-style device self-registration with center approval. Still pending real-hardware
> walkthroughs (a real VPS, two physical machines, Windows) — see [TODO](TODO.md) for the tracked
> items and acceptance criteria.

## What it is

Run the meshlet server on a VPS with a public IPv4 address, install agents on your Linux/Windows devices, and get a private virtual network you fully control:

- Stable overlay IPv4 addresses between devices (relayed through your VPS)
- Access to remote LANs behind a gateway device
- Alias prefixes for overlapping LAN subnets (e.g. two `192.168.1.0/24`)
- Web console for networks, devices, routes and diagnostics

Not in scope for v1: public relay networks, P2P/NAT hole punching, L2 bridging, internet exit VPN.

## Documentation

- [Analysis overview](https://cuihairu.github.io/meshlet/analysis/) — structured breakdown by topic
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

Still open: real-hardware walkthroughs — deploying on a real VPS, two real Linux clients
interoperating, and the Windows dataplane backend (ADR-008). See [TODO](TODO.md).

## License

[Apache-2.0](LICENSE)

---

[中文说明](README.zh.md)

## 本地测试口径

CI 与本地开发按改动面三路分流——改一行文档不该全量编译。

1. **文档改动**（`*.md`、`docs/**`、图片）：不编译。主 CI workflow 的
   `paths-ignore` 已跳过这些路径。
2. **代码改动**：只跑改动子集，不全量。
   - `cargo test -p <改动 crate>`
3. **全量**（`cargo test --workspace`）：仅以下情形触发——Cargo.toml / Cargo.lock / console/pnpm-lock.yaml、
   `.github/**`、Docker/Compose 配置、发布前。

