<p align="center"><img src="logo-copper.svg" width="64" height="64"></p>

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
> Early stage: the Rust workspace and a minimal control-plane server exist (network,
> invite and device-enrollment API over in-memory state). WireGuard transport is not
> wired yet — see [TODO](TODO.md) for tracked items and acceptance criteria.

## What it is (planned)

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

Phase 0 done (analysis, ADRs, docs). Phase 1 in progress: domain crates (CIDR/IPAM/conflict/entities/invites), a control-plane server with network/invite/enrollment API, console auth (Argon2id, sessions, rate limiting, CSRF), SQLite migrations, a React console (served by the server via console_dir), online-status verdicts with source + update-time annotation, a config-revision state machine where a DB write never claims to be effective until applied (failures stay visible), and machine credentials for external callers (mlt_ API tokens, read/write scopes, revocable, audit-attributed), 176 tests green. Three high-risk areas remain for validation: WireGuard routing under VPS relay, alias DNAT/SNAT for overlapping subnets, and Windows/Linux network config with safe rollback.

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
3. **全量**（`cargo test --workspace`）：仅以下情形触发——Cargo.toml / Cargo.lock / console/package-lock.json、
   `.github/**`、Docker/Compose 配置、发布前。

