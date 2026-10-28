<p align="center"><img src="logo-copper.svg" width="64" height="64"></p>

> **English** | [中文](README.zh.md)

<h1 align="center">meshlet</h1>

<p align="center">
<a href="https://github.com/cuihairu/meshlet/releases"><img alt="Status" src="https://img.shields.io/badge/status-in%20development-orange"></a>
</p>

<p align="center">
<a href="https://github.com/cuihairu/meshlet/actions/workflows/ci.yml"><img src="https://github.com/cuihairu/meshlet/actions/workflows/ci.yml/badge.svg" alt="Tests"></a> <a href="https://github.com/cuihairu/meshlet/actions/workflows/docs.yml"><img src="https://github.com/cuihairu/meshlet/actions/workflows/docs.yml/badge.svg" alt="Docs deploy"></a> <a href="https://cuihairu.github.io/meshlet/"><img src="https://img.shields.io/badge/docs-site-brightgreen" alt="Docs"></a> <a href="LICENSE"><img src="https://img.shields.io/badge/license-Apache--2.0-blue" alt="License"></a> <a href="https://cuihairu.github.io/meshlet/design/logo-preview.html"><img src="https://img.shields.io/badge/logo-B%20amber%20copper-C97B2E" alt="Logo variant"></a>
</p>

Self-hosted private networking on your own VPS — Rust + WireGuard.

> [!NOTE]
> The control plane, WireGuard hub/agent, LAN routing and Alias NAT, console, authentication,
> audit, backup and device approval are implemented. This revision adds single-instance network
> isolation, device apply receipts, hub recovery, last-good-plan rollback, Direct LAN SNAT and
> service permissions, with local Linux kernel and unprivileged service regression evidence.
> Windows and long-run soak acceptance remain pending. See [TODO](todo.md).

## Nightly builds and one-command installation

The [nightly workflow](https://github.com/cuihairu/meshlet/actions/workflows/nightly.yml) runs daily at **19:17 UTC (03:17 Asia/Shanghai)** and supports manual dispatch. After the checks and required Linux kernel dataplane tests pass, it publishes a rolling [nightly prerelease](https://github.com/cuihairu/meshlet/releases/tag/nightly) and an immutable dated release. Packages include the server, agent, CLI, web console and systemd units for Linux x86_64 and ARM64.
**Install the server on your VPS:**

```bash
curl -fsSL https://github.com/cuihairu/meshlet/releases/download/nightly/install.sh | sudo bash -s -- server
```

The installer needs a shell, `curl` (or `wget`) and `sudo`, plus package-manager write access. A minimal Debian container ships none of those, so start with `apt-get update && apt-get install -y curl sudo` — or fetch with `wget -qO-` and pipe into `bash`.

The installer installs dependencies, verifies the archive's SHA-256, creates a service account and local WireGuard key, and enables the service. The console listens on `127.0.0.1:8080` by default. To access a remote VPS:

```bash
ssh -L 8080:127.0.0.1:8080 user@your-vps
```

Open `http://127.0.0.1:8080`, create the administrator, a network and a device bootstrap token. Allow the network's UDP port in the VPS firewall: `51820` for the first network by default, increasing by one for each subsequent network. Configure an HTTPS reverse proxy for public administration as described in the [installation guide](docs/guide/install.md).

**Install an agent on a Linux device:**

```bash
curl -fsSL https://github.com/cuihairu/meshlet/releases/download/nightly/install.sh | sudo bash -s -- agent \
  --server-url 'https://meshlet.example.com' \
  --hub-endpoint 'YOUR_VPS_PUBLIC_IP:51820' \
  --bootstrap-token 'TOKEN_FROM_THE_CONSOLE' \
  --name 'home-linux'
```

Approve the device in the console, then apply the network's current revision. Hub execution, device receipts and connectivity probes are reported separately.

Re-run the same role to upgrade to the latest successful nightly. Existing TOML files, private keys, device credentials and databases are preserved; installed devices do not automatically upgrade each day. To install a dated release, replace `nightly` in the download URL with its full release tag and pass `--version 'THAT_TAG'`. Use `--no-start` to install without starting the service.

```bash
systemctl status meshlet-server   # use meshlet-agent on a device
journalctl -u meshlet-server -n 100 --no-pager
cat /usr/local/share/meshlet/server-build-info
```

The workflow must be merged into the default branch and run successfully once before download assets exist. This installer requires Linux with systemd; the Windows dataplane remains pending. See the [installation guide](docs/guide/install.md) for configuration details.

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
- [TODO](todo.md) — tracked items with phase and acceptance criteria
- [Logo color options](https://cuihairu.github.io/meshlet/design/logo-preview.html)

## Status

Control plane (networks, invites, device enrollment, LAN routes, Alias mappings, diagnostics,
backup/restore) and the WireGuard dataplane (hub relay + agent: pull plan → reconcile → apply
tunnel/routes/NAT → heartbeat) are implemented and covered by the workspace test suite, including
privileged netns tests that drive a real kernel WireGuard and real iptables. Session auth, CSRF,
API tokens, audit logging, presence, the config-revision state machine (a DB write never claims
to be effective until applied), and ZeroTier-style device self-registration (bootstrap token →
pending → approve/deny) are in place.

The current implementation is not fully accepted for deployment. See the
[P0 fixes and nightly implementation record](docs/implementation/fixes-and-nightly-2026-10-17.md)
for local Linux evidence. ARM64 builds, the first nightly publication on the default branch,
empty-VPS installation, Windows support and real-device walkthroughs remain pending.
The current checklist at the top of [TODO](todo.md) records these limits.

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

