> **English** | [中文](README.zh.md)

<p align="center"><img src="logo-copper.svg" width="64" height="64"></p>

<h1 align="center">meshlet</h1>

<p align="center"><a href="https://github.com/cuihairu/meshlet/releases"><img alt="Status" src="https://img.shields.io/badge/status-in%20development-orange"></a> <a href="https://github.com/cuihairu/meshlet/actions/workflows/ci.yml"><img src="https://github.com/cuihairu/meshlet/actions/workflows/ci.yml/badge.svg" alt="Tests"></a> <a href="https://github.com/cuihairu/meshlet/actions/workflows/docs.yml"><img src="https://github.com/cuihairu/meshlet/actions/workflows/docs.yml/badge.svg" alt="Docs deploy"></a> <a href="https://cuihairu.github.io/meshlet/"><img src="https://img.shields.io/badge/docs-site-brightgreen" alt="Docs"></a> <a href="LICENSE"><img src="https://img.shields.io/badge/license-Apache--2.0-blue" alt="License"></a> <a href="https://cuihairu.github.io/meshlet/design/logo-preview.html"><img src="https://img.shields.io/badge/logo-B%20amber%20copper-C97B2E" alt="logo-B amber copper (approved)"></a></p>

Self-hosted private networking on your own VPS — Rust + WireGuard.

> [!NOTE]
> The control plane, WireGuard hub/agent, LAN routing and Alias NAT are implemented.
> So are the console, authentication, audit, backup and device approval.
> This revision adds single-instance network isolation, device apply receipts, hub recovery and last-good-plan rollback.
> It also adds Direct LAN SNAT and service permissions.
> Evidence comes from the local Linux kernel and unprivileged service regression runs.
> Windows backend modules are implemented and real-machine verified.
> Covered: routes, firewall, service control and uninstall cleanup.
> A Windows agent+CLI+tray-host zip and `install.ps1` now ship in the nightly release.
> The agent's live data-plane wiring and real-machine installer/tray-host acceptance remain pending (R-05, AGENT-WIN).
> Long-run soak acceptance also remains pending. See [TODO](todo.md).

## Nightly builds and one-command installation

The [nightly workflow](https://github.com/cuihairu/meshlet/actions/workflows/nightly.yml) runs daily at **19:17 UTC (03:17 Asia/Shanghai)** and supports manual dispatch. After the checks and the required Linux kernel dataplane tests pass, it publishes a rolling [nightly prerelease](https://github.com/cuihairu/meshlet/releases/tag/nightly). It also publishes an immutable dated release. The release carries Linux x86_64 / ARM64 static tar archives. It also carries per-component `deb` and `rpm` packages (`meshlet-server` / `meshlet-agent` / `meshlet-cli`). A Windows agent+CLI+tray-host zip and the `install.sh` / `install.ps1` installers ship alongside.
**Install the server on your VPS:**

```bash
curl -fsSL https://github.com/cuihairu/meshlet/releases/download/nightly/install.sh | sudo bash -s -- server
```

The installer needs a shell, `curl` (or `wget`) and `sudo`, plus package-manager write access. A minimal Debian container ships none of those. Start with `apt-get update && apt-get install -y curl sudo`, or fetch with `wget -qO-` and pipe into `bash`.

The installer installs dependencies and verifies the archive's SHA-256. Then it creates a service account and a local WireGuard key, and enables the service. The console listens on `127.0.0.1:8080` by default. To access a remote VPS:

```bash
ssh -L 8080:127.0.0.1:8080 user@your-vps
```

Open `http://127.0.0.1:8080`, create the administrator, a network and a device bootstrap token. Allow the network's UDP port in the VPS firewall. The first network defaults to `51820`, and each subsequent network increases by one. Configure an HTTPS reverse proxy for public administration as described in the [installation guide](docs/guide/install.md).

**Install an agent on a Linux device:**

```bash
curl -fsSL https://github.com/cuihairu/meshlet/releases/download/nightly/install.sh | sudo bash -s -- agent \
  --server-url 'https://meshlet.example.com' \
  --hub-endpoint 'YOUR_VPS_PUBLIC_IP:51820' \
  --bootstrap-token 'TOKEN_FROM_THE_CONSOLE' \
  --name 'home-linux'
```

Approve the device in the console, then apply the network's current revision. Hub execution, device receipts and connectivity probes are reported separately.

Re-run the same role to upgrade to the latest successful nightly. Existing TOML files, private keys, device credentials and databases are preserved. Installed devices do not automatically upgrade each day. To install a dated release, replace `nightly` in the download URL with its full release tag and pass `--version 'THAT_TAG'`. Use `--no-start` to install without starting the service.

```bash
systemctl status meshlet-server   # use meshlet-agent on a device
journalctl -u meshlet-server -n 100 --no-pager
cat /usr/local/share/meshlet/server-build-info
```

**Install from Linux packages (deb / rpm):**

The nightly release also publishes component-split packages for both architectures. `meshlet-server` ships the server binary, systemd unit, web console and example config. `meshlet-agent` ships the agent binary, systemd unit and example config. `meshlet-cli` is the standalone CLI:

```bash
# Debian / Ubuntu (replace amd64 with arm64 on ARM)
curl -fLO https://github.com/cuihairu/meshlet/releases/download/nightly/meshlet-server_0.0.0~nightly_amd64.deb
curl -fLO https://github.com/cuihairu/meshlet/releases/download/nightly/meshlet-agent_0.0.0~nightly_amd64.deb
sudo apt install ./meshlet-server_0.0.0~nightly_amd64.deb ./meshlet-agent_0.0.0~nightly_amd64.deb

# Fedora / RHEL (replace x86_64 with aarch64 on ARM)
sudo dnf install https://github.com/cuihairu/meshlet/releases/download/nightly/meshlet-server-0.0.0~nightly-1.x86_64.rpm
sudo dnf install https://github.com/cuihairu/meshlet/releases/download/nightly/meshlet-agent-0.0.0~nightly-1.x86_64.rpm
```

Packages create the service account and state directory, but deliberately do not generate live configuration. The configuration is machine-specific and contains keys and tokens: copy `/etc/meshlet/*.toml.example` and fill it in. Then generate the key (`wg genkey > /etc/meshlet/hub.key` for the server). Run `sudo systemctl enable --now meshlet-server` (or `meshlet-agent`). For a guided first install use `install.sh` above.

The workflow must be merged into the default branch and run successfully once before download assets exist. `install.sh` requires Linux with systemd; Windows agents install with `install.ps1` from the [Windows support](#windows-support) section below. See the [installation guide](docs/guide/install.md) for configuration details.

## Windows support

Windows is a data-plane target gated behind real-machine acceptance
([R-05](docs/implementation/r05-windows-acceptance.md), ADR-008). What the repository ships today:

- Backend modules are verified on real machines (Chinese Windows Server 2022, 2026-10-25/26). Covered: route management with `netsh interface ipv4` and firewall rules with `netsh advfirewall firewall`. Service control (`sc`) and uninstall cleanup are covered the same way: add / read-back / delete / idempotent re-delete. zh-CN output (GBK/CP936) is decoded by `windows_console`.
- WireGuardNT tunnel plan layer + CI: `windows_tunnel` renders the `WireGuardTunnel$<name>`
  service config and builds `wireguard.exe` argv; its file-level test runs on `windows-latest`
  CI. The real-machine tunnel lifecycle is still pending.
- Cross-platform evidence: full-workspace `cargo test` and
  `cargo clippy --workspace --all-targets -- -D warnings` pass on `stable-x86_64-pc-windows-gnu`. CI runs `cargo test --workspace` natively on `windows-latest`.

Still not available on Windows:

- The agent's live data-plane backend is not wired. `SystemBackend` on Windows is the explicit
  `unsupported` placeholder until the tunnel lifecycle, elevation exec and boot-recovery items pass
  real-machine acceptance. A Windows agent registers and reports status. Applying a tunnel/routes/NAT plan is rejected with an explicit error; nothing pretends to succeed.
- MSI is in the nightly, and real-machine install acceptance is pending. The nightly release publishes a Windows agent+CLI+tray-host zip (`meshlet-nightly-windows-x86_64.zip`). It also publishes an `install.ps1` installer ([install below](#install-the-agent-on-windows)). The MSI installer is `meshlet-nightly-windows-x86_64.msi`, built with cargo-wix. It packages server, agent, CLI and tray-host in one installer. It adds start-menu shortcuts and an Add/Remove Programs entry. Neither installer has been accepted on a real machine yet (AGENT-WIN-2, NIGHTLY-MSI-1 in `todo.md`).
- A Windows tray host ships, real-machine acceptance pending. `apps/tray-host` (`meshlet-tray-host.exe`) is a thin Win32 `Shell_NotifyIcon` host. It consumes the agent's four-state status PNGs (`TraySink`). `install.ps1` copies it, registers HKCU logon autostart with the agent state directory, and starts it unless `-NoStartTray` is passed. Real-machine walkthroughs (icon switching, menus) remain pending. Its menu splits two entries: **本地面板 (local panel)** — a read-only page the tray host serves itself on `127.0.0.1` (current node, direct peers, local routes read from the local state files, so it opens even when the server is unreachable) — and **控制台(网页) (web console)**, which opens `server_url`. On Linux the agent writes the same status PNGs and sends D-Bus desktop notifications. The repository holds no panel host binary for either platform's desktop shell beyond what ships here.

### Install the agent on Windows

The nightly release publishes a Windows agent+CLI+tray-host zip and `install.ps1`. Install (PowerShell, no
elevation needed — the agent runs in the user session, not as a machine service):

```powershell
Invoke-RestMethod https://github.com/cuihairu/meshlet/releases/download/nightly/install.ps1 -OutFile install.ps1
pwsh -File .\install.ps1 -ServerUrl 'https://meshlet.example.com' -HubEndpoint '203.0.113.10:51820' -BootstrapToken 'TOKEN_FROM_THE_CONSOLE' -DeviceName 'home-windows'
```

The installer verifies the zip's SHA-256 against the release `SHA256SUMS`. It installs `meshlet-agent.exe`, `meshlet-cli.exe` and `meshlet-tray-host.exe` into `%LOCALAPPDATA%\meshlet` and adds that directory to the user PATH. It generates an agent key and config once, and registers per-user HKCU Run autostart entries for the hidden agent and tray host.
Re-run it to upgrade — the existing `agent.toml` and key are preserved, so device credentials
survive. Offline/staged installs use `$env:MESHLET_INSTALL_ARCHIVE` and
`$env:MESHLET_INSTALL_SHA256SUMS`. The installer starts the background agent and tray host by default; pass `-NoStartTray` to skip the tray host's immediate start while keeping its logon autostart entry. Data-plane apply on Windows is still rejected until real-machine acceptance passes — see below.

### Build and run the agent on Windows (from source)

Prefer the installer above; build from source only when you want a local build. Cross-building from Linux to `x86_64-pc-windows-msvc` is check/clippy level only. Native builds on Windows (MSVC, the CI toolchain) are the supported path. Requires Rust (stable) and Git:

```powershell
git clone https://github.com/cuihairu/meshlet.git
cd meshlet
cargo build --release --bin meshlet-agent
```

Create `C:\ProgramData\meshlet\agent.toml`. Keys mirror the Linux example in the [installation guide](docs/guide/install.md); `interface` is the WireGuardNT tunnel name:

```toml
server_url = "https://meshlet.example.com"
state_dir = "C:\\ProgramData\\meshlet-agent"
# device_token = "…agent_token from enroll…"   # or the bootstrap pair below
# bootstrap_token = "…bootstrap token from the console…"
# device_name = "edge-win-1"

[dataplane]
enabled = true
interface = "wg-meshlet"                  # service shows as WireGuardTunnel$wg-meshlet
private_key_file = "C:\\ProgramData\\meshlet\\agent.key"
hub_endpoint = "203.0.113.10:51820"
poll_interval_secs = 30
```

Run it from an elevated terminal:

```powershell
meshlet-agent.exe C:\ProgramData\meshlet\agent.toml
```

Approve the device in the console, then apply the network's current revision. **Data-plane apply on Windows is currently rejected** (backend placeholder) until R-05 acceptance. The control plane (registration, heartbeats, status) works. A machine that only has the
`WireGuardTunnel$…` service (e.g. set up by hand) does **not** have the agent running — check for
`meshlet-agent.exe` in the process list. Real-machine installer and tray-host acceptance are
tracked as pending work — see [TODO](todo.md).

## What it is

Run the meshlet server on a VPS with a public IPv4 address. Then install agents on your Linux/Windows devices to get a private virtual network you fully control:

- Stable overlay IPv4 addresses between devices (relayed through your VPS)
- Access to remote LANs behind a gateway device
- Alias prefixes for overlapping LAN subnets (e.g. two `192.168.1.0/24`)
- Web console for networks, devices, routes and diagnostics

Connection strategy: the hub is always on. Devices first connect through the hub and exchange peer info, then upgrade to P2P direct. Direct paths are same-LAN links or hole-punch dialing to hub-observed public endpoints (`apps/agent/src/direct.rs`). Wide cross-NAT punch scenarios still need real-machine acceptance. Hub relay is the always-available fallback so links never drop.

Not in scope for v1: public relay networks, L2 bridging, internet exit VPN.

## Documentation

| Document | What it covers |
| --- | --- |
| [Analysis overview](https://cuihairu.github.io/meshlet/analysis/) | structured breakdown by topic |
| [Architecture and TODO review](docs/analysis/architecture-review-2026-10-17.md) | verified implementation gaps and proposed priorities (Chinese) |
| [Personal networking comparison](docs/analysis/personal-networking-comparison.md) | 61 capabilities compared with ZeroTier and Tailscale, with sources and feasibility (Chinese) |
| [External review archive (2026-10-13)](https://cuihairu.github.io/meshlet/review/chatgpt-2026-10-13.html) | verbatim archive of the external conversation; opinions only, verify against code before acting on anything |
| [TODO](todo.md) | tracked items with phase and acceptance criteria |
| [Logo color options](https://cuihairu.github.io/meshlet/design/logo-preview.html) |  |

## Status

The control plane and the WireGuard dataplane are implemented. The control plane covers networks, invites, device enrollment, LAN routes, Alias mappings, diagnostics, backup/restore. The WireGuard dataplane covers hub relay and the agent path.
Agent path: pull plan → reconcile → apply tunnel/routes/NAT → heartbeat. Both are covered by the workspace test suite. That includes privileged netns tests driving a real kernel WireGuard and real iptables. Session auth, CSRF, API tokens, audit logging and presence are in place. The config-revision state machine is in place too (a DB write never claims to be effective until applied). Device self-registration is ZeroTier-style: bootstrap token → pending → approve/deny.

The current implementation is not fully accepted for deployment. See the
[P0 fixes and nightly implementation record](docs/implementation/fixes-and-nightly-2026-10-17.md)
for local Linux evidence. ARM64 builds and the first nightly publication on the default branch remain pending. So do empty-VPS installation and real-device walkthroughs. On Windows the data-plane wiring (R-05) and real-machine installer/tray-host acceptance also remain pending. See [Windows support](#windows-support).
The current checklist at the top of [TODO](todo.md) records these limits.

## License

[Apache-2.0](LICENSE)

---

[Chinese version](README.zh.md)

## Local Testing Conventions

CI and local development gate on the surface area that changed. Editing one line of docs should not trigger a full build.

1. **Docs-only changes** (`*.md`, `docs/**`, images): no compile. The main CI workflow's
   `paths-ignore` already skips these paths.
2. Code changes: run only the affected subset, never the full suite.
   - `cargo test -p <changed crate>`
3. **Full suite** (`cargo test --workspace`): only for — Cargo.toml / Cargo.lock /
   console/pnpm-lock.yaml, `.github/**`, Docker/Compose config, and pre-release.

