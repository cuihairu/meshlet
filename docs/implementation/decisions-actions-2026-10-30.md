# Decisions immediate actions executed (2026-10-30)

> Record of the immediate actions from [blocked-item decisions](/decisions/2026-10-30-decisions) that need no
> key/account/user-private-data/external-software and were executed this round. The rest are marked
> 「待用户」 in that document. Repo facts are verified against the working tree (baseline `a11d376` +
> `51c70f3`/`6230d2b`); where the analysis and the code differ, the code wins.

---

## D2 — Windows dataplane wiring: implementation mapping

Scope: what a candidate Windows `SystemBackend` can be built from today, and what is missing. The
non-Linux alias is currently `unsupported::UnsupportedBackend`
(`crates/meshlet-network/src/lib.rs:60`). Wiring it is gated on
D1 (real machine) per the decision; this mapping is the design the wiring will follow.

### Primitives → candidate backend methods

The Linux backend implements `apply_tunnel_sync` / `apply_routes_sync` / `apply_nat_sync` /
`apply_device_plan_sync` / `rollback_sync` (`crates/meshlet-network/src/linux.rs`). The Windows
counterpart maps each to an existing primitive (plan layer + `#[cfg(windows)]` exec layer):

| Candidate method | Primitive (all in `crates/meshlet-network/src/`) | Notes |
|---|---|---|
| `apply_tunnel` | `windows_tunnel` — `render_wireguard_conf`, `WireGuardCommand` (install/start/stop/uninstall), `exec::run_wireguard_command`, `exec::write_tunnel_conf` | `WireGuardTunnel$<name>` managed service; private key written to the client protected dir, never carried by the server; `None` key = reuse existing (idempotent re-apply) |
| `apply_routes` | `windows_routes` — `NetshRouteCommand`, `replace_route_commands`, `exec::run_route_command`, `route_prefixes_on_interface` | `netsh interface ipv4`; delete-then-replace via `replace_route_commands` |
| firewall (part of plan) | `windows_firewall` — `FirewallRule`, `FirewallRuleCommand`, `firewall_rule_present`, `net_category_is_private` (D3: ICMPv4 + `Private` profile via `Set-NetConnectionProfile`) | rules only; `localip=<overlay>` scoping |
| service control | `windows_service` — `ServiceCommand` (create/start/stop/delete), `service_absent`, `service_not_active`, `classify_sc_failure` | idempotent 1060/1062 handling (real-machine documented) |
| elevation | `windows_elevation` — `ManagedExecutablePath` (`C:\Program Files\Meshlet`), `relaunch_elevated`, `current_process_is_elevated`, `classify_elevation_failure` | runas relaunch + probe; the elevated-exec question in the decision |
| console decode | `windows_console` — `decode_output` | CP936/GBK → UTF-8 (zh-CN output was the real-machine root cause) |
| `rollback` | `windows_cleanup` — `CleanupPlan`, `CleanupCommand`, `exec::run_cleanup_command` | idempotent service/route/firewall/tunnel teardown; real-machine e2e |
| status read-back | `windows_routes::route_prefixes_on_interface`, `windows_service::{service_absent, service_not_active}`, `windows_firewall::{firewall_rule_present, net_category_is_private}` | for reconcile diff and probe |
| failure classification | `windows_tunnel::classify_wireguard_failure`, `windows_service::classify_sc_failure`, `windows_routes::classify_netsh_route_failure`, `windows_elevation::classify_elevation_failure` | fail-closed; real-machine documented messages only |

### Gap: no Windows NAT / port-forward primitive

`apply_nat_sync` (`linux.rs:874`) implements alias-prefix NAT and Direct LAN SNAT via iptables. **No
Windows module provides the equivalent** — `windows_firewall` is rules/profile only, and there is no
`windows_nat`. The candidate backend therefore cannot apply a plan that carries NAT/forward segments.
Two honest options (to be chosen at wiring time, not now):

1. Add a Windows NAT primitive (e.g. `netsh interface portproxy` for L4 forward; WinNAT service for
   SNAT/alias) and verify on the real machine — a new module, not in the current 7.
2. Explicitly reject NAT-bearing plans on Windows (same fail-closed spirit as the current
   `unsupported` placeholder), and accept only tunnel+routes+firewall plans until option 1 is done.

The wiring decision must not silently drop NAT segments.

### HKCU login autostart vs elevated network execution

- `scripts/install.ps1` registers a **per-user HKCU Run** entry: the agent starts in the logged-in
  user session, **without elevation**. That is sufficient for the control plane (register/heartbeat/
  status) and for the D4 user-session tray host, but **not** for `netsh`/`sc`/`wireguard.exe` tunnel
  installation, which need elevation.
- The candidate wiring therefore needs one of: (a) elevate at the point of the privileged operation
  via `windows_elevation` (relaunch elevated / runas, with the managed-path check), or (b) a managed
  service that runs the network exec. Whether the existing `relaunch_elevated` path can carry the
  full capability — including background/无人登录 recovery — is a **real-machine question (D1)**,
  not answerable from code; it is recorded here, not asserted.

---

## D4 — Windows tray host: design spec

Consume the four-state PNGs the agent already writes (`apps/agent/src/tray.rs`, `TraySink`), per the
decision "prefer a thin Win32 `Shell_NotifyIcon` wrapper". The existing module comment already
declines `tray-icon`/`tao`/`winit`; the thin wrapper keeps that stance.

### State → icon / text / tooltip

`TrayState` (`apps/agent/src/tray.rs:66`) has four states, each with `accessible_name()` (en),
`tooltip()` (zh) and `color()`:

| State | accessible_name | tooltip | icon |
|---|---|---|---|
| `Online` | "Meshlet online" | 在线：控制通道正常，数据面与服务端期望一致 | current Online PNG / color (201,123,46) |
| `TunnelOnly` | "Meshlet tunnel only" | 隧道连通但控制通道失效 | current TunnelOnly PNG / (228,160,60) |
| `TunnelDrift` | "Meshlet tunnel drift" | 隧道异常：本地内核对象与服务端期望不一致 | current TunnelDrift PNG / (192,57,43) |
| `Offline` | "Meshlet offline" | 已断开：无新鲜的控制通道或隧道证据 | current Offline PNG / (120,130,138) |

Icon source: reuse the PNGs `TraySink::publish` writes (source of truth). Converting PNG → `HICON`
needs a decoder; prefer GDI+ or a minimal PNG decode over adding a heavy image crate. (Fallback if
decoding proves costly: draw the silhouette/`color()` directly via GDI, keeping the PNGs as the
canonical asset.)

### Menu and actions (v1)

- **打开面板**: open the panel. The agent has a local API (see `docs/analysis/agent-local-api-2026-10-19`);
  the v1 action opens the local panel URL, falling back to the server console if unset.
- **退出**: stop the current user-session agent (graceful shutdown of the reconcile loop). Per the
  decision, exit does **not** remove the persistent tunnel — the `WireGuardTunnel$<name>` service and
  routes stay. Menu copy must state this: 「退出仅停止当前用户会话的 agent，不删除已安装的隧道」.
- Two items only; no settings center / desktop panel / multi-platform GUI in v1 (decision: 明确不做).

### Single instance

One tray host per user session. A named mutex/object guards it: a second agent instance must not
create a duplicate icon — it signals the running one (or exits) instead.

### Host mechanics (thin wrapper)

- A hidden/message-only window + `WndProc`; `NOTIFYICONDATA`; `Shell_NotifyIcon` `NIM_ADD`/`NIM_MODIFY`/
  `NIM_DELETE`; context menu via `CreatePopupMenu` + `TrackPopupMenu` on `WM_RBUTTONUP`/`WM_CONTEXTMENU`;
  destroy the icon and unhook on exit.
- `WM_TASKBARCREATED` (Explorer restart) → re-add the icon; handle session lock/unlock.
- Status updates arrive from the agent's state channel; re-use `TrayState::derive` output rather than
  re-deriving in the host.

### Acceptance (real machine, D4)

逐态切换 and check icon/menu, Explorer-restart recovery, exit cleanup. This part is a **real-machine
item (待用户)**; this spec is the design the implementation will follow.

---

## D10 — Recovery acceptance contract (after restore, apply must not be expected to fix the network)

Adopted per the decision: **apply stays idempotent**; the recovery contract is
**stop service → restore backup → start service → verify convergence**. "数据库恢复完成" and
"系统真正可用" are two distinct progress states.

### Contract

1. Stop the write path and confirm stopped (no new writes into the to-be-replaced DB).
2. Restore the backup file.
3. Start the service; confirm the recovery path ran — the production startup recovery is
   `recover_once` (`apps/server/src/convergence.rs:194`), not a "click apply" action.
4. Verify convergence: peers, routes, necessary NAT, real connectivity.
5. Verify revoked/denied devices are still rejected (a replay of an old plan must pass current
   authorization — the decision's security constraint; it must not reopen a revoked device).

### Semantics

- `ConfigLedger::apply` returns idempotently for an already-`Applied` revision
  (`crates/meshlet-domain/src/config_state.rs:230`); re-clicking an old revision is **not** a recovery
  path and must not be presented as one.
- Reporting: "库恢复完成" is a true statement only when the restore finished; "网络恢复完成" requires
  step 4. Do not collapse them.
- A future "检查并修复实际状态" action is a separate, authorized entry point (reusing restore and
  authorization constraints) — it must not silently change `apply`'s meaning.

### Acceptance criteria (recorded)

Stop-and-confirm-stopped → restore → start-and-confirm-recovery-completed → check peers/routes/NAT/
connectivity → revoked-device-still-rejected. The actual run is part of R-07 acceptance (environment
gated); the criteria are recorded here as the contract.
