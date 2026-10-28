# R-05: Windows Data-Plane Acceptance Record

This page transcribes **recorded real-machine evidence only** for the R-05 Windows
data-plane sub-items (routes, firewall, service, uninstall cleanup) accepted on a
real Chinese Windows Server 2022 during 2026-10-25/26. No value or conclusion on
this page was newly measured here. The R-05 parent item stays unchecked: three
real-machine gaps remain and are listed under [Still blocked](#still-blocked).

Sources: the `todo.md` R-05 data-plane sub-item (2026-10-25/26 record) and the
module headers of `crates/meshlet-network/src/windows_*.rs`.

## Machine and toolchain (as recorded)

- Real machine: Chinese Windows Server 2022 (local), sessions on 2026-10-25 and
  2026-10-26.
- Toolchain: GNU, `stable-x86_64-pc-windows-gnu` — full-workspace `cargo test`
  and `cargo clippy --workspace --all-targets -- -D warnings` both exit 0.
- CI: `.github/workflows/ci.yml` matrix `os: [ubuntu-latest, windows-latest]`
  runs `cargo test --workspace` natively on windows-latest, with `clippy -D
  warnings` there as well.

## The localization root cause and its fix

netsh / sc.exe **redirected output is the active code page, not UTF-8**.
Real-machine bytes: netsh deleting a missing route returns `D5 D2 B2 BB B5 BD D4
AA CB D8 A1 A3` (GBK for `找不到元素。`). The exec layers had decoded with
`String::from_utf8_lossy`, so all zh-CN text was lost to U+FFFD and every
localized idempotent-delete match failed — caught by the real-machine
`windows_netsh` integration test.

Fix recorded: `windows_console` — UTF-8 first (valid UTF-8 passes through
unchanged), non-UTF-8 decoded with `MultiByteToWideChar(CP_ACP)` (windows-sys
already a dependency, `Win32_Globalization` added). Discipline: never panic,
never return empty text pretending success (§10.3).

## Real-machine messages the classifiers match (verbatim)

| Surface | Message (zh-CN, decoded from CP936) | Classification |
|---|---|---|
| route missing | `找不到元素。` | idempotent success for route delete |
| sc service missing | `指定的服务未安装。` (exit 1060) | idempotent success for service stop/delete |
| sc service never started | `服务尚未启动。` (exit 1062) | idempotent success for service stop |
| firewall rule missing | `没有与指定标准相匹配的规则。` | idempotent success for rule delete |
| elevation required | `请求的操作需要提升(作为管理员运行)。` | `InsufficientPrivileges` |
| access denied | `拒绝访问。` | `InsufficientPrivileges` |

New real-machine discovery: `sc stop` of a never-started service returns 1062
`服务尚未启动。` — Stop's target state is "stopped", so not-running already
satisfies it; recorded as idempotent success (exit code 1060/1062 dual-channel
with the text match).

## Per-module verification status (from module headers)

- **`windows_routes`** — exec verified 2026-10-16 (CI runner, en-US) and
  2026-10-26 (Chinese Windows Server): add / show readback / delete /
  idempotent re-delete full loop.
- **`windows_firewall`** — exec verified 2026-10-26: add / show readback /
  delete / idempotent re-delete.
- **`windows_service`** — exec verified 2026-10-26: create / stop (incl.
  never-started 1062 idempotent) / delete / re-delete (1060 idempotent).
- **`windows_cleanup`** — plan layer only; exec reuses the three verified exec
  wrappers. The uninstall re-entry integration test `windows_cleanup_e2e`
  closed the loop on real hardware 2026-10-26: service create→stop→delete→
  re-delete, firewall add→show→delete→re-delete, and an empty-state
  `CleanupPlan` stepping through as idempotent.
- **`windows_elevation`** — plan layer (managed `.exe` path validation,
  `runas` command-line escaping, error code/text → `InsufficientPrivileges`)
  compiles and unit-tests on all platforms (66 tests); the `#[cfg(windows)]`
  exec layer (ShellExecuteW `runas` + TokenElevation query) passed
  `x86_64-pc-windows-msvc` clippy/check. **Never run on a real Windows
  machine** — must not be wired as `SystemBackend`.
- **`windows_tunnel`** (2026-10-27) — WireGuardNT plan layer (conf render,
  install/uninstall argv, idempotent re-apply, failure classification) +
  `#[cfg(windows)]` exec primitives landed; the file-level
  `tests/windows_tunnel.rs` runs on CI windows-latest. Real-machine tunnel
  lifecycle still pending (see below).
- **`windows_console`** — shared decoder; real-machine GBK bytes pinned as
  test constants.

## Test evidence (as recorded, acceptance snapshot)

- `meshlet-network`: **75 unit tests + 3 real-machine integration tests** all
  green (2026-10-25/26 snapshot; the crate has since grown with the tunnel
  plan layer).
- Full workspace `cargo test` and `cargo clippy` on
  `stable-x86_64-pc-windows-gnu`: exit 0.
- CI windows-latest runs `cargo test --workspace` natively.
- The previously failing `windows_netsh` case (idempotent re-delete) turned
  green after the CP936 fix.

## Still blocked

These three remain BLOCKED and are the reason R-05 stays unchecked. **win-worker
已永久停用 — the win-worker is permanently decommissioned; completing them
requires a user-provided rebootable Windows machine.**

1. **WireGuardNT tunnel full lifecycle** — install the WireGuardNT driver, then
   run install → start → stop → uninstall on real hardware.
2. **Elevation exec layer real-machine run** — the `windows_elevation` exec path
   has never executed on real Windows.
3. **Boot-recovery restart verification** — reboot and confirm the
   tunnel/route/firewall state recovers.
4. **#52 `SystemBackend` wiring decision** — deliberately deferred until 1–3 are
   accepted; until then Windows keeps the explicit [unsupported] placeholder
   and no data-plane operation pretends to succeed (§10.3, §12.2).
