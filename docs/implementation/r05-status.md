# R-05 验收现状矩阵（2026-11-09 本机静态核实）

对 [R-05 验收记录](/implementation/r05-windows-acceptance) 与
[AGENT-WIN-2](/agent-win-2-acceptance) 的逐项核对结论。本页只做**证据核对**（本席 headless
Linux，无法执行 Windows 真机项）；每项标注 PASS / MISSING / BLOCKED(环境) 与 file:line 证据，
不新造任何结论。父项 R-05 与 #52 保持未勾。

汇总：**6 项 PASS（已有真机证据）/ 3 项 BLOCKED(真机待执行) / 1 项接线 BLOCKED(前置三项)**。

## 已有真机证据（PASS）

| # | 项 | 状态 | 真机证据 |
|---|---|---|---|
| 1 | `windows_routes` exec（add/show/delete/幂等重删） | PASS | 2026-10-16 CI runner en-US + 2026-10-26 中文 Server 2022 全循环（r05-windows-acceptance.md:54-56） |
| 2 | `windows_firewall` exec（add/show/delete/幂等重删） | PASS | 2026-10-26 真机（r05-windows-acceptance.md:57-58） |
| 3 | `windows_service` exec（create/stop/删除；1060/1062 双通道幂等） | PASS | 2026-10-26 真机，含「服务尚未启动」1062 新发现（r05-windows-acceptance.md:47-50,59-60） |
| 4 | `windows_cleanup` 卸载清理（重入集成测试真机闭环） | PASS | `windows_cleanup_e2e` 2026-10-26 真机：service/route/firewall 幂等 step-through（r05-windows-acceptance.md:61-65） |
| 5 | `windows_console` CP936/GBK 解码 | PASS | 真机 GBK 字节序列（`找不到元素。` 等 6 条）钉为测试常量（r05-windows-acceptance.md:24-34,36-45,76-78） |
| 6 | AGENT-WIN-2 端到端（Win11 imac） | PASS | 2026-10-31：隧道服务 Running、ping hub/self、路由表、防火墙规则、agent 计划任务、tray-host 全绿（agent-win-2-acceptance.md:12-21） |

AGENT-WIN-2 附带两条真机发现：

- **KernelDrift 持续重放**：隧道系手动预装、状态与计划不一致，agent 持续纠回、功能正常——
  这是 reconcile 漂移纠回循环的真机工作证据（agent-win-2-acceptance.md:24）。
- **tray GDI 占位图标**（PNG 未解码）：代码侧已修——`apps/tray-host/src/icon.rs:95,105` 已有
  `png_decode`；真机复核归 AGENT-WIN-3。
- 页脚「5/5 项通过」与表内 8 行的计数不一致，按原文如实转录，不改写
  （agent-win-2-acceptance.md:21）。

## 仍缺真机证据（BLOCKED(环境)——等用户在真机执行，优先 imac）

| # | 项 | 状态 | 缺口与证据 |
|---|---|---|---|
| B1 | WireGuardNT 隧道**全生命周期**（驱动安装→install→start→stop→uninstall） | BLOCKED(真机) | r05-windows-acceptance.md:97-98；模块头自证「执行层真机报文、开机恢复重启验证」未取（crates/meshlet-network/src/windows_tunnel.rs:362-366，「TODO #52 / R-05 保持未勾」:42）。AGENT-WIN-2 只证明 start 之后能运行——驱动是手动预装的（agent-win-2-acceptance.md:5），install/uninstall/驱动安装三步仍无真机证据 |
| B2 | `windows_elevation` exec 层真机首跑 | BLOCKED(真机) | 计划层 66 测试全平台绿，但 `#[cfg(windows)]` exec 层「**Never run on a real Windows machine** — must not be wired as SystemBackend」（r05-windows-acceptance.md:66-71,99-100；执行层入口 windows_elevation.rs:194 起） |
| B3 | boot-recovery 重启恢复（重启后隧道/路由/防火墙状态复原） | BLOCKED(真机) | r05-windows-acceptance.md:101-102；windows_tunnel.rs:366 同证 |

## 接线决定（BLOCKED 于上三项）

| 项 | 状态 | 说明 |
|---|---|---|
| #52 `SystemBackend` 接线 | BLOCKED(前置) | Windows 保持显式 `unsupported` 占位（crates/meshlet-network/src/lib.rs:90，`UnsupportedBackend` 定义 unsupported.rs:23、impl :195，每操作显式 `Unsupported`）。r05-windows-acceptance.md:103-105 原文「deliberately deferred until 1–3 are accepted」。设计确认已落 [ADR-008 接线门槛](/decisions/2026-11-09-adr-008-windows-v1-gate)——tunnel-only v1 口径 + D2 原语映射就绪，缺的只有 B1–B3 真机证据 |

## 执行路径

- 真机资源：win-worker 已永久停用（r05-windows-acceptance.md:94）；2026-11-05 起三台 Windows
  可用（imac 192.168.5.117 / openclaw 10.240.0.3 / work-win11 `cuihaitao` 10.240.0.5，
  r07-deployment-acceptance.md:203-206），R-05 验收在 imac 进行中。
- B1–B3 需要用户手动在真机跑（本席无法代执行）；跑通后回填本矩阵并勾 R-05。
