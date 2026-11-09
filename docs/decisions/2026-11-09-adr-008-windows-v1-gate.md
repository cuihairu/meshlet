# ADR-008 设计确认：Windows `SystemBackend` 接线门槛（#52）

日期：2026-11-09。性质：对 [ADR-008](/decisions/adr-008-windows-network-backend) 的设计确认与
依赖梳理，不是新的方向决策。结论：**#52 不是「没活」，是「阻塞于 R-05 三项真机验收」**——
接线设计已经就绪（见下），缺的是只有真机能产生的证据。

## ADR-008 的原文结论（复读）

- Status: *Accepted as a platform direction; complete support remains unverified*——平台方向已定，
  完整支持未验证。
- 「Do not claim Windows support until the lifecycle and acceptance matrix is complete」——
  验收矩阵齐之前不得声称支持。
- Revisit 条件：a supported Windows environment **and** test plan；验收必须覆盖 installation、
  elevation、repeated apply、partial failure、uninstall、route cleanup、**reboot recovery**。

ADR-008 列的七项验收面与 R-05 三项真机缺口的对应关系：installation/部分安装 = tunnel
lifecycle 的 install 侧；elevation = elevation exec；uninstall/route cleanup = 已 PASS 的
windows_cleanup_e2e；reboot recovery = boot-recovery 重启项。

## tunnel-only v1 口径

Windows v1 是 **Overlay client**（设备侧只装隧道 + 路由 + 防火墙规则），**不含 gateway/NAT**：

- ADR-006 的 alias-prefix NAT 是网关侧能力；ADR-002 的 hub 中继在 Linux hub 上执行。
- 代码事实：Windows 侧**没有 NAT 原语**——`windows_firewall` 只有规则/profile，无 `windows_nat`
  模块；Linux 的 `apply_nat_sync`（iptables）没有 Windows 对应物。这是
  [D2 实装映射](/implementation/decisions-actions-2026-10-30) 已记录的 gap。
- v1 口径即 D2 的选项 2：**NAT-bearing 计划在 Windows 上显式拒绝（fail-closed）**，只接受
  tunnel+routes+firewall 计划；绝不静默丢弃 NAT 段（§10.3）。若未来需要 Windows 网关，走
  D2 选项 1（新增 `windows_nat` 模块 + 真机验证），作为 v2 立项，不在 #52 范围内。

## 接线依赖图（#52 的前置）

```
#52 SystemBackend 接线（lib.rs:90 unsupported::UnsupportedBackend → 真实实现）
 ├─ R-05-1 WireGuardNT 隧道全生命周期真机（驱动安装→install→start→stop→uninstall）——BLOCKED
 ├─ R-05-2 elevation exec 层真机首跑（windows_elevation.rs:194 起的 #[cfg(windows)] 层从未真机执行）——BLOCKED
 ├─ R-05-3 boot-recovery 重启恢复验证——BLOCKED
 ├─ tunnel-only v1 设计口径确认（本文档）——已确认
 └─ 接线设计映射（D2：原语→backend 方法表）——已就绪
```

前置三项未过真机之前，Windows 保持显式 `unsupported` 占位（`lib.rs:90`；每个数据面操作报
`NetworkError::Unsupported`，绝不假装生效，§10.3/§12.2）——这是 ADR-007 降级纪律的平台镜像，
也是 r05 验收记录明确写下的接线决定：「deliberately deferred until 1–3 are accepted」。

## 为什么是阻塞而不是缺设计

- **设计**：D2（2026-10-30）已把候选 backend 的每个方法映射到既有原语
  （`windows_tunnel`/`windows_routes`/`windows_firewall`/`windows_service`/`windows_elevation`/
  `windows_console`/`windows_cleanup`），含幂等重应用、私钥不出客户端、状态读回与失败分类。
- **计划层质量**：全部七模块计划层在 Linux 上单测跑绿；routes/firewall/service/uninstall 四面
  已有 2026-10-25/26 中文 Server 2022 真机证据（见 [R-05 状态矩阵](/implementation/r05-status)）。
- **缺口唯一来源**：三个只有真机能产生的事件——隧道全生命周期、elevation exec、重启恢复。
  win-worker 已永久停用；2026-11-05 起三台 Windows 真机可用（imac / openclaw / work-win11），
  R-05 验收在 imac 上进行中。执行属真机手动项（巡检单口径：BLOCKED，需用户执行，优先 imac）。

## 接线时的已知真机问题（elevation 模型）

D2 记录的未答题保留给真机：`scripts/install.ps1` 的 HKCU Run 自启是**非提权**会话——控制面够用，
但 `netsh`/`sc`/`wireguard.exe` 需要提权。接线时在 (a) 操作点经 `windows_elevation` runas 提权
与 (b) 托管服务承载网络执行 之间二选一；`relaunch_elevated` 能否承载全部能力（含无人登录恢复）
是真机问题（D1），代码侧答不了。AGENT-WIN-2（2026-10-31）的部署用了计划任务 SYSTEM 方案，
是该问题的一条真机数据点，但未按 (a)/(b) 口径验收——留到 R-05-2 一并结论。
