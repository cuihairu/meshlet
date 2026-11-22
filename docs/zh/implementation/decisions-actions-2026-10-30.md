# 决策立即动作执行（2026-10-30）

> 记录自[阻塞项代决记录](/zh/decisions/2026-10-30-decisions)中无需密钥/账号/用户私有数据/外部软件、本轮已执行的「立即动作」。其余在该文档中标「待用户」。仓库事实以工作树为准核对（基线 `a11d376` + `51c70f3`/`6230d2b`）；分析结论与代码不一致处，以代码为准。

---

## D2 — Windows 数据面接线：实现映射

范围：今天能从哪些材料搭建候选 Windows `SystemBackend`，以及缺什么。非 Linux 别名目前是 `unsupported::UnsupportedBackend`（`crates/meshlet-network/src/lib.rs:60`）。按决策，接线以 D1（真机）为门禁；本映射是接线将遵循的设计。

### 原语 → 候选后端方法

Linux 后端实现 `apply_tunnel_sync` / `apply_routes_sync` / `apply_nat_sync` / `apply_device_plan_sync` / `rollback_sync`（`crates/meshlet-network/src/linux.rs`）。Windows 对应侧把每个映射到既有原语（计划层 + `#[cfg(windows)]` 执行层）：

| 候选方法 | 原语（全在 `crates/meshlet-network/src/`） | 备注 |
|---|---|---|
| `apply_tunnel` | `windows_tunnel` — `render_wireguard_conf`、`WireGuardCommand`（install/start/stop/uninstall）、`exec::run_wireguard_command`、`exec::write_tunnel_conf` | `WireGuardTunnel$<name>` 受管服务；私钥写入客户端受保护目录、绝不由服务端携带；`None` 密钥 = 复用既有（幂等重应用） |
| `apply_routes` | `windows_routes` — `NetshRouteCommand`、`replace_route_commands`、`exec::run_route_command`、`route_prefixes_on_interface` | `netsh interface ipv4`；经 `replace_route_commands` 先删后换 |
| 防火墙（计划一部分） | `windows_firewall` — `FirewallRule`、`FirewallRuleCommand`、`firewall_rule_present`、`net_category_is_private`（D3：经 `Set-NetConnectionProfile` 的 ICMPv4 + `Private` 配置文件） | 仅规则；`localip=<overlay>` 限定作用域 |
| 服务控制 | `windows_service` — `ServiceCommand`（create/start/stop/delete）、`service_absent`、`service_not_active`、`classify_sc_failure` | 幂等处理 1060/1062（真机已文档化） |
| 提权 | `windows_elevation` — `ManagedExecutablePath`（`C:\Program Files\Meshlet`）、`relaunch_elevated`、`current_process_is_elevated`、`classify_elevation_failure` | runas 重启 + 探测；决策中的「提权执行」问题 |
| 控制台解码 | `windows_console` — `decode_output` | CP936/GBK → UTF-8（zh-CN 输出曾是真机根因） |
| `rollback` | `windows_cleanup` — `CleanupPlan`、`CleanupCommand`、`exec::run_cleanup_command` | 幂等拆除服务/路由/防火墙/隧道；真机端到端 |
| 状态读回 | `windows_routes::route_prefixes_on_interface`、`windows_service::{service_absent, service_not_active}`、`windows_firewall::{firewall_rule_present, net_category_is_private}` | 供对账差异与探测 |
| 失败分类 | `windows_tunnel::classify_wireguard_failure`、`windows_service::classify_sc_failure`、`windows_routes::classify_netsh_route_failure`、`windows_elevation::classify_elevation_failure` | 失败关闭；仅真机文档化的消息 |

### 缺口：无 Windows NAT/端口转发原语

`apply_nat_sync`（`linux.rs:874`）经 iptables 实现 alias 前缀 NAT 与直连 LAN SNAT。**没有 Windows 模块提供等价物**——`windows_firewall` 只管规则/配置文件，且没有 `windows_nat`。因此候选后端无法应用携带 NAT/转发段的计划。两个如实选项（接线时再选，非现在）：

1. 新增 Windows NAT 原语（如 L4 转发用 `netsh interface portproxy`；SNAT/alias 用 WinNAT 服务）并在真机验证——新模块，不在现有 7 个之内。
2. 在 Windows 上显式拒绝携带 NAT 的计划（与现有 `unsupported` 占位同款失败关闭精神），选项 1 完成前只接受隧道+路由+防火墙计划。

接线决策不得静默丢弃 NAT 段。

### HKCU 登录自启 vs 提权网络执行

- `scripts/install.ps1` 注册**每用户 HKCU Run** 项：agent 在已登录用户会话中启动，**不带提权**。这对控制面（注册/心跳/状态）与 D4 的用户会话托盘宿主足够，但对需要提权的 `netsh`/`sc`/`wireguard.exe` 隧道安装不够。
- 因此候选接线需要其一：(a) 经 `windows_elevation` 在特权操作点提权（relaunch elevated / runas，带受管路径检查），或 (b) 运行网络执行的受管服务。既有 `relaunch_elevated` 路径能否承担完整能力——包括后台/无人登录恢复——是**真机问题（D1）**，代码回答不了；在此记录，不作断言。

---

## D4 — Windows 托盘宿主：设计规格

按决策「首选薄 Win32 `Shell_NotifyIcon` 封装」消费 agent 已写的四态 PNG（`apps/agent/src/tray.rs`、`TraySink`）。既有模块注释已否决 `tray-icon`/`tao`/`winit`；薄封装延续这一立场。

### 状态 → 图标/文本/提示

`TrayState`（`apps/agent/src/tray.rs:66`）有四态，各有 `accessible_name()`（en）、`tooltip()`（zh）与 `color()`：

| 状态 | accessible_name | tooltip | 图标 |
|---|---|---|---|
| `Online` | "Meshlet online" | 在线：控制通道正常，数据面与服务端期望一致 | 现有 Online PNG / 颜色 (201,123,46) |
| `TunnelOnly` | "Meshlet tunnel only" | 隧道连通但控制通道失效 | 现有 TunnelOnly PNG / (228,160,60) |
| `TunnelDrift` | "Meshlet tunnel drift" | 隧道异常：本地内核对象与服务端期望不一致 | 现有 TunnelDrift PNG / (192,57,43) |
| `Offline` | "Meshlet offline" | 已断开：无新鲜的控制通道或隧道证据 | 现有 Offline PNG / (120,130,138) |

图标来源：复用 `TraySink::publish` 写入的 PNG（真值源）。PNG → `HICON` 需要解码器；优先 GDI+ 或极简 PNG 解码，而非引入重型图像 crate。（若解码代价高，后备：直接经 GDI 画轮廓/`color()`，PNG 仍为规范素材。）

### 菜单与动作（v1）

- **入口分流（2026-11-06 用户定案，取代上一版「打开本地 panel URL，缺省回落 server 控制台」的口径）**:
  - **本地面板** — tray-host 自托管的 loopback 只读页（`127.0.0.1` 随机端口，`apps/tray-host/src/panel.rs`），三块内容：当前节点（名称 / 虚拟 IP / 公钥指纹 / 状态灯 / hub 控制通道 / 版本 / EnvProbe）、直连节点（`direct-peers.json` 全量）、本地路由（`applied.json` 计划路由）。数据只读 `{state_dir}` 下的状态文件，**server 不可达时照样打开**。这是托盘的默认入口。
  - **控制台(网页)** — 原 v1 行为：浏览器打开 `server_url`（server 根路径托管的控制台）。本地 API（`docs/analysis/agent-local-api-2026-10-19`）仍只读鉴权那一支，与本页无关。
- **退出**：停止当前用户会话 agent（对账循环优雅关停）。按决策，退出**不**删除持久隧道——`WireGuardTunnel$<name>` 服务与路由保留。菜单文案必须写明：「退出仅停止当前用户会话的 agent，不删除已安装的隧道」。
- v1 无设置中心/桌面面板/多平台 GUI（决策：明确不做）。活跃菜单为：首行状态 + 「直连节点」/「连接节点…」子菜单 + 「本地面板」/「控制台(网页)」 + 「退出」。

### 单实例

每用户会话一个托盘宿主。命名互斥量/对象守卫：第二个 agent 实例不得创建重复图标——改为通知正在运行的实例（或退出）。

### 宿主机制（薄封装）

- 隐藏/仅消息窗口 + `WndProc`；`NOTIFYICONDATA`；`Shell_NotifyIcon` `NIM_ADD`/`NIM_MODIFY`/`NIM_DELETE`；经 `CreatePopupMenu` + `WM_RBUTTONUP`/`WM_CONTEXTMENU` 上的 `TrackPopupMenu` 出上下文菜单；退出时销毁图标并解除挂钩。
- `WM_TASKBARCREATED`（资源管理器重启）→ 重新添加图标；处理会话锁定/解锁。
- 状态更新来自 agent 的状态通道；复用 `TrayState::derive` 输出，不在宿主重新推导。

### 验收（真机，D4）

逐态切换并检查图标/菜单、资源管理器重启恢复、退出清理。此部分属**真机项（待用户）**；本规格是实现将遵循的设计。

---

## D10 — 恢复验收合同（恢复后，不应指望 apply 修复网络）

按决策采纳：**apply 保持幂等**；恢复合同为：停服务 → 恢复备份 → 启动服务 → 验证收敛。「数据库恢复完成」与「系统真正可用」是两个不同进度状态。

### 合同

1. 停止写入路径并确认已停（不再向将被替换的库写入）。
2. 恢复备份文件。
3. 启动服务；确认恢复路径已运行——生产启动恢复是 `recover_once`（`apps/server/src/convergence.rs:194`），不是「点 apply」动作。
4. 验证收敛：peer、路由、必要 NAT、真实连通。
5. 验证已撤销/被拒设备仍被拒（旧计划重放必须通过当前授权——决策的安全约束；不得重新开放已撤销设备）。

### 语义

- `ConfigLedger::apply` 对已 `Applied` 的修订幂等返回（`crates/meshlet-domain/src/config_state.rs:230`）；重点旧修订**不是**恢复路径，不得如此呈现。
- 上报：「库恢复完成」仅在恢复确实完成时为真；「网络恢复完成」需要第 4 步。不得合并两者。
- 未来「检查并修复实际状态」动作是独立、经授权的入口（复用恢复与授权约束）——不得静默改变 `apply` 的含义。

### 验收标准（记录在案）

停并确认已停 → 恢复 → 启动并确认恢复完成 → 检查 peer/路由/NAT/连通 → 撤销设备仍被拒。实际执行属 R-07 验收（环境门禁）；标准在此记录为合同。
