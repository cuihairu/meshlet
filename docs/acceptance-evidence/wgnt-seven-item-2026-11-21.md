# ADR-008 七项验收面（nt 模型）imac 首跑：item 1 抓到真缺陷 + 回滚通过

日期：2026-11-21（夜，imac 真机）。性质：ADR-008 七项验收面按 wireguard-nt
模型重跑的首轮。结论：**item 1（installation）抓到 nt 接线真缺陷——nt 隧道
本身起来了且通包，但 apply 在 mesh 可达性防火墙步被拒、agent 陷入恢复错误
循环；回滚路径（nt→service）实测通过，imac 已回到服务模型健康态。items
2-7 被该缺陷阻塞，待修复后重跑。**

测试物：imac 上暂存的 agent 二进制（`C:\Users\cui\AppData\Local\meshlet\`
`meshlet-agent.exe`，SHA256 `197FF7FEF816A4B35FE733E9D61CC987027D80BCE80F8C373EA046813560F22A`，
BUILD_INFO commit `e75e36e`、built_at `2026-11-21T10:55:14Z`、
`source_dirty=true`、target `x86_64-pc-windows-msvc`）+ 同目录
`wireguard.dll`（SHA256 `B1B85E072C45D81358BE29D94C599DC76652F912BE8C0F0A41E2D5D89A6461D3`，
与真机 PoC 同 dll）。注意：该构建**不含** hub failover（6d20fad），
nt 相关代码全在 e75e36e 之内，验收口径不受影响。

运行载体：`\MeshletAgentDeploy`（S4U / Highest / UserId `cui` / **LogonTrigger
仅**）——agent 进程提权（elevation 面覆盖，见 item 2）。

## 前置（pre-flight，服务模型健康基线）

- `WireGuardTunnel$wg-meshlet` 服务 RUNNING；`wireguard.exe` PID 24368 持有
  UDP 51820；adapter `wg-meshlet` Up（ifIndex 65，MTU 未设 2147483552）。
- 路由：`10.240.0.0/16 → ifIndex 65`，`10.240.0.7/32`、`10.240.255.255/32`
  （metric 256）。
- 防火墙：`Meshlet-ICMPv4-In` + `Meshlet-Direct-UDP-In`（Any profile，Enabled）。
- `applied.json`：revision 33、hub 51820、listen 51820、hub peer `vLkJ…`、
  applied `2026-11-19T14:27:53Z`；`direct-port.json`=`{"listen_port":51820}`。
- hub ping `10.240.0.1`：3/3，0% 丢，4-6ms。SSH overlay（m-imac→10.240.0.7）
  通。证据 `base.txt`。

## item 1 installation（nt 切入）——**抓到真缺陷，部分 PASS**

切 `[dataplane] tunnel_backend = "nt"` → 停旧 agent → 起 nt agent → 60s 核验：

**nt 隧道确实起来了**（功能面全过）：
- `wireguard.exe` 进程消失（stale service 卸载生效）；`WireGuardTunnel$wg-meshlet`
  → 1060（服务不在了）。§1.2 服务单例互踩面清除。
- UDP 51820 改由 `meshlet-agent.exe`（PID 97980）进程内持有——nt 模型
  in-process 绑定实锤。
- nt adapter **OS Name = `WireGuard`**、InterfaceDescription =
  `wg-mlt-wg-mdc44 Tunnel`、ifIndex 42、Up；地址 `10.240.0.7/16` 在其上；
  路由 `10.240.0.0/16 → ifIndex 42`（metric 5）。
- `wg show WireGuard` 读回：pubkey `QmAF…`（与基线一致）、listen 51820、
  hub peer `vLkJ…` endpoint `106.14.216.177:51820`、握手 2s 前（新鲜）。
- hub ping `10.240.0.1`：3/3，0% 丢，5-6ms。

**但 apply 被拒，agent 陷入恢复错误循环**（`state_now.txt` 全段实录）：
```
ERROR meshlet_agent::agent::reconcile: could not restore the last successful
device plan error=apply the desired plan: apply rejected: netsh network category
set private for rule `wg-meshlet` failed (exit 1): Set-NetConnectionProfile :
找不到具有参数名 'InterfaceAlias'... MSFT_NetConnectionProfile ...
restore_error=... retry_in_secs=8/16/30
```
即 `ensure_mesh_reachability_sync`（`Set-NetConnectionProfile -InterfaceAlias
'wg-meshlet' -NetworkCategory Private`）失败——**接口 `wg-meshlet` 在 nt 模型下
不存在**（stale service 卸载时已随 `wg-meshlet` adapter 删除；nt adapter 的
OS 别名是 `WireGuard`）。apply 在 adapter 创建/up/路由之后、防火墙联动之前
被拒 → `applied.json` 未更新、`Meshlet-Direct-UDP-In` 未重加（幸好基线已有），
agent 每 30s 重试、永不成功。**隧道能通包纯因 adapter 已 up + 基线防火墙
规则仍在**——属「功能可用但 apply 从未成功」的带病态。

### 根因（代码侧）

- `crates/meshlet-network/src/windows/process_cmds.rs` `ensure_mesh_reachability_sync`
  与 `probe_net_category_is_private` 均用 `self.interface`（= `wg-meshlet`）
  作为 `-InterfaceAlias`；nt 模型下真实接口名不是它。
- 更深一层：nt adapter 的 **OS 级 InterfaceAlias 是 `WireGuard`**（驱动给
  adapter 的固定名，隧道名 `wg-mlt-wg-mdc44` 只出现在
  `InterfaceDescription`）。因此 `nt_adapter_name()`（返回 `wg-mlt-wg-mdc44`）
  也**不是** `Set-NetConnectionProfile`/`Get-NetIPAddress` 可用的别名——
  `backend.rs` `nt_adapter_address`（按 `InterfaceAlias == wg-mlt-<handle>`
  匹配）与 `inspect_sync` 的别名假设**同样被本证据否定**（实际读数是别名
  `WireGuard`）。修法需以「按 InterfaceDescription 含 `wg-mlt-<handle>` Tunnel
  匹配」或驱动侧查询取 OS 名，而非硬编码任一名称。

## item 2 elevation —— 覆盖（随 item 1 证据）

agent 经 S4U/Highest 任务运行，adapter create/open/set_config/up 全部在
agent 进程内成功、无额外 UAC——nt adapter API 的提权面在 agent 运行载体下
成立（PoC 的「提权小 exe」面已在此前 4/4 PASS）。

## item 3-7 —— **BLOCKED（被 item 1 缺陷阻塞）**

repeated apply / partial failure / uninstall / route cleanup / reboot recovery
均需 nt 模型 apply 成功为前提；当前 apply 恒拒、agent 恒错，结果不可信，
不在带病态上预支结论。**待修复后整轮重跑。**

## item R rollback（nt→service）——**通过**

`state_now` 后按回滚路径：恢复原 config（无 `tunnel_backend` = 默认
service）→ 停 nt agent → **nt adapter 随进程消亡（无 `wg-mlt*` 残留）、
UDP 51820 释放**（进程终止→句柄回收→驱动清理，无 name/port 冲突面）→ 起
service agent → `rollback.txt` 实录：

- `wireguard.exe` PID 98288 复现、持有 UDP 51820；`WireGuardTunnel$wg-meshlet`
  服务 RUNNING；adapter `wg-meshlet` Up（ifIndex 65）；路由 `10.240.0.0/16
  → ifIndex 65` 复原。
- `wg show wg-meshlet` 读回：pubkey `QmAF…`、listen 51820、hub peer `vLkJ…`
  与基线一致；hub ping 3/3 0% 丢 5-6ms。
- 日志 `applied the desired device plan ... reason=KernelDrift`——apply 成功、
  无错误循环。
- 收尾核验：`wg-meshlet` 网络类别回到 **Private**、`OpenSSH Server (sshd)`
  规则 Private+Any、overlay SSH（m-imac→10.240.0.7）恢复。

**结论：回滚路径完整、干净、无残留；生产态（服务模型）已恢复。**

## 判读与建议

- **item 1 缺陷是 nt 接线的真缺陷**，非验收环境问题：`ensure_mesh_reachability_sync`
  用的接口名在 nt 模型下不存在；且 nt adapter 的 OS 别名（`WireGuard`）与
  代码假设（`wg-meshlet` / `wg-mlt-<handle>`）都不符。修复需同时覆盖
  `process_cmds.rs` 的 mesh 可达性步与 `backend.rs` 的 `nt_adapter_address`/
  `inspect_sync` 别名读数。
- **修复方向建议**：以 `InterfaceDescription`（含 `wg-mlt-<handle> Tunnel`）
  反查 adapter 的 OS `Name`（`Get-NetAdapter`），或驱动/句柄侧取 OS 名；不要
  硬编码 `wg-meshlet` 或 `wg-mlt-<handle>`。修复后重建二进制（本机 windows-gnu
  交叉；msvc 交叉被 cc-rs 缺 lib.exe 卡死）、重部署 imac、整轮重跑 items 1-7。
- 本机当前无代码改动（纯验收+回滚），工作区净。

## 附：验收证据文件

`docs/acceptance-evidence/nt-seven-accept-2026-11-21/`：`base.txt`（前置）、
`switch.txt`（nt 切入核验）、`state_now.txt`（错误循环实录）、`adapt.txt`
（nt adapter 命名实证）、`rollback.txt`（回滚实录）、`cat.txt`（回滚后
类别/防火墙核验）。
