# nt KernelDrift route-reconcile fix — 真机验收（2026-11-22）

**结论**：`routes_from_peers` 修复（`23935ca`）在 nt 真机（imac 测试床，LAN `192.168.5.117`，nt adapter `wg-mlt-wg-mdc44`）**验证通过**——pre-fix 二进制恒 `KernelDrift` 每 30-45s 重放（260 次且持续增长），post-fix 二进制仅启动冷应用一次，随后 **4.5+ 分钟零 KernelDrift**，对账循环照常（direct-peer 迁移持续）。

## 背景（缺陷）

`nt_inspect_sync` 的 `installed_routes` = peers allowed-ips 并集（hub `10.240.0.0/16` 恒在）；叶节点 `plan.routes=[]`。`drifted()` 按「installed route 不在 plan.routes」判「计划外路由」→ 每轮 KernelDrift 重放死循环（`crates/meshlet-network/src/windows/backend.rs:201-207` + `apps/agent/src/reconcile.rs:253-261`，pre-existing，非 dce5e92 引入）。

## 修复（23935ca）

`NetworkSnapshot.routes_from_peers` 新字段（nt 恒 true、service/Linux false）；`drifted()`（apps/agent/src/reconcile.rs:243）与 `device_plan_matches`（crates/meshlet-network/src/reconcile.rs:114）在 `routes_from_peers` 时跳过 `plan.routes` 对照——路由已由 peer 身份级 allowed-ips 比对完全决定，hub `/16` 不再判计划外路由。2 单测（`nt_peer_implied_routes_are_not_route_drift`、`peer_implied_routes_skip_plan_route_check`）；门禁 workspace test 绿、clippy `-D warnings` 双腿、fmt、windows-gnu check、docs build 全绿。

## 验收

- **pre 基线**（18cef2e 二进制，PID 544）：KernelDrift 计数 245（11:06）→ 250（11:09）→ 260（11:16 pre-swap），~30-45s 间隔，`reason=KernelDrift` 恒现。
- **swap**（11:17:28 local，23935ca 二进制 PID 11816，部署法见 `deploy-method.txt`）：exe SHA256 部署前后一致（`6f17ffc1…`）。
- **post**：启动冷应用一次（03:17:32Z，`reason=KernelDrift`——冷启动把 adapter 装配到位），随后 **03:17:35Z 起零 KernelDrift**（观察至 03:45Z，28 分钟）；日志总额 261（260 pre + 1 冷应用，不再增长）；对账循环活跃（direct-peer promote/p2p_direct 持续）；nt adapter Up、`10.240.0.7/16` Preferred。
- **对照**：pre 260 次 vs post 1 次（冷应用），重放死循环终止。

## 修正（2026-11-22 11:45 local）

**原「如实披露」首条「overlay 10.240.0.7 自 coding-vm 不可达」已撤销并更正**：修复部署后 overlay **已恢复且稳定、直连**——coding-vm→imac `10.240.0.7` 10/10 ping 0% 丢包（~2ms），`ssh m-imac` 通；coding-vm 侧有直连 peer（imac `192.168.5.117:51820` LAN endpoint、10.240.0.7/32、握手新鲜 15s keepalive）；imac 侧亦达 hub（`10.240.0.1` True）与 coding-vm（`10.240.0.4` True）。**与修复的因果关系按「重合+机制」陈述（未做对照实验）**：旧二进制每 30-45s 重放 KernelDrift 会反复拆装隧道（flap），与 overlay 不可达同期；修复后重放停→隧道稳定→overlay 恢复+直连建立。原「另案」判断系把修复前的连通症状误当作独立问题——**实际 overlay 恢复正是本修复的副效**。`p2p_direct=7`、`promoted=99/demoted=97`（直连在，循环残留）。

## 原始证据

`baseline-kerneldrift.txt`（pre 计数与样例）、`post-swap-kerneldrift.txt`（post 计数与样例）、`build-info.txt`（commit+哈希）、`deploy-method.txt`（部署法）。

## 如实披露

- 本机 `Model=MS-7C70`（MSI 主板）——证据文档长期称「imac」，实为 nt 测试床机；现网三台仍 wireguard.exe 模型，本批只验证 nt 路由对账修复，**不涉生产切换**（禁写「已切换」）。
- 本修复前后 overlay 连通性变化见上「修正」节：不可达→恢复，与修复部署重合；因果未做对照实验，按重合+机制陈述。LAN SSH（192.168.5.117）全程正常。
