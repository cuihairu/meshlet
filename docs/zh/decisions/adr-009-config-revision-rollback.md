# ADR-009：配置版本、应用状态与回滚机制

- 状态：Accepted
- 日期：2026-10-14
- 期次：Phase 0
- 来源：[存档 §10](../review/chatgpt-2026-10-13.md#_10-配置状态机与事务应用)

## 背景

数据库写入成功 ≠ WireGuard/路由/NAT 已生效（§10.1）。配置变更跨"期望状态 → 编译 → 应用到 OS"多步，且必须可回滚、可并发安全。

## 问题

如何建模配置的应用过程与失败恢复？

## 候选方案

1. **版本化 Revision + 状态机 + 幂等应用 + 乐观并发**
2. 直接写库即视为生效
3. 每次变更整体重建（无版本）

## 决定

- 每次变更生成新的 `ConfigRevision`（network 内单调递增 + `desired_config_hash`）；
- 状态机：`pending → applying → applied | failed → rollback_pending → rolled_back`；非法跃迁拒绝；不确定结果进入明确失败态，不假装成功；
- 应用幂等：同一版本重复应用结果一致，不破坏网络；
- 并发：同一 Network 串行化（乐观锁：revision 冲突即拒绝/重试），避免交叉修改 Peer/路由/NAT；
- 回滚只删除/恢复 Meshlet 自有对象（ADR-007 的 table/chain 与接口归属），**不得清空系统路由**；
- 控制台显示以应用状态为准，不以 DB 写入为准。

## 理由

- 状态机让"半配置"可见可诊断（§12.2 验收）；
- 幂等 + 期望态哈希支撑服务端重启后按库内期望重建（§17.3）。

## 缺点与风险

- 状态机实现与 OS 操作必须严格对应，测试矩阵较大；
- applying 崩溃后的"未知态"需要 inspect 协调（backend inspect 能力是前提）。

## 2026-10-17 修订：执行计划、设备回执与恢复

- 只允许应用当前修订；旧 Pending 和旧 Applied 请求均拒绝，未知版本仍为 404。当前 Applied 的重复请求不重新收敛新资源。
- hub 执行前持久化 Applying 意图；成功计划、修订结果和资源状态在同一 SQLite 事务提交。公共成功计划保存到 `hub_deployments`，不包含私钥。
- `apply_status` 是 hub 结果，`convergence` 单独报告设备回执与业务探测。设备计划哈希基于实际配置，包含版本、MTU、公钥与规则，区别于网络修订簿记哈希。
- 设备只确认当前 `desired_revision` 与确切 `plan_hash`；候选计划在 hub 成功后下发，路由/Alias 等待全部相关 Active 设备回执，避免将生命周期 Active 当作配置确认。旧 ACK 不能覆盖新状态。
- 回滚重放上一份成功 hub 计划并读回，同时恢复路由/Alias 期望项；首次应用失败仅清理本网络的 hub。恢复失败保持不确定状态。撤销的设备不会因旧计划恢复而重新进入 hub。
- 服务启动立即、随后每 30 秒检查最后成功计划；Applied 簿记不能代替内核检查。恢复错误持久化并在当前修订详情中报告。
- 业务健康未探测时明确报告 `not_probed`，不把 WireGuard 配置成功当作业务可达。

验证入口：`apps/server/tests/single_instance.rs`、`agent_plan.rs`、`revisions.rs`；真实 VPS 与 Windows 验收另列 TODO。

## 重新评估条件

- 配置变更频率升高到需要异步队列；
- 多管理员并发成为常态，需要细粒度锁。
