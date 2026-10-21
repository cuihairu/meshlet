# R-04：Linux Agent 端到端进展

R-04 仍未整体完成。注册、启动恢复、执行回执、重试和升级已实现；真实连接诊断还需要真机部署验收。

## 已完成

- 自举注册优先复用已保存的 agent 凭证，把凭证写成 `0600` 秘密文件；本机私钥只生成或复用，绝不上送。流程与权限证据在 `apps/agent/src/bootstrap.rs:17`、`apps/agent/src/bootstrap.rs:67`、`apps/agent/src/bootstrap.rs:146`。
- 服务端只保存 Bootstrap Token 的 SHA-256 摘要（`crates/meshlet-domain/src/entities.rs:141`）。注册把摘要连同使用与撤销状态入库，列表响应不泄露摘要（`apps/server/tests/device_registration.rs:278`）。
- 启动恢复读取已应用计划账本，通过期望哈希与内核状态对比识别漂移和损坏账本，只在需要时重放。证据在 `apps/agent/src/reconcile.rs:68`、`apps/agent/src/reconcile.rs:86`。
- 每次计划应用都上报精确 Revision 回执；失败会留在内存队列，并在下一个 tick 开始时重试。证据在 `apps/agent/src/agent.rs:136`、`apps/agent/src/agent.rs:140`。队列上限 16 且丢弃最旧条目由 `apps/agent/src/agent.rs:701` 锁定。
- 自更新先拉取公开 manifest，再校验二进制 SHA-256，通过后原子替换二进制、保留备份并写入 restart 标记。版本选择、哈希不匹配、Current 不动作和安装覆盖在 `apps/agent/src/self_update.rs:219` 到 `apps/agent/src/self_update.rs:259`。服务端在 `apps/server/src/lib.rs:941` 暴露 `/api/v1/update-manifest`。
- 心跳采集真实内核证据，并向 Hub 发送不分片的大包探测；缺失值明确表示未证实，不会补默认值。证据在 `apps/agent/src/agent.rs:422`、`crates/meshlet-domain/src/entities.rs:156`。

## 遗留

- 执行真实 VPS 到设备的连接诊断验收并归档证据。TODO 中的对应拆分项显式留下轮。
