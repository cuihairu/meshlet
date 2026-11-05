# Task: P2P-⑤ hub 暴露节点公网端点（用户令 2026-11-04）

todo.md 该项含定位，grep 后直接动手，勿通读大仓。

交付：
1. hub 心跳源地址目前只存 IP 丢端口：`apps/server/src/agent.rs:114` `direct_observed_ip` 返回 `Option<Ipv4Addr>`；改为记录含端口（或并入候选生成）。观测点在 `apps/server/src/agent.rs:263` → 存 `DeviceDirectState.observed_ip`（p2p.rs:160）。
2. `meshlet-api-types` Device 增 `observed_endpoint` / `public_endpoint`（`observed_ip:listen_port`）；公网候选可由 `endpoint_candidates` 合成（p2p.rs:173）。同步 `console/src/api/index.ts` 的 `Device` 类型。
3. console 设备表/诊断页展示新字段。
4. 底层数据同供后续拓扑图/节点下钻，详析见 docs/analysis/easytier-comparison.md P0。

门禁与流程：
- 按改动范围跑测试 + clippy -D warnings，全绿才 commit；改文档则真跑 docs 构建。
- 单 commit（英文简短），rebase 后推，禁 force push。
- 每完成一小步即单 commit 推送，勿攒批。
- 完成后把 todo.md 的 P2P-⑤ 勾掉或注明进度（验收项如实标注）。

后续可选项（不强制本轮）：MT-005 [P2] 任务超时回收重派/重试上限/worktree 隔离/标签路由，范围大，先 grep 定位出拆解再动手。
