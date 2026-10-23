# R-04：Linux Agent 端到端进展

R-04 已完成：注册、启动恢复、执行回执、重试与升级均已实现，真实跨主机连接诊断已于 2026-10-24 验收（证据见下方「验收 2026-10-24」）。

## 已完成

- 自举注册优先复用已保存的 agent 凭证，把凭证写成 `0600` 秘密文件；本机私钥只生成或复用，绝不上送。流程与权限证据在 `apps/agent/src/bootstrap.rs:17`、`apps/agent/src/bootstrap.rs:67`、`apps/agent/src/bootstrap.rs:146`。
- 服务端只保存 Bootstrap Token 的 SHA-256 摘要（`crates/meshlet-domain/src/entities.rs:141`）。注册把摘要连同使用与撤销状态入库，列表响应不泄露摘要（`apps/server/tests/device_registration.rs:278`）。
- 启动恢复读取已应用计划账本，通过期望哈希与内核状态对比识别漂移和损坏账本，只在需要时重放。证据在 `apps/agent/src/reconcile.rs:68`、`apps/agent/src/reconcile.rs:86`。
- 每次计划应用都上报精确 Revision 回执；失败会留在内存队列，并在下一个 tick 开始时重试。证据在 `apps/agent/src/agent.rs:136`、`apps/agent/src/agent.rs:140`。队列上限 16 且丢弃最旧条目由 `apps/agent/src/agent.rs:701` 锁定。
- 自更新先拉取公开 manifest，再校验二进制 SHA-256，通过后原子替换二进制、保留备份并写入 restart 标记。版本选择、哈希不匹配、Current 不动作和安装覆盖在 `apps/agent/src/self_update.rs:219` 到 `apps/agent/src/self_update.rs:259`。服务端在 `apps/server/src/lib.rs:941` 暴露 `/api/v1/update-manifest`。
- 心跳采集真实内核证据，并向 Hub 发送不分片的大包探测；缺失值明确表示未证实，不会补默认值。证据在 `apps/agent/src/agent.rs:422`、`crates/meshlet-domain/src/entities.rs:156`。

## 遗留

- ~~执行真实 VPS 到设备的连接诊断验收并归档证据。~~ 本轮已完成，见下方验收记录。

## 验收 2026-10-24（真实跨主机运行）

- 环境：PVE 实验台，hub CT 192.168.5.150（wg0 10.240.0.1/16，:51820）+ 两台设备 CT（10.240.0.2/.3），实验台时钟为 UTC（2026-10-23T22:xxZ）。空库上的完整控制面走查：`POST /api/v1/auth/bootstrap`（201）、登录、二次 bootstrap → 409 `admin user already exists; bootstrap is closed`；`POST /networks` 建 `net-1` 10.240.0.0/16；bootstrap token `max_uses=5` 仅创建时返回原文，列表只给元数据（两台设备入网后 `bt-1 used_count=2`，库里只有 64 字符 SHA-256 摘要，无任何原文）；两台设备持 bootstrap token 自注册、换得 `0600` 保存的 agent token；`POST .../devices/{id}/approve` ×2 立账修订；随后 `POST .../config-revisions/3/apply`（200，`applied` 22:16:37Z）——在该调用之前 desired 端点一律 503 `dataplane_not_configured`，agent 指数退避（实测 `retry_in_secs=256`），apply 后自行收敛。
- 真实跨主机连通（hub ⇄ 每台设备，wg0 overlay）：基线 20×64 B 双向 20/20（平均 0.47–0.94 ms）；DF 边界 `ping -M do`：载荷 1392（1420−28）双向 5/5；负例 1419/1472 从 hub 侧 → `0 received, +2 errors, 100% packet loss`。一台设备尚停在 1480 时，它自己到 hub 的 DF 1419 能通、已收敛到 1420 的兄弟设备不通——边界跟随各端自己的接口，证明探测测的是真实路径而非桩。
- 连接诊断（13 项检查）收敛后全绿：`api_reachable`、`server_peer_configured`（2 台带 hub 侧 peer）、`recent_handshake`（`2/2 … inside the 120s window`）、`config_revision_consistent`（`latest revision #3 is applied at 2026-10-23T22:16:37Z`）、`mtu_planned`（`pve-dev-1 reading 1420 probe 1392; pve-dev-2 reading 1420 probe 1392`）全 pass；LAN/alias/NAT 各项按设计为 `not_applicable`/`unavailable`。设备心跳原文证据：`{"tunnel_mtu":1420,"nat_rules_present":false,"nat_snat_rules_present":false,"mtu_probe_payload":1392}`。
- MTU 收敛（本轮修复的缺陷：旧 agent 把「未配置」当「不动接口」，漂移永不愈合）：修复版 agent（`sha256/16 2114bd9e…`）下，手工抬到 1480 的接口在下个 tick 回到 1420（`applied the desired device plan … reason=KernelDrift`，22:24:53Z）；hub 配置显式 `tunnel_mtu = 1480`（根表）后两台设备一个 tick 内到 1480（`reason=DesiredConfigChanged`），探测报 `probe 1452`，诊断说 `tunnel_mtu = 1480 is explicitly configured; device evidence confirms the plan`；删掉该键后两台设备自行愈合回 1420（22:33:43/22:33:53Z），DF 边界随之回移（1392 通、1452 不通）。
- 如实记录、未在本轮修：hub 自身 `wg0` 的 MTU 跟随**已 apply 的修订**（approve 时立账），设备计划则读服务器实时配置——配置改 MTU 后 hub 停在 1420、设备已到 1480，hub 侧 DF 探测失败而诊断仍按设备证据判 pass。在新修订立账并 apply 之前，隧道容量受 hub 发送侧限制。后续可把实时 MTU 折进 hub 计划，或让诊断同时比对 hub 接口。
- 第一次尝试把 `tunnel_mtu` 追加在 hub TOML 的 `[backup]` 表之后，服务器正确地保持了默认值——记录为「该键只属于根表」的反向证明。
