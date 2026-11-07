---
outline: deep
---

# 源码分层术语表

定义锚定 2026-11-07 读取的源码。[分层分析](./source-layer-analysis)解释概念之间的组合关系。

| 术语 | 英文 | 定义 | file:line |
|---|---|---|---|
| 服务器配置 | Server configuration | 类型化 hub 运行输入，覆盖监听、数据库、overlay、在线窗口、备份、隧道 MTU、数据面、可信代理与 SSH 分发。 | `crates/meshlet-config/src/lib.rs:134` |
| 代理配置 | Agent configuration | 类型化设备运行输入，覆盖 hub URL、状态目录、凭据、托盘、升级与数据面对账。 | `crates/meshlet-config/src/lib.rs:386` |
| 网段信任组 | Network segment | 网络作用域的信任前缀；自定义网段有意排除默认 overlay 网段，跨段必须有 grant。 | `crates/meshlet-domain/src/segments.rs:25` |
| 网段授权 | Segment grant | 单向 source→destination 授权，只有进入 `Applied` 后才影响后续路由规划。 | `crates/meshlet-domain/src/segments.rs:146` |
| Overlay IPAM | Overlay IPAM | 在网络 CIDR 内确定性分配与释放设备地址。 | `crates/meshlet-domain/src/ipam.rs:58` |
| 冲突检查 | Conflict check | 校验期望 LAN 路由的目的重叠、alias 前缀重叠与 alias 目标不匹配。 | `crates/meshlet-domain/src/conflict.rs:180` |
| Hub 路由计划 | Hub route plan | 从 Active 设备与授权路由推导 hub peer 与 AllowedIPs。 | `crates/meshlet-domain/src/peer_routes.rs:47` |
| 客户端路由计划 | Client route plan | 推导设备的 AllowedIPs 与路由目的地，排除自身本地前缀。 | `crates/meshlet-domain/src/peer_routes.rs:100` |
| 期望配置哈希 | Desired configuration hash | 对 overlay、hub、Active 设备、路由、alias 与已应用 grant 做确定性 SHA-256；删除会改变哈希。 | `crates/meshlet-domain/src/config_state.rs:36` |
| 配置修订账本 | Configuration revision ledger | 每网络单调修订簿记：记录是 `Pending`，只有 backend 成功才 `Applied`。 | `crates/meshlet-domain/src/config_state.rs:156` |
| 配置应用边界 | Configuration apply backend | 修订簿记与主机/网络效果之间的显式接口；失败与不确定必须可见。 | `crates/meshlet-domain/src/config_state.rs:119` |
| 内存网状状态 | Mesh state | 服务端内存聚合，组合网络、设备、注册、路由、alias、网段、修订、任务、诊断与发布。 | `apps/server/src/service.rs:485` |
| 共享持久化锁 | Shared persist mutex | 服务端全局互斥锁，为所有状态变更请求排序内存修改与 SQLite 镜像。 | `apps/server/src/auth.rs:65` |
| 控制面迁移 | Control-plane migrations | 启动时嵌入并执行的有序 SQLite schema。 | `apps/server/src/store.rs:17` |
| 控制面恢复 | Control-plane recovery | 启动重建内存聚合，并收敛中断修订与过期部署。 | `apps/server/src/persist.rs:1307`、`apps/server/src/convergence.rs:20` |
| Hub 数据面后端 | Hub data-plane backend | 服务端本机适配器，把策略快照翻译成隧道与路由效果，并重新过滤当前授权。 | `apps/server/src/revision.rs:150`、`:166` |
| 数据面计划 | Device plan | 发给 agent 的结构化隧道、路由、NAT、发布、SSH、修订与哈希对象；不携带设备私钥。 | `crates/meshlet-network/src/lib.rs:227` |
| 设备计划构建器 | Device-plan builder | 把 `MeshState` 投影为一台设备的计划，按网段可见性与路由所有权过滤。 | `apps/server/src/device_plan.rs:89` |
| 网络后端 | Network backend | 平台无关的 inspect/隧道/路由/NAT/rollback 边界，由 Linux、Windows 或显式 unsupported 实现。 | `crates/meshlet-network/src/lib.rs:89`、`:707` |
| 设备对账 | Agent reconciliation | 决策重放前比较计划哈希、期望计划、内核快照、允许的额外 peer 与账本。 | `apps/agent/src/reconcile.rs:20`、`:133` |
| 应用账本 | Applied ledger | 最近成功应用的计划的原子 JSON 记录，用于重启恢复与漂移诊断。 | `apps/agent/src/reconcile.rs:54` |
| 直连决策 | Direct-path decision | 探测分类与迟滞状态机，用于把 peer 从中继升级到直连或回退中继。 | `crates/meshlet-domain/src/p2p.rs:171`、`:472` |
| 服务发布计划 | Publishing plan | 设备上对账的类型化转发、HTTP 路由/监听、分割 DNS 与探针集合。 | `crates/meshlet-publish/src/plan.rs:14` |
| 发布运行时 | Publishing runtime | 设备本地 tokio 运行时，负责启动、替换、停止发布监听并上报结果。 | `crates/meshlet-publish/src/runtime.rs:86`、`:128` |
| 发布授权策略 | Publishing authorization policy | 在连接转发或 HTTP 后端前执行的来源 CIDR 或 Bearer token 准入。 | `crates/meshlet-publish/src/authorization.rs:45` |
| 任务状态机 | Task state machine | assigned/acknowledged/running/done/failed 的严格跃迁与显式结果。 | `crates/meshlet-domain/src/task.rs:54`、`:157` |
| 任务工作线程 | Task worker | 设备侧幂等轮询执行循环，背后是持久任务账本。 | `apps/agent/src/tasks.rs:254`、`:270` |
| 管理 API | Management API | Cookie 会话或 `mlt_` token API；写操作额外要求已认证写者与 CSRF extractor。 | `apps/server/src/auth.rs:504`、`:521` |
| 代理 API | Agent API | 设备 Bearer 凭据 API，与管理认证分离。 | `apps/server/src/agent.rs:223` |
| 路由表 | Router table | Axum 组合公开、管理、agent、诊断、任务、指标、审计、备份、发布与可选控制台静态路由。 | `apps/server/src/lib.rs:979`、`:1113` |
| 统一错误契约 | Unified error contract | 与 OpenAPI 契约一致的 snake_case 错误码和响应信封。 | `crates/meshlet-api-types/src/lib.rs:8`、`:24` |
| 命令目录 | Command catalog | 渲染 CLI 帮助并钉住 CLI/托盘命令文案的唯一目录。 | `crates/meshlet-commands/src/lib.rs:14`、`:32` |
| 运行指标 | Runtime metrics | 有界进程内计数与抓取时量规，输出 Prometheus。 | `apps/server/src/metrics.rs:31`、`:67` |
| 诊断报告 | Diagnostics report | 覆盖控制面、隧道、路由、转发与 alias 的 13 项封闭检查；运行时落库并审计。 | `apps/server/src/diagnostics.rs:33`、`:60`、`:852` |
| 本地状态图 | Local status graph | 供托盘宿主与 CLI status 消费的设备本地 JSON/PNG 输出。 | `apps/agent/src/tray.rs:344`、`apps/tray-host/src/panel.rs:313` |
| 控制台静态目录 | Console static directory | 可选的 server 文件系统目录，作为网页控制台 fallback 提供服务。 | `apps/server/src/lib.rs:1113` |
| 数据面 systemd 模式 | Dataplane systemd mode | 仅在启用 hub 数据面时加网络 capability 与转发的 drop-in。 | `deploy/systemd/meshlet-server.service.d/dataplane.conf:1` |
| 设备 systemd 生命周期 | Agent systemd lifecycle | 要求 dataplane、token 与私钥，且只授予网络管理/raw 访问 capability 的服务契约。 | `deploy/systemd/meshlet-agent.service:18`、`:35` |
