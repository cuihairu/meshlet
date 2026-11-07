---
outline: deep
---

# 源码分层分析（2026-11-07）

本页归纳 2026-11-07 源码中真实存在的抽象层；层是运行职责，不是目录名。[术语表](./source-layer-glossary)逐条给出英文与源码锚点，英文页是同步对应版本。

## 抽象层

### 配置契约层

类型化 TOML 输入把运维意图与运行行为分开。`ServerConfig` 承载 hub 的监听、SQLite 路径、overlay、在线窗口、备份、隧道 MTU、数据面、可信代理与 SSH 分发（`crates/meshlet-config/src/lib.rs:134`）；`AgentConfig` 承载 server URL、状态目录、凭据、托盘、升级与设备数据面（`crates/meshlet-config/src/lib.rs:386`）。两套 schema 都通过显式 raw TOML 结构解码并拒绝未知字段（`crates/meshlet-config/src/lib.rs:38`），默认值固定在代码中（`crates/meshlet-config/src/lib.rs:181`）。

实现落在 `apps/server`、`apps/agent` 与平台应用。不存在覆盖所有配置的单一协议文件：agent TOML 从 `apps/agent/src/main.rs:62` 解析；Windows 托盘应用只编辑刻意简化的扁平 TOML 投影（`apps/tray-app/src-tauri/src/main.rs:57`）。server unit 为默认控制面提供无特权硬化（`deploy/systemd/meshlet-server.service:17`），dataplane drop-in 只加 `CAP_NET_ADMIN` 与 `CAP_NET_RAW`（`deploy/systemd/meshlet-server.service.d/dataplane.conf:1`）。

### 策略与规划层

该层在任何外部效果之前做决策。领域实体与 `DeviceRegistry` 在无运行时 I/O 的前提下定义网络、设备、密钥与生命周期（`crates/meshlet-domain/src/entities.rs:9`、`:291`）；IPAM 分配并释放 overlay 地址（`crates/meshlet-domain/src/ipam.rs:58`）；网段信任与单向 grant 决定路由可见性（`crates/meshlet-domain/src/segments.rs:25`、`:146`）；冲突检查校验 LAN 路由与 alias 前缀（`crates/meshlet-domain/src/conflict.rs:180`）；路由推导得到 hub 与客户端 AllowedIPs（`crates/meshlet-domain/src/peer_routes.rs:47`、`:100`）。直连选择同样是策略：状态机分类探测并执行迟滞（`crates/meshlet-domain/src/p2p.rs:171`、`:472`）。

服务端 `MeshState` 是组合这些决策的聚合。其集合覆盖网络、IPAM、注册、设备、路由、alias、网段、修订、任务、诊断与发布（`apps/server/src/service.rs:485`）。设备计划构建器把该策略聚合翻译成类型化 `DevicePlan`（`apps/server/src/device_plan.rs:89`）。

### 修订与状态收敛层

修订账本区分“记录意图”和“产生效果”。`desired_config_hash` 对授权快照做确定性哈希（`crates/meshlet-domain/src/config_state.rs:36`）；`ConfigLedger` 为每个网络分配单调修订，且只允许当前修订经 backend 应用（`crates/meshlet-domain/src/config_state.rs:156`、`:215`）。`ConfigApplyBackend` 是效果边界，失败必须显式（`crates/meshlet-domain/src/config_state.rs:119`）。

应用包装保持这一区别。`UnconfiguredBackend` 拒绝伪装成功（`apps/server/src/revision.rs:73`）；backend factory 按网络串行 apply 与 rollback（`apps/server/src/revision.rs:100`）；`HubDataPlaneBackend` 构造 hub 快照、按当前授权重新过滤并整体下发隧道与路由（`apps/server/src/revision.rs:150`、`:166`、`:197`）。启动恢复比较持久状态与 hub 部署日志，后台循环收敛中断修订（`apps/server/src/convergence.rs:20`、`:88`）。

### 持久化层

控制面使用双形态状态：内存 `MeshState` 作为事务内策略工作的事实形态，SQLite 作为可重启镜像。`store::connect` 应用迁移并配置 WAL 与 `synchronous=NORMAL`（`apps/server/src/store.rs:20`）；`persist::load` 从表重建内存聚合（`apps/server/src/persist.rs:1307`）；写路径用共享 `state.persist` 锁，保证内存变更与 SQLite 提交有序（`apps/server/src/auth.rs:65`、`apps/server/src/service.rs:100`）。备份用 SQLite `VACUUM INTO`，恢复先校验 schema、行数与内容再做受守卫的原子改名（`apps/server/src/persist.rs:2013`、`:2124`）。

SQLite 是唯一关系存储。没有 Redis、MySQL、服务端通用键值缓存或长期进程内存契约；agent 与本地 UI 使用原子 JSON 账本。

### 设备对账与操作系统执行层

agent 消费结构化计划、记录最近成功计划并对账内核。主循环拉计划、应用、回传回执与心跳，并驱动本地任务、直连、探测、托盘、升级与发布子系统（`apps/agent/src/agent.rs:43`）。对账先比较期望哈希与 `applied.json` 账本（`apps/agent/src/reconcile.rs:20`），账本原子落盘（`apps/agent/src/reconcile.rs:54`）。

平台边界是 `SystemBackend`：类型别名按平台选择 Linux、Windows 或显式 unsupported（`crates/meshlet-network/src/lib.rs:89`、`:95`）。`NetworkBackend` trait 暴露 inspect、隧道、路由、NAT 与 rollback（`crates/meshlet-network/src/lib.rs:707`)。Linux 执行在同一个同步方法中处理隧道、路由、宿主防火墙、直连端口防火墙、NAT 与过期 NAT 清理（`crates/meshlet-network/src/linux.rs:1606`）。

### 服务发布层

发布是类型化子计划，不是 Shell 片段。`PublishPlan` 携带转发、HTTP 路由与监听、DNS 和探针（`crates/meshlet-publish/src/plan.rs:14`）。控制面保存 CRUD 记录、校验、分配修订，并为单台设备投影启用对象（`apps/server/src/publish.rs:1214`、`:1294`）。`Publisher` 拥有设备本地 tokio 任务并按计划对账（`crates/meshlet-publish/src/runtime.rs:86`、`:128`）。L4 授权在连接后端前检查来源 CIDR 或 Bearer token（`crates/meshlet-publish/src/authorization.rs:45`）。

### 任务与消息层

任务层是对“服务端不下发 Shell 命令”纪律的显式扩展。领域状态机严格推进（`crates/meshlet-domain/src/task.rs:54`、`:157`）；服务端派发与回收由共享 persist 锁串行化（`apps/server/src/task.rs:628`、`:709`）；agent 执行是幂等 worker（`apps/agent/src/tasks.rs:254`、`:270`），实际进程在本机按超时与日志尾部捕获运行（`apps/agent/src/tasks.rs:90`、`:412`）。

### 接口层

Axum router 暴露公开、管理与 agent API。管理请求经用户认证，写请求还要 `WriteUser` 加 CSRF（`apps/server/src/auth.rs:504`、`:521`）；agent 请求使用独立 Bearer extractor（`apps/server/src/agent.rs:223`）。router 组合与可选控制台静态 fallback 明确（`apps/server/src/lib.rs:979`、`:1113`）。除 `crates/meshlet-api-types/src/lib.rs:8`、`docs/architecture/api-contract.md` 与 `docs/public/api/openapi.yaml` 外，没有通用 schema 文件。

CLI 与本地 UI 是状态的独立消费者。CLI 读 agent 产生的文件，只在显式任务命令中调用 HTTP（`apps/cli/src/main.rs:78`、`:896`）；Tauri 托盘读写本地配置与状态 JSON（`apps/tray-app/src-tauri/src/main.rs:57`）；Windows tray host 不监听 agent 通道，而是轮询状态文件并重建菜单（`apps/tray-host/src/main.rs:106`、`:430`）。

### 可观测与诊断层

遥测经 `op_log!` 与中间件输出结构化 JSON（`apps/server/src/telemetry.rs:41`）。指标维护有界进程内计数并在抓取时计算量规，输出 Prometheus（`apps/server/src/metrics.rs:31`、`:67`）。诊断是 13 项封闭检查，带层与状态词表（`apps/server/src/diagnostics.rs:33`、`:43`）；一次运行落库并审计（`apps/server/src/diagnostics.rs:852`）。运行证据始终与期望配置分离。

### 平台打包与生命周期层

systemd unit 定义 server 的两种模式：仅控制面与启用数据面。基础 unit 保持空 capability 集（`deploy/systemd/meshlet-server.service:17`）；drop-in 只在数据面模式加网络 capability 并打开转发（`deploy/systemd/meshlet-server.service.d/dataplane.conf:1`）。agent unit 要求数据面、device token 与私钥，且只授予两个网络 capability（`deploy/systemd/meshlet-agent.service:18`）。Windows MSI/ZIP 使用独立打包脚本（`scripts/package-release.sh:13`）。

## 拆分理由

1. **配置与运行分离**：raw TOML 解码为类型化运行结构，未知字段失败（`crates/meshlet-config/src/lib.rs:38`、`:201`、`:347`）。
2. **策略先于状态变更**：IPAM、网段、冲突与直连决策是纯领域函数（`crates/meshlet-domain/src/ipam.rs:58`、`crates/meshlet-domain/src/segments.rs:146`、`crates/meshlet-domain/src/conflict.rs:180`、`crates/meshlet-domain/src/p2p.rs:171`）。
3. **期望状态与实际状态不混用**：记录得到 `Pending`，backend 应用后才 `Applied`，结果不确定进入 `Failed`（`crates/meshlet-domain/src/config_state.rs:1`）。
4. **计划生产与执行分离**：server 构造无私钥的 `DevicePlan`（`apps/server/src/device_plan.rs:84`），agent 本地注入私钥（`apps/agent/src/agent.rs:637`）。
5. **操作系统后端隔离**：所有调用方经平台 `SystemBackend` 别名（`crates/meshlet-network/src/lib.rs:89`），trait 承载 inspect/apply/rollback 语义（`crates/meshlet-network/src/lib.rs:707`）。
6. **发布是独立边界**：有类型化校验和独立设备本地任务运行时（`crates/meshlet-publish/src/plan.rs:43`、`crates/meshlet-publish/src/runtime.rs:128`）。
7. **任务是显式例外通道**：任务模块自身记录操作员下发命令对结构化计划纪律的例外（`apps/server/src/task.rs:13`）。
8. **API 与本地接口通道分离**：管理认证、agent 认证与本地 UI 文件输入是不同边界（`apps/server/src/auth.rs:504`、`apps/server/src/agent.rs:223`、`apps/tray-host/src/main.rs:106`）。
9. **证据只追加且来自运行**：指标、诊断、心跳、回执与探针报告独立于期望状态更新（`apps/server/src/metrics.rs:31`、`apps/server/src/diagnostics.rs:60`、`apps/server/src/publish.rs:1320`）。
10. **生命周期安全按部署作用域拆分**：基础 server unit 无 capability，dataplane drop-in 与 agent unit 只加所需网络 capability（`deploy/systemd/meshlet-server.service:28`、`deploy/systemd/meshlet-server.service.d/dataplane.conf:2`、`deploy/systemd/meshlet-agent.service:35`）。

## 调用面

- 管理 UI/API → Axum `Router` → Cookie/API token extractor → service 函数 → SQLite 镜像。
- Agent → HTTP Bearer 端点 → `DevicePlan` 拉取、回执、心跳、直连候选、发布健康与任务 ack/结果。
- Hub 修订 → `ConfigApplyBackend` → `SystemBackend` → 本机 WireGuard、路由、防火墙与转发。
- 设备修订 → agent 对账 → `SystemBackend` → 本机 WireGuard、路由、防火墙、NAT、转发与 `applied.json`。
- CLI/本地托盘 → 本地 JSON 与 TOML 文件；只有显式任务命令走 HTTP。

## 生命周期

1. 加载并校验配置。
2. 获取数据库文件锁，连接 SQLite，应用迁移，重建 `MeshState`。
3. 安装工厂、恢复循环、定时备份、路由与可选静态控制台。
4. agent 解析凭据、注入本机私钥，进入对账循环。
5. 修订记录意图，经已配置 backend 应用，持久化回执，并收敛中断工作。
6. 发布与任务运行时独立运行、上报证据，并随计划移除或进程退出停止。

## 状态存储清单

| 组件 | 存储 | 证据 |
|---|---|---|
| 控制面 | SQLite `meshlet.db` + WAL/SHM | `crates/meshlet-config/src/lib.rs:136`、`apps/server/src/store.rs:20`、`migrations/001_init.sql:1` |
| Agent 对账 | `applied.json` | `apps/agent/src/reconcile.rs:20`、`:54` |
| 直连 | `direct.json`、`direct-peers.json`、`direct-switch-events.json` | `apps/agent/src/agent.rs:1154`、`apps/agent/src/direct.rs:143` |
| 任务 worker | `tasks.json` | `apps/agent/src/agent.rs:1159`、`apps/agent/src/tasks.rs:90` |
| 托盘/状态 | `tray/status.json`、`tray/icon-*.png`、`tray/lang`、SSH 同步状态 | `apps/agent/src/tray.rs:344`、`apps/agent/src/ssh_sync.rs:415` |
| Server 备份 | 带时间戳的 SQLite 快照 | `apps/server/src/persist.rs:2013` |

未使用 Redis 或 MySQL。
