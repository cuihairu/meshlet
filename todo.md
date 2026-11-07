# TODO

## 源码分层分析 2026-11-07

### 抽象层清单

- 配置契约层：把 TOML 运维输入解析、校验并投影为 server/agent/本地 UI 的类型化运行配置。——`crates/meshlet-config/src/lib.rs:38`
- 策略与规划层：做 IPAM、网段可见性、冲突、路由推导和直连选择，不产生 I/O。——`crates/meshlet-domain/src/ipam.rs:58`
- 修订与状态收敛层：记录单调期望修订，经显式 backend 应用并区分 pending/applied/failed。——`crates/meshlet-domain/src/config_state.rs:156`
- 持久化层：以内存 `MeshState` 处理事务，SQLite 做迁移、镜像、启动恢复、备份与离线恢复。——`apps/server/src/persist.rs:1307`
- 设备对账与操作系统执行层：agent 比较期望与内核，经平台 backend 应用隧道/路由/NAT。——`crates/meshlet-network/src/linux.rs:1606`
- 服务发布层：类型化 L4/HTTP/DNS/探针 CRUD、投影与设备本地监听运行时。——`crates/meshlet-publish/src/runtime.rs:128`
- 任务与消息层：操作员显式任务经严格状态机、幂等通道与设备本地受控执行。——`apps/server/src/task.rs:709`
- 接口层：组合管理 API、agent API、CLI、托盘与控制台静态入口，并隔离认证通道。——`apps/server/src/lib.rs:979`
- 可观测与诊断层：结构化遥测、有界指标、诊断快照与心跳/回执/探针证据。——`apps/server/src/diagnostics.rs:852`
- 平台打包与生命周期层：systemd 控制面/数据面与 agent 生命周期，以及 Windows 安装打包。——`deploy/systemd/meshlet-agent.service:18`

### 超大文件候选（>1000 行）

- [ ] LAY-001 [P1] 拆分 `apps/server/src/service.rs`（3045 行）——混合 `MeshState` 聚合、错误映射、生命周期、网络/设备/邀请/路由/alias/网段/诊断与视图转换，单一文件已横跨策略与接口契约。（`apps/server/src/service.rs:485`）
- [ ] LAY-002 [P1] 拆分 `apps/server/src/persist.rs`（2703 行）——同时承载 SQLite 重建、实体写入、任务加载、备份、恢复与诊断快照，恢复安全和逐表映射可各自成为边界。（`apps/server/src/persist.rs:1307`）
- [ ] LAY-003 [P1] 拆分 `apps/server/src/publish.rs`（2546 行）——发布对象结构、四类 CRUD、认证解析、健康回报与设备计划投影在同一模块，控制器与领域规则可分离。（`apps/server/src/publish.rs:1214`）
- [ ] LAY-004 [P1] 拆分 `crates/meshlet-network/src/linux.rs`（2507 行）——Linux 后端把接口探测、命令运行、隧道/路由/NAT/防火墙、诊断和解析器集中在一个实现内。（`crates/meshlet-network/src/linux.rs:1606`）
- [ ] LAY-005 [P1] 拆分 `apps/server/tests/single_instance.rs`（2211 行）——集成测试把实例锁、备份/恢复、心跳、修订与多进程生命周期铺在同一文件。（`apps/server/tests/single_instance.rs:1`）
- [ ] LAY-006 [P1] 拆分 `apps/agent/src/agent.rs`（1913 行）——`Agent` 同时驱动对账、回执、心跳、直连、RTT、任务 kick、托盘、SSH 同步、自升级和发布。（`apps/agent/src/agent.rs:43`）
- [ ] LAY-007 [P1] 拆分 `apps/tray-host/src/panel.rs`（1738 行）——本地面板把快照读取、HTML 渲染、JS 注入、HTTP server 与本地协议文案合并。（`apps/tray-host/src/panel.rs:313`）
- [ ] LAY-008 [P1] 拆分 `apps/server/tests/dual_site_end_to_end.rs`（1690 行）——跨站点端到端用例覆盖注册、路由、NAT、收敛和备份恢复，适合按业务场景拆分。（`apps/server/tests/dual_site_end_to_end.rs:1`）
- [ ] LAY-009 [P1] 拆分 `apps/server/src/task.rs`（1536 行）——任务记录、派发/回收策略、agent 通道和 console 路由集中，状态推进与 API 可拆开。（`apps/server/src/task.rs:628`）
- [ ] LAY-010 [P1] 拆分 `apps/tray-host/src/main.rs`（1472 行）——Win32 托盘宿主、进程看门狗、菜单/图标、面板启动和 CLI 联动都在入口文件。（`apps/tray-host/src/main.rs:430`）
- [ ] LAY-011 [P1] 拆分 `apps/cli/src/main.rs`（1461 行）——CLI 同时包含参数分发、本地状态读取、Windows 诊断、任务 HTTP 客户端与表格渲染。（`apps/cli/src/main.rs:78`）
- [ ] LAY-012 [P1] 拆分 `crates/meshlet-network/tests/backend_wiring.rs`（1460 行）——网络后端集成测试覆盖命令桥、netns、隧道、路由、NAT 与恢复多个场景。（`crates/meshlet-network/tests/backend_wiring.rs:1`）
- [ ] LAY-013 [P1] 拆分 `crates/meshlet-network/src/windows.rs`（1402 行）——Windows 后端合并进程命令、WireGuard、netsh、路由、NAT、诊断与测试解析。（`crates/meshlet-network/src/windows.rs:1391`）
- [ ] LAY-014 [P1] 拆分 `apps/agent/tests/agent_reconcile.rs`（1378 行）——agent 集成测试集中内核对账、文件账本、任务、托盘与 SSH 同步流程。（`apps/agent/tests/agent_reconcile.rs:1`）
- [ ] LAY-015 [P1] 拆分 `apps/server/tests/backup.rs`（1296 行）——备份/恢复测试同时覆盖 schema 校验、并发、内容差异和审计，可按边界拆组。（`apps/server/tests/backup.rs:1`）
- [ ] LAY-016 [P1] 拆分 `apps/tray-app/src-tauri/src/main.rs`（1241 行）——Tauri 命令、本地 TOML 读写、状态分档、i18n、窗口/托盘和前端逻辑在同一入口。（`apps/tray-app/src-tauri/src/main.rs:57`）
- [ ] LAY-017 [P1] 拆分 `apps/agent/src/tray.rs`（1228 行）——托盘状态机、PNG 编码、文件 sink、DBus 通知模型与大量测试共存。（`apps/agent/src/tray.rs:344`）
- [ ] LAY-018 [P1] 拆分 `crates/meshlet-domain/src/config_state.rs`（1222 行）——期望哈希、修订状态机、apply/rollback 语义与存储迁移规则集中一处。（`crates/meshlet-domain/src/config_state.rs:156`）
- [ ] LAY-019 [P1] 拆分 `crates/meshlet-domain/src/p2p.rs`（1219 行）——端点推导、探测分类、状态跃迁和迟滞策略同处一个领域模块，可按纯函数职责细分。（`crates/meshlet-domain/src/p2p.rs:171`）
- [ ] LAY-020 [P1] 拆分 `apps/server/tests/publish.rs`（1203 行）——发布集成测试覆盖四类对象、鉴权、健康回报与持久化，适合按对象族拆分。（`apps/server/tests/publish.rs:1`）
- [ ] LAY-021 [P1] 拆分 `crates/meshlet-config/src/lib.rs`（1189 行）——server/agent 配置、原始 TOML schema、默认值、校验与跨平台数据面选项集中在单文件。（`crates/meshlet-config/src/lib.rs:38`）
- [ ] LAY-022 [P1] 拆分 `apps/server/src/lib.rs`（1146 行）——通用写路径助手、根 router、大量网络/设备路由和 console fallback 混在一个 crate 入口。（`apps/server/src/lib.rs:979`）
- [ ] LAY-023 [P1] 拆分 `apps/agent/src/direct.rs`（1111 行）——直连管理器、协议消息、ledger、防火墙动作、RTT 合并和状态导出聚合在一起。（`apps/agent/src/direct.rs:143`）
- [ ] LAY-024 [P1] 拆分 `apps/server/src/auth.rs`（1069 行）——AppState、AuthStore、登录限流、会话/API token extractor、CSRF 与 auth API 端点集中。（`apps/server/src/auth.rs:51`）
- [ ] LAY-025 [P1] 拆分 `apps/server/src/revision.rs`（1028 行）——revision API、hub plan 翻译、授权过滤、backend 工厂与部署恢复在同一文件。（`apps/server/src/revision.rs:150`）
- [ ] LAY-026 [P1] 拆分 `crates/meshlet-network/src/lib.rs`（1020 行）——计划类型、SSH 段、对账规则、诊断载体和平台 trait 共用一个入口文件。（`crates/meshlet-network/src/lib.rs:707`）

### 目录/分类不合理处

- `apps/tray-app/dist/popup.html` 是与 `apps/tray-app/popup.html` 并存的构建产物，源码清单不应把 dist 形态混入应用源（`apps/tray-app/dist/popup.html:1`）。
- server 的通用写路径助手与根 router 放在 `apps/server/src/lib.rs`，而 alias、segment、publish、task、diagnostics 已有独立模块；根路由和通用 helper 可进一步按域归位（`apps/server/src/lib.rs:1113`）。
- `apps/tray-app` 是 Tauri 应用但 Rust 入口位于子目录 `src-tauri/src/main.rs`，静态 UI 与 Rust 生命周期在同一应用目录内形成两类构建体系；若后续继续扩展，应明确前端源与原生入口的顶层边界（`apps/tray-app/src-tauri/src/main.rs:1`）。
