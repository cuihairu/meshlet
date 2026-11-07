---
outline: deep
---

# Source Layer Glossary

The definitions are anchored to the source read on 2026-11-07. The [layer analysis](./source-layer-analysis) explains how these concepts fit together.

| Term | English | Definition | Evidence |
|---|---|---|---|
| 服务器配置 | Server configuration | Typed hub runtime input covering listener, database, overlay, presence, backup, tunnel MTU, dataplane, trusted proxies, and SSH distribution. | `crates/meshlet-config/src/lib.rs:134` |
| 代理配置 | Agent configuration | Typed device runtime input covering hub URL, state directory, credentials, tray, upgrade, and dataplane reconciliation. | `crates/meshlet-config/src/lib.rs:386` |
| 网段信任组 | Network segment | A network-scoped trust prefix; custom segments intentionally exclude the default overlay segment and require a grant to cross. | `crates/meshlet-domain/src/segments.rs:25` |
| 网段授权 | Segment grant | A one-way source-to-destination authorization that only affects future route planning after it reaches `Applied`. | `crates/meshlet-domain/src/segments.rs:146` |
| Overlay IPAM | Overlay IPAM | Deterministic allocation and release of device addresses inside a network CIDR. | `crates/meshlet-domain/src/ipam.rs:58` |
| 冲突检查 | Conflict check | Validation of destination overlap, alias-prefix overlap, and alias-target mismatch across desired LAN routes. | `crates/meshlet-domain/src/conflict.rs:180` |
| Hub 路由计划 | Hub route plan | Derivation of hub peers and AllowedIPs from active devices and authorized routes. | `crates/meshlet-domain/src/peer_routes.rs:47` |
| 客户端路由计划 | Client route plan | Derivation of a device's AllowedIPs and routed destinations, excluding its own local prefixes. | `crates/meshlet-domain/src/peer_routes.rs:100` |
| 期望配置哈希 | Desired configuration hash | Deterministic SHA-256 over overlay, hub, active devices, routes, aliases, and applied grants; deletion changes the hash. | `crates/meshlet-domain/src/config_state.rs:36` |
| 配置修订账本 | Configuration revision ledger | Per-network, monotonic revision bookkeeping where recording is `Pending` and only backend success reaches `Applied`. | `crates/meshlet-domain/src/config_state.rs:156` |
| 配置应用边界 | Configuration apply backend | The explicit interface between revision bookkeeping and host/network effect; failure and uncertainty must remain visible. | `crates/meshlet-domain/src/config_state.rs:119` |
| 内存网状状态 | Mesh state | The server's in-memory aggregate composing networks, devices, registrations, routes, aliases, segments, revisions, tasks, diagnostics, and publishing. | `apps/server/src/service.rs:485` |
| 共享持久化锁 | Shared persist mutex | Server-wide mutex ordering the in-memory mutation and SQLite mirror for every state-changing request. | `apps/server/src/auth.rs:65` |
| 控制面迁移 | Control-plane migrations | Ordered SQLite schema definitions embedded and applied by the server at startup. | `apps/server/src/store.rs:17` |
| 控制面恢复 | Control-plane recovery | Rebuild of the memory aggregate at startup plus convergence of interrupted revisions and stale deployments. | `apps/server/src/persist.rs:1307`, `apps/server/src/convergence.rs:20` |
| Hub 数据面后端 | Hub data-plane backend | Server-local adapter translating a policy snapshot into tunnel and route effects with prior authorization re-filtering. | `apps/server/src/revision.rs:150`, `:166` |
| 数据面计划 | Device plan | Structured tunnel, route, NAT, publishing, SSH, revision, and hash object sent to an agent; it never carries the device private key. | `crates/meshlet-network/src/lib.rs:227` |
| 设备计划构建器 | Device-plan builder | Projection of `MeshState` into one device's plan, filtered by segment visibility and route ownership. | `apps/server/src/device_plan.rs:89` |
| 网络后端 | Network backend | Platform-neutral inspect/tunnel/route/NAT/rollback boundary implemented by Linux, Windows, or explicit unsupported behavior. | `crates/meshlet-network/src/lib.rs:89`, `:707` |
| 设备对账 | Agent reconciliation | Comparison of plan hash, desired plan, kernel snapshot, allowed extra peers, and ledger before deciding to replay. | `apps/agent/src/reconcile.rs:20`, `:133` |
| 应用账本 | Applied ledger | Atomic JSON record of the last successfully applied plan, used for restart recovery and drift diagnosis. | `apps/agent/src/reconcile.rs:54` |
| 直连决策 | Direct-path decision | Probe classification and hysteresis state machine for promoting a peer from relay to direct path or returning to relay. | `crates/meshlet-domain/src/p2p.rs:171`, `:472` |
| 服务发布计划 | Publishing plan | Typed set of forwards, HTTP routes/listener, split-horizon DNS, and probes reconciled on a device. | `crates/meshlet-publish/src/plan.rs:14` |
| 发布运行时 | Publishing runtime | Device-local tokio runtime that starts, replaces, stops, and reports publishing listeners. | `crates/meshlet-publish/src/runtime.rs:86`, `:128` |
| 发布授权策略 | Publishing authorization policy | Source-CIDR or bearer-token admission performed before a forwarding or HTTP backend connection. | `crates/meshlet-publish/src/authorization.rs:45` |
| 任务状态机 | Task state machine | Strict assigned/acknowledged/running/done/failed transitions with explicit outcomes. | `crates/meshlet-domain/src/task.rs:54`, `:157` |
| 任务工作线程 | Task worker | Device-side idempotent polling and execution loop backed by a persistent task ledger. | `apps/agent/src/tasks.rs:254`, `:270` |
| 管理 API | Management API | Cookie-session or `mlt_` token API; writes additionally require an authenticated writer and CSRF extractor. | `apps/server/src/auth.rs:504`, `:521` |
| 代理 API | Agent API | Device Bearer credential API separated from management authentication. | `apps/server/src/agent.rs:223` |
| 路由表 | Router table | Axum composition of public, management, agent, diagnostics, tasks, metrics, audit, backup, publishing, and optional static console routes. | `apps/server/src/lib.rs:979`, `:1113` |
| 统一错误契约 | Unified error contract | Shared snake_case error codes and response envelope aligned with the OpenAPI contract. | `crates/meshlet-api-types/src/lib.rs:8`, `:24` |
| 命令目录 | Command catalog | Single catalog used to render CLI help and pin CLI/tray command wording. | `crates/meshlet-commands/src/lib.rs:14`, `:32` |
| 运行指标 | Runtime metrics | Bounded in-process counters plus scrape-time gauges exposed in Prometheus format. | `apps/server/src/metrics.rs:31`, `:67` |
| 诊断报告 | Diagnostics report | Thirteen closed checks across control-plane, tunnel, routing, forwarding, and alias layers; persisted and audited when run. | `apps/server/src/diagnostics.rs:33`, `:60`, `:852` |
| 本地状态图 | Local status graph | Device-local JSON and PNG outputs consumed by tray hosts and CLI status commands. | `apps/agent/src/tray.rs:344`, `apps/tray-host/src/panel.rs:313` |
| 控制台静态目录 | Console static directory | Optional server filesystem directory served as the web console fallback. | `apps/server/src/lib.rs:1113` |
| 数据面 systemd 模式 | Dataplane systemd mode | Drop-in that adds network capabilities and forwarding only when the hub dataplane is enabled. | `deploy/systemd/meshlet-server.service.d/dataplane.conf:1` |
| 设备 systemd 生命周期 | Agent systemd lifecycle | Service contract requiring dataplane, token, and private key while limiting capabilities to network administration/raw access. | `deploy/systemd/meshlet-agent.service:18`, `:35` |
