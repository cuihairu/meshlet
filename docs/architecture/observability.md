# 可观测性：结构化日志与指标

> 落地口径：[存档 §17.1（日志）/ §17.2（指标）](../review/chatgpt-2026-10-13)。
> 实现：`apps/server/src/telemetry.rs`（日志）、`apps/server/src/metrics.rs`（指标）。

## 一、结构化日志（§17.1）

**八字段必须齐全**——每条操作日志都是结构化 JSON 行，字段是顶层键，**不适用
的字段留空串（`""`），字段本身仍在**；不是把值拼进消息文本。

| 字段 | 说明 | 代码位置 |
| --- | --- | --- |
| `time` | 事件时刻（ISO-8601 UTC，与库内时间戳同源） | `telemetry::op_log!` 宏展开 |
| `component` | 组件：`http` / `auth` / `network` / `device` / `route` / `revision` / `agent` | 各 handler 的调用点 |
| `operation` | 操作名（`create_network` / `apply_revision` / …；访问日志用路由模板） | 同上 |
| `network_id` | 适用时；不适用为空串 | 同上 |
| `device_id` | 适用时（`enroll` / `heartbeat` / `revoke`）；不适用为空串 | 同上 |
| `config_revision` | 适用时（修订号字符串）；不适用为空串 | 同上 |
| `error_category` | `none` / `not_found` / `validation` / `conflict` / `unauthorized` / `forbidden` / `rate_limited` / `internal`（稳定字符串，不随错误文本变化） | `telemetry::ErrorCategory` |
| `result` | `ok` / `error` | 同上 |

两个层次：

- **访问日志**（`telemetry::request_log` 中间件，挂在全部 `/api` 路由上）：
  每个已路由请求一条，`component=http`，`operation` = 路由模板（不含路径
  参数，基数有界），`result` / `error_category` 由响应状态派生；
- **领域事件**（各 handler 的 `op_log!` 调用）：完成业务动作后记录，携带真实
  的 `network_id` / `device_id` / `config_revision`，失败路径带 `error_category`。

生产输出为 JSON（`main.rs` 的 `fmt().json().flatten_event(true)`），每行一个
事件，字段可直接被日志系统索引。验收测试：
`apps/server/tests/observability.rs`（每个事件断言八字段齐全）与
`telemetry.rs` 单元测试（宏展开即八字段）。

## 二、指标（§17.2 八项）

端点：`GET /api/v1/system/metrics`（Prometheus 文本格式 0.0.4；管理面认证：
会话 Cookie 或读 scope 的 API Token，见[外部调用方指南](../guide/external-caller)）。
实现：`apps/server/src/metrics.rs`——进程内计数注册表 + 抓取时从
`MeshState` 现算的量规，**零新增依赖**。

按数据来源分两类（这是「不依赖单一指标」的结构性保证）：

**A. 控制面事件计数器**（进程内累加，随请求推进）：

| §17.2 条目 | 指标 | 递增点 |
| --- | --- | --- |
| 配置应用成功率 | `meshlet_config_apply_success_ratio`（gauge，= applied/(applied+failed)，**首次 apply 前省略**——无样本 ≠ 100% 健康） | `revision.rs` apply handler |
| 配置应用失败数 | `meshlet_config_apply_total{result="failed"}` | 同上（以状态机结论计数，不凭响应码） |
| 路由冲突数 | `meshlet_route_conflicts_total`（仅计「目的网段与 overlay/既有路由重叠」；网关未激活等其它 409 不计——`ServiceError::RouteConflict` 变体保证口径） | `lib.rs` `create_route_handler` |
| （补充）回滚结果 | `meshlet_config_rollback_total{result="rolled_back"/"unconfirmed"}` | `revision.rs` rollback handler |
| （补充）agent 心跳 | `meshlet_agent_heartbeats_total` | `agent.rs` heartbeat handler |
| （补充）服务端接口 | `meshlet_http_requests_total{method,route,status_class}`、`meshlet_http_response_bytes_total` | `telemetry::request_log` 中间件 |

**B. 数据面证据量规**（抓取时从 `MeshState` 现算，`service::gauge_snapshot`）：

| §17.2 条目 | 指标 | 数据源 |
| --- | --- | --- |
| 在线设备数 | `meshlet_devices_online` | presence 引擎（agent 上报证据，`presence.rs` `evaluate`） |
| 活跃 Peer 数 | `meshlet_devices_active` | 注册表 `status == Active`（在册 Peer） |
| 最近握手时间 | `meshlet_last_handshake_timestamp_seconds`（0 = 从未观测到）、`meshlet_devices_with_recent_handshake`（握手窗口内设备数） | 设备 `last_handshake_at`（agent 心跳上报的 `wg show` 读数） |
| 服务端流量和接口状态 | `meshlet_interface_up`（≥1 台设备有近期握手证据 = 1；主机侧接口读数待数据面 backend 落地后并入） | 同上 + 数据面后端（未落地） |
| Alias 应用状态 | `meshlet_alias_apply_status`（**Phase 4 未落地：恒 0 = 「无东西可应用」，不是「健康」**，HELP 文本已写明） | Alias 映射（ADR-006，未落地） |

## 三、组合判读规则（为什么不依赖单一指标）

§17.2 明令「不要依赖单个指标判断端到端网络健康」。原因：控制面证据（agent
心跳）与数据面证据（WireGuard 握手）是**两条独立来源**，单看任一都会误判：

| 单一指标读数 | 误判 | 交叉判读 |
| --- | --- | --- |
| `devices_online = N`（心跳新鲜） | 控制面在册但隧道已断（agent 进程活着 ≠ 隧道通） | 同时看 `devices_with_recent_handshake`：若长期 < online，隧道层面有问题 |
| `devices_with_recent_handshake = N` | 隧道在但 agent 已挂（握手保活还在 ≠ agent 功能正常） | 同时看 `devices_online`：若掉到 0，是 agent/控制通道问题 |
| `config_apply_success_ratio = 1.0` | 数据面从未接入时 apply 全失败，比率反而可能长期为 0——比率单独无意义 | 同时看 `config_apply_total` 样本量与 `devices_with_recent_handshake` |
| `alias_apply_status = 0` | Phase 4 未落地，0 = 无东西可应用，**不是**健康 | 只用其它指标判读 |

规则（写死在指标 HELP 文本与测试 `gauges_come_from_the_snapshot_not_from_statics`）：

- `meshlet_devices_online` 与 `meshlet_devices_with_recent_handshake`
  **必须一起看**（HELP 文本：`read together with meshlet_devices_online, never alone`）；
- 「端到端健康」的最小组合 = 在线/握手交叉（数据面活着）+ apply 成功率
  （配置落地）+ HTTP 5xx 计数（控制面本身没坏）。

## 四、运维入口

- 抓取：`curl -H "Authorization: Bearer mlt_..." http://<server>/api/v1/system/metrics`
  （API Token 需读 scope，签发见[外部调用方指南](../guide/external-caller)）；
- 日志：进程 stdout，JSON 每行一事件；`RUST_LOG` 可调级别（默认
  `meshlet_server=info,tower_http=info`）；
- 测试证据：`cargo test -p meshlet-server --test observability`（指标端点
  认证、控制面计数、数据面量规、冲突口径、日志八字段、认证事件）。
