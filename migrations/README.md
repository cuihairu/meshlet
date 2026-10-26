# migrations

SQLx migrations 落库目录。当前版本：`013_publish_tls_passthrough.sql`。

| 版本 | 内容 |
| --- | --- |
| 001_init | Phase 1 核心实体：9 表（users / networks / devices / device_keys / invitations / lan_routes / alias_mappings / config_revisions / audit_events） |
| 002_sessions | 控制台会话（`sessions`） |
| 003_agent_tokens | agent 凭证摘要 + 设备在线证据时间戳（`agent_tokens`，`devices` 增 last_handshake_at / last_report_at） |
| 004_api_tokens | 外部调用 API Token 摘要（`api_tokens`） |
| 005_recovery | 单调计数器持久化（`mesh_meta`） |
| 006_diagnostics | 诊断快照（`diagnostics_runs`） |
| 007_dataplane_evidence | 心跳回传数据面证据（`devices.dataplane_evidence`） |
| 008_device_registrations | 设备自举注册：`bootstrap_tokens`（自举码摘要）+ `device_registrations`（Pending 申请） |
| 009_deployments | `hub_deployments`（公共成功计划、恢复错误）+ `device_apply_receipts`（设备版本/哈希回执） |
| 010_segments | ADR-012 网段信任组：`segments`、`segment_grants` 与设备段归属回填 |
| 011_segment_defaults | 补齐缺失默认段并回填全部设备；默认段 ID 统一为 `seg-<network_id>` |
| 012_publish | R-06 服务发布：`publish_forwards`、`publish_http_routes`、`publish_probes`、`publish_dns_records`（四类期望配置对象）+ `publish_probe_reports`（探针健康镜像，每探针一条） |
| 013_publish_tls_passthrough | M1 更名：`publish_http_routes.tls_termination` → `tls_passthrough`（该列从来是 SNI 嗅探 + 字节直通，不做 TLS 终结；仅改列名，语义与取值不变） |

## 应用方式

```rust
// apps/server/src/store.rs
let pool = meshlet_server::store::connect("sqlite:/var/lib/meshlet/meshlet.db").await?;
```

`connect()` 在连接时执行 `sqlx::migrate!("../../migrations")`，并：
- `max_connections(1)`：SQLite 写入串行，单进程控制平面足够（ADR-002）；
- `after_connect` 里 `PRAGMA foreign_keys = ON`：SQLite 默认关闭外键，必须逐连接开启
  （migration 自身事务内的 PRAGMA 是 no-op）。

## 001_init.sql 覆盖

9 张表：`users` / `networks` / `devices` / `device_keys` / `invitations` /
`lan_routes` / `alias_mappings` / `config_revisions` / `audit_events`。

关键约束（集成测试见 `apps/server/tests/migrations.rs`）：
- `devices`：`UNIQUE(network_id, name)`、`UNIQUE(network_id, virtual_ipv4)`，
  只存 `public_key`，**无任何私钥列**（ADR-010 / §11.2）；
- `invitations`：`token_hash UNIQUE`，只存摘要，不存原始 token；
- `config_revisions`：复合主键 `(network_id, revision)`；
- 外键：`devices.network_id → networks.id` 等，孤儿设备被拒绝。

设计基线见 [docs/architecture/domain-model.md](../docs/architecture/domain-model.md)（ADR-003/009）。
