# migrations

SQLx migrations 落库目录。当前版本：`008_device_registrations.sql`。

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
