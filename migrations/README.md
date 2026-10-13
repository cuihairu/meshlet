# migrations

SQLx migrations 落库目录。当前版本：`001_init.sql`（Phase 1 核心实体）。

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
