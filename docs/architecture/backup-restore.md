# 备份与恢复

> 来源：[存档 §17.4](../review/chatgpt-2026-10-13.md)。实现：`apps/server/src/persist.rs`
> （`backup_to` / `backup_once` / `validate_backup` / `restore_from_backup`）、
> `apps/server/src/backup.rs`（端点）、`apps/server/src/main.rs`（`restore` 子命令与
> 定时任务）、`crates/meshlet-config`（`[backup]` 配置）。

## 定位：备份 ≠ 同步

- 备份**只写本地路径**（`[backup] dir`），无任何外发、云上传或遥测；
- **默认不自动备份**（`[backup] auto` 默认 `false`）：开自动备份必须显式配置；
- 备份目录未配置时 `POST /api/v1/system/backup` 明确返回
  `503 backup_not_configured`——默认部署不产生任何备份文件。

## 一致性备份

备份用 SQLite `VACUUM INTO` 语义：**单一自洽快照**，由 SQLite 读事务保证一致性
（WAL 下与并发写入互不阻塞），产物是**一个可独立打开的完整数据库文件**——
表结构与迁移（001–005，共 13 张表）齐全，备份时刻的内容自洽。

| 维度 | 行为 |
|---|---|
| 触发 | `POST /api/v1/system/backup`（会话或 `write` scope Token + CSRF）🔒；或 `[backup] auto = true` 的定时任务 |
| 位置 | `<dir>/meshlet-backup-<UTC 时间戳>.db`（毫秒精度，排序即时间序） |
| 不覆盖 | 目标文件已存在则拒绝（`409 conflict`），既有备份绝不被静默覆盖 |
| 权限 | 落盘即收紧为 `0600`（含口令哈希等敏感材料，等价于数据库本体） |
| 自检 | 写完后独立只读打开 + `PRAGMA quick_check` + 必需表齐全校验，摘要随响应返回 |
| 审计 | `system.backup`（端点：actor = 操作者；定时任务：actor 为空） |

响应即备份内容摘要（`path` / `bytes` / 各表行数）——数字来自**备份文件本体**的
读取，顺带证明备份可用。

配置示例：

```toml
[backup]
dir = "/var/lib/meshlet/backups"   # 备份目录（缺省不配置 = 端点 503）
auto = false                        # 显式开启定时备份（默认关）
interval_secs = 86400               # 定时间隔（秒，默认一天）
```

定时任务每 `interval_secs` 写一份（启动后首拍立即写一份），失败只记日志，
不影响服务。

## 恢复

恢复是**离线操作**：活动库文件不能在被服务时替换，因此恢复走
`meshlet-server` 子命令而不是 HTTP：

```bash
# 1. 停止服务
systemctl stop meshlet-server
# 2. 从备份恢复（同一 DB 路径，来自配置）
meshlet-server restore /var/lib/meshlet/backups/meshlet-backup-20261014T132859410Z.db /etc/meshlet/meshlet.toml
# 3. 启动服务（按 §17.3 语义加载到期望状态）
systemctl start meshlet-server
```

恢复流程（**任何一步失败都不触碰活动库——不留半恢复状态**）：

1. **校验备份**：独立只读打开 + `quick_check` + 必需表齐全；损坏或 schema
   不完整的备份明确拒绝，并点名缺失的表；
2. **拒绝未合并的 WAL**：备份旁挂着非空 `-wal` 时拒绝（只拷贝主文件会静默
   丢已提交事务）——重取备份再恢复；
3. **占用检查**：活动库存在时要求可独占加锁，失败即提示「先停
   meshlet-server」；
4. **拷贝 → 复验 → 原子换名**：备份复制到 `<db>.restore-tmp` 并再次校验，
   清掉旧 `-wal`/`-shm`，再原子换名覆盖活动库（中途失败仍停在旧库）；
5. **留痕**：`system.restore` 审计事件（actor 为空，detail 记源路径与内容摘要）；
6. **按期望状态协调**：复用 §17.3 的启动重建——IPAM 已分配集合、路由 id
   序列、修订序列与 `desired_config_hash` 逐字段恢复。

### 恢复的收敛语义与正常启动完全一致

恢复**不比 §17.3 启动更弱**——同一条 `persist::load` 路径：

| 备份里的状态 | 恢复后 | 依据 |
|---|---|---|
| `applying`（进程中断时正在应用） | `failed` + error_summary 点名进程中断 | §10.3 不假装成功 |
| `rollback_pending` | 原样保留，可继续回滚 | 未确认 ≠ 成功 |
| `applied` | 原样保留，**不重放 backend** | §10.3 幂等 |
| 被更新修订取代的 `failed` 修订 | 回滚仍返回 `409`（跨恢复成立） | §10.4 交叉破坏防线 |
| 在线证据时间戳 | 按 DB 原值恢复，判定在读取时刻做——旧证据不虚构 `online` | §12.4 保守判定 |

## 运维建议

- **备份文件等同数据库本体**（含口令哈希与 Token 摘要）：权限 0600，出机即加密；
- 恢复前先停服务，恢复后启动服务确认 `meshlet state rebuilt from database`
  日志与审计里的 `system.restore`；
- 校验一次备份是否可用：直接打开它（如 `sqlite3 <backup> 'select count(*) from networks'`）
  或让它过一遍 `validate_backup`（`meshlet-backup` 文件名即时间序，恢复任一份即可）；
- 备份不是同步：多机/异地副本不在本能力范围内（§17.4 的边界声明）。
