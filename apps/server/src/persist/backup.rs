//! Mesh 状态持久化与启动重建（[存档 §17.3](../../docs/review/chatgpt-2026-10-13.md)）
//! 与一致性备份/恢复（[存档 §17.4](../../docs/review/chatgpt-2026-10-13.md)）。
//!
//! 请求路径：`MeshState` 仍是唯一事实源（`service.rs`）；每次变更在锁内
//! 完成后，由 handler 把**新行**镜像到 SQLite（本模块的 `insert_*`/
//! `update_*`/`delete_*`）。落库失败 → 请求 500（「不落库不放行」，与审计
//! 的「不留痕不放行」同纪律）；内存与 DB 的写序由 `AppState::persist` 互斥
//! 串行化（变更 + 落库同临界区），任何并发交错都不会让旧行覆盖新行。
//!
//! 启动路径（[`load`]）：
//! 1. 从 DB 装载 networks/devices/lan_routes/invitations/config_revisions/
//!    `mesh_meta`（route_seq），重建 `MeshState`——IPAM 保留全部已分配地址
//!    （含已撤销设备），修订序列与哈希逐字回放；
//! 2. **中断收敛（§10.3）**：停在 `applying` 的修订结果不可知，一律落
//!    `failed` + 中断诊断并回写 DB（不假装成功）；`rollback_pending` 保留
//!    可重试；已 `applied` 不重放 backend；
//! 3. presence 证据时间戳按 DB 原值恢复——重启**不虚构**在线（§12.4）：
//!    判定发生在读取时刻，无新鲜证据即 `offline`/`tunnel_only`。
//!
//! 备份/恢复（§17.4）：[`backup_to`] 以 `VACUUM INTO` 产生单一自洽的本地
//! 快照（一致性由 SQLite 快照本身保证）；[`restore_from_backup`] 校验 →
//! 原子换名 → 留痕 → 复用 [`load`] 重建，语义与正常启动一致。
//!
//! 客户端（agent）侧重启恢复随数据面 backend 落地（拉取期望配置重新应用），
//! 本模块先把「服务端重启不丢期望状态」钉死。

use super::shared::MeshStatePersistedView;
use super::tasks::load;
use sqlx::sqlite::SqliteConnection;
use sqlx::{ConnectOptions, Executor, SqlitePool};
use std::path::{Path, PathBuf};
use std::str::FromStr as _;
use std::time::Duration;

// ---------------------------------------------------------------------------
// 一致性备份与恢复（存档 §17.4）
// ---------------------------------------------------------------------------

const LEGACY_REQUIRED_TABLES: [&str; 16] = [
    "agent_tokens",
    "alias_mappings",
    "audit_events",
    "bootstrap_tokens",
    "config_revisions",
    "device_keys",
    "device_registrations",
    "devices",
    "diagnostics_runs",
    "invitations",
    "lan_routes",
    "mesh_meta",
    "networks",
    "sessions",
    "users",
    "api_tokens",
];

/// 备份/恢复错误（§17.4：明确拒绝，绝不留半恢复状态）。
#[derive(Debug)]
pub enum BackupError {
    /// 备份目标文件已存在（不覆盖既有备份）。
    TargetExists(String),
    /// 源不是数据库或内容损坏（quick_check/打开失败）。
    Corrupt(String),
    /// 数据库合法但缺表（不完整备份，拒绝恢复）。
    IncompleteSchema {
        missing: Vec<String>,
    },
    /// 活动库被占用（恢复前必须先停 meshlet-server）。
    Locked(String),
    Io(std::io::Error),
    Db(sqlx::Error),
}

impl std::fmt::Display for BackupError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::TargetExists(path) => write!(f, "backup target already exists: {path}"),
            Self::Corrupt(why) => write!(f, "backup file is not a usable database: {why}"),
            Self::IncompleteSchema { missing } => {
                write!(
                    f,
                    "backup is missing required tables: {}",
                    missing.join(", ")
                )
            }
            Self::Locked(why) => {
                write!(
                    f,
                    "database is locked ({why}); stop meshlet-server before restore"
                )
            }
            Self::Io(e) => write!(f, "io: {e}"),
            Self::Db(e) => write!(f, "db: {e}"),
        }
    }
}

impl std::error::Error for BackupError {}

impl From<sqlx::Error> for BackupError {
    fn from(e: sqlx::Error) -> Self {
        let text = e.to_string();
        // SQLite「database is locked / busy」→ 提示先停服务再恢复。
        if text.contains("locked") || text.contains("busy") {
            return Self::Locked(text);
        }
        Self::Db(e)
    }
}

impl From<std::io::Error> for BackupError {
    fn from(e: std::io::Error) -> Self {
        Self::Io(e)
    }
}

/// 一次备份的报告（路径 + 字节数 + **从备份文件本体读出的**内容摘要——
/// 顺带证明备份文件可独立打开且 schema 完整）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BackupReport {
    pub path: String,
    pub bytes: u64,
    pub view: MeshStatePersistedView,
}

/// 校验备份文件：独立只读打开 + `quick_check` + 必需表齐全，返回内容摘要。
///
/// 任何一步失败都按 [`BackupError::Corrupt`] / [`BackupError::IncompleteSchema`]
/// 拒绝——损坏/不完整的备份绝不进入恢复流程。只读连接必须按 RAII drop 释放
/// （池式 close 对 SQLite 文件句柄的释放是惰性的；Windows 上会挡住恢复拷贝）。
pub async fn validate_backup(path: &Path) -> Result<MeshStatePersistedView, BackupError> {
    let mut connection =
        sqlx::sqlite::SqliteConnectOptions::from_str(&format!("sqlite:{}", path.display()))?
            .read_only(true)
            .connect()
            .await
            .map_err(|e| BackupError::Corrupt(e.to_string()))?;

    // 把校验结果先移出连接作用域，再显式 drop，确保 `copy`/`rename` 之前
    // 没有文件句柄还挂在备份或 staging 文件上。
    let result = validate_on(&mut connection).await.map_err(|e| match e {
        e @ BackupError::IncompleteSchema { .. } => e,
        e => BackupError::Corrupt(e.to_string()),
    });
    drop(connection);
    result
}

async fn validate_on(pool: &mut SqliteConnection) -> Result<MeshStatePersistedView, BackupError> {
    let check: Vec<String> = sqlx::query_scalar("PRAGMA quick_check")
        .fetch_all(&mut *pool)
        .await?;
    if check.iter().any(|r| r != "ok") {
        return Err(BackupError::Corrupt(check.join("; ")));
    }

    let tables: Vec<String> = sqlx::query_scalar(
        "SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%' \
         AND name NOT LIKE '_sqlx_%'",
    )
    .fetch_all(&mut *pool)
    .await?;
    let base_missing: Vec<String> = LEGACY_REQUIRED_TABLES
        .iter()
        .filter(|t| !tables.iter().any(|have| have == **t))
        .map(|t| t.to_string())
        .collect();
    if !base_missing.is_empty() {
        return Err(BackupError::IncompleteSchema {
            missing: base_missing,
        });
    }
    let has_migration_history: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type='table' AND name='_sqlx_migrations')",
    )
    .fetch_one(&mut *pool)
    .await?;
    if !has_migration_history {
        return Err(BackupError::IncompleteSchema {
            missing: vec!["_sqlx_migrations".into()],
        });
    }
    let latest: Option<i64> =
        sqlx::query_scalar("SELECT MAX(version) FROM _sqlx_migrations WHERE success=1")
            .fetch_one(&mut *pool)
            .await?;
    let mut required = LEGACY_REQUIRED_TABLES.to_vec();
    if latest.is_some_and(|v| v >= 9) {
        required.extend(["hub_deployments", "device_apply_receipts"]);
    }
    if latest.is_some_and(|v| v >= 10) {
        required.extend(["segments", "segment_grants"]);
    }
    let missing: Vec<String> = required
        .iter()
        .filter(|t| !tables.iter().any(|have| have == *t))
        .map(|t| t.to_string())
        .collect();
    if !missing.is_empty() {
        return Err(BackupError::IncompleteSchema { missing });
    }

    let has_segments = tables.iter().any(|table| table == "segments");
    let has_publish = tables.iter().any(|table| table == "publish_forwards");
    Ok(MeshStatePersistedView {
        networks: count_on(&mut *pool, "networks").await?,
        devices: count_on(&mut *pool, "devices").await?,
        registrations: count_on(&mut *pool, "device_registrations").await?,
        routes: count_on(&mut *pool, "lan_routes").await?,
        aliases: count_on(&mut *pool, "alias_mappings").await?,
        segments: if has_segments {
            count_on(&mut *pool, "segments").await?
        } else {
            0
        },
        segment_grants: if has_segments {
            count_on(&mut *pool, "segment_grants").await?
        } else {
            0
        },
        invites: count_on(&mut *pool, "invitations").await?,
        publishes: if has_publish {
            count_on(&mut *pool, "publish_forwards").await?
                + count_on(&mut *pool, "publish_http_routes").await?
                + count_on(&mut *pool, "publish_probes").await?
                + count_on(&mut *pool, "publish_dns_records").await?
        } else {
            0
        },
        revisions: count_on(&mut *pool, "config_revisions").await?,
    })
}

async fn count_on<'e, E>(pool: E, table: &str) -> Result<usize, BackupError>
where
    E: Executor<'e, Database = sqlx::Sqlite> + 'e,
{
    // Callers use fixed schema table names, never user input.
    let n: i64 = sqlx::query_scalar(&format!("SELECT COUNT(*) FROM {table}"))
        .fetch_one(pool)
        .await?;
    Ok(usize::try_from(n).unwrap_or(0))
}

/// 生成备份目录下的唯一文件名（毫秒时间戳，排序即时间序）。
fn backup_filename(now: chrono::DateTime<chrono::Utc>) -> String {
    format!("meshlet-backup-{}.db", now.format("%Y%m%dT%H%M%S%3fZ"))
}

/// 写一份一致性备份到 `dir`（SQLite `VACUUM INTO` 在线备份语义）。
///
/// - 备份是**单一自洽快照**（WAL 下由 SQLite 读事务保证），可独立打开；
/// - 目标文件已存在则拒绝（不静默覆盖既有备份）；
/// - 备份文件含口令哈希等敏感材料，落盘即收紧权限（0600）。
///
/// 一致性来自 SQLite 快照本身，与 `AppState::persist` 互斥无关。
pub async fn backup_to(pool: &SqlitePool, dir: &Path) -> Result<BackupReport, BackupError> {
    tokio::fs::create_dir_all(dir).await?;
    let path = dir.join(backup_filename(chrono::Utc::now()));
    if path.exists() {
        return Err(BackupError::TargetExists(path.display().to_string()));
    }
    sqlx::query("VACUUM INTO ?")
        .bind(path.display().to_string())
        .execute(pool)
        .await?;
    restrict_permissions(&path);
    let bytes = tokio::fs::metadata(&path).await?.len();
    let view = validate_backup(&path).await?;
    Ok(BackupReport {
        path: path.display().to_string(),
        bytes,
        view,
    })
}

/// 备份落盘即收紧权限（unix）；其它平台沿用系统默认。
fn restrict_permissions(path: &Path) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600));
    }
    #[cfg(not(unix))]
    let _ = path;
}

/// 恢复后的库应归属谁。
///
/// `restore` 子命令通常由 root 执行，而服务以非特权用户运行（随包单元
/// `User=meshlet`）；不修复归属，恢复出的库是 root 所有，服务启动即
/// `unable to open database file` 并 crash-loop。优先级：被替换的既有活动库
/// （原地恢复，最常见），其次数据目录本身（空目录里的首次恢复）。
#[cfg(unix)]
pub(super) fn resolve_restored_database_owner(
    database: &Path,
    prior_owner: Option<(u32, u32)>,
) -> Option<(u32, u32)> {
    use std::os::unix::fs::MetadataExt as _;
    prior_owner.or_else(|| {
        database
            .parent()
            .and_then(|dir| dir.metadata().ok())
            .map(|m| (m.uid(), m.gid()))
    })
}

/// 把恢复出的库设回服务用户的归属。必须在换名**之后**调用（换名前读到的
/// 是旧库）；root 之外执行时 chown 必然 EPERM，而文件本就归当前用户，忽略。
#[cfg(unix)]
fn apply_restored_database_owner(database: &Path, prior_owner: Option<(u32, u32)>) {
    if let Some((uid, gid)) = resolve_restored_database_owner(database, prior_owner) {
        let _ = std::os::unix::fs::chown(database, Some(uid), Some(gid));
    }
}

/// 备份一次并留痕（`system.backup` 审计事件）。端点（actor=操作者）与
/// 定时任务（actor=None）共用；审计失败即备份失败（与业务同库，§16.5）。
pub async fn backup_once(
    pool: &SqlitePool,
    dir: &Path,
    actor: Option<&str>,
) -> Result<BackupReport, BackupError> {
    let report = backup_to(pool, dir).await?;
    crate::audit::AuditStore::new(pool.clone())
        .record(
            actor,
            "system.backup",
            "server",
            Some(&report.path),
            Some(serde_json::json!({
                "bytes": report.bytes,
                "networks": report.view.networks,
                "devices": report.view.devices,
                "routes": report.view.routes,
                "invites": report.view.invites,
                "revisions": report.view.revisions,
            })),
        )
        .await?;
    Ok(report)
}

/// 一次恢复的报告。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RestoreReport {
    pub source: String,
    pub database: String,
    pub summary: MeshStatePersistedView,
    /// §10.3 中断收敛（applying → failed）的修订（network_id, revision）。
    pub interrupted: Vec<(String, u64)>,
}

/// 从备份文件恢复活动库（存档 §17.4）。
///
/// 流程（任何一步失败都不触碰活动库——**不留半恢复状态**）：
/// 1. 实例锁（[`crate::instance_lock`]）：meshlet-server 在跑则整体拒绝——
///    WAL 下空闲服务不持写事务，第 4 步的 `BEGIN EXCLUSIVE` 拦不住「换名后
///    旧 inode 继续吃写入」的丢数据路径（2026-10-24 验收实录）；
/// 2. 校验备份（[`validate_backup`]：独立打开 + quick_check + 必需表齐全）；
/// 3. 拒绝旁挂非空 WAL 的备份（只拷主文件会静默丢已提交事务）；
/// 4. 活动库可独占加锁（否则提示先停 meshlet-server；advisory 锁之外的
///    外来 SQLite 连接由这一步兜底）；
/// 5. 备份 → 临时文件 → 再校验 → 原子换名；替换前清掉旧 `-wal`/`-shm`；
/// 6. 打开恢复后的库，留痕 `system.restore` 审计事件；
/// 7. 复用 §17.3 [`load`] 重建 + 收敛（applying → failed、rollback_pending
///    保留、applied 不重放——与正常启动完全同一条路径，不比现在更弱）。
pub async fn restore_from_backup(
    backup: &Path,
    database: &Path,
    thresholds: meshlet_domain::PresenceThresholds,
) -> Result<RestoreReport, BackupError> {
    // 实例锁守卫：拿不到（服务在跑）或打不开（无法证明没服务在跑）都拒绝。
    // 锁持有到函数返回，恢复期间启动的服务会得到明确失败而不是半恢复。
    let _instance_guard = match crate::instance_lock::try_acquire(database) {
        Ok(lock) => lock,
        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
            return Err(BackupError::Locked(format!(
                "lock {} is held (meshlet-server is running); stop meshlet-server before restore",
                crate::instance_lock::lock_path(database).display(),
            )));
        }
        Err(error) => {
            return Err(BackupError::Locked(format!(
                "cannot verify the live database is unused ({}: {error}); stop meshlet-server before restore",
                crate::instance_lock::lock_path(database).display(),
            )));
        }
    };
    let view = validate_backup(backup).await?;

    // 备份旁挂着**非空**的 WAL（有人对备份文件写过且未 checkpoint）——只拷贝
    // 主文件会静默丢已提交事务，明确拒绝：重取备份或先 checkpoint。
    // 零字节 WAL（TRUNCATE checkpoint 之后）不含任何帧，无害放行。
    let wal = PathBuf::from(format!("{}-wal", backup.display()));
    if wal.metadata().map(|m| m.len() > 0).unwrap_or(false) {
        return Err(BackupError::Corrupt(
            "backup has an unsettled write-ahead log (backup-wal has frames); re-take the backup before restoring"
                .into(),
        ));
    }

    // 活动库存在则要求可独占加锁（best-effort 防呆：服务器在跑时 WAL 下
    // 常规写大概率立刻可见）。
    if database.exists() {
        let options = sqlx::sqlite::SqliteConnectOptions::from_str(&format!(
            "sqlite:{}",
            database.display()
        ))?
        .create_if_missing(false);
        let mut connection = options.connect().await?;
        match sqlx::query("BEGIN EXCLUSIVE")
            .execute(&mut connection)
            .await
        {
            Ok(_) => {
                let _ = sqlx::query("COMMIT").execute(&mut connection).await;
            }
            Err(error) => return Err(BackupError::from(error)),
        }
        drop(connection);
    }

    // 拷贝到临时文件并复验（拷贝本身损坏也拒绝），再原子换名。
    // 先记下既有活动库归属：服务以独立用户运行，而恢复通常由 root 执行。
    #[cfg(unix)]
    let prior_owner = database.metadata().ok().map(|m| {
        use std::os::unix::fs::MetadataExt as _;
        (m.uid(), m.gid())
    });

    let tmp = database.with_extension("restore-tmp");
    let _ = tokio::fs::remove_file(&tmp).await;
    copy_with_windows_busy_retry(backup, &tmp).await?;
    restrict_permissions(&tmp);
    validate_backup(&tmp).await?;

    // Upgrade and validate in staging; a failed migration must not replace the live DB.
    let pool = crate::store::connect(&format!("sqlite:{}", tmp.display())).await?;
    crate::audit::AuditStore::new(pool.clone())
        .record(
            None,
            "system.restore",
            "server",
            Some(&database.display().to_string()),
            Some(serde_json::json!({
                "source": backup.display().to_string(),
                "networks": view.networks,
                "devices": view.devices,
                "routes": view.routes,
                "invites": view.invites,
                "revisions": view.revisions,
            })),
        )
        .await?;
    let boot = load(&pool, thresholds).await?;
    sqlx::query("PRAGMA wal_checkpoint(TRUNCATE)")
        .execute(&pool)
        .await?;
    pool.close().await;
    validate_backup(&tmp).await?;
    // 换名前清掉两类旁挂：既有活动库的 `-wal`/`-shm`（旧库的），以及
    // staging 文件自身的——pool 关闭后残留在库里即悬空垃圾。
    for base in [tmp.as_path(), database] {
        for suffix in ["-wal", "-shm"] {
            let _ =
                tokio::fs::remove_file(PathBuf::from(format!("{}{suffix}", base.display()))).await;
        }
    }
    rename_with_windows_busy_retry(&tmp, database).await?;
    sync_parent_dir(database);
    // 恢复通常由 root 执行，服务以独立用户运行：不归还归属，服务起来即打不开库。
    #[cfg(unix)]
    apply_restored_database_owner(database, prior_owner);

    Ok(RestoreReport {
        source: backup.display().to_string(),
        database: database.display().to_string(),
        summary: boot.summary,
        interrupted: boot.interrupted,
    })
}

/// fsync 父目录（unix），换名落盘；失败忽略（best-effort）。
fn sync_parent_dir(database: &Path) {
    #[cfg(unix)]
    {
        if let Some(parent) = database.parent() {
            if let Ok(dir) = std::fs::File::open(parent) {
                let _ = dir.sync_all();
            }
        }
    }
    #[cfg(not(unix))]
    let _ = database;
}

/// Windows 上 SQLite 句柄关闭后，OS 仍可能短暂挡住文件独占访问。
/// 只重试「另一个进程正在使用文件」这一类瞬态失败，其它 IO 错误原样返回。
async fn copy_with_windows_busy_retry(from: &Path, to: &Path) -> Result<(), BackupError> {
    let mut attempt = 1u32;
    loop {
        match tokio::fs::copy(from, to).await {
            Ok(_) => return Ok(()),
            Err(error) if error.raw_os_error() == Some(32) && attempt < 10 => {
                tokio::time::sleep(Duration::from_millis((25 * attempt) as u64)).await;
                attempt += 1;
            }
            Err(error) => return Err(error.into()),
        }
    }
}

/// 同上：原子换名也可能因 staging 文件句柄尚未释放而短暂失败。
async fn rename_with_windows_busy_retry(from: &Path, to: &Path) -> Result<(), BackupError> {
    let mut attempt = 1u32;
    loop {
        match tokio::fs::rename(from, to).await {
            Ok(_) => return Ok(()),
            Err(error) if error.raw_os_error() == Some(32) && attempt < 10 => {
                tokio::time::sleep(Duration::from_millis((25 * attempt) as u64)).await;
                attempt += 1;
            }
            Err(error) => return Err(error.into()),
        }
    }
}
