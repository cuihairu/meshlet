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

use meshlet_domain::{
    ConfigRevision, DesiredStateStatus, Device, DeviceId, DeviceStatus, Invite, InviteId, Ipv4Cidr,
    LanRoute, LanRouteId, Network, NetworkId, NetworkStatus, Platform, ReturnPathMode, RouteMode,
};
use sqlx::sqlite::SqlitePoolOptions;
use sqlx::SqlitePool;
use std::path::{Path, PathBuf};
use std::str::FromStr as _;

use crate::service::{MeshState, ServiceError};

/// §10.3 中断诊断：点名进程中断，调用方可据此解释「为什么没应用」。
pub const INTERRUPTED_SUMMARY: &str =
    "interrupted: server process restarted while this revision was being applied; \
     outcome unknown, marked failed (archive 10.3: never pretend success)";

/// 启动重建结果（供日志与测试断言）。
pub struct BootState {
    /// 重建出的 Mesh 状态（交 `AppState` 运行）。
    pub mesh: MeshState,
    /// 重建摘要（日志与测试断言）。
    pub summary: MeshStatePersistedView,
    /// 被 §10.3 中断收敛（applying → failed）的修订（network_id, revision）。
    pub interrupted: Vec<(String, u64)>,
}

/// [`BootState`] 的可断言摘要（`MeshState` 字段私有，不直接暴露）。
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct MeshStatePersistedView {
    pub networks: usize,
    pub devices: usize,
    pub routes: usize,
    pub invites: usize,
    pub revisions: usize,
}

// ---------------------------------------------------------------------------
// 状态 ↔ 行
// ---------------------------------------------------------------------------

fn device_status_to_str(s: DeviceStatus) -> &'static str {
    match s {
        DeviceStatus::Pending => "pending",
        DeviceStatus::Active => "active",
        DeviceStatus::Revoked => "revoked",
    }
}

fn device_status_parse(s: &str) -> Result<DeviceStatus, String> {
    match s {
        "pending" => Ok(DeviceStatus::Pending),
        "active" => Ok(DeviceStatus::Active),
        "revoked" => Ok(DeviceStatus::Revoked),
        other => Err(format!("unknown device status {other:?}")),
    }
}

fn network_status_to_str(s: NetworkStatus) -> &'static str {
    match s {
        NetworkStatus::Active => "active",
        NetworkStatus::Deleting => "deleting",
    }
}

fn network_status_parse(s: &str) -> Result<NetworkStatus, String> {
    match s {
        "active" => Ok(NetworkStatus::Active),
        "deleting" => Ok(NetworkStatus::Deleting),
        other => Err(format!("unknown network status {other:?}")),
    }
}

fn desired_status_to_str(s: DesiredStateStatus) -> &'static str {
    s.as_str()
}

fn desired_status_parse(s: &str) -> Result<DesiredStateStatus, String> {
    match s {
        "pending" => Ok(DesiredStateStatus::Pending),
        "applied" => Ok(DesiredStateStatus::Applied),
        "failed" => Ok(DesiredStateStatus::Failed),
        other => Err(format!("unknown desired status {other:?}")),
    }
}

fn apply_status_parse(s: &str) -> Result<meshlet_domain::ApplyStatus, String> {
    use meshlet_domain::ApplyStatus;
    match s {
        "pending" => Ok(ApplyStatus::Pending),
        "applying" => Ok(ApplyStatus::Applying),
        "applied" => Ok(ApplyStatus::Applied),
        "failed" => Ok(ApplyStatus::Failed),
        "rollback_pending" => Ok(ApplyStatus::RollbackPending),
        "rolled_back" => Ok(ApplyStatus::RolledBack),
        other => Err(format!("unknown apply status {other:?}")),
    }
}

fn platform_to_str(p: Platform) -> &'static str {
    match p {
        Platform::Linux => "linux",
        Platform::Windows => "windows",
    }
}

fn platform_parse(s: &str) -> Result<Platform, String> {
    match s {
        "linux" => Ok(Platform::Linux),
        "windows" => Ok(Platform::Windows),
        other => Err(format!("unknown platform {other:?}")),
    }
}

fn corrupt(what: &str, e: impl std::fmt::Display) -> sqlx::Error {
    sqlx::Error::Io(std::io::Error::new(
        std::io::ErrorKind::InvalidData,
        format!("corrupt persisted state: {what}: {e}"),
    ))
}

// ---------------------------------------------------------------------------
// 写路径（新行镜像）
// ---------------------------------------------------------------------------

/// 落库一个网络行。
pub async fn insert_network(pool: &SqlitePool, n: &Network) -> Result<(), sqlx::Error> {
    sqlx::query(
        "INSERT INTO networks (id, name, overlay_cidr, status, created_at, updated_at)
         VALUES (?, ?, ?, ?, ?, ?)",
    )
    .bind(n.id.to_string())
    .bind(&n.name)
    .bind(n.overlay_cidr.to_string())
    .bind(network_status_to_str(n.status))
    .bind(&n.created_at)
    .bind(&n.updated_at)
    .execute(pool)
    .await?;
    Ok(())
}

/// 落库一台设备行（enroll）。
pub async fn insert_device(pool: &SqlitePool, d: &Device) -> Result<(), sqlx::Error> {
    sqlx::query(
        "INSERT INTO devices
           (id, network_id, name, virtual_ipv4, public_key, platform, status,
            last_seen_at, last_handshake_at, last_report_at, created_at, revoked_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(d.id.to_string())
    .bind(d.network_id.to_string())
    .bind(&d.name)
    .bind(d.virtual_ipv4.to_string())
    .bind(&d.public_key)
    .bind(platform_to_str(d.platform))
    .bind(device_status_to_str(d.status))
    .bind(&d.last_seen_at)
    .bind(&d.last_handshake_at)
    .bind(&d.last_report_at)
    .bind(&d.created_at)
    .bind(&d.revoked_at)
    .execute(pool)
    .await?;
    Ok(())
}

/// 回写设备状态（撤销：status/revoked_at）。
pub async fn update_device_status(pool: &SqlitePool, d: &Device) -> Result<(), sqlx::Error> {
    sqlx::query("UPDATE devices SET status = ?, revoked_at = ? WHERE id = ?")
        .bind(device_status_to_str(d.status))
        .bind(&d.revoked_at)
        .bind(d.id.to_string())
        .execute(pool)
        .await?;
    Ok(())
}

/// 回写在线证据时间戳（心跳路径，§14.1）。
pub async fn update_device_presence(pool: &SqlitePool, d: &Device) -> Result<(), sqlx::Error> {
    sqlx::query(
        "UPDATE devices SET last_seen_at = ?, last_handshake_at = ?, last_report_at = ? \
         WHERE id = ?",
    )
    .bind(&d.last_seen_at)
    .bind(&d.last_handshake_at)
    .bind(&d.last_report_at)
    .bind(d.id.to_string())
    .execute(pool)
    .await?;
    Ok(())
}

/// 落库一条 LAN 路由 + 当前路由 id 序列（同一事务）。
pub async fn insert_route(
    pool: &SqlitePool,
    r: &LanRoute,
    route_seq: u64,
) -> Result<(), sqlx::Error> {
    let mut tx = pool.begin().await?;
    sqlx::query(
        "INSERT INTO lan_routes
           (id, network_id, gateway_device_id, destination_cidr, route_mode,
            return_path_mode, status, created_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(r.id.to_string())
    .bind(r.network_id.to_string())
    .bind(r.gateway_device_id.to_string())
    .bind(r.destination_cidr.to_string())
    .bind(r.route_mode.as_str())
    .bind(r.return_path_mode.as_str())
    .bind(desired_status_to_str(r.status))
    .bind(&r.created_at)
    .execute(&mut *tx)
    .await?;
    save_route_seq_tx(&mut tx, route_seq).await?;
    tx.commit().await?;
    Ok(())
}

async fn save_route_seq_tx(
    tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
    route_seq: u64,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "INSERT INTO mesh_meta (key, value) VALUES ('route_seq', ?)
         ON CONFLICT (key) DO UPDATE SET value = excluded.value",
    )
    .bind(route_seq.to_string())
    .execute(&mut **tx)
    .await?;
    Ok(())
}

/// 删除一条 LAN 路由（路由 id 序列不回退，已删 id 不复用）。
pub async fn delete_route(pool: &SqlitePool, route_id: &str) -> Result<(), sqlx::Error> {
    sqlx::query("DELETE FROM lan_routes WHERE id = ?")
        .bind(route_id)
        .execute(pool)
        .await?;
    Ok(())
}

/// 撤销设备时移除其发布的全部路由（§11.5）。
pub async fn delete_routes_of_device(
    pool: &SqlitePool,
    gateway_device_id: &str,
) -> Result<(), sqlx::Error> {
    sqlx::query("DELETE FROM lan_routes WHERE gateway_device_id = ?")
        .bind(gateway_device_id)
        .execute(pool)
        .await?;
    Ok(())
}

/// 落库一个新修订（`record` 产生，恒 `pending`）。
pub async fn insert_revision(pool: &SqlitePool, r: &ConfigRevision) -> Result<(), sqlx::Error> {
    sqlx::query(
        "INSERT INTO config_revisions
           (network_id, revision, desired_config_hash, apply_status, created_at,
            applied_at, error_summary)
         VALUES (?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(r.network_id.to_string())
    .bind(r.revision as i64)
    .bind(&r.desired_config_hash)
    .bind(r.apply_status.as_str())
    .bind(&r.created_at)
    .bind(&r.applied_at)
    .bind(&r.error_summary)
    .execute(pool)
    .await?;
    Ok(())
}

/// 回写修订的应用状态（apply/rollback/中断收敛）。
pub async fn update_revision_status(
    pool: &SqlitePool,
    r: &ConfigRevision,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "UPDATE config_revisions
         SET apply_status = ?, applied_at = ?, error_summary = ?
         WHERE network_id = ? AND revision = ?",
    )
    .bind(r.apply_status.as_str())
    .bind(&r.applied_at)
    .bind(&r.error_summary)
    .bind(r.network_id.to_string())
    .bind(r.revision as i64)
    .execute(pool)
    .await?;
    Ok(())
}

/// 落库/回写一份邀请（创建、兑换递增 `used_count`、撤销）。
pub async fn save_invite(pool: &SqlitePool, i: &Invite) -> Result<(), sqlx::Error> {
    sqlx::query(
        "INSERT INTO invitations
           (id, network_id, token_hash, expires_at, max_uses, used_count, created_at, revoked_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?)
         ON CONFLICT (id) DO UPDATE SET
           used_count = excluded.used_count,
           revoked_at = excluded.revoked_at",
    )
    .bind(i.id.to_string())
    .bind(i.network_id.to_string())
    .bind(&i.token_hash)
    .bind(&i.expires_at)
    .bind(i.max_uses)
    .bind(i.used_count)
    .bind(&i.created_at)
    .bind(&i.revoked_at)
    .execute(pool)
    .await?;
    Ok(())
}

// ---------------------------------------------------------------------------
// 启动重建（§17.3）
// ---------------------------------------------------------------------------

/// 从 DB 重建 `MeshState` 并做 §10.3 中断收敛。
///
/// 期望状态逐字恢复（设备虚拟 IP / 路由 / 修订号与哈希与重启前一致）；
/// IPAM 重放全部分配；`applying` 修订收敛为 `failed` 并**回写 DB**（第二次
/// 重启看到的已是 `failed`，收敛幂等）。
pub async fn load(
    pool: &SqlitePool,
    thresholds: meshlet_domain::PresenceThresholds,
) -> Result<BootState, sqlx::Error> {
    let mut state = MeshState::new(thresholds);

    // 网络按创建顺序（net-N 序列决定插入序，列表展示稳定）。
    let network_rows = sqlx::query_as::<_, (String, String, String, String, String, String)>(
        "SELECT id, name, overlay_cidr, status, created_at, updated_at
         FROM networks ORDER BY created_at, id",
    )
    .fetch_all(pool)
    .await?;
    for (id, name, overlay_cidr, status, created_at, updated_at) in network_rows {
        let overlay: Ipv4Cidr = overlay_cidr
            .parse()
            .map_err(|e| corrupt("network overlay_cidr", e))?;
        let network = Network {
            status: network_status_parse(&status).map_err(|e| corrupt("network status", e))?,
            id: NetworkId(id),
            name,
            overlay_cidr: overlay,
            created_at,
            updated_at,
        };
        state
            .restore_network(network)
            .map_err(|e| corrupt("restore network", e.to_string()))?;
    }
    let networks = state.network_count();

    // 设备：注册表顺序 = 加入顺序（created_at, id）；IPAM 逐一保留地址。
    let device_rows = sqlx::query_as::<
        _,
        (
            String,
            String,
            String,
            String,
            String,
            String,
            String,
            Option<String>,
            Option<String>,
            Option<String>,
            String,
            Option<String>,
        ),
    >(
        "SELECT id, network_id, name, virtual_ipv4, public_key, platform, status,
                last_seen_at, last_handshake_at, last_report_at, created_at, revoked_at
         FROM devices ORDER BY created_at, id",
    )
    .fetch_all(pool)
    .await?;
    for row in device_rows {
        let device = Device {
            id: DeviceId(row.0),
            network_id: NetworkId(row.1),
            name: row.2,
            virtual_ipv4: row
                .3
                .parse()
                .map_err(|e| corrupt("device virtual_ipv4", e))?,
            public_key: row.4,
            platform: platform_parse(&row.5).map_err(|e| corrupt("device platform", e))?,
            status: device_status_parse(&row.6).map_err(|e| corrupt("device status", e))?,
            last_seen_at: row.7,
            last_handshake_at: row.8,
            last_report_at: row.9,
            created_at: row.10,
            revoked_at: row.11,
        };
        state
            .restore_device(device)
            .map_err(|e| corrupt("restore device", e.to_string()))?;
    }
    let devices = state.device_count();

    // LAN 路由 + 路由 id 序列。
    let route_rows = sqlx::query_as::<
        _,
        (
            String,
            String,
            String,
            String,
            String,
            String,
            String,
            String,
        ),
    >(
        "SELECT id, network_id, gateway_device_id, destination_cidr, route_mode,
                return_path_mode, status, created_at
         FROM lan_routes ORDER BY created_at, id",
    )
    .fetch_all(pool)
    .await?;
    for row in route_rows {
        let route = LanRoute {
            id: LanRouteId(row.0),
            network_id: NetworkId(row.1),
            gateway_device_id: DeviceId(row.2),
            destination_cidr: row
                .3
                .parse()
                .map_err(|e| corrupt("route destination_cidr", e))?,
            route_mode: RouteMode::parse(&row.4)
                .ok_or_else(|| corrupt("route route_mode", format!("{:?}", row.4)))?,
            return_path_mode: ReturnPathMode::parse(&row.5)
                .ok_or_else(|| corrupt("route return_path_mode", format!("{:?}", row.5)))?,
            status: desired_status_parse(&row.6).map_err(|e| corrupt("route status", e))?,
            created_at: row.7,
        };
        state.restore_route(route);
    }
    let routes = state.route_count();

    let route_seq: Option<String> =
        sqlx::query_scalar("SELECT value FROM mesh_meta WHERE key = 'route_seq'")
            .fetch_optional(pool)
            .await?;
    if let Some(seq) = route_seq {
        let seq: u64 = seq
            .parse()
            .map_err(|e: std::num::ParseIntError| corrupt("mesh_meta route_seq", e))?;
        state.set_route_seq(seq);
    }

    // 邀请（摘要索引；撤销/兑换计数如常恢复，未兑换的邀请跨重启仍可用）。
    let invite_rows = sqlx::query_as::<
        _,
        (
            String,
            String,
            String,
            Option<String>,
            i64,
            i64,
            String,
            Option<String>,
        ),
    >(
        "SELECT id, network_id, token_hash, expires_at, max_uses, used_count,
                created_at, revoked_at
         FROM invitations ORDER BY created_at, id",
    )
    .fetch_all(pool)
    .await?;
    for row in invite_rows {
        let invite = Invite {
            id: InviteId(row.0),
            network_id: NetworkId(row.1),
            token_hash: row.2,
            expires_at: row.3,
            max_uses: u32::try_from(row.4)
                .map_err(|e| corrupt("invite max_uses", e.to_string()))?,
            used_count: u32::try_from(row.5)
                .map_err(|e| corrupt("invite used_count", e.to_string()))?,
            created_at: row.6,
            revoked_at: row.7,
        };
        state.restore_invite(invite);
    }
    let invites = state.invite_count();

    // 修订簿记：逐字回放（哈希/状态/时间原样），随后做 §10.3 中断收敛。
    let revision_rows = sqlx::query_as::<
        _,
        (
            String,
            i64,
            String,
            String,
            String,
            Option<String>,
            Option<String>,
        ),
    >(
        "SELECT network_id, revision, desired_config_hash, apply_status, created_at,
                applied_at, error_summary
         FROM config_revisions ORDER BY network_id, revision",
    )
    .fetch_all(pool)
    .await?;
    let mut revisions = Vec::with_capacity(revision_rows.len());
    for row in revision_rows {
        revisions.push(ConfigRevision {
            network_id: NetworkId(row.0),
            revision: u64::try_from(row.1)
                .map_err(|e| corrupt("revision number", e.to_string()))?,
            desired_config_hash: row.2,
            apply_status: apply_status_parse(&row.3).map_err(|e| corrupt("apply status", e))?,
            created_at: row.4,
            applied_at: row.5,
            error_summary: row.6,
        });
    }
    state.ledger.restore(revisions);

    // §10.3：applying 结果不可知 → failed（内存 + DB，幂等）。
    let interrupted = state.ledger.interrupt_applying(INTERRUPTED_SUMMARY);
    for (network_id, revision) in &interrupted {
        let r = state
            .ledger
            .get(network_id, *revision)
            .expect("just converged above");
        update_revision_status(pool, r).await?;
    }

    Ok(BootState {
        summary: MeshStatePersistedView {
            networks,
            devices,
            routes,
            invites,
            revisions: state.revision_count(),
        },
        interrupted: interrupted
            .into_iter()
            .map(|(nid, rev)| (nid.to_string(), rev))
            .collect(),
        mesh: state,
    })
}

/// 供 handler 把落库错误转为统一服务错误（500，内部细节不外泄）。
pub fn internal(e: sqlx::Error) -> ServiceError {
    ServiceError::Internal(format!("persist: {e}"))
}

// ---------------------------------------------------------------------------
// 一致性备份与恢复（存档 §17.4）
// ---------------------------------------------------------------------------

/// 备份文件需要的完整表集合（schema 完整性校验，migrations 001–005）。
const REQUIRED_TABLES: [&str; 13] = [
    "agent_tokens",
    "alias_mappings",
    "audit_events",
    "config_revisions",
    "device_keys",
    "devices",
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
/// 拒绝——损坏/不完整的备份绝不进入恢复流程。只读连接用后显式关闭
/// （sqlx 池 drop 是惰性的；Windows 上未关句柄会挡住后续 rename）。
pub async fn validate_backup(path: &Path) -> Result<MeshStatePersistedView, BackupError> {
    let options =
        sqlx::sqlite::SqliteConnectOptions::from_str(&format!("sqlite:{}", path.display()))?
            .read_only(true);
    let pool = SqlitePoolOptions::new()
        .max_connections(1)
        .connect_with(options)
        .await
        .map_err(|e| BackupError::Corrupt(e.to_string()))?;
    // 打开成功但校验查询失败（code 26「file is not a database」等）同样是
    // 「不是可用数据库」，按 Corrupt 拒绝；schema 不完整单独保留可区分错误。
    let result = validate_on(&pool).await.map_err(|e| match e {
        e @ BackupError::IncompleteSchema { .. } => e,
        e => BackupError::Corrupt(e.to_string()),
    });
    pool.close().await;
    result
}

async fn validate_on(pool: &SqlitePool) -> Result<MeshStatePersistedView, BackupError> {
    let check: Vec<String> = sqlx::query_scalar("PRAGMA quick_check")
        .fetch_all(pool)
        .await?;
    if check.iter().any(|r| r != "ok") {
        return Err(BackupError::Corrupt(check.join("; ")));
    }

    let tables: Vec<String> = sqlx::query_scalar(
        "SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%' \
         AND name NOT LIKE '_sqlx_%'",
    )
    .fetch_all(pool)
    .await?;
    let missing: Vec<String> = REQUIRED_TABLES
        .iter()
        .filter(|t| !tables.iter().any(|have| have == *t))
        .map(|t| t.to_string())
        .collect();
    if !missing.is_empty() {
        return Err(BackupError::IncompleteSchema { missing });
    }

    Ok(MeshStatePersistedView {
        networks: count(pool, "networks").await?,
        devices: count(pool, "devices").await?,
        routes: count(pool, "lan_routes").await?,
        invites: count(pool, "invitations").await?,
        revisions: count(pool, "config_revisions").await?,
    })
}

async fn count(pool: &sqlx::SqlitePool, table: &str) -> Result<usize, BackupError> {
    // 表名来自 REQUIRED_TABLES 白名单，不是用户输入。
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
/// 1. 校验备份（[`validate_backup`]：独立打开 + quick_check + 必需表齐全）；
/// 2. 活动库可独占加锁（否则提示先停 meshlet-server）；
/// 3. 备份 → 临时文件 → 再校验 → 原子换名；替换前清掉旧 `-wal`/`-shm`；
/// 4. 打开恢复后的库，留痕 `system.restore` 审计事件；
/// 5. 复用 §17.3 [`load`] 重建 + 收敛（applying → failed、rollback_pending
///    保留、applied 不重放——与正常启动完全同一条路径，不比现在更弱）。
pub async fn restore_from_backup(
    backup: &Path,
    database: &Path,
    thresholds: meshlet_domain::PresenceThresholds,
) -> Result<RestoreReport, BackupError> {
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
        let pool = SqlitePoolOptions::new()
            .max_connections(1)
            .acquire_timeout(std::time::Duration::from_secs(2))
            .connect_with(options)
            .await?;
        let lock = sqlx::query("BEGIN EXCLUSIVE").execute(&pool).await;
        match lock {
            Ok(_) => {
                let _ = sqlx::query("COMMIT").execute(&pool).await;
            }
            Err(e) => {
                pool.close().await;
                return Err(BackupError::from(e));
            }
        }
        pool.close().await;
    }

    // 拷贝到临时文件并复验（拷贝本身损坏也拒绝），再原子换名。
    let tmp = database.with_extension("restore-tmp");
    let _ = tokio::fs::remove_file(&tmp).await;
    tokio::fs::copy(backup, &tmp).await?;
    restrict_permissions(&tmp);
    validate_backup(&tmp).await?;

    for suffix in ["-wal", "-shm"] {
        let _ =
            tokio::fs::remove_file(PathBuf::from(format!("{}{suffix}", database.display()))).await;
    }
    tokio::fs::rename(&tmp, database).await?;
    sync_parent_dir(database);

    // 打开恢复后的库：跑 migrations（no-op）、留痕、按 §17.3 重建 + 收敛。
    let pool = crate::store::connect(&format!("sqlite:{}", database.display())).await?;
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
    pool.close().await;

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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn enums_round_trip_through_persisted_strings() {
        // 持久化字符串与 API 展示一致，往返无损（重启重建依赖）。
        for s in ["pending", "active", "revoked"] {
            assert_eq!(device_status_to_str(device_status_parse(s).unwrap()), s);
        }
        for s in ["active", "deleting"] {
            assert_eq!(network_status_to_str(network_status_parse(s).unwrap()), s);
        }
        for s in ["pending", "applied", "failed"] {
            assert_eq!(desired_status_to_str(desired_status_parse(s).unwrap()), s);
        }
        for s in [
            "pending",
            "applying",
            "applied",
            "failed",
            "rollback_pending",
            "rolled_back",
        ] {
            assert_eq!(apply_status_parse(s).unwrap().as_str(), s);
        }
        for s in ["linux", "windows"] {
            assert_eq!(platform_to_str(platform_parse(s).unwrap()), s);
        }
        assert!(device_status_parse("bogus").is_err());
    }
}
