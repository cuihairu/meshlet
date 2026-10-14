//! Mesh 状态持久化与启动重建（[存档 §17.3](../../docs/review/chatgpt-2026-10-13.md)）。
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
//! 客户端（agent）侧重启恢复随数据面 backend 落地（拉取期望配置重新应用），
//! 本模块先把「服务端重启不丢期望状态」钉死。

use meshlet_domain::{
    ConfigRevision, DesiredStateStatus, Device, DeviceId, DeviceStatus, Invite, InviteId, Ipv4Cidr,
    LanRoute, LanRouteId, Network, NetworkId, NetworkStatus, Platform, ReturnPathMode, RouteMode,
};
use sqlx::SqlitePool;

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
