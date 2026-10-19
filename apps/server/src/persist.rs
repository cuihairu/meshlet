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
    AliasMapping, BootstrapToken, BootstrapTokenId, ConfigRevision, DesiredStateStatus, Device,
    DeviceId, DeviceRegistration, DeviceStatus, Invite, InviteId, Ipv4Cidr, LanRoute, LanRouteId,
    Network, NetworkId, NetworkStatus, Platform, ReturnPathMode, RouteMode, Segment, SegmentGrant,
    SegmentId, TranslationMode,
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
    /// 待审批的设备注册申请（ZeroTier 式，Pending 不计入 `devices`）。
    pub registrations: usize,
    pub routes: usize,
    pub aliases: usize,
    pub segments: usize,
    pub segment_grants: usize,
    pub invites: usize,
    pub revisions: usize,
}

#[derive(Clone)]
pub struct AuditDraft<'a> {
    pub actor_id: Option<&'a str>,
    pub action: &'a str,
    pub target_type: &'a str,
    pub target_id: &'a str,
    pub detail: Option<serde_json::Value>,
}

async fn insert_audit_tx(
    tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
    audit: &AuditDraft<'_>,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "INSERT INTO audit_events \
         (actor_id, action, target_type, target_id, detail, created_at) \
         VALUES (?, ?, ?, ?, ?, ?)",
    )
    .bind(audit.actor_id)
    .bind(audit.action)
    .bind(audit.target_type)
    .bind(audit.target_id)
    .bind(audit.detail.as_ref().map(serde_json::Value::to_string))
    .bind(crate::service::now())
    .execute(&mut **tx)
    .await?;
    Ok(())
}

async fn insert_revision_tx(
    tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
    revision: &ConfigRevision,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "INSERT INTO config_revisions
           (network_id, revision, desired_config_hash, apply_status, created_at,
            applied_at, error_summary)
         VALUES (?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(revision.network_id.to_string())
    .bind(revision.revision as i64)
    .bind(&revision.desired_config_hash)
    .bind(revision.apply_status.as_str())
    .bind(&revision.created_at)
    .bind(&revision.applied_at)
    .bind(&revision.error_summary)
    .execute(&mut **tx)
    .await?;
    Ok(())
}

async fn insert_device_tx(
    tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
    device: &Device,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "INSERT INTO devices
            (id, network_id, name, virtual_ipv4, public_key, platform, status, segment_id,
            last_seen_at, last_handshake_at, last_report_at, dataplane_evidence,
            created_at, revoked_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(device.id.to_string())
    .bind(device.network_id.to_string())
    .bind(&device.name)
    .bind(device.virtual_ipv4.to_string())
    .bind(&device.public_key)
    .bind(platform_to_str(device.platform))
    .bind(device_status_to_str(device.status))
    .bind(device.segment_id.to_string())
    .bind(&device.last_seen_at)
    .bind(&device.last_handshake_at)
    .bind(&device.last_report_at)
    .bind(
        device
            .dataplane_evidence
            .as_ref()
            .map(serde_json::to_string)
            .transpose()
            .map_err(|e| {
                sqlx::Error::Io(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    e.to_string(),
                ))
            })?,
    )
    .bind(&device.created_at)
    .bind(&device.revoked_at)
    .execute(&mut **tx)
    .await?;
    Ok(())
}

async fn insert_route_row_tx(
    tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
    route: &LanRoute,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "INSERT INTO lan_routes
           (id, network_id, gateway_device_id, destination_cidr, route_mode,
            return_path_mode, status, created_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(route.id.to_string())
    .bind(route.network_id.to_string())
    .bind(route.gateway_device_id.to_string())
    .bind(route.destination_cidr.to_string())
    .bind(route.route_mode.as_str())
    .bind(route.return_path_mode.as_str())
    .bind(desired_status_to_str(route.status))
    .bind(&route.created_at)
    .execute(&mut **tx)
    .await?;
    Ok(())
}

async fn insert_alias_row_tx(
    tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
    alias: &AliasMapping,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "INSERT INTO alias_mappings
           (id, network_id, lan_route_id, alias_cidr, target_cidr, translation_mode,
            status, created_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(alias.id.to_string())
    .bind(alias.network_id.to_string())
    .bind(alias.lan_route_id.to_string())
    .bind(alias.alias_cidr.to_string())
    .bind(alias.target_cidr.to_string())
    .bind(alias.translation_mode.as_str())
    .bind(desired_status_to_str(alias.status))
    .bind(crate::service::now())
    .execute(&mut **tx)
    .await?;
    Ok(())
}

pub async fn commit_network(
    pool: &SqlitePool,
    network: &Network,
    revision: &ConfigRevision,
    audit: &AuditDraft<'_>,
) -> Result<(), sqlx::Error> {
    let mut tx = pool.begin().await?;
    sqlx::query(
        "INSERT INTO networks (id, name, overlay_cidr, status, created_at, updated_at)
         VALUES (?, ?, ?, ?, ?, ?)",
    )
    .bind(network.id.to_string())
    .bind(&network.name)
    .bind(network.overlay_cidr.to_string())
    .bind(network_status_to_str(network.status))
    .bind(&network.created_at)
    .bind(&network.updated_at)
    .execute(&mut *tx)
    .await?;
    sqlx::query(
        "INSERT INTO segments (id, network_id, name, cidr, status, created_at)
         VALUES (?, ?, 'default', ?, 'active', ?)",
    )
    .bind(meshlet_domain::default_segment_id(&network.id).to_string())
    .bind(network.id.to_string())
    .bind(network.overlay_cidr.to_string())
    .bind(&network.created_at)
    .execute(&mut *tx)
    .await?;
    insert_revision_tx(&mut tx, revision).await?;
    insert_audit_tx(&mut tx, audit).await?;
    tx.commit().await?;
    Ok(())
}

pub async fn commit_enrollment(
    pool: &SqlitePool,
    device: &Device,
    revision: &ConfigRevision,
    invite: &Invite,
    audit: &AuditDraft<'_>,
) -> Result<String, sqlx::Error> {
    let raw_agent_token = meshlet_domain::generate_token();
    let mut tx = pool.begin().await?;
    insert_device_tx(&mut tx, device).await?;
    insert_revision_tx(&mut tx, revision).await?;
    sqlx::query(
        "INSERT INTO invitations
           (id, network_id, token_hash, expires_at, max_uses, used_count, created_at, revoked_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?)
         ON CONFLICT (id) DO UPDATE SET
           used_count = excluded.used_count,
           revoked_at = excluded.revoked_at",
    )
    .bind(invite.id.to_string())
    .bind(invite.network_id.to_string())
    .bind(&invite.token_hash)
    .bind(&invite.expires_at)
    .bind(invite.max_uses)
    .bind(invite.used_count)
    .bind(&invite.created_at)
    .bind(&invite.revoked_at)
    .execute(&mut *tx)
    .await?;
    sqlx::query("INSERT INTO agent_tokens (token_hash, device_id, created_at) VALUES (?, ?, ?)")
        .bind(meshlet_domain::token_hash(&raw_agent_token))
        .bind(device.id.to_string())
        .bind(crate::service::now())
        .execute(&mut *tx)
        .await?;
    insert_audit_tx(&mut tx, audit).await?;
    tx.commit().await?;
    Ok(raw_agent_token)
}

pub async fn commit_route(
    pool: &SqlitePool,
    route: &LanRoute,
    route_seq: u64,
    revision: &ConfigRevision,
    audit: &AuditDraft<'_>,
) -> Result<(), sqlx::Error> {
    let mut tx = pool.begin().await?;
    insert_route_row_tx(&mut tx, route).await?;
    save_seq_tx(&mut tx, "route_seq", route_seq).await?;
    insert_revision_tx(&mut tx, revision).await?;
    insert_audit_tx(&mut tx, audit).await?;
    tx.commit().await?;
    Ok(())
}

pub async fn commit_alias(
    pool: &SqlitePool,
    alias: &AliasMapping,
    route_seq: u64,
    revision: &ConfigRevision,
    audit: &AuditDraft<'_>,
) -> Result<(), sqlx::Error> {
    let mut tx = pool.begin().await?;
    insert_alias_row_tx(&mut tx, alias).await?;
    save_seq_tx(&mut tx, "route_seq", route_seq).await?;
    insert_revision_tx(&mut tx, revision).await?;
    insert_audit_tx(&mut tx, audit).await?;
    tx.commit().await?;
    Ok(())
}

pub async fn commit_host_forward(
    pool: &SqlitePool,
    route: &LanRoute,
    alias: &AliasMapping,
    route_seq: u64,
    revision: &ConfigRevision,
    audit: &AuditDraft<'_>,
) -> Result<(), sqlx::Error> {
    let mut tx = pool.begin().await?;
    insert_route_row_tx(&mut tx, route).await?;
    insert_alias_row_tx(&mut tx, alias).await?;
    save_seq_tx(&mut tx, "route_seq", route_seq).await?;
    insert_revision_tx(&mut tx, revision).await?;
    insert_audit_tx(&mut tx, audit).await?;
    tx.commit().await?;
    Ok(())
}

pub async fn commit_segment(
    pool: &SqlitePool,
    segment: &Segment,
    route_seq: u64,
    revision: &ConfigRevision,
    audit: &AuditDraft<'_>,
) -> Result<(), sqlx::Error> {
    let mut tx = pool.begin().await?;
    sqlx::query(
        "INSERT INTO segments (id, network_id, name, cidr, status, created_at)
         VALUES (?, ?, ?, ?, ?, ?)",
    )
    .bind(segment.id.to_string())
    .bind(segment.network_id.to_string())
    .bind(&segment.name)
    .bind(segment.cidr.to_string())
    .bind(segment.status.as_str())
    .bind(&segment.created_at)
    .execute(&mut *tx)
    .await?;
    save_seq_tx(&mut tx, "route_seq", route_seq).await?;
    insert_revision_tx(&mut tx, revision).await?;
    insert_audit_tx(&mut tx, audit).await?;
    tx.commit().await?;
    Ok(())
}

pub async fn commit_segment_grant(
    pool: &SqlitePool,
    grant: &SegmentGrant,
    route_seq: u64,
    revision: &ConfigRevision,
    audit: &AuditDraft<'_>,
) -> Result<(), sqlx::Error> {
    let mut tx = pool.begin().await?;
    sqlx::query(
        "INSERT INTO segment_grants
           (id, network_id, source_segment_id, destination_segment_id, status, created_at,
            revoked_at)
         VALUES (?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(grant.id.to_string())
    .bind(grant.network_id.to_string())
    .bind(grant.source_segment_id.to_string())
    .bind(grant.destination_segment_id.to_string())
    .bind(grant.status.as_str())
    .bind(&grant.created_at)
    .bind(&grant.revoked_at)
    .execute(&mut *tx)
    .await?;
    save_seq_tx(&mut tx, "route_seq", route_seq).await?;
    insert_revision_tx(&mut tx, revision).await?;
    insert_audit_tx(&mut tx, audit).await?;
    tx.commit().await?;
    Ok(())
}

pub async fn commit_segment_grant_status(
    pool: &SqlitePool,
    grant: &SegmentGrant,
    revision: &ConfigRevision,
    audit: &AuditDraft<'_>,
) -> Result<(), sqlx::Error> {
    let mut tx = pool.begin().await?;
    sqlx::query(
        "UPDATE segment_grants
         SET status = ?, revoked_at = ?
         WHERE id = ? AND network_id = ?",
    )
    .bind(grant.status.as_str())
    .bind(&grant.revoked_at)
    .bind(grant.id.to_string())
    .bind(grant.network_id.to_string())
    .execute(&mut *tx)
    .await?;
    insert_revision_tx(&mut tx, revision).await?;
    insert_audit_tx(&mut tx, audit).await?;
    tx.commit().await?;
    Ok(())
}

pub async fn commit_route_delete(
    pool: &SqlitePool,
    route_id: &str,
    revision: &ConfigRevision,
    audit: &AuditDraft<'_>,
) -> Result<(), sqlx::Error> {
    let mut tx = pool.begin().await?;
    sqlx::query("DELETE FROM alias_mappings WHERE lan_route_id = ?")
        .bind(route_id)
        .execute(&mut *tx)
        .await?;
    sqlx::query("DELETE FROM lan_routes WHERE id = ?")
        .bind(route_id)
        .execute(&mut *tx)
        .await?;
    insert_revision_tx(&mut tx, revision).await?;
    insert_audit_tx(&mut tx, audit).await?;
    tx.commit().await?;
    Ok(())
}

pub async fn commit_approve_registration(
    pool: &SqlitePool,
    registration: &DeviceRegistration,
    device: &Device,
    revision: &ConfigRevision,
    audit: &AuditDraft<'_>,
) -> Result<(), sqlx::Error> {
    let mut tx = pool.begin().await?;
    sqlx::query(
        "INSERT INTO devices
            (id, network_id, name, virtual_ipv4, public_key, platform, status, segment_id,
            last_seen_at, last_handshake_at, last_report_at, dataplane_evidence,
            created_at, approved_at, revoked_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(device.id.to_string())
    .bind(device.network_id.to_string())
    .bind(&device.name)
    .bind(device.virtual_ipv4.to_string())
    .bind(&device.public_key)
    .bind(platform_to_str(device.platform))
    .bind(device_status_to_str(device.status))
    .bind(device.segment_id.to_string())
    .bind(&device.last_seen_at)
    .bind(&device.last_handshake_at)
    .bind(&device.last_report_at)
    .bind(
        device
            .dataplane_evidence
            .as_ref()
            .map(serde_json::to_string)
            .transpose()
            .map_err(|e| {
                sqlx::Error::Io(std::io::Error::new(std::io::ErrorKind::InvalidData, e))
            })?,
    )
    .bind(&device.created_at)
    .bind(&device.approved_at)
    .bind(&device.revoked_at)
    .execute(&mut *tx)
    .await?;
    sqlx::query("DELETE FROM device_registrations WHERE id = ?")
        .bind(registration.id.to_string())
        .execute(&mut *tx)
        .await?;
    insert_revision_tx(&mut tx, revision).await?;
    insert_audit_tx(&mut tx, audit).await?;
    tx.commit().await?;
    Ok(())
}

pub async fn commit_revoke_device(
    pool: &SqlitePool,
    device: &Device,
    revision: &ConfigRevision,
    audit: &AuditDraft<'_>,
) -> Result<(), sqlx::Error> {
    let mut tx = pool.begin().await?;
    sqlx::query("UPDATE devices SET status = ?, revoked_at = ? WHERE id = ?")
        .bind(device_status_to_str(device.status))
        .bind(&device.revoked_at)
        .bind(device.id.to_string())
        .execute(&mut *tx)
        .await?;
    sqlx::query(
        "DELETE FROM alias_mappings WHERE lan_route_id IN
           (SELECT id FROM lan_routes WHERE gateway_device_id = ?)",
    )
    .bind(device.id.to_string())
    .execute(&mut *tx)
    .await?;
    sqlx::query("DELETE FROM lan_routes WHERE gateway_device_id = ?")
        .bind(device.id.to_string())
        .execute(&mut *tx)
        .await?;
    insert_revision_tx(&mut tx, revision).await?;
    sqlx::query(
        "UPDATE agent_tokens SET revoked_at = ? WHERE device_id = ? AND revoked_at IS NULL",
    )
    .bind(crate::service::now())
    .bind(device.id.to_string())
    .execute(&mut *tx)
    .await?;
    insert_audit_tx(&mut tx, audit).await?;
    tx.commit().await?;
    Ok(())
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

fn segment_status_parse(value: &str) -> Result<meshlet_domain::SegmentStatus, String> {
    meshlet_domain::SegmentStatus::parse(value).ok_or_else(|| format!("unknown status {value:?}"))
}

fn segment_grant_status_parse(value: &str) -> Result<meshlet_domain::SegmentGrantStatus, String> {
    meshlet_domain::SegmentGrantStatus::parse(value)
        .ok_or_else(|| format!("unknown status {value:?}"))
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
    let mut tx = pool.begin().await?;
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
    .execute(&mut *tx)
    .await?;
    sqlx::query(
        "INSERT INTO segments (id, network_id, name, cidr, status, created_at)
         VALUES (?, ?, 'default', ?, 'active', ?)",
    )
    .bind(meshlet_domain::default_segment_id(&n.id).to_string())
    .bind(n.id.to_string())
    .bind(n.overlay_cidr.to_string())
    .bind(&n.created_at)
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(())
}

/// 数据面证据 → JSON 列值（`None` → NULL）。
fn evidence_json(d: &Device) -> Option<String> {
    d.dataplane_evidence
        .as_ref()
        .map(|e| serde_json::to_string(e).expect("DataplaneEvidence serialization cannot fail"))
}

/// 落库一台设备行（enroll）。
pub async fn insert_device(pool: &SqlitePool, d: &Device) -> Result<(), sqlx::Error> {
    sqlx::query(
        "INSERT INTO devices
            (id, network_id, name, virtual_ipv4, public_key, platform, status, segment_id,
            last_seen_at, last_handshake_at, last_report_at, dataplane_evidence,
            created_at, revoked_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(d.id.to_string())
    .bind(d.network_id.to_string())
    .bind(&d.name)
    .bind(d.virtual_ipv4.to_string())
    .bind(&d.public_key)
    .bind(platform_to_str(d.platform))
    .bind(device_status_to_str(d.status))
    .bind(d.segment_id.to_string())
    .bind(&d.last_seen_at)
    .bind(&d.last_handshake_at)
    .bind(&d.last_report_at)
    .bind(evidence_json(d))
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

/// 回写在线证据时间戳 + 数据面实测证据（心跳路径，§14.1/§7.5）。
pub async fn update_device_presence(pool: &SqlitePool, d: &Device) -> Result<(), sqlx::Error> {
    sqlx::query(
        "UPDATE devices SET last_seen_at = ?, last_handshake_at = ?, last_report_at = ?, \
         dataplane_evidence = ? WHERE id = ?",
    )
    .bind(&d.last_seen_at)
    .bind(&d.last_handshake_at)
    .bind(&d.last_report_at)
    .bind(evidence_json(d))
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
    save_seq_tx(&mut tx, "route_seq", route_seq).await?;
    tx.commit().await?;
    Ok(())
}

async fn save_seq_tx(
    tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
    key: &str,
    seq: u64,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "INSERT INTO mesh_meta (key, value) VALUES (?, ?)
         ON CONFLICT (key) DO UPDATE SET value = excluded.value",
    )
    .bind(key)
    .bind(seq.to_string())
    .execute(&mut **tx)
    .await?;
    Ok(())
}

/// 落库一条自举码（只存摘要，§11.3）+ 当前自举码序列（同一事务）。
/// `bootstrap_seq` 驱动 `bt-N`；注册申请序列（`dev-reg-N`）另见
/// [`insert_registration`]——前缀不冲突，故各自单调即可。
pub async fn save_bootstrap_token(
    pool: &SqlitePool,
    t: &BootstrapToken,
    bootstrap_seq: u64,
) -> Result<(), sqlx::Error> {
    let mut tx = pool.begin().await?;
    sqlx::query(
        "INSERT INTO bootstrap_tokens
           (id, network_id, token_hash, max_uses, used_count, created_at, revoked_at)
         VALUES (?, ?, ?, ?, ?, ?, ?)
         ON CONFLICT (id) DO UPDATE SET
           used_count = excluded.used_count,
           revoked_at = excluded.revoked_at",
    )
    .bind(t.id.to_string())
    .bind(t.network_id.to_string())
    .bind(&t.token_hash)
    .bind(t.max_uses)
    .bind(t.used_count as i64)
    .bind(&t.created_at)
    .bind(&t.revoked_at)
    .execute(&mut *tx)
    .await?;
    save_seq_tx(&mut tx, "bootstrap_seq", bootstrap_seq).await?;
    tx.commit().await?;
    Ok(())
}

/// 撤销自举码：只回写撤销时刻（整行 upsert，与 `save_invite` 同语义）。
pub async fn revoke_bootstrap_token_db(
    pool: &SqlitePool,
    id: &BootstrapTokenId,
    revoked_at: &str,
) -> Result<(), sqlx::Error> {
    sqlx::query("UPDATE bootstrap_tokens SET revoked_at = ? WHERE id = ?")
        .bind(revoked_at)
        .bind(id.to_string())
        .execute(pool)
        .await?;
    Ok(())
}

/// 登记一条设备注册申请（Pending）+ 当前注册序列（同一事务）。
pub async fn insert_registration(
    pool: &SqlitePool,
    r: &DeviceRegistration,
    registration_seq: u64,
) -> Result<(), sqlx::Error> {
    let mut tx = pool.begin().await?;
    sqlx::query(
        "INSERT INTO device_registrations
           (id, network_id, name, public_key, platform, requested_at)
         VALUES (?, ?, ?, ?, ?, ?)",
    )
    .bind(r.id.to_string())
    .bind(r.network_id.to_string())
    .bind(&r.name)
    .bind(&r.public_key)
    .bind(platform_to_str(r.platform))
    .bind(&r.requested_at)
    .execute(&mut *tx)
    .await?;
    save_seq_tx(&mut tx, "registration_seq", registration_seq).await?;
    tx.commit().await?;
    Ok(())
}

/// 删除一条注册申请（批准/拒绝），并连带清掉它签发的 agent 凭证。
/// Pending 申请不在 `devices` 表，故无需回滚设备行/路由。
pub async fn delete_registration_db(pool: &SqlitePool, id: &DeviceId) -> Result<(), sqlx::Error> {
    let mut tx = pool.begin().await?;
    sqlx::query("DELETE FROM device_registrations WHERE id = ?")
        .bind(id.to_string())
        .execute(&mut *tx)
        .await?;
    sqlx::query("DELETE FROM agent_tokens WHERE device_id = ?")
        .bind(id.to_string())
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;
    Ok(())
}

/// 批准：把注册申请（不改 id）转成 `devices` 行并释放申请记录（同一事务）。
/// `virtual_ipv4` 是批准时刻刚从 IPAM 分配的真实地址（不再用占位值）。
///
/// **不轮换 agent 凭证**：凭证绑定的是设备 id（注册时即分配、批准沿用），
/// 设备身份未变；轮换会把原始凭证只塞进批准响应、设备端永远拿不到（批准后
/// 401）。Pending 期签发的凭证继续有效，撤销走 `revoke_device` 既有路径。
pub async fn promote_registration(
    pool: &SqlitePool,
    r: &DeviceRegistration,
    device: &Device,
) -> Result<(), sqlx::Error> {
    let mut tx = pool.begin().await?;
    // 列集与 insert_device 一致 + approved_at：Pending 期心跳证据直接带入
    // （批准后 presence 连续，§7.5 证据不因转正而清零）。
    sqlx::query(
        "INSERT INTO devices
            (id, network_id, name, virtual_ipv4, public_key, platform, status, segment_id,
            last_seen_at, last_handshake_at, last_report_at, dataplane_evidence,
            created_at, approved_at, revoked_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(device.id.to_string())
    .bind(device.network_id.to_string())
    .bind(&device.name)
    .bind(device.virtual_ipv4.to_string())
    .bind(&device.public_key)
    .bind(platform_to_str(device.platform))
    .bind(device_status_to_str(device.status))
    .bind(device.segment_id.to_string())
    .bind(&device.last_seen_at)
    .bind(&device.last_handshake_at)
    .bind(&device.last_report_at)
    .bind(evidence_json(device))
    .bind(&device.created_at)
    .bind(&device.approved_at)
    .bind(&device.revoked_at)
    .execute(&mut *tx)
    .await?;
    sqlx::query("DELETE FROM device_registrations WHERE id = ?")
        .bind(r.id.to_string())
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;
    Ok(())
}

/// Pending 设备无 `devices` 行，心跳证据只落注册申请表（§7.5/§12.4）。
pub async fn update_registration_report(
    pool: &SqlitePool,
    id: &DeviceId,
    last_report_at: &str,
    dataplane_evidence: Option<&str>,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "UPDATE device_registrations SET last_report_at = ?, dataplane_evidence = ? WHERE id = ?",
    )
    .bind(last_report_at)
    .bind(dataplane_evidence)
    .bind(id.to_string())
    .execute(pool)
    .await?;
    Ok(())
}

/// 落库一条 Alias 映射（§12.6）。alias id 与路由共用 `route_seq` 序列
/// （`al-N` / `rt-N` 同源单调，已删 id 不复用），同一事务保存序列。
pub async fn insert_alias(
    pool: &SqlitePool,
    a: &AliasMapping,
    route_seq: u64,
) -> Result<(), sqlx::Error> {
    let mut tx = pool.begin().await?;
    sqlx::query(
        "INSERT INTO alias_mappings
           (id, network_id, lan_route_id, alias_cidr, target_cidr, translation_mode,
            status, created_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(a.id.to_string())
    .bind(a.network_id.to_string())
    .bind(a.lan_route_id.to_string())
    .bind(a.alias_cidr.to_string())
    .bind(a.target_cidr.to_string())
    .bind(a.translation_mode.as_str())
    .bind(desired_status_to_str(a.status))
    .bind(crate::service::now())
    .execute(&mut *tx)
    .await?;
    save_seq_tx(&mut tx, "route_seq", route_seq).await?;
    tx.commit().await?;
    Ok(())
}

/// 事务性落库 Host Forward 的两条镜像（LAN Route + Alias）。
///
/// 内存路径已保证“创建即整单元”；这里把同一原子边界带到 SQLite：任一行
/// 写入失败时路由序列和另一行一起回滚。
pub async fn insert_host_forward(
    pool: &SqlitePool,
    route: &LanRoute,
    alias: &AliasMapping,
    route_seq: u64,
) -> Result<(), sqlx::Error> {
    let mut tx = pool.begin().await?;
    sqlx::query(
        "INSERT INTO lan_routes
           (id, network_id, gateway_device_id, destination_cidr, route_mode,
            return_path_mode, status, created_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(route.id.to_string())
    .bind(route.network_id.to_string())
    .bind(route.gateway_device_id.to_string())
    .bind(route.destination_cidr.to_string())
    .bind(route.route_mode.as_str())
    .bind(route.return_path_mode.as_str())
    .bind(desired_status_to_str(route.status))
    .bind(&route.created_at)
    .execute(&mut *tx)
    .await?;
    sqlx::query(
        "INSERT INTO alias_mappings
           (id, network_id, lan_route_id, alias_cidr, target_cidr, translation_mode,
            status, created_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(alias.id.to_string())
    .bind(alias.network_id.to_string())
    .bind(alias.lan_route_id.to_string())
    .bind(alias.alias_cidr.to_string())
    .bind(alias.target_cidr.to_string())
    .bind(alias.translation_mode.as_str())
    .bind(desired_status_to_str(alias.status))
    .bind(crate::service::now())
    .execute(&mut *tx)
    .await?;
    save_seq_tx(&mut tx, "route_seq", route_seq).await?;
    tx.commit().await?;
    Ok(())
}

/// 删除一条 LAN 路由及其绑定 Alias（§12.6 所有权清理：alias-路由是一对一
/// 单元；FK 约束下必须先删子行）。路由 id 序列不回退，已删 id 不复用。
pub async fn delete_route(pool: &SqlitePool, route_id: &str) -> Result<(), sqlx::Error> {
    let mut tx = pool.begin().await?;
    sqlx::query("DELETE FROM alias_mappings WHERE lan_route_id = ?")
        .bind(route_id)
        .execute(&mut *tx)
        .await?;
    sqlx::query("DELETE FROM lan_routes WHERE id = ?")
        .bind(route_id)
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;
    Ok(())
}

/// 撤销设备时移除其发布的全部路由与绑定 Alias（§11.5 + §12.6 级联清理）。
pub async fn delete_routes_of_device(
    pool: &SqlitePool,
    gateway_device_id: &str,
) -> Result<(), sqlx::Error> {
    let mut tx = pool.begin().await?;
    sqlx::query(
        "DELETE FROM alias_mappings WHERE lan_route_id IN
           (SELECT id FROM lan_routes WHERE gateway_device_id = ?)",
    )
    .bind(gateway_device_id)
    .execute(&mut *tx)
    .await?;
    sqlx::query("DELETE FROM lan_routes WHERE gateway_device_id = ?")
        .bind(gateway_device_id)
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;
    Ok(())
}

/// 回写收敛后的期望项状态（apply / rollback 结论，§10.1）。
///
/// 与 [`update_revision_status`] 同一条纪律：修订结论落库后，路由/映射的
/// `status` 也必须落库——重启后 [`load`] 重建的账本不得把「已生效」说成
/// `pending`，也不得让「已回滚」继续显示为 `applied`。
pub async fn update_desired_status(
    pool: &SqlitePool,
    settle: &crate::service::DesiredStateSettle,
) -> Result<(), sqlx::Error> {
    if settle.routes.is_empty() && settle.aliases.is_empty() {
        return Ok(());
    }
    let mut tx = pool.begin().await?;
    for (id, status) in &settle.routes {
        sqlx::query("UPDATE lan_routes SET status = ? WHERE id = ?")
            .bind(desired_status_to_str(*status))
            .bind(id)
            .execute(&mut *tx)
            .await?;
    }
    for (id, status) in &settle.aliases {
        sqlx::query("UPDATE alias_mappings SET status = ? WHERE id = ?")
            .bind(desired_status_to_str(*status))
            .bind(id)
            .execute(&mut *tx)
            .await?;
    }
    tx.commit().await?;
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

    let missing_defaults: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM networks n
         WHERE NOT EXISTS (
             SELECT 1 FROM segments s
             WHERE s.network_id = n.id AND s.name = 'default'
         )",
    )
    .fetch_one(pool)
    .await?;
    if missing_defaults != 0 {
        return Err(corrupt(
            "default segments",
            format!("{missing_defaults} network(s) have no default segment"),
        ));
    }
    let invalid_assignments: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM devices d
         LEFT JOIN segments s ON s.id = d.segment_id AND s.network_id = d.network_id
         WHERE s.id IS NULL",
    )
    .fetch_one(pool)
    .await?;
    if invalid_assignments != 0 {
        return Err(corrupt(
            "device segment assignments",
            format!("{invalid_assignments} device(s) have no segment in their network"),
        ));
    }

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

    let segment_rows = sqlx::query_as::<_, (String, String, String, String, String, String)>(
        "SELECT id, network_id, name, cidr, status, created_at
         FROM segments ORDER BY created_at, id",
    )
    .fetch_all(pool)
    .await?;
    for (id, network_id, name, cidr, status, created_at) in segment_rows {
        let segment = Segment {
            id: SegmentId(id),
            network_id: NetworkId(network_id),
            name,
            cidr: cidr.parse().map_err(|e| corrupt("segment cidr", e))?,
            status: segment_status_parse(&status).map_err(|e| corrupt("segment status", e))?,
            created_at,
        };
        state
            .restore_segment(segment)
            .map_err(|e| corrupt("restore segment", e.to_string()))?;
    }
    let segments = state.segment_count();

    let segment_grant_rows = sqlx::query_as::<
        _,
        (
            String,
            String,
            String,
            String,
            String,
            String,
            Option<String>,
        ),
    >(
        "SELECT id, network_id, source_segment_id, destination_segment_id, status,
                created_at, revoked_at
         FROM segment_grants ORDER BY created_at, id",
    )
    .fetch_all(pool)
    .await?;
    for (id, network_id, source, destination, status, created_at, revoked_at) in segment_grant_rows
    {
        let grant = meshlet_domain::SegmentGrant {
            id: meshlet_domain::SegmentGrantId(id),
            network_id: NetworkId(network_id),
            source_segment_id: SegmentId(source),
            destination_segment_id: SegmentId(destination),
            status: segment_grant_status_parse(&status)
                .map_err(|e| corrupt("segment grant status", e))?,
            created_at,
            revoked_at,
        };
        state
            .restore_segment_grant(grant)
            .map_err(|e| corrupt("restore segment grant", e.to_string()))?;
    }
    let segment_grants = state.segment_grant_count();

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
            Option<String>,
            String,
            Option<String>,
            Option<String>,
            Option<String>,
        ),
    >(
        "SELECT id, network_id, name, virtual_ipv4, public_key, platform, status,
                last_seen_at, last_handshake_at, last_report_at, dataplane_evidence,
                created_at, approved_at, revoked_at, segment_id
         FROM devices ORDER BY created_at, id",
    )
    .fetch_all(pool)
    .await?;
    for row in device_rows {
        let evidence = row
            .10
            .map(|raw| serde_json::from_str(&raw))
            .transpose()
            .map_err(|e| corrupt("device dataplane_evidence", e))?;
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
            dataplane_evidence: evidence,
            created_at: row.11,
            approved_at: row.12,
            revoked_at: row.13,
            segment_id: SegmentId(
                row.14
                    .ok_or_else(|| corrupt("device segment_id", "NULL after migration"))?,
            ),
        };
        state
            .restore_device(device)
            .map_err(|e| corrupt("restore device", e.to_string()))?;
    }
    let devices = state.device_count();

    // 待审批的注册申请（ZeroTier 式）：不进 IPAM、不进期望配置，重启后仍待批。
    let reg_rows = sqlx::query_as::<
        _,
        (
            String,
            String,
            String,
            String,
            String,
            String,
            Option<String>,
            Option<String>,
        ),
    >(
        "SELECT id, network_id, name, public_key, platform, requested_at,
                last_report_at, dataplane_evidence
         FROM device_registrations ORDER BY requested_at, id",
    )
    .fetch_all(pool)
    .await?;
    for (id, network_id, name, public_key, platform, requested_at, last_report_at, evidence) in
        reg_rows
    {
        let evidence = evidence
            .map(|raw| serde_json::from_str(&raw))
            .transpose()
            .map_err(|e| corrupt("registration dataplane_evidence", e))?;
        let registration = DeviceRegistration {
            id: DeviceId(id),
            network_id: NetworkId(network_id),
            name,
            public_key,
            platform: platform_parse(&platform).map_err(|e| corrupt("registration platform", e))?,
            requested_at,
            last_report_at,
            dataplane_evidence: evidence,
        };
        state
            .restore_registration(registration)
            .map_err(|e| corrupt("restore registration", e.to_string()))?;
    }
    let registrations = state.registration_count();

    // 自举码（摘要索引；撤销/次数上限如常恢复）。
    let bt_rows = sqlx::query_as::<
        _,
        (
            String,
            String,
            String,
            Option<i64>,
            i64,
            String,
            Option<String>,
        ),
    >(
        "SELECT id, network_id, token_hash, max_uses, used_count, created_at, revoked_at
         FROM bootstrap_tokens ORDER BY created_at, id",
    )
    .fetch_all(pool)
    .await?;
    for (id, network_id, token_hash, max_uses, used_count, created_at, revoked_at) in bt_rows {
        let token = BootstrapToken {
            id: BootstrapTokenId(id),
            network_id: NetworkId(network_id),
            token_hash,
            max_uses: max_uses.map(|n| n as u32),
            used_count: used_count as u32,
            created_at,
            revoked_at,
        };
        state
            .bootstrap_tokens
            .insert(token.token_hash.clone(), token);
    }

    // 自举码与注册申请各持一条序列（`bt-N` / `dev-reg-N`，前缀不冲突）。
    for key in ["bootstrap_seq", "registration_seq"] {
        let value: Option<String> =
            sqlx::query_scalar(&format!("SELECT value FROM mesh_meta WHERE key = '{key}'"))
                .fetch_optional(pool)
                .await?;
        if let Some(v) = value {
            let seq: u64 = v
                .parse()
                .map_err(|e: std::num::ParseIntError| corrupt(&format!("mesh_meta {key}"), e))?;
            match key {
                "bootstrap_seq" => state.set_bootstrap_seq(seq),
                _ => state.set_registration_seq(seq),
            }
        }
    }

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

    // Alias 映射（§12.6）：随绑定路由重建。孤儿行（绑定路由已删，正常写
    // 路径不会产生，只有手改库才可能）不进内存——单元语义在启动时即收敛。
    let bound_routes: std::collections::HashSet<String> = state.bound_route_ids();
    let alias_rows = sqlx::query_as::<_, (String, String, String, String, String, String, String)>(
        "SELECT id, network_id, lan_route_id, alias_cidr, target_cidr, translation_mode, status
         FROM alias_mappings ORDER BY id",
    )
    .fetch_all(pool)
    .await?;
    for (id, network_id, lan_route_id, alias_cidr, target_cidr, translation_mode, status) in
        alias_rows
    {
        if !bound_routes.contains(&lan_route_id) {
            continue;
        }
        let alias = AliasMapping {
            id: meshlet_domain::entities::AliasMappingId(id),
            network_id: NetworkId(network_id),
            lan_route_id: LanRouteId(lan_route_id),
            alias_cidr: alias_cidr
                .parse()
                .map_err(|e| corrupt("alias alias_cidr", e))?,
            target_cidr: target_cidr
                .parse()
                .map_err(|e| corrupt("alias target_cidr", e))?,
            translation_mode: TranslationMode::parse(&translation_mode).ok_or_else(|| {
                corrupt("alias translation_mode", format!("{:?}", translation_mode))
            })?,
            status: desired_status_parse(&status).map_err(|e| corrupt("alias status", e))?,
        };
        state.restore_alias(alias);
    }
    let aliases = state.alias_count();

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
    for (id, json) in
        sqlx::query_as::<_, (String, String)>("SELECT network_id, plan_json FROM hub_deployments")
            .fetch_all(pool)
            .await?
    {
        let saved = serde_json::from_str(&json).map_err(|e| corrupt("hub deployment", e))?;
        state.deployments.insert(id, saved);
    }

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
            registrations,
            routes,
            aliases,
            segments,
            segment_grants,
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
    .fetch_one(pool)
    .await?;
    if !has_migration_history {
        return Err(BackupError::IncompleteSchema {
            missing: vec!["_sqlx_migrations".into()],
        });
    }
    let latest: Option<i64> =
        sqlx::query_scalar("SELECT MAX(version) FROM _sqlx_migrations WHERE success=1")
            .fetch_one(pool)
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
    Ok(MeshStatePersistedView {
        networks: count(pool, "networks").await?,
        devices: count(pool, "devices").await?,
        registrations: count(pool, "device_registrations").await?,
        routes: count(pool, "lan_routes").await?,
        aliases: count(pool, "alias_mappings").await?,
        segments: if has_segments {
            count(pool, "segments").await?
        } else {
            0
        },
        segment_grants: if has_segments {
            count(pool, "segment_grants").await?
        } else {
            0
        },
        invites: count(pool, "invitations").await?,
        revisions: count(pool, "config_revisions").await?,
    })
}

async fn count(pool: &sqlx::SqlitePool, table: &str) -> Result<usize, BackupError> {
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
    for suffix in ["-wal", "-shm"] {
        let _ =
            tokio::fs::remove_file(PathBuf::from(format!("{}{suffix}", database.display()))).await;
    }
    tokio::fs::rename(&tmp, database).await?;
    sync_parent_dir(database);

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

// ---------------------------------------------------------------------------
// 诊断运行快照（存档 §12.7，migration 006）
// ---------------------------------------------------------------------------

/// 落一行诊断快照（`POST /networks/{id}/diagnostics`）：报告以 JSON 存储，
/// 按行号取「最近一次」。
pub async fn insert_diagnostics_run(
    pool: &SqlitePool,
    network_id: &str,
    checked_at: &str,
    report_json: &str,
) -> Result<(), sqlx::Error> {
    sqlx::query("INSERT INTO diagnostics_runs (network_id, checked_at, report) VALUES (?, ?, ?)")
        .bind(network_id)
        .bind(checked_at)
        .bind(report_json)
        .execute(pool)
        .await?;
    Ok(())
}

/// 最近一次诊断快照的 JSON（`GET /networks/{id}/diagnostics`）；从未运行
/// 返回 `None`（端点据此 404，不现算、不假称有）。
pub async fn latest_diagnostics_run(
    pool: &SqlitePool,
    network_id: &str,
) -> Result<Option<String>, sqlx::Error> {
    let row: Option<(String,)> = sqlx::query_as(
        "SELECT report FROM diagnostics_runs WHERE network_id = ? ORDER BY id DESC LIMIT 1",
    )
    .bind(network_id)
    .fetch_optional(pool)
    .await?;
    Ok(row.map(|(report,)| report))
}

/// Alias 映射行（诊断 §12.7 第 10 项的输入）。行由服务写路径产生（写入前
/// 已域层校验）；万一损坏的行跳过而不panic——诊断对脏库报冲突而非崩溃。
pub async fn alias_rows(
    pool: &SqlitePool,
    network_id: &str,
) -> Result<Vec<AliasMapping>, sqlx::Error> {
    let rows = sqlx::query_as::<_, (String, String, String, String, String, String, String)>(
        "SELECT id, network_id, lan_route_id, alias_cidr, target_cidr, translation_mode, status
         FROM alias_mappings WHERE network_id = ? ORDER BY id",
    )
    .bind(network_id)
    .fetch_all(pool)
    .await?;
    Ok(rows
        .into_iter()
        .filter_map(
            |(
                id,
                row_network_id,
                lan_route_id,
                alias_cidr,
                target_cidr,
                translation_mode,
                status,
            )| {
                Some(AliasMapping {
                    id: meshlet_domain::entities::AliasMappingId(id),
                    network_id: NetworkId(row_network_id),
                    lan_route_id: LanRouteId(lan_route_id),
                    alias_cidr: alias_cidr.parse().ok()?,
                    target_cidr: target_cidr.parse().ok()?,
                    translation_mode: TranslationMode::parse(&translation_mode)?,
                    status: desired_status_parse(&status).ok()?,
                })
            },
        )
        .collect())
}

/// Commit the hub outcome, resource states and recovery journal atomically.
pub(crate) async fn commit_application(
    pool: &SqlitePool,
    revision: &ConfigRevision,
    settle: &crate::service::DesiredStateSettle,
    deployment: Option<&crate::revision::Deployment>,
) -> Result<(), sqlx::Error> {
    let mut tx = pool.begin().await?;
    if let Some(deployment) = deployment {
        let json = serde_json::to_string(deployment).map_err(|e| corrupt("hub deployment", e))?;
        sqlx::query("INSERT INTO hub_deployments(network_id,plan_json) VALUES(?,?) ON CONFLICT(network_id) DO UPDATE SET plan_json=excluded.plan_json,recovery_error=NULL")
            .bind(revision.network_id.to_string()).bind(json).execute(&mut *tx).await?;
    }
    write_outcome_tx(&mut tx, revision, settle).await?;
    tx.commit().await
}

async fn write_outcome_tx(
    tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
    revision: &ConfigRevision,
    settle: &crate::service::DesiredStateSettle,
) -> Result<(), sqlx::Error> {
    sqlx::query("UPDATE config_revisions SET apply_status=?,applied_at=?,error_summary=? WHERE network_id=? AND revision=?")
        .bind(revision.apply_status.as_str()).bind(&revision.applied_at).bind(&revision.error_summary).bind(revision.network_id.to_string()).bind(revision.revision as i64).execute(&mut **tx).await?;
    for (id, status) in &settle.routes {
        sqlx::query("UPDATE lan_routes SET status=? WHERE id=?")
            .bind(status.as_str())
            .bind(id)
            .execute(&mut **tx)
            .await?;
    }
    for (id, status) in &settle.aliases {
        sqlx::query("UPDATE alias_mappings SET status=? WHERE id=?")
            .bind(status.as_str())
            .bind(id)
            .execute(&mut **tx)
            .await?;
    }
    Ok(())
}

/// Commit restored resources, cleared receipts and rollback outcome together.
pub(crate) async fn commit_rollback(
    pool: &SqlitePool,
    revision: &ConfigRevision,
    settle: &crate::service::DesiredStateSettle,
    restore: bool,
    saved: Option<&crate::revision::Deployment>,
) -> Result<(), sqlx::Error> {
    let mut tx = pool.begin().await?;
    if restore {
        let network = revision.network_id.to_string();
        sqlx::query("DELETE FROM alias_mappings WHERE network_id=?")
            .bind(&network)
            .execute(&mut *tx)
            .await?;
        sqlx::query("DELETE FROM lan_routes WHERE network_id=?")
            .bind(&network)
            .execute(&mut *tx)
            .await?;
        if let Some(saved) = saved {
            for r in &saved.routes {
                sqlx::query("INSERT INTO lan_routes(id,network_id,gateway_device_id,destination_cidr,route_mode,return_path_mode,status,created_at) VALUES(?,?,?,?,?,?,?,?)")
                    .bind(r.id.to_string()).bind(&network).bind(r.gateway_device_id.to_string()).bind(r.destination_cidr.to_string()).bind(r.route_mode.as_str()).bind(r.return_path_mode.as_str()).bind("pending").bind(&r.created_at).execute(&mut *tx).await?;
            }
            for a in &saved.aliases {
                sqlx::query("INSERT INTO alias_mappings(id,network_id,lan_route_id,alias_cidr,target_cidr,translation_mode,status,created_at) VALUES(?,?,?,?,?,?,?,?)")
                    .bind(a.id.to_string()).bind(&network).bind(a.lan_route_id.to_string()).bind(a.alias_cidr.to_string()).bind(a.target_cidr.to_string()).bind(a.translation_mode.as_str()).bind("pending").bind(crate::service::now()).execute(&mut *tx).await?;
            }
        }
        sqlx::query("DELETE FROM device_apply_receipts WHERE device_id IN (SELECT id FROM devices WHERE network_id=?)").bind(&network).execute(&mut *tx).await?;
    }
    write_outcome_tx(&mut tx, revision, settle).await?;
    tx.commit().await
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

    #[tokio::test]
    async fn device_segment_assignment_survives_database_reload() {
        let pool = crate::store::connect("sqlite::memory:").await.unwrap();
        let network_id = NetworkId("net-1".into());
        let network = Network::new(
            network_id.clone(),
            "home",
            "10.240.0.0/16".parse().unwrap(),
            "2026-10-17T00:00:00Z".into(),
        );
        insert_network(&pool, &network).await.unwrap();
        let default_id = meshlet_domain::default_segment_id(&network_id);
        let persisted_default: String =
            sqlx::query_scalar("SELECT id FROM segments WHERE network_id = ? AND name = 'default'")
                .bind(network_id.to_string())
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(persisted_default, default_id.to_string());

        let custom_segment = SegmentId("seg-net-1-lab".into());
        sqlx::query(
            "INSERT INTO segments (id, network_id, name, cidr, status, created_at)
             VALUES (?, ?, 'lab', '10.240.1.0/24', 'active', '2026-10-17T00:00:00Z')",
        )
        .bind(custom_segment.to_string())
        .bind(network_id.to_string())
        .execute(&pool)
        .await
        .unwrap();
        let device = Device {
            id: DeviceId("dev-1".into()),
            network_id: network_id.clone(),
            name: "lab-device".into(),
            virtual_ipv4: "10.240.1.2".parse().unwrap(),
            public_key: "public-key".into(),
            platform: Platform::Linux,
            status: DeviceStatus::Active,
            last_seen_at: None,
            last_handshake_at: None,
            last_report_at: None,
            dataplane_evidence: None,
            created_at: "2026-10-17T00:00:00Z".into(),
            approved_at: None,
            segment_id: custom_segment.clone(),
            revoked_at: None,
        };
        insert_device(&pool, &device).await.unwrap();

        let boot = load(&pool, meshlet_domain::PresenceThresholds::default())
            .await
            .unwrap();
        let restored = boot
            .mesh
            .registry
            .find_by_id(&DeviceId("dev-1".into()))
            .unwrap();
        assert_eq!(restored.segment_id, custom_segment);
        assert_eq!(boot.summary.segments, 2);
        pool.close().await;
    }

    #[tokio::test]
    async fn segment_grants_survive_database_reload() {
        let pool = crate::store::connect("sqlite::memory:").await.unwrap();
        let network_id = NetworkId("net-1".into());
        let network = Network::new(
            network_id.clone(),
            "home",
            "10.240.0.0/16".parse().unwrap(),
            "2026-10-17T00:00:00Z".into(),
        );
        insert_network(&pool, &network).await.unwrap();
        sqlx::query(
            "INSERT INTO segments (id, network_id, name, cidr, status, created_at)
             VALUES ('seg-net-1-a', ?, 'a', '10.240.1.0/24', 'active', ?),
                    ('seg-net-1-b', ?, 'b', '10.240.2.0/24', 'active', ?)",
        )
        .bind(network_id.to_string())
        .bind(&network.created_at)
        .bind(network_id.to_string())
        .bind(&network.created_at)
        .execute(&pool)
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO segment_grants
             (id, network_id, source_segment_id, destination_segment_id, status,
              created_at, revoked_at)
             VALUES ('sg-net-1-1', ?, 'seg-net-1-a', 'seg-net-1-b', 'applied', ?, NULL)",
        )
        .bind(network_id.to_string())
        .bind(&network.created_at)
        .execute(&pool)
        .await
        .unwrap();

        let boot = load(&pool, meshlet_domain::PresenceThresholds::default())
            .await
            .unwrap();
        assert_eq!(
            boot.mesh.segment_grants("net-1"),
            &[meshlet_domain::SegmentGrant {
                id: meshlet_domain::SegmentGrantId("sg-net-1-1".into()),
                network_id: network_id.clone(),
                source_segment_id: SegmentId("seg-net-1-a".into()),
                destination_segment_id: SegmentId("seg-net-1-b".into()),
                status: meshlet_domain::SegmentGrantStatus::Applied,
                created_at: network.created_at.clone(),
                revoked_at: None,
            }]
        );
        pool.close().await;
    }

    #[tokio::test]
    async fn load_rejects_overlapping_segment_containment() {
        let pool = crate::store::connect("sqlite::memory:").await.unwrap();
        let network_id = NetworkId("net-1".into());
        let network = Network::new(
            network_id.clone(),
            "home",
            "10.240.0.0/16".parse().unwrap(),
            "2026-10-17T00:00:00Z".into(),
        );
        insert_network(&pool, &network).await.unwrap();
        sqlx::query(
            "INSERT INTO segments (id, network_id, name, cidr, status, created_at)
             VALUES ('seg-net-1-lab', ?, 'lab', '10.240.0.0/15', 'active', ?)",
        )
        .bind(network_id.to_string())
        .bind(&network.created_at)
        .execute(&pool)
        .await
        .unwrap();
        let error = match load(&pool, meshlet_domain::PresenceThresholds::default()).await {
            Ok(_) => panic!("overlapping segment containment must fail load"),
            Err(error) => error,
        };
        assert!(error.to_string().contains("outside overlay"), "{error}");
        pool.close().await;
    }
}
