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

use super::entities::update_revision_status;
use super::shared::{
    apply_status_parse, corrupt, desired_status_parse, device_status_parse, insert_audit_tx,
    network_status_parse, platform_parse, save_seq_tx, segment_grant_status_parse,
    segment_status_parse, AuditDraft, MeshStatePersistedView,
};
use meshlet_domain::{
    AliasMapping, BootstrapToken, BootstrapTokenId, ConfigRevision, Device, DeviceId,
    DeviceRegistration, Invite, InviteId, Ipv4Cidr, LanRoute, LanRouteId, Network, NetworkId,
    ReturnPathMode, RouteMode, Segment, SegmentId, TranslationMode,
};
use sqlx::{Row, SqlitePool};
use std::collections::BTreeMap;

use crate::service::{MeshState, ServiceError};

/// Interrupted revision summary restored by boot reconstruction.
pub const INTERRUPTED_SUMMARY: &str =
    "interrupted: server process restarted while this revision was being applied; \
     outcome unknown, marked failed (archive 10.3: never pretend success)";

/// Boot reconstruction result.
pub struct BootState {
    pub mesh: MeshState,
    pub summary: MeshStatePersistedView,
    pub interrupted: Vec<(String, u64)>,
}
pub async fn commit_task(
    pool: &SqlitePool,
    r: &crate::task::TaskRecord,
    task_seq: Option<u64>,
    audit: Option<&AuditDraft<'_>>,
) -> Result<(), sqlx::Error> {
    let (exit_code, log_tail) = r
        .result
        .as_ref()
        .map(|res| (Some(res.exit_code), Some(res.log_tail.as_str())))
        .unwrap_or((None, None));
    let mut tx = pool.begin().await?;
    sqlx::query(
        "INSERT INTO tasks
           (id, network_id, target_device_id, cmd, workdir, timeout_secs,
            state, retry_limit, result_ref, exit_code, log_tail,
            confirmed_at, rejected_at, parent_task_id, created_at, updated_at,
            required_labels)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
         ON CONFLICT (id) DO UPDATE SET
           state = excluded.state,
           result_ref = excluded.result_ref,
           exit_code = excluded.exit_code,
           log_tail = excluded.log_tail,
           confirmed_at = excluded.confirmed_at,
           rejected_at = excluded.rejected_at,
           parent_task_id = excluded.parent_task_id,
           updated_at = excluded.updated_at,
           required_labels = excluded.required_labels",
    )
    .bind(r.task.id.to_string())
    .bind(r.network_id.to_string())
    .bind(r.task.target_node.to_string())
    .bind(&r.task.payload.cmd)
    .bind(&r.task.payload.workdir)
    .bind(r.task.payload.timeout_secs.map(|s| s as i64))
    .bind(r.task.state.as_str())
    .bind(r.task.retry_limit as i64)
    .bind(r.result_ref())
    .bind(exit_code)
    .bind(log_tail)
    .bind(&r.confirmed_at)
    .bind(&r.rejected_at)
    .bind(&r.parent_task_id)
    .bind(&r.created_at)
    .bind(&r.updated_at)
    .bind(
        serde_json::to_string(&r.task.payload.required_labels).map_err(|e| {
            sqlx::Error::Io(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                e.to_string(),
            ))
        })?,
    )
    .execute(&mut *tx)
    .await?;
    if let Some(seq) = task_seq {
        save_seq_tx(&mut tx, "task_seq", seq).await?;
    }
    if let Some(audit) = audit {
        insert_audit_tx(&mut tx, audit).await?;
    }
    tx.commit().await?;
    Ok(())
}

/// 从 DB 恢复任务队列（MT-002 重启恢复）：`tasks` 行 + `mesh_meta.task_seq`。
pub async fn load_tasks(pool: &SqlitePool, state: &mut MeshState) -> Result<(), sqlx::Error> {
    let rows = sqlx::query(
        "SELECT id, network_id, target_device_id, cmd, workdir, timeout_secs,
                state, retry_limit, result_ref, exit_code, log_tail,
                confirmed_at, rejected_at, parent_task_id,
                created_at, updated_at, required_labels
         FROM tasks ORDER BY created_at",
    )
    .fetch_all(pool)
    .await?;
    for row in rows {
        let id: String = row.get("id");
        let network_id: String = row.get("network_id");
        let target: String = row.get("target_device_id");
        let cmd: String = row.get("cmd");
        let workdir: Option<String> = row.get("workdir");
        let timeout_secs: Option<i64> = row.get("timeout_secs");
        let state_str: String = row.get("state");
        let retry_limit: i64 = row.get("retry_limit");
        let result_ref: Option<String> = row.get("result_ref");
        let exit_code: Option<i64> = row.get("exit_code");
        let log_tail: Option<String> = row.get("log_tail");
        let confirmed_at: Option<String> = row.get("confirmed_at");
        let rejected_at: Option<String> = row.get("rejected_at");
        let parent_task_id: Option<String> = row.get("parent_task_id");
        let created_at: String = row.get("created_at");
        let updated_at: String = row.get("updated_at");
        let labels_raw: String = row.get("required_labels");
        let required_labels: BTreeMap<String, String> =
            serde_json::from_str(&labels_raw).map_err(|e| corrupt("task required_labels", e))?;

        let task_state = match state_str.as_str() {
            "assigned" => meshlet_domain::TaskState::Assigned,
            "acked" => meshlet_domain::TaskState::Acked,
            "running" => meshlet_domain::TaskState::Running,
            "done" => meshlet_domain::TaskState::Done,
            "failed" => meshlet_domain::TaskState::Failed,
            _ => continue, // 未知状态行（不应发生）；跳过避免启动失败
        };
        let mut task = meshlet_domain::Task::new(
            meshlet_domain::TaskId(id.clone()),
            meshlet_domain::DeviceId(target),
            meshlet_domain::TaskPayload {
                cmd,
                workdir,
                timeout_secs: timeout_secs.map(|s| s as u64),
                required_labels,
            },
            retry_limit as u32,
        );
        task.state = task_state;
        if let Some(r) = result_ref {
            task.record_result(r);
        }
        let result = match (exit_code, log_tail) {
            (Some(code), Some(tail)) => Some(crate::task::TaskResult {
                exit_code: code as i32,
                log_tail: tail,
            }),
            _ => None,
        };
        state.tasks.insert(
            id,
            crate::task::TaskRecord {
                task,
                network_id: meshlet_domain::NetworkId(network_id),
                result,
                confirmed_at,
                rejected_at,
                parent_task_id,
                created_at,
                updated_at,
            },
        );
    }
    // 任务 id 序列（`task-{seq}`）从 mesh_meta 恢复，重启不归零、不重号。
    if let Ok(seq) =
        sqlx::query_scalar::<_, i64>("SELECT value FROM mesh_meta WHERE key = 'task_seq'")
            .fetch_one(pool)
            .await
    {
        state.set_task_seq(seq as u64);
    }
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
            String,
        ),
    >(
        "SELECT id, network_id, name, virtual_ipv4, public_key, platform, status,
                last_seen_at, last_handshake_at, last_report_at, dataplane_evidence,
                created_at, approved_at, revoked_at, segment_id, labels
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
            labels: serde_json::from_str(&row.15).map_err(|e| corrupt("device labels", e))?,
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
        let mut saved = serde_json::from_str(&json).map_err(|e| corrupt("hub deployment", e))?;
        // 日志可能在失败修订（journal 未更新）与撤销并存时短暂滞留旧计划：
        // 装载即按当前授权快照过滤，恢复路径读到的永远是已授权子集。
        crate::revision::enforce_authorization(&state, &id, &mut saved);
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

    // 服务发布对象（R-06）：四张表 + mesh_meta.publish_seq + 健康证据镜像。
    crate::publish::persist::load(pool, &mut state).await?;
    // 任务队列（MT-002）：恢复任务 + mesh_meta.task_seq（断线补派不丢、不重复）。
    load_tasks(pool, &mut state).await?;

    Ok(BootState {
        summary: MeshStatePersistedView {
            networks,
            devices,
            registrations,
            routes,
            aliases,
            publishes: crate::publish::publish_object_count(&state),
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
