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

use super::shared::{corrupt, desired_status_parse};
use meshlet_domain::{AliasMapping, ConfigRevision, LanRouteId, NetworkId, TranslationMode};
use sqlx::SqlitePool;

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

/// Alias mapping rows used by diagnostics.
///
/// Write paths validate these rows before persistence. A corrupt row is
/// skipped so diagnostics report conflicts rather than crash.
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
            // 已确认的 hub 计划同样回落到回滚结果（调用方已按当前授权快照
            // 过滤），否则下次重启会从日志里读回更早的、含被撤销设备的计划。
            let json = serde_json::to_string(saved).map_err(|e| corrupt("hub deployment", e))?;
            sqlx::query("INSERT INTO hub_deployments(network_id,plan_json) VALUES(?,?) ON CONFLICT(network_id) DO UPDATE SET plan_json=excluded.plan_json,recovery_error=NULL")
                .bind(&network).bind(json).execute(&mut *tx).await?;
        }
        sqlx::query("DELETE FROM device_apply_receipts WHERE device_id IN (SELECT id FROM devices WHERE network_id=?)").bind(&network).execute(&mut *tx).await?;
    }
    write_outcome_tx(&mut tx, revision, settle).await?;
    tx.commit().await
}
