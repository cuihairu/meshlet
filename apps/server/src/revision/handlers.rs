use super::backend::{deployment, enforce_authorization};
use super::{to_revision_view, RevisionView};
use axum::extract::{Path, State};
use axum::Json;
use std::sync::Arc;

use crate::auth::{AuthenticatedUser, CsrfHeader, SharedAppState, WriteUser};
use crate::service::{self, ServiceError};

fn network_id_of(id: &str) -> meshlet_domain::NetworkId {
    meshlet_domain::NetworkId(id.to_string())
}

/// `GET /api/v1/networks/{network_id}/config-revisions`：全部修订（升序）。
pub async fn list_revisions_handler(
    State(state): State<SharedAppState>,
    AuthenticatedUser(_user): AuthenticatedUser,
    Path(network_id): Path<String>,
) -> Result<Json<Vec<RevisionView>>, ServiceError> {
    let mut views = {
        let guard = state.mesh.lock().unwrap();
        service::require_network(&guard, &network_id)?;
        guard
            .ledger
            .revisions(&network_id_of(&network_id))
            .iter()
            .map(to_revision_view)
            .collect::<Vec<_>>()
    };
    if let Some(last) = views
        .iter_mut()
        .rev()
        .find(|r| r.apply_status != "rolled_back")
    {
        last.convergence = Some(
            serde_json::to_value(crate::convergence::status(&state, &network_id).await?)
                .map_err(|e| ServiceError::Internal(e.to_string()))?,
        );
    }
    Ok(Json(views))
}

/// `GET /api/v1/networks/{network_id}/config-revisions/{revision}`：版本详情。
pub async fn get_revision_handler(
    State(state): State<SharedAppState>,
    AuthenticatedUser(_user): AuthenticatedUser,
    Path((network_id, revision)): Path<(String, u64)>,
) -> Result<Json<RevisionView>, ServiceError> {
    let (mut view, current) = {
        let guard = state.mesh.lock().unwrap();
        service::require_network(&guard, &network_id)?;
        let r = guard
            .ledger
            .get(&network_id_of(&network_id), revision)
            .ok_or_else(|| ServiceError::RevisionNotFound(revision.to_string()))?;
        (
            to_revision_view(r),
            guard
                .ledger
                .current(&network_id_of(&network_id))
                .is_some_and(|r| r.revision == revision),
        )
    };
    if current {
        view.convergence = Some(
            serde_json::to_value(crate::convergence::status(&state, &network_id).await?)
                .map_err(|e| ServiceError::Internal(e.to_string()))?,
        );
    }
    Ok(Json(view))
}

/// `POST .../config-revisions/{revision}/apply`：把该修订应用到实际环境。
///
/// 返回该修订的当前视图——`apply_status` 是结论；backend 失败时同样 200，
/// 但状态为 `failed` 且 `error_summary` 说明原因（失败可见，不伪装成功）。
pub fn apply_revision_handler(
    State(state): State<SharedAppState>,
    WriteUser(user_id): WriteUser,
    CsrfHeader: CsrfHeader,
    Path((network_id, revision)): Path<(String, u64)>,
) -> impl std::future::Future<Output = Result<Json<RevisionView>, ServiceError>> + Send {
    apply_revision_impl(state, user_id, network_id, revision)
}

async fn apply_revision_impl(
    state: SharedAppState,
    user_id: meshlet_domain::UserId,
    network_id: String,
    revision: u64,
) -> Result<Json<RevisionView>, ServiceError> {
    let (revision_permit, should_apply) = {
        let revision_lock = state.revision_lock(&network_id);
        let revision_permit = revision_lock.clone().lock_owned().await;
        let _persist = state.persist.lock().await;
        let should_apply;
        {
            let guard = state.mesh.lock().unwrap();
            service::require_network(&guard, &network_id)?;
            should_apply = guard
                .ledger
                .get(&network_id_of(&network_id), revision)
                .is_some_and(|r| r.apply_status == meshlet_domain::ApplyStatus::Pending);
        }
        if should_apply {
            let result = sqlx::query("UPDATE config_revisions SET apply_status='applying' WHERE network_id=? AND revision=? AND apply_status='pending'")
                .bind(&network_id).bind(revision as i64).execute(state.auth.pool()).await.map_err(crate::persist::internal)?;
            if result.rows_affected() != 1 {
                return Err(ServiceError::Conflict(
                    "revision state changed while recording apply intent".to_string(),
                ));
            }
            state
                .mesh
                .lock()
                .unwrap()
                .ledger
                .reserve_apply(&network_id_of(&network_id), revision);
        }
        (revision_permit, should_apply)
    };
    let now = service::now();
    let target_network = network_id_of(&network_id);
    let task_network = target_network.clone();
    let backend_factory = Arc::clone(&state.apply_backend);
    let mesh = Arc::clone(&state.mesh);
    let task_network_id = network_id.clone();
    let task_result = tokio::task::spawn_blocking(move || {
        let _revision_permit = revision_permit;
        let mut staged = mesh.lock().unwrap().clone();
        let mut backend = backend_factory(&staged, &task_network_id);
        let result = staged
            .ledger
            .apply(&task_network, revision, backend.as_mut(), now);
        (result, _revision_permit)
    })
    .await
    .map_err(|error| ServiceError::Internal(format!("revision apply task failed: {error}")))?;
    let (apply_result, revision_permit) = task_result;
    let applied = apply_result.map_err(ServiceError::from_ledger)?;
    let _revision_permit = revision_permit;
    let (settle, candidate, applied) = {
        let _persist = state.persist.lock().await;
        let mut guard = state.mesh.lock().unwrap();
        service::require_network(&guard, &network_id)?;
        if guard.ledger.current(&target_network).map(|r| r.revision) != Some(revision) {
            return Err(ServiceError::Conflict(
                "revision superseded while applying".to_string(),
            ));
        }
        guard.ledger.restore_revision(applied.clone());
        let (settle, candidate) = {
            // 结论收敛到每条期望项（§10.1 的路由/映射层镜像）：只有真下发到内核
            // 的前缀才转 `applied`，agent 数据面据此取计划。
            let success = applied.apply_status == meshlet_domain::ApplyStatus::Applied;
            let candidate = if success && should_apply && state.dataplane.enabled {
                Some(
                    deployment(
                        &guard,
                        &network_id,
                        &state.dataplane,
                        state.tunnel_mtu,
                        revision,
                    )
                    .map_err(ServiceError::Internal)?,
                )
            } else {
                None
            };
            let settle = if success && !should_apply {
                service::DesiredStateSettle::default()
            } else if success && state.dataplane.enabled {
                service::settle_desired_with_status(
                    &mut guard,
                    &network_id,
                    meshlet_domain::DesiredStateStatus::Pending,
                )
            } else {
                service::settle_desired_state(&mut guard, &network_id, success)
            };
            (settle, candidate)
        };
        drop(guard);
        drop(_persist);
        (settle, candidate, applied)
    };
    if let Err(error) =
        crate::persist::commit_application(state.auth.pool(), &applied, &settle, candidate.as_ref())
            .await
    {
        let message = format!("apply outcome could not be persisted: {error}");
        let mut mesh = state.mesh.lock().unwrap();
        mesh.ledger
            .mark_apply_unconfirmed(&network_id_of(&network_id), revision, message.clone());
        service::settle_desired_state(&mut mesh, &network_id, false);
        return Err(ServiceError::Internal(message));
    }
    if let Some(candidate) = candidate {
        state
            .mesh
            .lock()
            .unwrap()
            .deployments
            .insert(network_id.clone(), candidate);
    }
    // 应用失败必留痕（§16.5）；结果以 apply_status 为准（`applied` 即成功，
    // 其余一律按失败留痕），不凭响应码判断。
    let mut view = to_revision_view(&applied);
    view.convergence = Some(
        serde_json::to_value(crate::convergence::status(&state, &network_id).await?)
            .map_err(|e| ServiceError::Internal(e.to_string()))?,
    );
    let applied_ok = view.apply_status == "applied";
    let (action, detail) = if !applied_ok {
        (
            "revision.apply_failed",
            serde_json::json!({
                "network_id": network_id,
                "error_summary": view.error_summary,
            }),
        )
    } else {
        (
            "revision.applied",
            serde_json::json!({ "network_id": network_id }),
        )
    };
    crate::audit::record_or_fail(
        &state,
        Some(&user_id.0),
        action,
        "revision",
        Some(&revision.to_string()),
        Some(detail),
    )
    .await?;
    // 指标（§17.2 配置应用成功率/失败数）：以状态机结论计数，不凭响应码。
    state.metrics.record_config_apply(applied_ok);
    if applied_ok {
        crate::op_log!(
            info,
            "revision",
            "apply_revision",
            &network_id,
            crate::telemetry::NOT_APPLICABLE,
            &revision.to_string(),
            crate::telemetry::ErrorCategory::None.as_str(),
            crate::telemetry::RESULT_OK
        );
    } else {
        crate::op_log!(
            warn,
            "revision",
            "apply_revision",
            &network_id,
            crate::telemetry::NOT_APPLICABLE,
            &revision.to_string(),
            crate::telemetry::ErrorCategory::Internal.as_str(),
            crate::telemetry::RESULT_ERROR
        );
    }
    Ok(Json(view))
}

/// `POST .../config-revisions/{revision}/rollback`：回滚一个 `Failed` 修订。
/// 回滚只允许动 Meshlet 自有对象（ADR-007），不得清空系统路由（§10.3）。
pub fn rollback_revision_handler(
    State(state): State<SharedAppState>,
    WriteUser(user_id): WriteUser,
    CsrfHeader: CsrfHeader,
    Path((network_id, revision)): Path<(String, u64)>,
) -> impl std::future::Future<Output = Result<Json<RevisionView>, ServiceError>> + Send {
    rollback_revision_impl(state, user_id, network_id, revision)
}

async fn rollback_revision_impl(
    state: SharedAppState,
    user_id: meshlet_domain::UserId,
    network_id: String,
    revision: u64,
) -> Result<Json<RevisionView>, ServiceError> {
    let revision_permit = {
        let revision_lock = state.revision_lock(&network_id);
        let revision_permit = revision_lock.clone().lock_owned().await;
        let _persist = state.persist.lock().await;
        let should_rollback;
        {
            let guard = state.mesh.lock().unwrap();
            service::require_network(&guard, &network_id)?;
            let target = guard
                .ledger
                .get(&network_id_of(&network_id), revision)
                .ok_or_else(|| ServiceError::RevisionNotFound(revision.to_string()))?;
            if target.apply_status == meshlet_domain::ApplyStatus::RolledBack {
                return Ok(Json(to_revision_view(target)));
            }
            should_rollback = guard
                .ledger
                .current(&network_id_of(&network_id))
                .is_some_and(|r| r.revision == revision)
                && matches!(
                    target.apply_status,
                    meshlet_domain::ApplyStatus::Failed
                        | meshlet_domain::ApplyStatus::RollbackPending
                );
        }
        if should_rollback {
            let result = sqlx::query("UPDATE config_revisions SET apply_status='rollback_pending' WHERE network_id=? AND revision=? AND apply_status='failed'")
                .bind(&network_id).bind(revision as i64).execute(state.auth.pool()).await.map_err(crate::persist::internal)?;
            if result.rows_affected() != 1 {
                return Err(ServiceError::Conflict(
                    "revision state changed while recording rollback intent".to_string(),
                ));
            }
            state
                .mesh
                .lock()
                .unwrap()
                .ledger
                .reserve_rollback(&network_id_of(&network_id), revision);
        }
        revision_permit
    };
    let target_network = network_id_of(&network_id);
    let task_network = target_network.clone();
    let backend_factory = Arc::clone(&state.apply_backend);
    let mesh = Arc::clone(&state.mesh);
    let task_network_id = network_id.clone();
    let task_result = tokio::task::spawn_blocking(move || {
        let _revision_permit = revision_permit;
        let mut staged = mesh.lock().unwrap().clone();
        let mut backend = backend_factory(&staged, &task_network_id);
        let result = staged
            .ledger
            .rollback(&task_network, revision, backend.as_mut());
        (result, _revision_permit)
    })
    .await
    .map_err(|error| ServiceError::Internal(format!("revision rollback task failed: {error}")))?;
    let (rollback_result, revision_permit) = task_result;
    let rolled = rollback_result.map_err(ServiceError::from_ledger)?;
    let _revision_permit = revision_permit;
    let (settle, saved) = {
        let _persist = state.persist.lock().await;
        let mut guard = state.mesh.lock().unwrap();
        service::require_network(&guard, &network_id)?;
        if guard.ledger.current(&target_network).map(|r| r.revision) != Some(revision) {
            return Err(ServiceError::Conflict(
                "revision superseded while rolling back".to_string(),
            ));
        }
        guard.ledger.restore_revision(rolled.clone());
        if rolled.apply_status == meshlet_domain::ApplyStatus::RolledBack && state.dataplane.enabled
        {
            if let Some(mut saved) = guard.deployments.get(&network_id).cloned() {
                // 回滚回落到上一份已确认计划（可能早于最近的撤销），写回日志前
                // 先过当前授权快照，否则被撤销的设备会随日志重新获得授权。
                enforce_authorization(&guard, &network_id, &mut saved);
                guard
                    .lan_routes
                    .insert(network_id.clone(), saved.routes.clone());
                guard
                    .aliases
                    .insert(network_id.clone(), saved.aliases.clone());
                guard.deployments.insert(network_id.clone(), saved);
            } else {
                guard.lan_routes.remove(&network_id);
                guard.aliases.remove(&network_id);
            }
        }
        // 回滚清理了 hub 侧对象 → 期望项不得继续显示 `applied`（§10.3）：
        // 回滚确认即转 `failed`，未确认（rollback_pending）同样不算生效。
        let settle = if rolled.apply_status == meshlet_domain::ApplyStatus::RolledBack
            && state.dataplane.enabled
        {
            service::settle_desired_with_status(
                &mut guard,
                &network_id,
                meshlet_domain::DesiredStateStatus::Pending,
            )
        } else {
            service::settle_desired_state(&mut guard, &network_id, false)
        };
        let saved = guard.deployments.get(&network_id).cloned();
        (settle, saved)
    };
    let restore =
        rolled.apply_status == meshlet_domain::ApplyStatus::RolledBack && state.dataplane.enabled;
    let committed = crate::persist::commit_rollback(
        state.auth.pool(),
        &rolled,
        &settle,
        restore,
        saved.as_ref(),
    )
    .await;
    if let Err(error) = committed {
        let message = format!("rollback outcome could not be persisted: {error}");
        state.mesh.lock().unwrap().ledger.mark_rollback_unconfirmed(
            &network_id_of(&network_id),
            revision,
            message.clone(),
        );
        return Err(ServiceError::Internal(message));
    }
    // 回滚失败同样留痕（§16.5）：无 backend 的回滚停在 `rollback_pending`
    //（明确未完成）——除 `rolled_back` 外一律按失败留痕。
    let mut view = to_revision_view(&rolled);
    if rolled.apply_status != meshlet_domain::ApplyStatus::RolledBack {
        view.convergence = Some(
            serde_json::to_value(crate::convergence::status(&state, &network_id).await?)
                .map_err(|e| ServiceError::Internal(e.to_string()))?,
        );
    }
    let rolled_back = view.apply_status == "rolled_back";
    let (action, detail) = if !rolled_back {
        (
            "revision.rollback_failed",
            serde_json::json!({
                "network_id": network_id,
                "error_summary": view.error_summary,
            }),
        )
    } else {
        (
            "revision.rolled_back",
            serde_json::json!({ "network_id": network_id }),
        )
    };
    crate::audit::record_or_fail(
        &state,
        Some(&user_id.0),
        action,
        "revision",
        Some(&revision.to_string()),
        Some(detail),
    )
    .await?;
    // 指标（§17.2 回滚结果）：`rolled_back` 计成功，`rollback_pending` 计未确认。
    state.metrics.record_config_rollback(rolled_back);
    if rolled_back {
        crate::op_log!(
            info,
            "revision",
            "rollback_revision",
            &network_id,
            crate::telemetry::NOT_APPLICABLE,
            &revision.to_string(),
            crate::telemetry::ErrorCategory::None.as_str(),
            crate::telemetry::RESULT_OK
        );
    } else {
        crate::op_log!(
            warn,
            "revision",
            "rollback_revision",
            &network_id,
            crate::telemetry::NOT_APPLICABLE,
            &revision.to_string(),
            crate::telemetry::ErrorCategory::Internal.as_str(),
            crate::telemetry::RESULT_ERROR
        );
    }
    Ok(Json(view))
}
