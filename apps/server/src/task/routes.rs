//! 任务 HTTP 路由：console 派发/确认/驳回与 agent 拉取/ack/result。

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::Json;

use meshlet_domain::Task;

use crate::agent::{AgentApiError, AuthorizedAgent};
use crate::auth::{AuthenticatedUser, CsrfHeader, SharedAppState, WriteUser};
use crate::service::{MeshState, ServiceError};

use super::dispatch::{ack, assign, confirm, pending_for, record_result, retry};
use super::models::{AssignTaskRequest, TaskResultReport, TaskView};

/// 按网络列任务（创建时间稳定排序；同秒并列按 id 决胜——`created_at` 秒级
/// 精度，`tasks` 又是 HashMap，无 id 决胜会退化为任意序）。
pub(crate) fn list_network(state: &MeshState, network_id: &str) -> Vec<TaskView> {
    let mut out: Vec<TaskView> = state
        .tasks
        .values()
        .filter(|rec| rec.network_id.to_string() == network_id)
        .map(TaskView::from)
        .collect();
    out.sort_by(|a, b| {
        a.created_at
            .cmp(&b.created_at)
            .then_with(|| a.id.cmp(&b.id))
    });
    out
}

/// 控制台路由（MT-002 派发；MT-003 列取/确认/驳回重跑）。
pub(crate) fn console_routes() -> axum::Router<SharedAppState> {
    axum::Router::new()
        .route(
            "/api/v1/networks/{network_id}/tasks",
            axum::routing::get(list_handler).post(assign_handler),
        )
        .route(
            "/api/v1/networks/{network_id}/tasks/{task_id}/confirm",
            axum::routing::post(confirm_handler),
        )
        .route(
            "/api/v1/networks/{network_id}/tasks/{task_id}/retry",
            axum::routing::post(retry_handler),
        )
}

/// 控制台派发（`POST /api/v1/networks/{network_id}/tasks`）。
pub(crate) async fn assign_handler(
    State(state): State<SharedAppState>,
    WriteUser(user_id): WriteUser,
    CsrfHeader: CsrfHeader,
    Path(network_id): Path<String>,
    Json(req): Json<AssignTaskRequest>,
) -> Result<(StatusCode, Json<TaskView>), ServiceError> {
    let _persist = state.persist.lock().await;
    let (view, record, new_seq, created) = {
        let mut guard = state.mesh.lock().unwrap();
        let (record, new_seq, created) = assign(&mut guard, &network_id, &req)?;
        let view = TaskView::from(&record);
        (view, record, new_seq, created)
    };
    let audit = crate::persist::AuditDraft {
        actor_id: Some(&user_id.0),
        action: "task.assigned",
        target_type: "task",
        target_id: &record.task.id.0,
        detail: Some(serde_json::json!({
            "network_id": network_id,
            "target_device_id": record.task.target_node.to_string(),
        })),
    };
    crate::persist::commit_task(state.auth.pool(), &record, new_seq, Some(&audit))
        .await
        .map_err(crate::persist::internal)?;
    let status = if created {
        StatusCode::CREATED
    } else {
        StatusCode::OK
    };
    Ok((status, Json(view)))
}

/// 控制台列取网络任务（`GET /api/v1/networks/{network_id}/tasks`）。
pub(crate) async fn list_handler(
    State(state): State<SharedAppState>,
    AuthenticatedUser(_user_id): AuthenticatedUser,
    Path(network_id): Path<String>,
) -> Result<Json<Vec<TaskView>>, ServiceError> {
    let guard = state.mesh.lock().unwrap();
    Ok(Json(list_network(&guard, &network_id)))
}

/// 控制台确认完成（`POST /api/v1/networks/{network_id}/tasks/{task_id}/confirm`）。
/// 仅 done 可确认；重复确认幂等 200。非终态任务不可确认 → 409。
pub(crate) async fn confirm_handler(
    State(state): State<SharedAppState>,
    WriteUser(user_id): WriteUser,
    CsrfHeader: CsrfHeader,
    Path((network_id, task_id)): Path<(String, String)>,
) -> Result<(StatusCode, Json<TaskView>), ServiceError> {
    let _persist = state.persist.lock().await;
    let (record, newly) = {
        let mut guard = state.mesh.lock().unwrap();
        // 任务必须属于该网络。
        let rec = guard
            .tasks
            .get(&task_id)
            .cloned()
            .ok_or_else(|| ServiceError::TaskNotFound(format!("task {task_id}")))?;
        if rec.network_id.to_string() != network_id {
            return Err(ServiceError::TaskNotFound(format!("task {task_id}")));
        }
        let newly = confirm(&mut guard, &task_id).ok_or_else(|| {
            ServiceError::Conflict(format!(
                "task {task_id} is {} and cannot be confirmed",
                rec.task.state.as_str()
            ))
        })?;
        (guard.tasks.get(&task_id).cloned(), newly)
    };
    if newly {
        let audit = crate::persist::AuditDraft {
            actor_id: Some(&user_id.0),
            action: "task.confirmed",
            target_type: "task",
            target_id: &task_id,
            detail: Some(serde_json::json!({ "network_id": network_id })),
        };
        crate::persist::commit_task(
            state.auth.pool(),
            record.as_ref().unwrap(),
            None,
            Some(&audit),
        )
        .await
        .map_err(crate::persist::internal)?;
    }
    Ok((
        StatusCode::OK,
        Json(TaskView::from(record.as_ref().unwrap())),
    ))
}

/// 控制台驳回重跑（`POST /api/v1/networks/{network_id}/tasks/{task_id}/retry`）。
/// 原任务置 rejected_at 并派发新一代（201 返回新任务）。非终态 → 409。
pub(crate) async fn retry_handler(
    State(state): State<SharedAppState>,
    WriteUser(user_id): WriteUser,
    CsrfHeader: CsrfHeader,
    Path((network_id, task_id)): Path<(String, String)>,
) -> Result<(StatusCode, Json<TaskView>), ServiceError> {
    let _persist = state.persist.lock().await;
    let (record, new_seq, orig) = {
        let mut guard = state.mesh.lock().unwrap();
        let (record, new_seq) = retry(&mut guard, &network_id, &task_id)?;
        // 被驳回的原任务此刻已置 rejected_at；取回供落库。
        let orig = guard.tasks.get(&task_id).cloned();
        (record, new_seq, orig)
    };
    // 原任务的 rejected_at 是新写入，不落库则重启后丢失「已驳回」事实
    // （审核 MAJOR：只落新代会丢原记录）。先落原任务（拒绝事实先行），
    // 再落新代。
    let orig = orig.ok_or_else(|| ServiceError::Internal("retried task vanished".into()))?;
    let reject_audit = crate::persist::AuditDraft {
        actor_id: Some(&user_id.0),
        action: "task.rejected",
        target_type: "task",
        target_id: &task_id,
        detail: Some(serde_json::json!({
            "network_id": network_id,
            "rerun": record.task.id.to_string(),
        })),
    };
    crate::persist::commit_task(state.auth.pool(), &orig, None, Some(&reject_audit))
        .await
        .map_err(crate::persist::internal)?;
    let audit = crate::persist::AuditDraft {
        actor_id: Some(&user_id.0),
        action: "task.retried",
        target_type: "task",
        target_id: &record.task.id.0,
        detail: Some(serde_json::json!({
            "network_id": network_id,
            "retry_of": task_id,
        })),
    };
    crate::persist::commit_task(state.auth.pool(), &record, Some(new_seq), Some(&audit))
        .await
        .map_err(crate::persist::internal)?;
    Ok((StatusCode::CREATED, Json(TaskView::from(&record))))
}

/// agent 拉取待办（`GET /api/v1/agent/tasks/pending`）。
pub(crate) async fn pending_handler(
    State(state): State<SharedAppState>,
    AuthorizedAgent(device_id): AuthorizedAgent,
) -> Result<Json<Vec<Task>>, AgentApiError> {
    let guard = state.mesh.lock().unwrap();
    Ok(Json(pending_for(&guard, &device_id)))
}

/// agent 确认接收（`POST /api/v1/agent/tasks/{id}/ack`）。
pub(crate) async fn ack_handler(
    State(state): State<SharedAppState>,
    AuthorizedAgent(device_id): AuthorizedAgent,
    Path(id): Path<String>,
) -> Result<StatusCode, AgentApiError> {
    let _persist = state.persist.lock().await;
    let (record, changed) = {
        let mut guard = state.mesh.lock().unwrap();
        // 只能确认发给自己的任务。
        let rec = guard
            .tasks
            .get(&id)
            .cloned()
            .ok_or_else(|| AgentApiError::NotFound(format!("task {id}")))?;
        if rec.task.target_node != device_id {
            return Err(AgentApiError::NotFound(format!("task {id}")));
        }
        let changed = ack(&mut guard, &id).is_some();
        (guard.tasks.get(&id).cloned(), changed)
    };
    // 幂等：已 acked / running / 终态时 ack 不再跃迁，也不重复落库 / 审计。
    if let (Some(record), true) = (record, changed) {
        let audit = crate::persist::AuditDraft {
            actor_id: Some(&device_id.0),
            action: "task.acked",
            target_type: "task",
            target_id: &id,
            detail: None,
        };
        crate::persist::commit_task(state.auth.pool(), &record, None, Some(&audit))
            .await
            .map_err(|e| AgentApiError::Internal(format!("persist: {e}")))?;
    }
    Ok(StatusCode::OK)
}

/// agent 回传结果（`POST /api/v1/agent/tasks/{id}/result`）。
pub(crate) async fn result_handler(
    State(state): State<SharedAppState>,
    AuthorizedAgent(device_id): AuthorizedAgent,
    Path(id): Path<String>,
    Json(report): Json<TaskResultReport>,
) -> Result<Json<TaskView>, AgentApiError> {
    let _persist = state.persist.lock().await;
    let record = {
        let mut guard = state.mesh.lock().unwrap();
        let rec = guard
            .tasks
            .get(&id)
            .cloned()
            .ok_or_else(|| AgentApiError::NotFound(format!("task {id}")))?;
        if rec.task.target_node != device_id {
            return Err(AgentApiError::NotFound(format!("task {id}")));
        }
        record_result(&mut guard, &id, report.exit_code, &report.log_tail);
        guard.tasks.get(&id).cloned().expect("task exists")
    };
    let audit = crate::persist::AuditDraft {
        actor_id: Some(&device_id.0),
        action: "task.result",
        target_type: "task",
        target_id: &id,
        detail: Some(serde_json::json!({ "exit_code": report.exit_code })),
    };
    crate::persist::commit_task(state.auth.pool(), &record, None, Some(&audit))
        .await
        .map_err(|e| AgentApiError::Internal(format!("persist: {e}")))?;
    Ok(Json(TaskView::from(&record)))
}

/// 供诊断 / 控制台列取全部任务（MT-003 会加分列面板，此处只给稳定排序）。
#[allow(dead_code)]
pub(crate) fn list(state: &MeshState) -> Vec<TaskView> {
    let mut out: Vec<TaskView> = state.tasks.values().map(TaskView::from).collect();
    out.sort_by(|a, b| a.created_at.cmp(&b.created_at));
    out
}
