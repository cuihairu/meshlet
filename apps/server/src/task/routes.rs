//! Task HTTP routes: console dispatch/confirm/reject and agent pull/ack/result.

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::Json;

use meshlet_domain::Task;

use crate::agent::{AgentApiError, AuthorizedAgent};
use crate::auth::{AuthenticatedUser, CsrfHeader, SharedAppState, WriteUser};
use crate::service::{MeshState, ServiceError};

use super::dispatch::{ack, assign, confirm, pending_for, record_result, retry};
use super::models::{AssignTaskRequest, TaskResultReport, TaskView};

/// List tasks per network (stable ordering by creation time; ties within the same second are broken by id —
/// `created_at` has second-level precision and `tasks` is a HashMap, so without the id tiebreak the order would
/// degenerate into an arbitrary one).
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

/// Console routes (MT-002 dispatch; MT-003 list/fetch, confirm, reject-and-rerun).
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

/// Console dispatch (`POST /api/v1/networks/{network_id}/tasks`).
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

/// Console listing of a network's tasks (`GET /api/v1/networks/{network_id}/tasks`).
pub(crate) async fn list_handler(
    State(state): State<SharedAppState>,
    AuthenticatedUser(_user_id): AuthenticatedUser,
    Path(network_id): Path<String>,
) -> Result<Json<Vec<TaskView>>, ServiceError> {
    let guard = state.mesh.lock().unwrap();
    Ok(Json(list_network(&guard, &network_id)))
}

/// Console confirmation of completion (`POST /api/v1/networks/{network_id}/tasks/{task_id}/confirm`).
/// Only a done task can be confirmed; confirming again is an idempotent 200. A non-terminal task cannot be
/// confirmed -> 409.
pub(crate) async fn confirm_handler(
    State(state): State<SharedAppState>,
    WriteUser(user_id): WriteUser,
    CsrfHeader: CsrfHeader,
    Path((network_id, task_id)): Path<(String, String)>,
) -> Result<(StatusCode, Json<TaskView>), ServiceError> {
    let _persist = state.persist.lock().await;
    let (record, newly) = {
        let mut guard = state.mesh.lock().unwrap();
        // The task must belong to that network.
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

/// Console rejection with re-run (`POST /api/v1/networks/{network_id}/tasks/{task_id}/retry`).
/// The original task gets rejected_at and a new generation is dispatched (201 returns the new task).
/// Non-terminal -> 409.
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
        // The rejected original task has just been stamped with rejected_at; fetch it back for persistence.
        let orig = guard.tasks.get(&task_id).cloned();
        (record, new_seq, orig)
    };
    // The original task's rejected_at is a fresh write; if it is not persisted, the "was
    // rejected" fact is lost after a restart (review MAJOR: persisting only the new
    // generation would lose the original record). Persist the original task first (the
    // rejection fact comes first), then the new generation.
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

/// Agent pulls its pending work (`GET /api/v1/agent/tasks/pending`).
pub(crate) async fn pending_handler(
    State(state): State<SharedAppState>,
    AuthorizedAgent(device_id): AuthorizedAgent,
) -> Result<Json<Vec<Task>>, AgentApiError> {
    let guard = state.mesh.lock().unwrap();
    Ok(Json(pending_for(&guard, &device_id)))
}

/// Agent acknowledges receipt (`POST /api/v1/agent/tasks/{id}/ack`).
pub(crate) async fn ack_handler(
    State(state): State<SharedAppState>,
    AuthorizedAgent(device_id): AuthorizedAgent,
    Path(id): Path<String>,
) -> Result<StatusCode, AgentApiError> {
    let _persist = state.persist.lock().await;
    let (record, changed) = {
        let mut guard = state.mesh.lock().unwrap();
        // It can only acknowledge tasks addressed to itself.
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
    // Idempotent: once acked / running / terminal, acking no longer transitions and does not re-persist or re-audit.
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

/// Agent returns the result (`POST /api/v1/agent/tasks/{id}/result`).
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

/// For diagnostics / console listing of all tasks (MT-003 will add a per-column panel; here only a stable order is provided).
#[allow(dead_code)]
pub(crate) fn list(state: &MeshState) -> Vec<TaskView> {
    let mut out: Vec<TaskView> = state.tasks.values().map(TaskView::from).collect();
    out.sort_by(|a, b| a.created_at.cmp(&b.created_at));
    out
}
