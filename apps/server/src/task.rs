//! 任务通道（MT-002）：server 经既有 agent 拉取通道派任务 → agent 回
//! **ack** → 运行（心跳沿用既有心跳）→ 回传 **exit code + 日志尾部**。
//!
//! 幂等语义（对齐 F-2030 流量补报）：
//! - `task id` 是幂等键：assign 带显式 id 时按 id 去重（同 id 已存在则原样
//!   返回，不重复建）；断线补派重发同 id；
//! - ack / result 对已越过该步的状态**幂等成功**（补派重发 ack、重复回执
//!   都不报错、不重跑）——严格状态机在 [meshlet_domain::TaskState]，本模块
//!   只做「沿合法路径推进 + 幂等容忍」的接线；
//! - result 回执会沿状态机合法路径补完缺失的 ack/start，终态后重复回执只
//!   更新日志尾部，不改变终态。
//!
//! 安全边界：任务由控制台用户显式派发（[AuthenticatedUser]），agent 侧
//! 端点一律 [AuthorizedAgent] 认证；agent 只执行下发任务里的命令（MT-002
//! 用户令明确该通道是既有「绝不执行服务端任意 Shell 命令」纪律的显式例外）。

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::Json;
use serde::{Deserialize, Serialize};

use meshlet_domain::{
    DeviceId, NetworkId, Task, TaskAction, TaskEvent, TaskId, TaskOutcome, TaskPayload, TaskState,
};

use crate::agent::{AgentApiError, AuthorizedAgent};
use crate::auth::{CsrfHeader, SharedAppState, WriteUser};
use crate::service::{self, MeshState, ServiceError};

/// 一次任务执行的结果（exit code + 日志尾部）。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TaskResult {
    /// 进程退出码（0 = 成功，非 0 = 失败）。
    pub exit_code: i32,
    /// 命令输出尾部（捕获 stdout+stderr 的最后若干行）。
    pub log_tail: String,
}

/// 服务端任务记录：领域 [Task] + 网络归属 + 结果 + 时间戳。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TaskRecord {
    /// 领域任务（状态机 + 幂等键 + 负载）。
    pub task: Task,
    /// 归属网络。
    pub network_id: NetworkId,
    /// 执行结果（终态后有值）。
    pub result: Option<TaskResult>,
    /// 创建时间（RFC 3339）。
    pub created_at: String,
    /// 最近更新时间（RFC 3339）。
    pub updated_at: String,
}

impl TaskRecord {
    /// 结果引用：结果落在任务记录内，result_ref 即任务 id（console 据其取回）。
    pub(crate) fn result_ref(&self) -> Option<String> {
        self.result.as_ref().map(|_| self.task.id.to_string())
    }
}

/// 控制台派发请求（`POST /api/v1/networks/{network_id}/tasks`）。
#[derive(Debug, Clone, Deserialize)]
pub struct AssignTaskRequest {
    /// 幂等键；缺省时服务端生成 `task-{seq}`。显式传已有 id 则幂等返回已有任务。
    pub id: Option<String>,
    /// 目标设备。
    pub target_device_id: String,
    /// 要执行的命令。
    pub cmd: String,
    /// 工作目录。
    pub workdir: Option<String>,
    /// 超时（秒）。
    pub timeout_secs: Option<u64>,
    /// 重试上限。
    pub retry_limit: Option<u32>,
}

/// 控制台/结果视图（含状态与执行结果）。
#[derive(Debug, Clone, Serialize)]
pub struct TaskView {
    pub id: String,
    pub network_id: String,
    pub target_device_id: String,
    pub cmd: String,
    pub workdir: Option<String>,
    pub timeout_secs: Option<u64>,
    pub state: String,
    pub retry_limit: u32,
    pub result_ref: Option<String>,
    pub exit_code: Option<i32>,
    pub log_tail: Option<String>,
    pub created_at: String,
    pub updated_at: String,
}

impl From<&TaskRecord> for TaskView {
    fn from(rec: &TaskRecord) -> Self {
        TaskView {
            id: rec.task.id.to_string(),
            network_id: rec.network_id.to_string(),
            target_device_id: rec.task.target_node.to_string(),
            cmd: rec.task.payload.cmd.clone(),
            workdir: rec.task.payload.workdir.clone(),
            timeout_secs: rec.task.payload.timeout_secs,
            state: rec.task.state.as_str().to_string(),
            retry_limit: rec.task.retry_limit,
            result_ref: rec.result_ref(),
            exit_code: rec.result.as_ref().map(|r| r.exit_code),
            log_tail: rec.result.as_ref().map(|r| r.log_tail.clone()),
            created_at: rec.created_at.clone(),
            updated_at: rec.updated_at.clone(),
        }
    }
}

/// agent 结果回执（`POST /api/v1/agent/tasks/{id}/result`）。
#[derive(Debug, Clone, Deserialize)]
pub struct TaskResultReport {
    /// 进程退出码。
    pub exit_code: i32,
    /// 命令输出尾部。
    pub log_tail: String,
}

/// 派发任务（assign）。显式 id 已存在 → 幂等返回已有记录（`new_seq=None,
/// created=false`）；否则创建 `task-{seq}`（或显式 id）并置
/// [TaskState::Assigned]。返回 `(记录, 新 task_seq, 是否新建)`。
pub(crate) fn assign(
    state: &mut MeshState,
    network_id: &str,
    req: &AssignTaskRequest,
) -> Result<(TaskRecord, Option<u64>, bool), ServiceError> {
    // 目标设备必须归属该网络且为 Active（与发布对象同一纪律）。
    let _device = crate::publish::device_in_network(state, network_id, &req.target_device_id)?;

    // 幂等键：同 id 已存在（无论状态）→ 原样返回，不重复建、不重置状态。
    let (id, new_seq) = match &req.id {
        Some(id) => {
            if let Some(existing) = state.tasks.get(id) {
                return Ok((existing.clone(), None, false));
            }
            (TaskId(id.clone()), None)
        }
        None => {
            let seq = state.task_seq() + 1;
            state.set_task_seq(seq);
            (TaskId(format!("task-{seq}")), Some(seq))
        }
    };

    let payload = TaskPayload {
        cmd: req.cmd.clone(),
        workdir: req.workdir.clone(),
        timeout_secs: req.timeout_secs,
    };
    let task = Task::new(
        id,
        DeviceId(req.target_device_id.clone()),
        payload,
        req.retry_limit.unwrap_or(0),
    );
    let now = service::now();
    let record = TaskRecord {
        task,
        network_id: NetworkId(network_id.to_string()),
        result: None,
        created_at: now.clone(),
        updated_at: now,
    };
    state.tasks.insert(record.task.id.0.clone(), record.clone());
    Ok((record, new_seq, true))
}

/// 目标设备的待办（assigned / acked，按 id 确定性排序）。
pub(crate) fn pending_for(state: &MeshState, device_id: &DeviceId) -> Vec<Task> {
    let mut out: Vec<Task> = state
        .tasks
        .values()
        .filter(|rec| rec.task.target_node == *device_id)
        .filter(|rec| matches!(rec.task.state, TaskState::Assigned | TaskState::Acked))
        .map(|rec| rec.task.clone())
        .collect();
    out.sort_by(|a, b| a.id.cmp(&b.id));
    out
}

/// ack：assigned→acked；已越过 assigned 视为幂等成功（补派重发 ack 不报错）。
/// 返回是否发生了跃迁（`Some(action)`）或任务不存在（`None`）。
pub(crate) fn ack(state: &mut MeshState, id: &str) -> Option<TaskAction> {
    let rec = state.tasks.get_mut(id)?;
    match rec.task.state {
        TaskState::Assigned => {
            let action = rec.task.apply(TaskEvent::Ack).ok()?;
            rec.updated_at = service::now();
            Some(action)
        }
        _ => None, // 幂等：已 acked / running / 终态不再跃迁
    }
}

/// 记录结果：沿合法状态机路径推进到 done|failed（缺 ack/start 补完），
/// 已是终态则幂等更新日志尾部；返回本次动作（终态幂等返回 `None`）。
pub(crate) fn record_result(
    state: &mut MeshState,
    id: &str,
    exit_code: i32,
    log_tail: &str,
) -> Option<TaskAction> {
    let rec = state.tasks.get_mut(id)?;
    let outcome = if exit_code == 0 {
        TaskOutcome::Success
    } else {
        TaskOutcome::Failure
    };
    // 沿合法路径补完缺失的前置跃迁（断线丢 ack/start 时 result 自会补上）。
    if rec.task.state == TaskState::Assigned {
        let _ = rec.task.apply(TaskEvent::Ack);
    }
    if rec.task.state == TaskState::Acked {
        let _ = rec.task.apply(TaskEvent::Start);
    }
    let action = if matches!(rec.task.state, TaskState::Running) {
        rec.task.apply(TaskEvent::Complete(outcome)).ok()
    } else {
        None // 已是终态：幂等重复回执，只更新结果尾部
    };
    rec.result = Some(TaskResult {
        exit_code,
        log_tail: log_tail.to_string(),
    });
    rec.updated_at = service::now();
    action
}

/// 控制台路由（MT-002：任务派发）。
pub(crate) fn console_routes() -> axum::Router<SharedAppState> {
    axum::Router::new().route(
        "/api/v1/networks/{network_id}/tasks",
        axum::routing::post(assign_handler),
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
