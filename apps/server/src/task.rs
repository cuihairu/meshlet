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
use crate::auth::{AuthenticatedUser, CsrfHeader, SharedAppState, WriteUser};
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
    /// 用户确认完成时刻（RFC 3339）。确认是用户侧动作，agent 端点绝无
    /// 确认能力（「agent 不得自判 done」）。
    pub confirmed_at: Option<String>,
    /// 用户驳回重跑时刻（RFC 3339）。被驳回任务保留原记录。
    pub rejected_at: Option<String>,
    /// 被驳回时的父任务 id（重跑新代指向被驳回任务；首代任务为 `None`）。
    pub parent_task_id: Option<String>,
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
    pub confirmed_at: Option<String>,
    pub rejected_at: Option<String>,
    pub parent_task_id: Option<String>,
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
            confirmed_at: rec.confirmed_at.clone(),
            rejected_at: rec.rejected_at.clone(),
            parent_task_id: rec.parent_task_id.clone(),
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
        confirmed_at: None,
        rejected_at: None,
        parent_task_id: None,
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

/// 确认完成（MT-003 用户侧动作）：仅 `done` 可确认，重复确认幂等。
/// 返回 `None` = 任务不存在或非 done；`Some(false)` = 已确认过（幂等）；
/// `Some(true)` = 本次新确认。
pub(crate) fn confirm(state: &mut MeshState, id: &str) -> Option<bool> {
    let rec = state.tasks.get_mut(id)?;
    if rec.task.state != TaskState::Done {
        return None;
    }
    if rec.confirmed_at.is_some() {
        return Some(false);
    }
    let now = service::now();
    rec.confirmed_at = Some(now.clone());
    rec.updated_at = now;
    Some(true)
}

/// 驳回重跑（MT-003 用户侧动作）：原任务（done|failed）置 `rejected_at`，
/// 并派发新一代任务——id 为 `{root}-r{n}`（root = 重试链的原始任务 id；
/// 换新 id 是因为 agent 账本按 task id 去重，沿用旧 id 永远不会重跑），
/// 负载/目标/重试上限原样继承。返回 `(新记录, 新 task_seq)`。
///
/// `Err(ServiceError::Conflict)` = 任务不存在于该网络或非终态（运行中
/// 不可驳回）。
pub(crate) fn retry(
    state: &mut MeshState,
    network_id: &str,
    id: &str,
) -> Result<(TaskRecord, u64), ServiceError> {
    let orig = state
        .tasks
        .get(id)
        .filter(|rec| rec.network_id.to_string() == network_id)
        .cloned()
        .ok_or_else(|| ServiceError::TaskNotFound(format!("task {id}")))?;
    if !matches!(orig.task.state, TaskState::Done | TaskState::Failed) {
        return Err(ServiceError::Conflict(format!(
            "task {id} is {} and cannot be retried",
            orig.task.state.as_str()
        )));
    }
    // 重入防护：该任务已驳回且仍有一个进行中的重跑子代（assigned/acked/
    // running）→ 409，防双击/双 POST 重复下发同一条命令。
    let has_live_child = state.tasks.values().any(|rec| {
        rec.parent_task_id.as_deref() == Some(id)
            && !matches!(rec.task.state, TaskState::Done | TaskState::Failed)
    });
    if has_live_child {
        return Err(ServiceError::Conflict(format!(
            "task {id} has a pending rerun and cannot be retried again"
        )));
    }

    let now = service::now();
    let rejected = {
        let rec = state.tasks.get_mut(id).expect("task exists");
        rec.rejected_at = Some(now.clone());
        rec.updated_at = now.clone();
        rec.clone()
    };

    // 重试链的根：被驳回任务若是重跑代，则沿 parent 回到根，代号续接。
    let root = rejected
        .parent_task_id
        .clone()
        .unwrap_or_else(|| id.to_string());
    let next = next_retry_seq(state, &root);
    let new_id = format!("{root}-r{next}");
    let task = Task::new(
        TaskId(new_id),
        orig.task.target_node.clone(),
        orig.task.payload.clone(),
        orig.task.retry_limit,
    );
    let seq = state.task_seq() + 1;
    state.set_task_seq(seq);
    let record = TaskRecord {
        task,
        network_id: NetworkId(network_id.to_string()),
        result: None,
        confirmed_at: None,
        rejected_at: None,
        parent_task_id: Some(id.to_string()),
        created_at: now.clone(),
        updated_at: now,
    };
    state.tasks.insert(record.task.id.0.clone(), record.clone());
    Ok((record, seq))
}

/// 重试链下一个代号：扫 `{root}-r{n}` 的最大 n + 1。
fn next_retry_seq(state: &MeshState, root: &str) -> u64 {
    let prefix = format!("{root}-r");
    state
        .tasks
        .keys()
        .filter_map(|k| k.strip_prefix(&prefix))
        .filter_map(|suffix| suffix.parse::<u64>().ok())
        .max()
        .unwrap_or(0)
        + 1
}

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
