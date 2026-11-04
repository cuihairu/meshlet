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
        required_labels: Default::default(),
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

// -- MT-005 超时回收重派 + 重试上限 ------------------------------------------
//
// agent 侧 `run_task` 只保证「活着的 agent 会按时杀子进程并回执」；agent 死亡
// /断线时任务会永远停在 assigned|acked（running 只在单次请求内瞬时存在，
// 不持久）。回收语义：
// - 超时窗口 = `max(payload.timeout_secs 或 DEFAULT_RECOVERY_TIMEOUT_SECS,
//   MIN_RECOVERY_SECS)`；地板值防止把「agent 轮询周期慢但活着」误判成卡死
//   （超短 timeout 的任务派给刚巧在下个轮询间隙的 agent 时不该立刻回收）；
// - 回收 = 沿状态机合法路径推进到 failed（复用 record_result 的补完模式），
//   落合成结果（exit 124 = GNU timeout 惯例）；
// - 重派 = 复用 MT-003 代际机制 `{root}-r{n}`：换新 id（agent 账本按 id
//   去重，沿用旧 id 死过的 agent 重启后只补报不重跑）；预算用尽
//   （已产生的代数 ≥ retry_limit）只标记失败，不再派发。

/// 任务未显式指定超时时的回收窗口（与 agent `DEFAULT_TIMEOUT_SECS` 契约值
/// 对齐：agent 会在 300s 杀子进程，超过 300s 未回执 = agent 已死）。
const DEFAULT_RECOVERY_TIMEOUT_SECS: u64 = 300;
/// 回收窗口地板（秒）：即使任务 timeout_secs 很小，也不在短于一个 agent
/// 轮询周期前回收。
const MIN_RECOVERY_SECS: u64 = 60;
/// 回收任务的合成退出码（GNU `timeout(1)` 惯例：124 = 超时）。
const TIMEOUT_EXIT: i32 = 124;
/// 回收任务的合成日志尾部（控制台可见，解释失败来源）。
const TIMEOUT_LOG: &str = "reclaimed: task timed out awaiting agent";

/// 回收策略（窗口参数抽出来便于测试与配置化）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct TaskRecoveryPolicy {
    /// 任务未指定 `timeout_secs` 时的窗口。
    pub default_timeout_secs: u64,
    /// 窗口地板（防误回收）。
    pub min_recovery_secs: u64,
}

impl Default for TaskRecoveryPolicy {
    fn default() -> Self {
        Self {
            default_timeout_secs: DEFAULT_RECOVERY_TIMEOUT_SECS,
            min_recovery_secs: MIN_RECOVERY_SECS,
        }
    }
}

impl TaskRecoveryPolicy {
    /// 任务的有效回收窗口：显式超时与地板取大。
    fn window(&self, task: &Task) -> u64 {
        task.payload
            .timeout_secs
            .unwrap_or(self.default_timeout_secs)
            .max(self.min_recovery_secs)
    }
}

/// 一次回收的结果（审计与测试断言用）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct TaskRecovery {
    /// 被回收（标记超时失败）的任务 id。
    pub reclaimed: String,
    /// 重派的新代 id；`None` = retry 预算用尽，仅标记失败。
    pub redispatch: Option<String>,
}

/// 卡死判定（纯函数）：非终态任务进入当前状态已超过有效回收窗口。
/// 终态（done|failed）永不回收；running 不持久存在，这里自然不命中。
fn is_stuck(rec: &TaskRecord, age_secs: u64, policy: &TaskRecoveryPolicy) -> bool {
    matches!(rec.task.state, TaskState::Assigned | TaskState::Acked)
        && age_secs > policy.window(&rec.task)
}

/// `updated_at`（RFC3339）距今的秒数；解析失败返回 `None`（不回收——
/// 坏数据不该触发回收动作）。
fn age_secs(updated_at: &str, now_unix: i64) -> Option<u64> {
    let ts = chrono::DateTime::parse_from_rfc3339(updated_at)
        .ok()?
        .timestamp();
    Some((now_unix - ts).max(0) as u64)
}

/// 回收一轮卡死任务（MT-005 核心，纯状态变更，不碰 DB——落库由调用方做）。
/// 返回本次回收清单（含重派新代 id）。
pub(crate) fn recover_stuck_tasks(
    state: &mut MeshState,
    now_unix: i64,
    policy: &TaskRecoveryPolicy,
) -> Vec<TaskRecovery> {
    // 先收集再改：遍历中改 `state.tasks` 是借用错误。
    let stuck: Vec<String> = state
        .tasks
        .iter()
        .filter_map(|(id, rec)| {
            let age = age_secs(&rec.updated_at, now_unix)?;
            is_stuck(rec, age, policy).then(|| id.clone())
        })
        .collect();
    stuck.into_iter().map(|id| reclaim(state, &id)).collect()
}

/// 回收单个任务：沿状态机推进到 failed + 合成超时结果；预算内则派发
/// `{root}-r{n}` 新代（负载/目标/上限继承，parent 指向本任务）。
fn reclaim(state: &mut MeshState, id: &str) -> TaskRecovery {
    let mut rec = state.tasks.get(id).cloned().expect("reclaimed task exists");
    // 补完缺失的前置跃迁（与 record_result 同模式），推进到 failed。
    if rec.task.state == TaskState::Assigned {
        let _ = rec.task.apply(TaskEvent::Ack);
    }
    if rec.task.state == TaskState::Acked {
        let _ = rec.task.apply(TaskEvent::Start);
    }
    let _ = rec.task.apply(TaskEvent::Complete(TaskOutcome::Failure));
    let now = service::now();
    rec.result = Some(TaskResult {
        exit_code: TIMEOUT_EXIT,
        log_tail: TIMEOUT_LOG.to_string(),
    });
    rec.updated_at = now.clone();
    state.tasks.insert(id.to_string(), rec.clone());

    // 重派预算：重试链根（首代 = 自身 id，重跑代沿 parent 回到根）已产生的
    // 代数 ≥ retry_limit 时不再派发。
    let root = rec.parent_task_id.clone().unwrap_or_else(|| id.to_string());
    let next = next_retry_seq(state, &root);
    let used = next - 1;
    let redispatch = if used < rec.task.retry_limit as u64 {
        let new_id = format!("{root}-r{next}");
        let task = Task::new(
            TaskId(new_id.clone()),
            rec.task.target_node.clone(),
            rec.task.payload.clone(),
            rec.task.retry_limit,
        );
        let record = TaskRecord {
            task,
            network_id: rec.network_id.clone(),
            result: None,
            confirmed_at: None,
            rejected_at: None,
            parent_task_id: Some(id.to_string()),
            created_at: now.clone(),
            updated_at: now,
        };
        state.tasks.insert(new_id.clone(), record);
        Some(new_id)
    } else {
        None
    };
    TaskRecovery {
        reclaimed: id.to_string(),
        redispatch,
    }
}

/// MT-005：周期超时回收后台任务。独立于数据面收敛（任务回收不依赖
/// `dataplane.enabled`——纯测试环境也应收起卡死任务）。
pub fn start_task_recovery(state: SharedAppState, interval_secs: u64) {
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(std::time::Duration::from_secs(interval_secs));
        loop {
            ticker.tick().await;
            if let Err(error) = task_recovery_once(state.clone()).await {
                tracing::error!(%error, "task recovery sweep failed");
            }
        }
    });
}

/// 一次回收：持 persist 锁串行化全部任务写路径（assign/ack/result/confirm/
/// retry 都先取 persist 锁），锁内改状态并收受影响记录，锁外落库。
async fn task_recovery_once(state: SharedAppState) -> Result<(), String> {
    let _persist = state.persist.lock().await;
    let now = service::now_unix();
    let policy = TaskRecoveryPolicy::default();
    // 锁内回收并收集受影响记录（被回收任务 + 重派新代）。
    let to_persist: Vec<TaskRecord> = {
        let mut mesh = state.mesh.lock().unwrap();
        let events = recover_stuck_tasks(&mut mesh, now, &policy);
        let mut records = Vec::new();
        for ev in &events {
            let reclaimed = mesh
                .tasks
                .get(&ev.reclaimed)
                .cloned()
                .expect("reclaimed task exists");
            records.push(reclaimed);
            if let Some(new_id) = &ev.redispatch {
                records.push(mesh.tasks.get(new_id).cloned().expect("redispatch exists"));
            }
        }
        records
    };
    // 锁外落库（persist 仍持有：无并发写同一任务）。被回收任务落
    // `task.reclaimed` 审计，重派新代落 `task.retried`。
    for record in to_persist {
        let is_reclaim = record.result.is_some();
        let audit = crate::persist::AuditDraft {
            actor_id: None,
            action: if is_reclaim {
                "task.reclaimed"
            } else {
                "task.retried"
            },
            target_type: "task",
            target_id: &record.task.id.0,
            detail: Some(serde_json::json!({ "network_id": record.network_id.to_string() })),
        };
        crate::persist::commit_task(state.auth.pool(), &record, None, Some(&audit))
            .await
            .map_err(|e| format!("persist task recovery: {e}"))?;
    }
    Ok(())
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

#[cfg(test)]
mod tests {
    use super::*;
    use meshlet_domain::PresenceThresholds;

    /// `now_unix - age` 的 RFC3339 时间戳（回收窗口测试用）。
    fn ts(now_unix: i64, age: u64) -> String {
        chrono::DateTime::from_timestamp(now_unix - age as i64, 0)
            .unwrap()
            .to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
    }

    /// 直插一条任务记录（绕过 assign，直接测回收逻辑）。
    struct NewTask<'a> {
        id: &'a str,
        state: TaskState,
        timeout_secs: Option<u64>,
        retry_limit: u32,
        parent: Option<&'a str>,
        age: u64,
    }

    fn insert(state: &mut MeshState, spec: NewTask<'_>, now_unix: i64) {
        let task = Task::new(
            TaskId(spec.id.to_string()),
            DeviceId("dev-1".into()),
            TaskPayload {
                cmd: "echo hi".into(),
                workdir: None,
                timeout_secs: spec.timeout_secs,
                required_labels: Default::default(),
            },
            spec.retry_limit,
        );
        let mut task = task;
        // 直插到目标非终态：assigned 直接建；acked 则补一次 ack。
        if spec.state == TaskState::Acked {
            task.apply(TaskEvent::Ack).unwrap();
        }
        let updated_at = ts(now_unix, spec.age);
        state.tasks.insert(
            spec.id.to_string(),
            TaskRecord {
                task,
                network_id: NetworkId("net-1".into()),
                result: None,
                confirmed_at: None,
                rejected_at: None,
                parent_task_id: spec.parent.map(|p| p.to_string()),
                created_at: updated_at.clone(),
                updated_at,
            },
        );
    }

    fn state() -> MeshState {
        MeshState::new(PresenceThresholds::default())
    }

    fn policy() -> TaskRecoveryPolicy {
        TaskRecoveryPolicy::default()
    }

    #[test]
    fn stuck_assigned_task_is_reclaimed_and_redispatched() {
        let now = 1_800_000_000;
        let mut st = state();
        insert(
            &mut st,
            NewTask {
                id: "task-1",
                state: TaskState::Assigned,
                timeout_secs: Some(300),
                retry_limit: 1,
                parent: None,
                age: 400,
            },
            now,
        );
        let events = recover_stuck_tasks(&mut st, now, &policy());
        assert_eq!(
            events,
            vec![TaskRecovery {
                reclaimed: "task-1".into(),
                redispatch: Some("task-1-r1".into()),
            }]
        );
        // 原任务终态 failed + 合成超时结果。
        let rec = st.tasks.get("task-1").unwrap();
        assert_eq!(rec.task.state, TaskState::Failed);
        let r = rec.result.as_ref().unwrap();
        assert_eq!(r.exit_code, TIMEOUT_EXIT);
        assert!(r.log_tail.contains("timed out"));
        // 新代 Assigned，parent 指向原任务，负载/上限继承。
        let gen = st.tasks.get("task-1-r1").unwrap();
        assert_eq!(gen.task.state, TaskState::Assigned);
        assert_eq!(gen.parent_task_id.as_deref(), Some("task-1"));
        assert_eq!(gen.task.retry_limit, 1);
        assert_eq!(gen.task.payload.cmd, "echo hi");
    }

    #[test]
    fn stuck_acked_task_is_reclaimed_and_redispatched() {
        let now = 1_800_000_000;
        let mut st = state();
        insert(
            &mut st,
            NewTask {
                id: "task-1",
                state: TaskState::Acked,
                timeout_secs: Some(300),
                retry_limit: 1,
                parent: None,
                age: 400,
            },
            now,
        );
        let events = recover_stuck_tasks(&mut st, now, &policy());
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].redispatch.as_deref(), Some("task-1-r1"));
        assert_eq!(
            st.tasks.get("task-1").unwrap().task.state,
            TaskState::Failed
        );
    }

    #[test]
    fn retry_budget_exhausted_marks_failed_without_redispatch() {
        let now = 1_800_000_000;
        let mut st = state();
        // retry_limit = 1 且已产生 r1 代：回收 r1 时代数=1 ≥ 上限 → 不再派发。
        insert(
            &mut st,
            NewTask {
                id: "task-1",
                state: TaskState::Assigned,
                timeout_secs: Some(300),
                retry_limit: 1,
                parent: None,
                age: 1,
            },
            now,
        );
        insert(
            &mut st,
            NewTask {
                id: "task-1-r1",
                state: TaskState::Acked,
                timeout_secs: Some(300),
                retry_limit: 1,
                parent: Some("task-1"),
                age: 400,
            },
            now,
        );
        let events = recover_stuck_tasks(&mut st, now, &policy());
        assert_eq!(
            events,
            vec![TaskRecovery {
                reclaimed: "task-1-r1".into(),
                redispatch: None,
            }]
        );
        assert_eq!(
            st.tasks.get("task-1-r1").unwrap().task.state,
            TaskState::Failed
        );
        assert!(!st.tasks.contains_key("task-1-r2"));
        // 预算内的原代（age=1，未卡）不受影响。
        assert_eq!(
            st.tasks.get("task-1").unwrap().task.state,
            TaskState::Assigned
        );
    }

    #[test]
    fn zero_retry_limit_means_single_attempt() {
        let now = 1_800_000_000;
        let mut st = state();
        insert(
            &mut st,
            NewTask {
                id: "task-1",
                state: TaskState::Acked,
                timeout_secs: Some(300),
                retry_limit: 0,
                parent: None,
                age: 400,
            },
            now,
        );
        let events = recover_stuck_tasks(&mut st, now, &policy());
        assert_eq!(events[0].redispatch, None);
        assert_eq!(
            st.tasks.get("task-1").unwrap().task.state,
            TaskState::Failed
        );
    }

    #[test]
    fn healthy_task_is_not_reclaimed() {
        let now = 1_800_000_000;
        let mut st = state();
        insert(
            &mut st,
            NewTask {
                id: "task-1",
                state: TaskState::Assigned,
                timeout_secs: Some(300),
                retry_limit: 1,
                parent: None,
                age: 10,
            },
            now,
        );
        insert(
            &mut st,
            NewTask {
                id: "task-2",
                state: TaskState::Acked,
                timeout_secs: Some(300),
                retry_limit: 1,
                parent: None,
                age: 50,
            },
            now,
        );
        assert!(recover_stuck_tasks(&mut st, now, &policy()).is_empty());
        assert_eq!(
            st.tasks.get("task-1").unwrap().task.state,
            TaskState::Assigned
        );
        assert_eq!(st.tasks.get("task-2").unwrap().task.state, TaskState::Acked);
    }

    #[test]
    fn terminal_tasks_are_never_reclaimed() {
        let now = 1_800_000_000;
        let mut st = state();
        insert(
            &mut st,
            NewTask {
                id: "task-done",
                state: TaskState::Assigned,
                timeout_secs: Some(300),
                retry_limit: 1,
                parent: None,
                age: 400,
            },
            now,
        );
        insert(
            &mut st,
            NewTask {
                id: "task-fail",
                state: TaskState::Assigned,
                timeout_secs: Some(300),
                retry_limit: 1,
                parent: None,
                age: 400,
            },
            now,
        );
        {
            let rec = st.tasks.get_mut("task-done").unwrap();
            rec.task.apply(TaskEvent::Ack).unwrap();
            rec.task.apply(TaskEvent::Start).unwrap();
            rec.task
                .apply(TaskEvent::Complete(TaskOutcome::Success))
                .unwrap();
        }
        {
            let rec = st.tasks.get_mut("task-fail").unwrap();
            rec.task.apply(TaskEvent::Ack).unwrap();
            rec.task.apply(TaskEvent::Start).unwrap();
            rec.task
                .apply(TaskEvent::Complete(TaskOutcome::Failure))
                .unwrap();
        }
        assert!(recover_stuck_tasks(&mut st, now, &policy()).is_empty());
    }

    #[test]
    fn small_timeout_respects_recovery_floor() {
        let now = 1_800_000_000;
        let mut st = state();
        // timeout=1s：30s 龄 < 地板 60s → 不回收；70s 龄 > 60s → 回收。
        insert(
            &mut st,
            NewTask {
                id: "task-fast",
                state: TaskState::Acked,
                timeout_secs: Some(1),
                retry_limit: 1,
                parent: None,
                age: 30,
            },
            now,
        );
        assert!(recover_stuck_tasks(&mut st, now, &policy()).is_empty());
        let events = recover_stuck_tasks(&mut st, now + 40, &policy());
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].reclaimed, "task-fast");
    }

    #[test]
    fn unparsable_updated_at_never_reclaims() {
        let now = 1_800_000_000;
        let mut st = state();
        insert(
            &mut st,
            NewTask {
                id: "task-1",
                state: TaskState::Acked,
                timeout_secs: Some(300),
                retry_limit: 1,
                parent: None,
                age: 400,
            },
            now,
        );
        st.tasks.get_mut("task-1").unwrap().updated_at = "not-a-time".into();
        assert!(recover_stuck_tasks(&mut st, now, &policy()).is_empty());
    }

    #[test]
    fn recovery_respects_explicit_timeout_window() {
        let now = 1_800_000_000;
        let mut st = state();
        // timeout=600 → 窗口 600s：age 400 未卡，age 700 卡。
        insert(
            &mut st,
            NewTask {
                id: "task-1",
                state: TaskState::Acked,
                timeout_secs: Some(600),
                retry_limit: 1,
                parent: None,
                age: 400,
            },
            now,
        );
        assert!(recover_stuck_tasks(&mut st, now, &policy()).is_empty());
        let events = recover_stuck_tasks(&mut st, now + 300, &policy());
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].reclaimed, "task-1");
    }
}
