//! 任务服务端记录、请求契约与视图投影。

use serde::{Deserialize, Serialize};

use meshlet_domain::{NetworkId, Task};

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
    /// 目标设备（MT-005 标签路由）：`None`/空 = 按 `required_labels` 自动选点
    /// （无标签要求 = 任意 Active 设备）；`Some` = 显式指定，须命中标签。
    #[serde(default)]
    pub target_device_id: Option<String>,
    /// 要执行的命令。
    pub cmd: String,
    /// 工作目录。
    pub workdir: Option<String>,
    /// 超时（秒）。
    pub timeout_secs: Option<u64>,
    /// 重试上限。
    pub retry_limit: Option<u32>,
    /// 标签路由要求（MT-005）：`(key, value)` 逐对命中目标节点标签才可派发；
    /// 缺省 = 无标签约束。
    #[serde(default)]
    pub required_labels: Option<std::collections::BTreeMap<String, String>>,
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
