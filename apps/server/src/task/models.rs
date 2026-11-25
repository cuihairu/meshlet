//! Task server-side records, request contracts and view projections.

use serde::{Deserialize, Serialize};

use meshlet_domain::{NetworkId, Task};

/// The outcome of one task execution (exit code + tail of the log).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TaskResult {
    /// Process exit code (0 = success, non-zero = failure).
    pub exit_code: i32,
    /// Tail of the command output (the last captured lines of stdout+stderr).
    pub log_tail: String,
}

/// Server-side task record: the domain [Task] + network ownership + result + timestamps.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TaskRecord {
    /// The domain task (state machine + idempotency key + payload).
    pub task: Task,
    /// Owning network.
    pub network_id: NetworkId,
    /// Execution result (present once the task reaches a terminal state).
    pub result: Option<TaskResult>,
    /// When the user confirmed completion (RFC 3339). Confirmation is a user-side
    /// action; the agent endpoints have no way to confirm ("the agent must not decide
    /// done on its own").
    pub confirmed_at: Option<String>,
    /// When the user rejected it for a re-run (RFC 3339). Rejected tasks keep their
    /// original record.
    pub rejected_at: Option<String>,
    /// The id of the parent task at rejection time (a re-run generation points at the
    /// rejected task; first-generation tasks are `None`).
    pub parent_task_id: Option<String>,
    /// Creation time (RFC 3339).
    pub created_at: String,
    /// Last update time (RFC 3339).
    pub updated_at: String,
}

impl TaskRecord {
    /// Result reference: the result lives inside the task record, so result_ref is the
    /// task id (the console fetches the result by it).
    pub(crate) fn result_ref(&self) -> Option<String> {
        self.result.as_ref().map(|_| self.task.id.to_string())
    }
}

/// Console dispatch request (`POST /api/v1/networks/{network_id}/tasks`).
#[derive(Debug, Clone, Deserialize)]
pub struct AssignTaskRequest {
    /// Idempotency key; when omitted the server generates `task-{seq}`. Passing an
    /// existing id idempotently returns the existing task.
    pub id: Option<String>,
    /// Target device (MT-005 label routing): `None`/empty = auto-select a point by
    /// `required_labels` (no label requirement = any Active device); `Some` =
    /// explicitly chosen, and labels must match.
    #[serde(default)]
    pub target_device_id: Option<String>,
    /// The command to execute.
    pub cmd: String,
    /// Working directory.
    pub workdir: Option<String>,
    /// Timeout (seconds).
    pub timeout_secs: Option<u64>,
    /// Retry limit.
    pub retry_limit: Option<u32>,
    /// Label routing requirement (MT-005): the target node's labels must match each
    /// `(key, value)` pair before dispatch; default = no label constraint.
    #[serde(default)]
    pub required_labels: Option<std::collections::BTreeMap<String, String>>,
}

/// Console/result view (with state and execution result).
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

/// Agent result report (`POST /api/v1/agent/tasks/{id}/result`).
#[derive(Debug, Clone, Deserialize)]
pub struct TaskResultReport {
    /// Process exit code.
    pub exit_code: i32,
    /// Tail of the command output.
    pub log_tail: String,
}
