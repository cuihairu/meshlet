//! 任务模型与状态机（MT-001，[todo.md](../../todo.md)「任务分配与确认通道」）。
//!
//! 纯逻辑层，无 IO：任务实体（`id` 为幂等键）、线性状态机
//! `assigned → acked → running → done | failed`，以及跃迁产生的审计操作名。
//! 派发通道（server → agent 下发、ack / 心跳 / exit code 回执、断线补派
//! 幂等）属于 MT-002 的执行层接线，不在这里。
//!
//! 设计要点：
//! - `id` 是**幂等键**：server 派发时生成，断线补派重发同一 id，agent 以
//!   id 去重不重复执行（对齐 F-2030 流量补报的幂等模式）；
//! - 状态机为严格线性：乱序 / 终态后的事件一律拒绝并报
//!   [TaskError::IllegalTransition]，而不是静默吞掉——乱序回执本身就是要
//!   暴露的异常；
//! - `retry_limit` 只是数据：是否重派由派发方按它决策（MT-005 超时回收 /
//!   重试上限），状态机本身不内建重试回路；
//! - 审计要求沿用仓库「审计用操作名」惯例（`operation() -> &'static str`），
//!   每次跃迁返回可落日志 / 审计事件的操作名。

use crate::entities::DeviceId;

/// 任务标识（服务端生成，幂等键；补派重发不换新值）。
#[derive(
    Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, serde::Serialize, serde::Deserialize,
)]
pub struct TaskId(pub String);

impl std::fmt::Display for TaskId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// 任务负载：要在目标节点上执行的一条命令。
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct TaskPayload {
    /// 要执行的命令。
    pub cmd: String,
    /// 工作目录；`None` 用 agent 默认目录。
    pub workdir: Option<String>,
    /// 超时（秒）；`None` 用 agent 默认超时。
    pub timeout_secs: Option<u64>,
}

/// 任务状态（线性状态机 `assigned → acked → running → done | failed`）。
///
/// serde 用小写变体名，与 [TaskState::as_str] 的下发契约一致。
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum TaskState {
    /// 已分配：server 已派发，尚未被 agent 确认。
    Assigned,
    /// agent 已确认接收（ack）。
    Acked,
    /// 正在目标节点上执行。
    Running,
    /// 执行成功（终态）。
    Done,
    /// 执行失败（终态）。
    Failed,
}

impl TaskState {
    /// 状态上报契约字段（`assigned` / `acked` / `running` / `done` /
    /// `failed`），供下发协议与控制台展示共用。
    pub fn as_str(self) -> &'static str {
        match self {
            TaskState::Assigned => "assigned",
            TaskState::Acked => "acked",
            TaskState::Running => "running",
            TaskState::Done => "done",
            TaskState::Failed => "failed",
        }
    }

    /// 状态机跃迁（纯函数）：只接受线性推进的合法跃迁，乱序 / 终态后的
    /// 事件一律 [TaskError::IllegalTransition]。
    pub fn transition(self, event: TaskEvent) -> Result<(TaskState, TaskAction), TaskError> {
        match (self, event) {
            (TaskState::Assigned, TaskEvent::Ack) => Ok((TaskState::Acked, TaskAction::Acked)),
            (TaskState::Acked, TaskEvent::Start) => Ok((TaskState::Running, TaskAction::Started)),
            (TaskState::Running, TaskEvent::Complete(TaskOutcome::Success)) => {
                Ok((TaskState::Done, TaskAction::Succeeded))
            }
            (TaskState::Running, TaskEvent::Complete(TaskOutcome::Failure)) => {
                Ok((TaskState::Failed, TaskAction::Failed))
            }
            (from, event) => Err(TaskError::IllegalTransition { from, event }),
        }
    }
}

/// 状态机输入事件（agent 侧上报的里程碑）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TaskEvent {
    /// agent 确认收到任务（ack）。
    Ack,
    /// agent 开始执行。
    Start,
    /// 执行结束，携带结果。
    Complete(TaskOutcome),
}

/// 一次执行的结果。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TaskOutcome {
    /// 成功（exit code 0）。
    Success,
    /// 失败（非 0 exit code / 超时 / 无法启动）。
    Failure,
}

/// 状态跃迁产生的动作：执行层据此记录审计事件 / 日志。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TaskAction {
    /// 任务已被 agent 确认接收。
    Acked,
    /// 任务开始执行。
    Started,
    /// 任务执行成功。
    Succeeded,
    /// 任务执行失败。
    Failed,
}

impl TaskAction {
    /// 审计用操作名（仓库审计惯例：短横线小写短语，错误消息不漂移）。
    pub fn operation(self) -> &'static str {
        match self {
            TaskAction::Acked => "task ack",
            TaskAction::Started => "task start",
            TaskAction::Succeeded => "task succeed",
            TaskAction::Failed => "task fail",
        }
    }
}

/// 状态机错误。
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum TaskError {
    /// 非法跃迁：乱序事件或终态后的事件。
    #[error("illegal task transition: {from:?} via {event:?}")]
    IllegalTransition {
        /// 收到事件时的状态。
        from: TaskState,
        /// 被拒绝的事件。
        event: TaskEvent,
    },
}

/// 一个任务（MT-001 实体）。
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Task {
    /// 幂等键；断线补派重发同一值。
    pub id: TaskId,
    /// 目标节点。
    pub target_node: DeviceId,
    /// 要执行的负载。
    pub payload: TaskPayload,
    /// 当前状态。
    pub state: TaskState,
    /// 重试上限（派发方重派决策的输入，状态机不内建重试）。
    pub retry_limit: u32,
    /// 结果引用（exit code + 日志尾部的存储 key 等）；完成前为 `None`。
    pub result_ref: Option<String>,
}

impl Task {
    /// 创建新任务（初始状态 [TaskState::Assigned]，无结果引用）。
    pub fn new(id: TaskId, target_node: DeviceId, payload: TaskPayload, retry_limit: u32) -> Self {
        Task {
            id,
            target_node,
            payload,
            state: TaskState::Assigned,
            retry_limit,
            result_ref: None,
        }
    }

    /// 应用一次状态机事件；成功则推进 `state` 并返回跃迁动作（审计用）。
    pub fn apply(&mut self, event: TaskEvent) -> Result<TaskAction, TaskError> {
        let (next, action) = self.state.transition(event)?;
        self.state = next;
        Ok(action)
    }

    /// 记录执行结果引用（完成时由执行层写入，如结果存储 key）。
    pub fn record_result(&mut self, result_ref: impl Into<String>) {
        self.result_ref = Some(result_ref.into());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn payload() -> TaskPayload {
        TaskPayload {
            cmd: "/usr/bin/true".into(),
            workdir: Some("/tmp".into()),
            timeout_secs: Some(30),
        }
    }

    fn task() -> Task {
        Task::new(
            TaskId("018f1e2a-9b4c-7d3e-a1b2-3c4d5e6f7a8b".into()),
            DeviceId("dev-1".into()),
            payload(),
            3,
        )
    }

    #[test]
    fn new_task_starts_assigned_with_no_result() {
        let task = task();
        assert_eq!(task.state, TaskState::Assigned);
        assert_eq!(task.result_ref, None);
        assert_eq!(task.retry_limit, 3);
        assert_eq!(task.state.as_str(), "assigned");
    }

    #[test]
    fn success_lifecycle_walks_the_full_chain() {
        let mut task = task();
        assert_eq!(task.apply(TaskEvent::Ack), Ok(TaskAction::Acked));
        assert_eq!(task.state, TaskState::Acked);
        assert_eq!(task.apply(TaskEvent::Start), Ok(TaskAction::Started));
        assert_eq!(task.state, TaskState::Running);
        assert_eq!(
            task.apply(TaskEvent::Complete(TaskOutcome::Success)),
            Ok(TaskAction::Succeeded)
        );
        assert_eq!(task.state, TaskState::Done);
        assert_eq!(task.state.as_str(), "done");
    }

    #[test]
    fn failure_lifecycle_ends_in_failed() {
        let mut task = task();
        task.apply(TaskEvent::Ack).unwrap();
        task.apply(TaskEvent::Start).unwrap();
        assert_eq!(
            task.apply(TaskEvent::Complete(TaskOutcome::Failure)),
            Ok(TaskAction::Failed)
        );
        assert_eq!(task.state, TaskState::Failed);
        assert_eq!(task.state.as_str(), "failed");
    }

    #[test]
    fn terminal_states_reject_every_event() {
        for terminal in [TaskState::Done, TaskState::Failed] {
            for event in [
                TaskEvent::Ack,
                TaskEvent::Start,
                TaskEvent::Complete(TaskOutcome::Success),
                TaskEvent::Complete(TaskOutcome::Failure),
            ] {
                assert_eq!(
                    terminal.transition(event),
                    Err(TaskError::IllegalTransition {
                        from: terminal,
                        event
                    }),
                    "terminal {terminal:?} must reject {event:?}"
                );
            }
        }
    }

    #[test]
    fn out_of_order_events_are_rejected() {
        // Assigned 只接受 Ack：Start / Complete 均为乱序。
        for event in [TaskEvent::Start, TaskEvent::Complete(TaskOutcome::Success)] {
            assert_eq!(
                TaskState::Assigned.transition(event),
                Err(TaskError::IllegalTransition {
                    from: TaskState::Assigned,
                    event
                })
            );
        }
        // Acked 只接受 Start：Ack（重复确认）/ Complete 均为乱序。
        for event in [TaskEvent::Ack, TaskEvent::Complete(TaskOutcome::Failure)] {
            assert_eq!(
                TaskState::Acked.transition(event),
                Err(TaskError::IllegalTransition {
                    from: TaskState::Acked,
                    event
                })
            );
        }
        // Running 不接受 Ack / Start（重复回执要暴露，不静默吞掉）。
        for event in [TaskEvent::Ack, TaskEvent::Start] {
            assert_eq!(
                TaskState::Running.transition(event),
                Err(TaskError::IllegalTransition {
                    from: TaskState::Running,
                    event
                })
            );
        }
    }

    #[test]
    fn apply_leaves_state_untouched_on_illegal_event() {
        let mut task = task();
        task.apply(TaskEvent::Ack).unwrap();
        // 乱序事件（Acked 时直接 Complete）被拒后状态不漂移。
        assert!(task
            .apply(TaskEvent::Complete(TaskOutcome::Success))
            .is_err());
        assert_eq!(task.state, TaskState::Acked);
    }

    #[test]
    fn audit_operation_names_are_stable() {
        assert_eq!(TaskAction::Acked.operation(), "task ack");
        assert_eq!(TaskAction::Started.operation(), "task start");
        assert_eq!(TaskAction::Succeeded.operation(), "task succeed");
        assert_eq!(TaskAction::Failed.operation(), "task fail");
    }

    #[test]
    fn record_result_fills_result_ref() {
        let mut task = task();
        task.apply(TaskEvent::Ack).unwrap();
        task.apply(TaskEvent::Start).unwrap();
        task.apply(TaskEvent::Complete(TaskOutcome::Success))
            .unwrap();
        task.record_result("results/018f1e2a.json");
        assert_eq!(task.result_ref.as_deref(), Some("results/018f1e2a.json"));
    }

    #[test]
    fn task_serializes_for_dispatch_round_trip() {
        let task = task();
        let json = serde_json::to_string(&task).unwrap();
        // 下发契约字段齐备：幂等键、目标节点、状态、重试上限。
        assert!(json.contains("\"assigned\""));
        assert!(json.contains("\"018f1e2a-9b4c-7d3e-a1b2-3c4d5e6f7a8b\""));
        let back: Task = serde_json::from_str(&json).unwrap();
        assert_eq!(back, task);
    }
}
