//! MT-005：卡死任务的超时回收与预算内重派。

use meshlet_domain::{Task, TaskEvent, TaskId, TaskOutcome, TaskState};

use crate::auth::SharedAppState;
use crate::service::{self, MeshState};

use super::dispatch::next_retry_seq;
use super::models::{TaskRecord, TaskResult};

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

    // 重派预算：重试链根（首代 = 自身 id，重跑代沿 parent 链回到根——逐代
    // 回溯，第二代+不能只看立即父）已产生的代数 ≥ retry_limit 时不再派发。
    let mut root = id.to_string();
    let mut parent = rec.parent_task_id.clone();
    while let Some(p) = parent {
        root = p.clone();
        parent = state
            .tasks
            .get(&p)
            .and_then(|p_rec| p_rec.parent_task_id.clone());
    }
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

/// 集成测试用：跑一轮与 [`start_task_recovery`] 相同的回收（正常路
/// 径是周期后台任务，无法从路由触发；`#[doc(hidden)]` 不进公共 API
/// 文档）。落库复用 [`task_recovery_once`]，保证与生产路径一致。
#[doc(hidden)]
pub async fn task_recovery_for_test(state: SharedAppState) {
    task_recovery_once(state)
        .await
        .expect("test recovery sweep");
}

/// 集成测试用：把任务 `updated_at` 拨老 `age_secs` 秒，使回收窗口判定
/// 命中（生产路径由 [`start_task_recovery`] 周期扫描，无法从路由触发；
/// `#[doc(hidden)]` 不进公共 API 文档）。
#[doc(hidden)]
pub fn age_task_for_test(state: &mut MeshState, id: &str, age_secs: u64) {
    if let Some(rec) = state.tasks.get_mut(id) {
        let now = service::now_unix();
        rec.updated_at = chrono::DateTime::from_timestamp(now - age_secs as i64, 0)
            .unwrap()
            .to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
    }
}

/// 集成测试用：读取任务记录（状态/结果/父链断言）。
#[doc(hidden)]
pub fn task_for_test(state: &MeshState, id: &str) -> Option<TaskRecord> {
    state.tasks.get(id).cloned()
}

/// 集成测试用：把任务沿合法状态机推进到终态（模拟 agent 完成；生产路径
/// 是 agent 回执，无法从路由直插终态）。`#[doc(hidden)]` 不进公共文档。
#[doc(hidden)]
pub fn complete_task_for_test(state: &mut MeshState, id: &str, success: bool) {
    if let Some(rec) = state.tasks.get_mut(id) {
        let _ = rec.task.apply(TaskEvent::Ack);
        let _ = rec.task.apply(TaskEvent::Start);
        let _ = rec.task.apply(TaskEvent::Complete(if success {
            TaskOutcome::Success
        } else {
            TaskOutcome::Failure
        }));
    }
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

#[cfg(test)]
mod tests {
    use meshlet_domain::{
        DeviceId, NetworkId, PresenceThresholds, Task, TaskEvent, TaskId, TaskOutcome, TaskPayload,
        TaskState,
    };

    use crate::service::MeshState;

    use super::super::models::TaskRecord;
    use super::{recover_stuck_tasks, TaskRecovery, TaskRecoveryPolicy, TIMEOUT_EXIT};

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

    /// 审核发现：深链（第二代 r2）回收必须沿 parent 链回到根——r2 的
    /// 立即父是 r1，只看一层会把 root 误判为 r1，数不到兄弟 r1，预算恒 0
    /// → 无限重派。回收 r2（r1、r2 两代已存在，limit=2）不应再派 r3。
    #[test]
    fn deep_chain_reclaim_walks_to_root_and_respects_budget() {
        let now = 1_800_000_000;
        let mut st = state();
        // 根（未卡）、r1（未卡）、r2（卡）：limit=2。
        insert(
            &mut st,
            NewTask {
                id: "task-1",
                state: TaskState::Assigned,
                timeout_secs: Some(300),
                retry_limit: 2,
                parent: None,
                age: 1,
            },
            now,
        );
        insert(
            &mut st,
            NewTask {
                id: "task-1-r1",
                state: TaskState::Assigned,
                timeout_secs: Some(300),
                retry_limit: 2,
                parent: Some("task-1"),
                age: 1,
            },
            now,
        );
        insert(
            &mut st,
            NewTask {
                id: "task-1-r2",
                state: TaskState::Acked,
                timeout_secs: Some(300),
                retry_limit: 2,
                parent: Some("task-1-r1"),
                age: 400,
            },
            now,
        );
        let events = recover_stuck_tasks(&mut st, now, &policy());
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].reclaimed, "task-1-r2");
        assert_eq!(events[0].redispatch, None, "budget exhausted at r2");
        assert_eq!(
            st.tasks.get("task-1-r2").unwrap().task.state,
            TaskState::Failed
        );
        assert!(!st.tasks.contains_key("task-1-r3"));
    }

    /// 审核发现：第二代 r2 驳回重跑（MT-003 retry）同样须沿 parent 链回到
    /// 根——r2 被驳回后新代应接 `task-1-r3`（不是挂在 r1 下重复 r1 计数）。
    #[test]
    fn retry_deep_chain_walks_to_root() {
        let now = 1_800_000_000;
        let mut st = state();
        // 根、r1、r2 全终态（可驳回），parent 链 task-1-r2 → r1 → root。
        for (id, parent) in [
            ("task-1", None),
            ("task-1-r1", Some("task-1")),
            ("task-1-r2", Some("task-1-r1")),
        ] {
            insert(
                &mut st,
                NewTask {
                    id,
                    state: TaskState::Assigned,
                    timeout_secs: Some(300),
                    retry_limit: 3,
                    parent,
                    age: 1,
                },
                now,
            );
            let rec = st.tasks.get_mut(id).unwrap();
            let _ = rec.task.apply(TaskEvent::Ack);
            let _ = rec.task.apply(TaskEvent::Start);
            let _ = rec.task.apply(TaskEvent::Complete(TaskOutcome::Success));
        }
        let (rec, _seq) = super::super::dispatch::retry(&mut st, "net-1", "task-1-r2").unwrap();
        assert_eq!(rec.task.id.0, "task-1-r3");
        assert_eq!(rec.parent_task_id.as_deref(), Some("task-1-r2"));
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
