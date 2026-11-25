//! MT-005: timeout reclamation of stuck tasks and in-budget redispatch.

use meshlet_domain::{Task, TaskEvent, TaskId, TaskOutcome, TaskState};

use crate::auth::SharedAppState;
use crate::service::{self, MeshState};

use super::dispatch::next_retry_seq;
use super::models::{TaskRecord, TaskResult};

// -- MT-005 timeout reclamation redispatch + retry cap ----------------------
//
// The agent side's `run_task` only guarantees that "a live agent will kill the
// child process on time and report back"; when the agent dies / disconnects the
// task stays at assigned|acked forever (running exists only transiently within a
// single request and is not persisted). Reclamation semantics:
// - Timeout window = `max(payload.timeout_secs or DEFAULT_RECOVERY_TIMEOUT_SECS,
//   MIN_RECOVERY_SECS)`; the floor prevents mistaking "the agent's polling
//   period is slow but it is alive" for a stuck task (a task with a very short
//   timeout dispatched to an agent that happens to sit in the next polling gap
//   must not be reclaimed immediately);
// - Reclaim = advance along a legal state-machine path to failed (reusing
//   record_result's completion pattern), recording a synthetic result (exit 124
//   = the GNU timeout convention);
// - Redispatch = reuse the MT-003 generation mechanism `{root}-r{n}`: a new id
//   (the agent ledger deduplicates by id, so reusing the old id would let an
//   agent that died only back-report after restart instead of rerunning); once
//   the budget is exhausted (generations already produced >= retry_limit) only
//   the failure is marked and nothing is dispatched.

/// Reclamation window when the task does not specify a timeout explicitly (aligned
/// with the agent's `DEFAULT_TIMEOUT_SECS` contract value: the agent kills the
/// child process at 300s, so no receipt beyond 300s means the agent is dead).
const DEFAULT_RECOVERY_TIMEOUT_SECS: u64 = 300;
/// Reclamation window floor (seconds): even when the task's timeout_secs is very
/// small, never reclaim before one agent polling period.
const MIN_RECOVERY_SECS: u64 = 60;
/// Synthetic exit code for a reclaimed task (the GNU `timeout(1)` convention: 124 = timed out).
const TIMEOUT_EXIT: i32 = 124;
/// Synthetic log tail for a reclaimed task (visible in the console, explaining where the failure came from).
const TIMEOUT_LOG: &str = "reclaimed: task timed out awaiting agent";

/// Reclamation policy (the window parameters are extracted to ease testing and configuration).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct TaskRecoveryPolicy {
    /// The window used when the task does not specify `timeout_secs`.
    pub default_timeout_secs: u64,
    /// Window floor (guards against wrongful reclamation).
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
    /// The task's effective reclamation window: the larger of the explicit timeout and the floor.
    fn window(&self, task: &Task) -> u64 {
        task.payload
            .timeout_secs
            .unwrap_or(self.default_timeout_secs)
            .max(self.min_recovery_secs)
    }
}

/// The outcome of one reclamation (used by audits and test assertions).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct TaskRecovery {
    /// The id of the task that was reclaimed (marked as failed by timeout).
    pub reclaimed: String,
    /// The new generation id from the redispatch; `None` = retry budget exhausted, only the failure is marked.
    pub redispatch: Option<String>,
}

/// Stuck determination (pure function): a non-terminal task has been in its
/// current state longer than the effective reclamation window. Terminal states
/// (done|failed) are never reclaimed; running is not persisted, so it
/// naturally does not match here.
fn is_stuck(rec: &TaskRecord, age_secs: u64, policy: &TaskRecoveryPolicy) -> bool {
    matches!(rec.task.state, TaskState::Assigned | TaskState::Acked)
        && age_secs > policy.window(&rec.task)
}

/// Seconds since `updated_at` (RFC3339); returns `None` when parsing fails
/// (no reclamation — corrupt data must not trigger a reclaim action).
fn age_secs(updated_at: &str, now_unix: i64) -> Option<u64> {
    let ts = chrono::DateTime::parse_from_rfc3339(updated_at)
        .ok()?
        .timestamp();
    Some((now_unix - ts).max(0) as u64)
}

/// Reclaim one round of stuck tasks (the MT-005 core; a pure state change that
/// never touches the DB — persistence is the caller's job). Returns this
/// round's reclamation list (including the redispatched new generation id).
pub(crate) fn recover_stuck_tasks(
    state: &mut MeshState,
    now_unix: i64,
    policy: &TaskRecoveryPolicy,
) -> Vec<TaskRecovery> {
    // Collect first, then modify: mutating `state.tasks` while iterating would be a borrow error.
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

/// Reclaim a single task: advance it to failed along the state machine + a
/// synthetic timeout result; within the budget, dispatch a `{root}-r{n}` new
/// generation (payload/target/limit inherited, with parent pointing at this task).
fn reclaim(state: &mut MeshState, id: &str) -> TaskRecovery {
    let mut rec = state.tasks.get(id).cloned().expect("reclaimed task exists");
    // Fill in the missing prerequisite transitions (same pattern as record_result), then advance to failed.
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

    // Redispatch budget: for the root of the retry chain (first generation = its
    // own id; reruns walk back up the parent chain to the root — generation by
    // generation, so second generation and beyond cannot look only at the
    // immediate parent), once the generations already produced >= retry_limit,
    // stop dispatching.
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

/// MT-005: the periodic timeout-reclaim background task. Independent of dataplane
/// convergence (task reclamation does not depend on `dataplane.enabled` — even
/// a pure test environment should reap stuck tasks).
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

/// For integration tests: run one round of reclamation identical to
/// [`start_task_recovery`] (the normal path is a periodic background task, not
/// triggerable from a route; `#[doc(hidden)]` keeps it out of the public API
/// docs). Persistence reuses [`task_recovery_once`], keeping it consistent with
/// the production path.
#[doc(hidden)]
pub async fn task_recovery_for_test(state: SharedAppState) {
    task_recovery_once(state)
        .await
        .expect("test recovery sweep");
}

/// For integration tests: age a task's `updated_at` back by `age_secs` seconds
/// so the reclamation-window judgment hits (the production path is the periodic
/// scan by [`start_task_recovery`], not triggerable from a route;
/// `#[doc(hidden)]` keeps it out of the public API docs).
#[doc(hidden)]
pub fn age_task_for_test(state: &mut MeshState, id: &str, age_secs: u64) {
    if let Some(rec) = state.tasks.get_mut(id) {
        let now = service::now_unix();
        rec.updated_at = chrono::DateTime::from_timestamp(now - age_secs as i64, 0)
            .unwrap()
            .to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
    }
}

/// For integration tests: read a task record (for state/result/parent-chain assertions).
#[doc(hidden)]
pub fn task_for_test(state: &MeshState, id: &str) -> Option<TaskRecord> {
    state.tasks.get(id).cloned()
}

/// For integration tests: advance a task along the legal state machine to a
/// terminal state (simulating agent completion; the production path is the
/// agent's report, so a terminal state cannot be inserted directly from a
/// route). `#[doc(hidden)]` keeps it out of the public docs.
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

/// One reclamation round: hold the persist lock to serialize every task write
/// path (assign/ack/result/confirm/retry all take the persist lock first);
/// mutate state and collect the affected records inside the lock, and persist
/// outside it.
async fn task_recovery_once(state: SharedAppState) -> Result<(), String> {
    let _persist = state.persist.lock().await;
    let now = service::now_unix();
    let policy = TaskRecoveryPolicy::default();
    // Reclaim inside the lock and collect the affected records (the reclaimed task + the redispatched new generation).
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
    // Persist outside the mesh lock (persist is still held: no concurrent writes
    // to the same task). The reclaimed task is recorded as a `task.reclaimed`
    // audit event, the redispatched new generation as `task.retried`.
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

    /// RFC3339 timestamp for `now_unix - age` (used by the reclamation-window tests).
    fn ts(now_unix: i64, age: u64) -> String {
        chrono::DateTime::from_timestamp(now_unix - age as i64, 0)
            .unwrap()
            .to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
    }

    /// Insert a task record directly (bypasses assign to exercise the reclaim logic directly).
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
        // Insert directly at the target non-terminal state: assigned is built as-is; acked gets one extra ack applied.
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
        // The original task ends terminal as failed + the synthetic timeout result.
        let rec = st.tasks.get("task-1").unwrap();
        assert_eq!(rec.task.state, TaskState::Failed);
        let r = rec.result.as_ref().unwrap();
        assert_eq!(r.exit_code, TIMEOUT_EXIT);
        assert!(r.log_tail.contains("timed out"));
        // The new generation is Assigned, its parent points at the original task, payload/limit inherited.
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
        // retry_limit = 1 and an r1 generation already exists: when r1 is reclaimed the generation count = 1 >= the cap → nothing is dispatched.
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
        // The in-budget original generation (age=1, not stuck) is untouched.
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

    /// Review finding: reclaiming a deep chain (second generation r2) must walk
    /// back to the root along the parent chain — r2's immediate parent is r1, and
    /// looking only one level deep would mistake r1 for the root, never count the
    /// sibling r1, and leave the budget at 0 → endless redispatch. Reclaiming r2
    /// (both generations r1 and r2 already exist, limit=2) must not dispatch r3.
    #[test]
    fn deep_chain_reclaim_walks_to_root_and_respects_budget() {
        let now = 1_800_000_000;
        let mut st = state();
        // Root (not stuck), r1 (not stuck), r2 (stuck): limit=2.
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

    /// Review finding: rerunning a rejected second generation r2 (MT-003 retry)
    /// must likewise walk back to the root along the parent chain — after r2 is
    /// rejected, the new generation should be `task-1-r3` (not hang under r1 and
    /// double count r1).
    #[test]
    fn retry_deep_chain_walks_to_root() {
        let now = 1_800_000_000;
        let mut st = state();
        // Root, r1 and r2 are all terminal (retriable); the parent chain is task-1-r2 → r1 → root.
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
        // timeout=1s: a 30s age < the 60s floor → not reclaimed; a 70s age > 60s → reclaimed.
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
        // timeout=600 → window 600s: age 400 is not stuck, age 700 is stuck.
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
