//! Task dispatch, state advancement, user confirmation and rejection rerun.

use meshlet_domain::{
    Device, DeviceId, NetworkId, Task, TaskAction, TaskEvent, TaskId, TaskOutcome, TaskPayload,
    TaskState,
};

use crate::service::{self, MeshState, ServiceError};

use super::models::{AssignTaskRequest, TaskRecord, TaskResult};

/// Dispatch a task (assign). An explicit id that already exists and belongs
/// to the requested network -> return the existing record idempotently
/// (`new_seq=None, created=false`); it belongs to another network -> 404;
/// otherwise create `task-{seq}` (or the explicit id, bumping the sequence
/// if the auto id collides with an existing task) and set
/// [TaskState::Assigned]. Returns `(record, new task_seq, whether newly
/// created)`.
pub(crate) fn assign(
    state: &mut MeshState,
    network_id: &str,
    req: &AssignTaskRequest,
) -> Result<(TaskRecord, Option<u64>, bool), ServiceError> {
    // Label routing requirement (MT-005): the default is unconstrained.
    let required = req.required_labels.clone().unwrap_or_default();

    // The idempotency key wins: the same id already exists (whatever its state)
    // and belongs to the requested network -> return it as is, without creating
    // a duplicate or resetting its state (re-sending the same dispatch request
    // must not reach a different verdict because labels / device state drifted);
    // it belongs to another network -> 404 (consistent with confirm/retry, and
    // does not leak other networks' tasks).
    let (id, new_seq) = match &req.id {
        Some(id) => {
            if let Some(existing) = state.tasks.get(id) {
                if existing.network_id.to_string() != network_id {
                    return Err(ServiceError::TaskNotFound(id.clone()));
                }
                return Ok((existing.clone(), None, false));
            }
            (TaskId(id.clone()), None)
        }
        None => {
            let mut seq = state.task_seq() + 1;
            while state.tasks.contains_key(&format!("task-{seq}")) {
                seq += 1;
            }
            state.set_task_seq(seq);
            (TaskId(format!("task-{seq}")), Some(seq))
        }
    };

    // Target device (MT-005 label routing): an explicitly specified one must
    // satisfy the label requirement; by default pick a device automatically by
    // label (no label requirement = any Active device).
    let target_id = match req.target_device_id.as_deref() {
        Some(id) if !id.is_empty() => {
            let device = crate::publish::device_in_network(state, network_id, id)?;
            if !device.matches_labels(&required) {
                return Err(ServiceError::Conflict(format!(
                    "device {id} does not match required labels {required:?}"
                )));
            }
            id.to_string()
        }
        _ => {
            let candidates: Vec<Device> = state
                .registry
                .devices()
                .iter()
                .filter(|d| d.network_id.to_string() == network_id)
                .cloned()
                .collect();
            let picked =
                meshlet_domain::select_by_labels(&candidates, &required).ok_or_else(|| {
                    ServiceError::Conflict(format!(
                    "no active device in network {network_id} matches required labels {required:?}"
                ))
                })?;
            picked.id.to_string()
        }
    };

    let payload = TaskPayload {
        cmd: req.cmd.clone(),
        workdir: req.workdir.clone(),
        timeout_secs: req.timeout_secs,
        required_labels: required.clone(),
    };
    let task = Task::new(
        id,
        DeviceId(target_id),
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

/// The target device's outstanding work (assigned / acked, sorted by id
/// deterministically).
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

/// ack: assigned -> acked; already past assigned is treated as an idempotent
/// success (re-sending an ack to backfill a missed dispatch does not error).
/// Returns whether a transition happened (`Some(action)`) or the task does
/// not exist (`None`).
pub(crate) fn ack(state: &mut MeshState, id: &str) -> Option<TaskAction> {
    let rec = state.tasks.get_mut(id)?;
    match rec.task.state {
        TaskState::Assigned => {
            let action = rec.task.apply(TaskEvent::Ack).ok()?;
            rec.updated_at = service::now();
            Some(action)
        }
        _ => None, // idempotent: already acked / running / terminal no longer transitions
    }
}

/// Record a result: advance along a legal state-machine path to done|failed
/// (filling in a missing ack/start); if already terminal, ignore idempotently
/// (never overwrite the terminal result/state -- a duplicate receipt is merely
/// discarded, so that when reaping races a live agent an old receipt cannot
/// rewrite a synthetic timeout result), returning `None`.
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
    // Fill in the missing prerequisite transitions along the legal path (when a
    // dropped connection lost ack/start, the result itself supplies them).
    if rec.task.state == TaskState::Assigned {
        let _ = rec.task.apply(TaskEvent::Ack);
    }
    if rec.task.state == TaskState::Acked {
        let _ = rec.task.apply(TaskEvent::Start);
    }
    let action = if matches!(rec.task.state, TaskState::Running) {
        rec.task.apply(TaskEvent::Complete(outcome)).ok()
    } else {
        // Already terminal (or out of order and unfillable): an idempotent duplicate
        // receipt, without overwriting the terminal result/state (when reaping
        // races a live agent, an old receipt must not rewrite a synthetic
        // timeout result).
        return None;
    };
    rec.result = Some(TaskResult {
        exit_code,
        log_tail: log_tail.to_string(),
    });
    rec.updated_at = service::now();
    action
}

/// Confirm completion (MT-003 user-side action): only `done` can be
/// confirmed; confirming again is idempotent.
/// Returns `None` = the task does not exist or is not done;
/// `Some(false)` = already confirmed (idempotent);
/// `Some(true)` = freshly confirmed this call.
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

/// Reject and rerun (MT-003 user-side action): stamp `rejected_at` on the
/// original task (done|failed) and dispatch a new generation -- its id is
/// `{root}-r{n}` (root = the original task id of the retry chain; a fresh id
/// is used because the agent ledger deduplicates by task id, so reusing the
/// old id would never rerun), inheriting payload / target / retry limit as
/// is. Returns `(new record, new task_seq)`.
///
/// `Err(ServiceError::Conflict)` = the task does not exist in that network, or
/// is not terminal (a running task cannot be rejected).
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
        .ok_or_else(|| ServiceError::TaskNotFound(id.to_string()))?;
    if !matches!(orig.task.state, TaskState::Done | TaskState::Failed) {
        return Err(ServiceError::Conflict(format!(
            "task {id} is {} and cannot be retried",
            orig.task.state.as_str()
        )));
    }
    // Re-entrancy guard: this task is already rejected and still has a rerun
    // child in flight (assigned/acked/running) -> 409, so a double click /
    // double POST cannot issue the same command twice.
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

    // Root of the retry chain: if the rejected task is itself a rerun
    // generation, walk the parent chain back to the root so the generation
    // number continues from there (walk it generation by generation -- a
    // second-or-later generation must not look only at its immediate parent:
    // the immediate parent of `task-1-r2` is `task-1-r1`, and root has to go
    // back to `task-1` in order to count its sibling `task-1-r1`).
    let mut root = id.to_string();
    let mut parent = rejected.parent_task_id.clone();
    while let Some(p) = parent {
        root = p.clone();
        parent = state
            .tasks
            .get(&p)
            .and_then(|rec| rec.parent_task_id.clone());
    }
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

/// The next generation number of the retry chain: the largest n in
/// `{root}-r{n}` plus one.
pub(crate) fn next_retry_seq(state: &MeshState, root: &str) -> u64 {
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

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use meshlet_domain::TaskState;

    use crate::service::{
        create_invite, create_network, enroll, CreateInviteRequest, CreateNetworkRequest,
        EnrollRequest, MeshState, ServiceError,
    };

    use super::super::models::AssignTaskRequest;
    use super::{assign, retry};

    /// Create a network plus two Active devices; returns
    /// (state, network_id, device_ids).
    fn mesh_with_devices() -> (MeshState, String, Vec<String>) {
        let mut st = MeshState::new(Default::default());
        let net = create_network(
            &mut st,
            CreateNetworkRequest {
                name: "10.240.0.0/16".into(),
                overlay_cidr: "10.240.0.0/16".into(),
            },
        )
        .unwrap();
        let invite = create_invite(
            &mut st,
            &net.id,
            CreateInviteRequest {
                expires_at: None,
                max_uses: Some(2),
            },
        )
        .unwrap();
        let mut ids = Vec::new();
        for i in 0..2 {
            let resp = enroll(
                &mut st,
                EnrollRequest {
                    invite_token: invite.token.clone(),
                    device_name: format!("dev-{i}"),
                    public_key: format!("key-{i}"),
                    platform: "linux".into(),
                },
            )
            .unwrap();
            ids.push(resp.device_id);
        }
        (st, net.id, ids)
    }

    fn labels(kv: &[(&str, &str)]) -> BTreeMap<String, String> {
        kv.iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect()
    }

    fn assign_req(target: Option<&str>, required: BTreeMap<String, String>) -> AssignTaskRequest {
        AssignTaskRequest {
            id: None,
            target_device_id: target.map(|s| s.to_string()),
            cmd: "echo hi".into(),
            workdir: None,
            timeout_secs: None,
            retry_limit: Some(0),
            required_labels: Some(required),
        }
    }

    #[test]
    fn assign_auto_id_skips_explicit_collision() {
        let (mut st, net, ids) = mesh_with_devices();
        // Occupy task-1 explicitly.
        let mut req = assign_req(Some(&ids[0]), BTreeMap::new());
        req.id = Some("task-1".into());
        let (rec, _, _) = assign(&mut st, &net, &req).unwrap();
        assert_eq!(rec.task.id.0, "task-1");

        // Automatic dispatch: does not overwrite task-1, takes task-2.
        let (rec, seq, _) =
            assign(&mut st, &net, &assign_req(Some(&ids[0]), BTreeMap::new())).unwrap();
        assert_eq!(rec.task.id.0, "task-2");
        assert_eq!(seq, Some(2));
        // The original task-1 is still there (not overwritten).
        assert_eq!(st.tasks.get("task-1").unwrap().task.payload.cmd, "echo hi");
        assert_eq!(st.tasks.get("task-2").unwrap().task.payload.cmd, "echo hi");
    }

    #[test]
    fn assign_without_target_selects_device_matching_labels() {
        let (mut st, net, ids) = mesh_with_devices();
        // Label dev-0 with role=builder; dev-1 gets none.
        crate::service::set_device_labels(&mut st, &net, &ids[0], labels(&[("role", "builder")]))
            .unwrap();
        let (rec, _seq, created) = assign(
            &mut st,
            &net,
            &assign_req(None, labels(&[("role", "builder")])),
        )
        .unwrap();
        assert!(created);
        // Only dev-0 can match (the sole role=builder).
        assert_eq!(rec.task.target_node.to_string(), ids[0]);
        assert_eq!(rec.task.payload.required_labels["role"], "builder");
    }

    #[test]
    fn assign_without_labels_picks_first_active_device_by_id() {
        let (mut st, net, ids) = mesh_with_devices();
        let (rec, _seq, _) = assign(&mut st, &net, &assign_req(None, BTreeMap::new())).unwrap();
        assert_eq!(rec.task.target_node.to_string(), ids[0]);
    }

    #[test]
    fn assign_with_target_not_matching_labels_is_rejected() {
        let (mut st, net, ids) = mesh_with_devices();
        crate::service::set_device_labels(&mut st, &net, &ids[0], labels(&[("role", "worker")]))
            .unwrap();
        let err = assign(
            &mut st,
            &net,
            &assign_req(Some(&ids[1]), labels(&[("role", "worker")])),
        )
        .unwrap_err();
        assert!(
            matches!(err, ServiceError::Conflict(_)),
            "expected Conflict, got {err:?}"
        );
    }

    #[test]
    fn assign_with_target_matching_labels_succeeds() {
        let (mut st, net, ids) = mesh_with_devices();
        crate::service::set_device_labels(&mut st, &net, &ids[0], labels(&[("role", "worker")]))
            .unwrap();
        let (rec, _seq, _) = assign(
            &mut st,
            &net,
            &assign_req(Some(&ids[0]), labels(&[("role", "worker")])),
        )
        .unwrap();
        assert_eq!(rec.task.target_node.to_string(), ids[0]);
    }

    #[test]
    fn assign_without_target_and_no_matching_device_is_rejected() {
        let (mut st, net, _ids) = mesh_with_devices();
        // Nobody carries role=builder.
        let err = assign(
            &mut st,
            &net,
            &assign_req(None, labels(&[("role", "builder")])),
        )
        .unwrap_err();
        assert!(
            matches!(err, ServiceError::Conflict(_)),
            "expected Conflict, got {err:?}"
        );
    }

    #[test]
    fn retry_rejects_non_terminal_task() {
        let (mut st, net, _ids) = mesh_with_devices();
        let (rec, _, _) = assign(&mut st, &net, &assign_req(None, BTreeMap::new())).unwrap();
        let err = retry(&mut st, &net, &rec.task.id.0).unwrap_err();
        assert!(matches!(err, ServiceError::Conflict(_)));
    }

    #[test]
    fn task_states_render_as_expected() {
        assert_eq!(TaskState::Assigned.as_str(), "assigned");
    }
}
