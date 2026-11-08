//! 任务派发、状态推进、用户确认与驳回重跑。

use meshlet_domain::{
    Device, DeviceId, NetworkId, Task, TaskAction, TaskEvent, TaskId, TaskOutcome, TaskPayload,
    TaskState,
};

use crate::service::{self, MeshState, ServiceError};

use super::models::{AssignTaskRequest, TaskRecord, TaskResult};

/// 派发任务（assign）。显式 id 已存在且归属请求网络 → 幂等返回已有记录
/// （`new_seq=None, created=false`）；归属其他网络 → 404；否则创建
/// `task-{seq}`（或显式 id，自动 id 与已有任务冲突则递增序列）并置
/// [TaskState::Assigned]。返回 `(记录, 新 task_seq, 是否新建)`。
pub(crate) fn assign(
    state: &mut MeshState,
    network_id: &str,
    req: &AssignTaskRequest,
) -> Result<(TaskRecord, Option<u64>, bool), ServiceError> {
    // 标签路由要求（MT-005）：缺省 = 无约束。
    let required = req.required_labels.clone().unwrap_or_default();

    // 幂等键优先：同 id 已存在（无论状态）且归属请求网络 → 原样返回，
    // 不重复建、不重置状态（重发同一派发请求不得因标签/设备状态漂移而
    // 改判）；归属其他网络 → 404（与 confirm/retry 一致，不泄漏他网任务）。
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

    // 目标设备（MT-005 标签路由）：显式指定须命中标签要求；缺省按标签
    // 自动选点（无标签要求 = 任意 Active 设备）。
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

/// 记录结果：沿合法状态机路径推进到 done|failed（缺 ack/start 补完）；
/// 已是终态则幂等忽略（不覆盖终态 result/state，重复回执只作废，防回收
/// 与活 agent 竞争时旧回执改写合成超时结果），返回 `None`。
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
        // 已是终态（或乱序不可补）：幂等重复回执，不覆盖终态
        // result/state（回收与活 agent 竞争时旧回执不得改写合成超时结果）。
        return None;
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
        .ok_or_else(|| ServiceError::TaskNotFound(id.to_string()))?;
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

    // 重试链的根：被驳回任务若是重跑代，则沿 parent 链回到根，代号续接
    // （逐代回溯，第二代+任务不能只看立即父——`task-1-r2` 的立即父是
    // `task-1-r1`，root 必须回溯到 `task-1` 才能数到兄弟 `task-1-r1`）。
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

/// 重试链下一个代号：扫 `{root}-r{n}` 的最大 n + 1。
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

    /// 建一个网络 + 两个 Active 设备，返回 (state, network_id, device_ids)。
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
        // 显式占掉 task-1。
        let mut req = assign_req(Some(&ids[0]), BTreeMap::new());
        req.id = Some("task-1".into());
        let (rec, _, _) = assign(&mut st, &net, &req).unwrap();
        assert_eq!(rec.task.id.0, "task-1");

        // 自动派发：不覆盖 task-1，取 task-2。
        let (rec, seq, _) =
            assign(&mut st, &net, &assign_req(Some(&ids[0]), BTreeMap::new())).unwrap();
        assert_eq!(rec.task.id.0, "task-2");
        assert_eq!(seq, Some(2));
        // 原 task-1 仍在（未被覆盖）。
        assert_eq!(st.tasks.get("task-1").unwrap().task.payload.cmd, "echo hi");
        assert_eq!(st.tasks.get("task-2").unwrap().task.payload.cmd, "echo hi");
    }

    #[test]
    fn assign_without_target_selects_device_matching_labels() {
        let (mut st, net, ids) = mesh_with_devices();
        // dev-0 打 role=builder；dev-1 不打。
        crate::service::set_device_labels(&mut st, &net, &ids[0], labels(&[("role", "builder")]))
            .unwrap();
        let (rec, _seq, created) = assign(
            &mut st,
            &net,
            &assign_req(None, labels(&[("role", "builder")])),
        )
        .unwrap();
        assert!(created);
        // 只可能命中 dev-0（唯一 role=builder）。
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
        // 无人打 role=builder。
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
