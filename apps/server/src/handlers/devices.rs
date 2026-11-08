//! 设备端点：列设备、吊销（锁外失效凭证 + 留痕）与 MT-005 标签更新
//! （不记修订，审计随标签同一事务）。

use crate::auth::{AuthenticatedUser, CsrfHeader, SharedAppState, WriteUser};
use crate::service;
use crate::service::{list_devices, revoke_device};
use axum::extract::State;
use axum::http::StatusCode;
use axum::Json;

pub(crate) async fn list_devices_handler(
    State(state): State<SharedAppState>,
    AuthenticatedUser(_user): AuthenticatedUser,
    axum::extract::Path(network_id): axum::extract::Path<String>,
) -> Result<Json<Vec<service::DeviceView>>, service::ServiceError> {
    let guard = state.mesh.lock().unwrap();
    Ok(Json(list_devices(&guard, &network_id)?))
}

pub(crate) async fn revoke_device_handler(
    State(state): State<SharedAppState>,
    WriteUser(user_id): WriteUser,
    CsrfHeader: CsrfHeader,
    axum::extract::Path((network_id, device_id)): axum::extract::Path<(String, String)>,
) -> Result<(StatusCode, Json<service::RevisionRef>), service::ServiceError> {
    // 先完成撤销 + 修订簿记 + 落库（同一互斥段），再在锁外失效 agent 凭证并留痕。
    let _persist = state.persist.lock().await;
    let (rev, device, revision, staged) = {
        let guard = state.mesh.lock().unwrap();
        let mut staged = guard.clone();
        let rev = revoke_device(&mut staged, &network_id, &device_id)?;
        let device = staged
            .registry
            .find_by_id(&meshlet_domain::DeviceId(device_id.clone()))
            .expect("just revoked")
            .clone();
        let revision = staged
            .ledger
            .get(
                &meshlet_domain::NetworkId(network_id.clone()),
                rev.revision_id,
            )
            .expect("just recorded")
            .clone();
        (rev, device, revision, staged)
    };
    let audit = crate::persist::AuditDraft {
        actor_id: Some(&user_id.0),
        action: "device.revoked",
        target_type: "device",
        target_id: &device_id,
        detail: Some(serde_json::json!({ "network_id": network_id })),
    };
    crate::persist::commit_revoke_device(state.auth.pool(), &device, &revision, &audit)
        .await
        .map_err(crate::persist::internal)?;
    *state.mesh.lock().unwrap() = staged;
    crate::op_log!(
        info,
        "device",
        "revoke_device",
        &network_id,
        &device_id,
        &rev.revision_id.to_string(),
        crate::telemetry::ErrorCategory::None.as_str(),
        crate::telemetry::RESULT_OK
    );
    Ok((StatusCode::ACCEPTED, Json(rev)))
}

/// MT-005 设备标签更新（`POST /api/v1/networks/{network_id}/devices/{device_id}/labels`）。
/// 标签是路由元数据：不记修订、不触发期望配置应用；内存变更 + 落库同一
/// 互斥段，审计随标签同一事务（「不留痕不放行」）。
pub(crate) async fn set_device_labels_handler(
    State(state): State<SharedAppState>,
    WriteUser(user_id): WriteUser,
    CsrfHeader: CsrfHeader,
    axum::extract::Path((network_id, device_id)): axum::extract::Path<(String, String)>,
    Json(req): Json<service::SetDeviceLabelsRequest>,
) -> Result<Json<service::DeviceView>, service::ServiceError> {
    let _persist = state.persist.lock().await;
    // 先克隆 → 变更克隆（mesh 锁在 await 前释放，future 须 Send）→ 落库
    // 成功才换入 live state（「不落库不放行」，与 revoke/approve 同一纪律）。
    let (device, staged) = {
        let guard = state.mesh.lock().unwrap();
        let mut staged = guard.clone();
        let device = service::set_device_labels(&mut staged, &network_id, &device_id, req.labels)?;
        (device, staged)
    };
    let audit = crate::persist::AuditDraft {
        actor_id: Some(&user_id.0),
        action: "device.labels_set",
        target_type: "device",
        target_id: &device_id,
        detail: Some(serde_json::json!({ "network_id": network_id, "labels": device.labels })),
    };
    crate::persist::commit_device_labels(state.auth.pool(), &device, &audit)
        .await
        .map_err(crate::persist::internal)?;
    *state.mesh.lock().unwrap() = staged;
    let view = service::device_view(&state.mesh.lock().unwrap(), &network_id, &device_id)?;
    crate::op_log!(
        info,
        "device",
        "set_device_labels",
        &network_id,
        &device_id,
        crate::telemetry::NOT_APPLICABLE,
        crate::telemetry::ErrorCategory::None.as_str(),
        crate::telemetry::RESULT_OK
    );
    Ok(Json(view))
}
