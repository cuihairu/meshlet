//! 设备自举注册（公开端点，凭自举码而来）：注册落 Pending → 控制中心
//! 审批/拒绝；agent 凭证仅此一次返回（§11.3）。

use crate::auth::{AuthenticatedUser, CsrfHeader, SharedAppState, WriteUser};
use crate::service;
use crate::service::{
    approve_registration, deny_registration, list_registrations, register_device,
};
use axum::extract::State;
use axum::http::StatusCode;
use axum::Json;

/// 设备自举注册（公开端点，设备凭自举码而来，无用户会话）。落 Pending
/// 申请并签发 agent 凭证——凭证**仅此一次**返回（§11.3）。
pub(crate) async fn register_device_handler(
    State(state): State<SharedAppState>,
    Json(req): Json<service::RegisterDeviceRequest>,
) -> Result<(StatusCode, Json<service::RegisterDeviceResponse>), service::ServiceError> {
    let _persist = state.persist.lock().await;
    // 摘要先行：req 被 service 消费后仍需定位刚被递增的自举码以落库。
    let token_hash = meshlet_domain::token_hash(&req.bootstrap_token);
    let (mut resp, registration, seq, token, bootstrap_seq) = {
        let mut guard = state.mesh.lock().unwrap();
        let resp = register_device(&mut guard, req)?;
        let registration = guard
            .registry
            .find_registration(&meshlet_domain::DeviceId(resp.device_id.clone()))
            .expect("just registered")
            .clone();
        // 使用次数随注册递增，同步落库——否则重启后计数回退，max_uses
        // 限制可被重启绕过。
        let token = guard
            .bootstrap_tokens
            .get(&token_hash)
            .expect("token validated by service")
            .clone();
        (
            resp,
            registration,
            guard.registration_seq(),
            token,
            guard.bootstrap_seq(),
        )
    };
    crate::persist::insert_registration(state.auth.pool(), &registration, seq)
        .await
        .map_err(crate::persist::internal)?;
    crate::persist::save_bootstrap_token(state.auth.pool(), &token, bootstrap_seq)
        .await
        .map_err(crate::persist::internal)?;
    let device_id = meshlet_domain::DeviceId(resp.device_id.clone());
    let (raw, _hash) = state
        .agent_tokens
        .issue(&device_id, service::now())
        .await
        .map_err(|e| service::ServiceError::Internal(e.to_string()))?;
    resp.agent_token = raw;
    // 注册者凭自举码而来，无用户 actor；agent 凭证原始材料不进审计（§16.5）。
    crate::audit::record_or_fail(
        &state,
        None,
        "device.registered",
        "device",
        Some(&resp.device_id),
        Some(serde_json::json!({
            "network_id": resp.network_id,
            "name": registration.name,
        })),
    )
    .await?;
    crate::op_log!(
        info,
        "device",
        "register",
        &resp.network_id,
        &resp.device_id,
        crate::telemetry::NOT_APPLICABLE,
        crate::telemetry::ErrorCategory::None.as_str(),
        crate::telemetry::RESULT_OK
    );
    Ok((StatusCode::CREATED, Json(resp)))
}

pub(crate) async fn list_registrations_handler(
    State(state): State<SharedAppState>,
    AuthenticatedUser(_user): AuthenticatedUser,
    axum::extract::Path(network_id): axum::extract::Path<String>,
) -> Result<Json<Vec<service::RegistrationView>>, service::ServiceError> {
    let guard = state.mesh.lock().unwrap();
    Ok(Json(list_registrations(&guard, &network_id)?))
}

/// 批准注册：Pending 申请转正为设备（此刻才分配 overlay 地址），新修订
/// 随期望配置下发；Pending 凭证作废并换发新凭证（仅此一次返回）。
pub(crate) async fn approve_registration_handler(
    State(state): State<SharedAppState>,
    WriteUser(user_id): WriteUser,
    CsrfHeader: CsrfHeader,
    axum::extract::Path((network_id, device_id)): axum::extract::Path<(String, String)>,
) -> Result<(StatusCode, Json<service::ApproveRegistrationResponse>), service::ServiceError> {
    let _persist = state.persist.lock().await;
    let (registration, device, revision, revision_id, approved_at, audit_detail, staged) = {
        let guard = state.mesh.lock().unwrap();
        let mut staged = guard.clone();
        let (registration, device, revision_id) =
            approve_registration(&mut staged, &network_id, &device_id)?;
        let revision = staged
            .ledger
            .get(&meshlet_domain::NetworkId(network_id.clone()), revision_id)
            .expect("just recorded")
            .clone();
        let approved_at = device.approved_at.clone().expect("just approved");
        let audit_detail = serde_json::json!({
            "network_id": network_id,
            "virtual_ipv4": device.virtual_ipv4.to_string(),
            "revision_id": revision_id,
        });
        (
            registration,
            device,
            revision,
            revision_id,
            approved_at,
            audit_detail,
            staged,
        )
    };
    let audit = crate::persist::AuditDraft {
        actor_id: Some(&user_id.0),
        action: "device.approved",
        target_type: "device",
        target_id: &device.id.to_string(),
        detail: Some(audit_detail.clone()),
    };
    crate::persist::commit_approve_registration(
        state.auth.pool(),
        &registration,
        &device,
        &revision,
        &audit,
    )
    .await
    .map_err(crate::persist::internal)?;
    *state.mesh.lock().unwrap() = staged;
    let resp = service::ApproveRegistrationResponse {
        device_id: device.id.to_string(),
        network_id: device.network_id.to_string(),
        virtual_ipv4: device.virtual_ipv4,
        fingerprint: crate::service::fingerprint_of(&device.public_key),
        revision_id,
        apply_status: meshlet_domain::ApplyStatus::Pending.as_str().to_string(),
        approved_at,
    };
    crate::op_log!(
        info,
        "device",
        "approve_registration",
        &network_id,
        &resp.device_id,
        &revision_id.to_string(),
        crate::telemetry::ErrorCategory::None.as_str(),
        crate::telemetry::RESULT_OK
    );
    Ok((StatusCode::CREATED, Json(resp)))
}

/// 拒绝注册：申请摘除、Pending 凭证作废。不记修订（期望配置从未包含过
/// Pending 申请）。
pub(crate) async fn deny_registration_handler(
    State(state): State<SharedAppState>,
    WriteUser(user_id): WriteUser,
    CsrfHeader: CsrfHeader,
    axum::extract::Path((network_id, device_id)): axum::extract::Path<(String, String)>,
) -> Result<StatusCode, service::ServiceError> {
    let _persist = state.persist.lock().await;
    let registration = {
        let mut guard = state.mesh.lock().unwrap();
        deny_registration(&mut guard, &network_id, &device_id)?
    };
    // 申请行 + Pending 凭证同一事务清理（persist::delete_registration_db）。
    crate::persist::delete_registration_db(state.auth.pool(), &registration.id)
        .await
        .map_err(crate::persist::internal)?;
    crate::audit::record_or_fail(
        &state,
        Some(&user_id.0),
        "device.denied",
        "device",
        Some(&registration.id.to_string()),
        Some(serde_json::json!({
            "network_id": network_id,
            "name": registration.name,
        })),
    )
    .await?;
    crate::op_log!(
        info,
        "device",
        "deny_registration",
        &network_id,
        &registration.id.to_string(),
        crate::telemetry::NOT_APPLICABLE,
        crate::telemetry::ErrorCategory::None.as_str(),
        crate::telemetry::RESULT_OK
    );
    Ok(StatusCode::NO_CONTENT)
}
