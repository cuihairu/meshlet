//! Device bootstrap registration (public endpoint, the device arrives holding a
//! bootstrap token): the registration lands as Pending → the control center
//! approves/denies it; agent credentials are returned exactly once (§11.3).

use crate::auth::{AuthenticatedUser, CsrfHeader, SharedAppState, WriteUser};
use crate::service;
use crate::service::{
    approve_registration, deny_registration, list_registrations, register_device,
};
use axum::extract::State;
use axum::http::StatusCode;
use axum::Json;

/// Device bootstrap registration (public endpoint; the device arrives with a
/// bootstrap token, no user session). Records a Pending request and issues the
/// agent credentials — the credentials are returned **exactly once** (§11.3).
pub(crate) async fn register_device_handler(
    State(state): State<SharedAppState>,
    Json(req): Json<service::RegisterDeviceRequest>,
) -> Result<(StatusCode, Json<service::RegisterDeviceResponse>), service::ServiceError> {
    let _persist = state.persist.lock().await;
    // Hash the token up front: req is consumed by the service, but we still need
    // to locate the just-incremented bootstrap token to persist it.
    let token_hash = meshlet_domain::token_hash(&req.bootstrap_token);
    let (mut resp, registration, seq, token, bootstrap_seq) = {
        let mut guard = state.mesh.lock().unwrap();
        let resp = register_device(&mut guard, req)?;
        let registration = guard
            .registry
            .find_registration(&meshlet_domain::DeviceId(resp.device_id.clone()))
            .expect("just registered")
            .clone();
        // The use count increments on registration and is persisted in the same step
        // — otherwise the count would roll back after a restart and the max_uses
        // limit could be bypassed by restarting.
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
    // The registrant arrives with a bootstrap token, so there is no user actor;
    // raw agent credential material never enters the audit trail (§16.5).
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

/// Approve a registration: the Pending request is promoted to a device (this is
/// when the overlay address gets allocated), and a new revision is pushed along
/// with the desired config; the Pending credential is voided and replaced with
/// a fresh one (returned exactly once).
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

/// Deny a registration: the request is removed and the Pending credential is
/// voided. No revision is recorded (the desired config has never included a
/// Pending request).
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
    // The request row and the Pending credential are cleaned up in the same
    // transaction (persist::delete_registration_db).
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
