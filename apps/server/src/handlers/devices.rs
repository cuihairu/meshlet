//! Device endpoints: listing, revocation (credential invalidation and tracing outside the lock), and MT-005 label updates
//! (no revision is recorded; the audit entry commits in the same transaction as the labels).

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
    // Finish revocation + revision bookkeeping + persistence first (in one
    // critical section), then invalidate the agent credential and record the
    // trail outside the lock.
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

/// MT-005 device label update (`POST /api/v1/networks/{network_id}/devices/{device_id}/labels`).
/// Labels are routing metadata: no revision is recorded and no desired-config
/// apply is triggered; the in-memory change and persistence happen in one
/// critical section, and the audit entry commits in the same transaction as the
/// labels ("no audit trail, no pass-through").
pub(crate) async fn set_device_labels_handler(
    State(state): State<SharedAppState>,
    WriteUser(user_id): WriteUser,
    CsrfHeader: CsrfHeader,
    axum::extract::Path((network_id, device_id)): axum::extract::Path<(String, String)>,
    Json(req): Json<service::SetDeviceLabelsRequest>,
) -> Result<Json<service::DeviceView>, service::ServiceError> {
    let _persist = state.persist.lock().await;
    // Clone first → mutate the clone (the mesh lock is released before the
    // await, so the future must be Send) → only swap the staged state into the
    // live state after persistence succeeds ("no persistence, no pass-through",
    // the same discipline as revoke/approve).
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
