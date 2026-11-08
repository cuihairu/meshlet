//! 邀请加入端点（公开，凭邀请 Token）：先变更+落库再签发 agent 凭证，
//! 锁不跨 mesh 锁的 await（future 须 Send）。

use crate::auth::SharedAppState;
use crate::service;
use crate::service::enroll;
use axum::extract::State;
use axum::http::StatusCode;
use axum::Json;

pub(crate) async fn enroll_handler(
    State(state): State<SharedAppState>,
    Json(req): Json<service::EnrollRequest>,
) -> Result<(StatusCode, Json<service::EnrollResponse>), service::ServiceError> {
    // 先完成加入（内存变更 + 落库同一互斥段），再签发 agent 凭证——锁不跨
    // mesh 锁的 await（future 须 Send）。
    let _persist = state.persist.lock().await;
    let invite_token = req.invite_token.clone();
    let (mut resp, device, revision, invite, staged) = {
        let guard = state.mesh.lock().unwrap();
        let mut staged = guard.clone();
        let resp = enroll(&mut staged, req)?;
        let device = staged
            .registry
            .find_by_id(&meshlet_domain::DeviceId(resp.device_id.clone()))
            .expect("just enrolled")
            .clone();
        let revision = staged
            .ledger
            .get(
                &meshlet_domain::NetworkId(resp.network_id.clone()),
                resp.revision_id,
            )
            .expect("just recorded")
            .clone();
        let invite = staged
            .invite_by_hash(&meshlet_domain::token_hash(&invite_token))
            .expect("invite just redeemed")
            .clone();
        (resp, device, revision, invite, staged)
    };
    let audit = crate::persist::AuditDraft {
        actor_id: None,
        action: "device.enrolled",
        target_type: "device",
        target_id: &resp.device_id,
        detail: Some(serde_json::json!({ "network_id": resp.network_id })),
    };
    let raw_agent_token =
        crate::persist::commit_enrollment(state.auth.pool(), &device, &revision, &invite, &audit)
            .await
            .map_err(crate::persist::internal)?;
    resp.agent_token = raw_agent_token;
    *state.mesh.lock().unwrap() = staged;
    crate::op_log!(
        info,
        "device",
        "enroll",
        &resp.network_id,
        &resp.device_id,
        &resp.revision_id.to_string(),
        crate::telemetry::ErrorCategory::None.as_str(),
        crate::telemetry::RESULT_OK
    );
    Ok((StatusCode::CREATED, Json(resp)))
}
