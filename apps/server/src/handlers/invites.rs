//! 邀请端点：签发（元数据留痕，原始 Token 不进审计 §16.5）与撤销。

use crate::auth::{CsrfHeader, SharedAppState, WriteUser};
use crate::service;
use crate::service::{create_invite, revoke_invite};
use axum::extract::State;
use axum::http::StatusCode;
use axum::Json;

pub(crate) async fn create_invite_handler(
    State(state): State<SharedAppState>,
    WriteUser(user_id): WriteUser,
    CsrfHeader: CsrfHeader,
    axum::extract::Path(network_id): axum::extract::Path<String>,
    Json(req): Json<service::CreateInviteRequest>,
) -> Result<(StatusCode, Json<service::CreateInviteResponse>), service::ServiceError> {
    let _persist = state.persist.lock().await;
    let (resp, invite) = {
        let mut guard = state.mesh.lock().unwrap();
        let resp = create_invite(&mut guard, &network_id, req)?;
        let invite = guard
            .invite_by_hash(&meshlet_domain::token_hash(&resp.token))
            .expect("just created")
            .clone();
        (resp, invite)
    };
    crate::persist::save_invite(state.auth.pool(), &invite)
        .await
        .map_err(crate::persist::internal)?;
    // 只留痕元数据（过期/次数上限）；原始邀请 Token 不进审计（§16.5）。
    crate::audit::record_or_fail(
        &state,
        Some(&user_id.0),
        "invite.created",
        "invite",
        Some(&resp.invite_id),
        Some(serde_json::json!({
            "network_id": network_id,
            "expires_at": resp.expires_at,
        })),
    )
    .await?;
    crate::op_log!(
        info,
        "network",
        "create_invite",
        &network_id,
        crate::telemetry::NOT_APPLICABLE,
        crate::telemetry::NOT_APPLICABLE,
        crate::telemetry::ErrorCategory::None.as_str(),
        crate::telemetry::RESULT_OK
    );
    Ok((StatusCode::CREATED, Json(resp)))
}

pub(crate) async fn revoke_invite_handler(
    State(state): State<SharedAppState>,
    WriteUser(user_id): WriteUser,
    CsrfHeader: CsrfHeader,
    axum::extract::Path((network_id, invite_id)): axum::extract::Path<(String, String)>,
) -> Result<StatusCode, service::ServiceError> {
    let _persist = state.persist.lock().await;
    let invite = {
        let mut guard = state.mesh.lock().unwrap();
        revoke_invite(&mut guard, &network_id, &invite_id)?;
        // 撤销落在内存后取回整份邀请（摘要索引），回写撤销时刻。
        let invite = guard
            .invites()
            .find(|i| i.id.to_string() == invite_id)
            .expect("just revoked")
            .clone();
        invite
    };
    crate::persist::save_invite(state.auth.pool(), &invite)
        .await
        .map_err(crate::persist::internal)?;
    crate::audit::record_or_fail(
        &state,
        Some(&user_id.0),
        "invite.revoked",
        "invite",
        Some(&invite_id),
        Some(serde_json::json!({ "network_id": network_id })),
    )
    .await?;
    crate::op_log!(
        info,
        "network",
        "revoke_invite",
        &network_id,
        crate::telemetry::NOT_APPLICABLE,
        crate::telemetry::NOT_APPLICABLE,
        crate::telemetry::ErrorCategory::None.as_str(),
        crate::telemetry::RESULT_OK
    );
    Ok(StatusCode::NO_CONTENT)
}
