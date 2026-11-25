//! Device bootstrap codes (the entry credential of ZeroTier-style bootstrap registration): issue / list / revoke.
//! Summary + sequence are persisted (§17.3: `bt-N` does not renumber after a restart); the raw bootstrap code is not audited
//! (§16.5, the same discipline as the invite Token).

use crate::auth::{AuthenticatedUser, CsrfHeader, SharedAppState, WriteUser};
use crate::service;
use crate::service::{create_bootstrap_token, list_bootstrap_tokens, revoke_bootstrap_token};
use axum::extract::State;
use axum::http::StatusCode;
use axum::Json;

pub(crate) async fn create_bootstrap_token_handler(
    State(state): State<SharedAppState>,
    WriteUser(user_id): WriteUser,
    CsrfHeader: CsrfHeader,
    axum::extract::Path(network_id): axum::extract::Path<String>,
    Json(req): Json<service::CreateBootstrapTokenRequest>,
) -> Result<(StatusCode, Json<service::CreateBootstrapTokenResponse>), service::ServiceError> {
    let _persist = state.persist.lock().await;
    let (resp, token, seq) = {
        let mut guard = state.mesh.lock().unwrap();
        let resp = create_bootstrap_token(&mut guard, &network_id, req)?;
        let token = guard
            .bootstrap_tokens
            .get(&meshlet_domain::token_hash(&resp.token))
            .expect("just created")
            .clone();
        (resp, token, guard.bootstrap_seq())
    };
    // Persist the summary + sequence (§17.3: bootstrap codes keep working after a restart, `bt-N` does not renumber).
    crate::persist::save_bootstrap_token(state.auth.pool(), &token, seq)
        .await
        .map_err(crate::persist::internal)?;
    // The raw bootstrap code is not audited (§16.5, the same discipline as the invite Token).
    crate::audit::record_or_fail(
        &state,
        Some(&user_id.0),
        "bootstrap_token.created",
        "bootstrap_token",
        Some(&resp.token_id),
        Some(serde_json::json!({
            "network_id": network_id,
            "max_uses": resp.max_uses,
        })),
    )
    .await?;
    crate::op_log!(
        info,
        "network",
        "create_bootstrap_token",
        &network_id,
        crate::telemetry::NOT_APPLICABLE,
        crate::telemetry::NOT_APPLICABLE,
        crate::telemetry::ErrorCategory::None.as_str(),
        crate::telemetry::RESULT_OK
    );
    Ok((StatusCode::CREATED, Json(resp)))
}

pub(crate) async fn list_bootstrap_tokens_handler(
    State(state): State<SharedAppState>,
    AuthenticatedUser(_user): AuthenticatedUser,
    axum::extract::Path(network_id): axum::extract::Path<String>,
) -> Result<Json<Vec<service::BootstrapTokenView>>, service::ServiceError> {
    let guard = state.mesh.lock().unwrap();
    Ok(Json(list_bootstrap_tokens(&guard, &network_id)?))
}

pub(crate) async fn revoke_bootstrap_token_handler(
    State(state): State<SharedAppState>,
    WriteUser(user_id): WriteUser,
    CsrfHeader: CsrfHeader,
    axum::extract::Path((network_id, token_id)): axum::extract::Path<(String, String)>,
) -> Result<StatusCode, service::ServiceError> {
    let _persist = state.persist.lock().await;
    let revoked_at = {
        let mut guard = state.mesh.lock().unwrap();
        revoke_bootstrap_token(&mut guard, &network_id, &token_id)?
    };
    crate::persist::revoke_bootstrap_token_db(
        state.auth.pool(),
        &meshlet_domain::BootstrapTokenId(token_id.clone()),
        &revoked_at,
    )
    .await
    .map_err(crate::persist::internal)?;
    crate::audit::record_or_fail(
        &state,
        Some(&user_id.0),
        "bootstrap_token.revoked",
        "bootstrap_token",
        Some(token_id.as_str()),
        Some(serde_json::json!({ "network_id": network_id })),
    )
    .await?;
    crate::op_log!(
        info,
        "network",
        "revoke_bootstrap_token",
        &network_id,
        crate::telemetry::NOT_APPLICABLE,
        crate::telemetry::NOT_APPLICABLE,
        crate::telemetry::ErrorCategory::None.as_str(),
        crate::telemetry::RESULT_OK
    );
    Ok(StatusCode::NO_CONTENT)
}
