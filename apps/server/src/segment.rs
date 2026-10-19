//! Segment 与单向 SegmentGrant 管理（ADR-012）。
//!
//! 授权先以 Pending 写入，只有显式 apply 后进入计划编译和期望哈希；
//! 未知段、重复对、同段授权、二次撤销均在任何状态变更前拒绝。

use axum::extract::State;
use axum::http::StatusCode;
use axum::routing::{delete, post};
use axum::{Json, Router};

use crate::auth::{AuthenticatedUser, CsrfHeader, SharedAppState, WriteUser};

pub fn routes() -> Router<SharedAppState> {
    Router::new()
        .route(
            "/api/v1/networks/{network_id}/segments",
            post(create_segment_handler).get(list_segments_handler),
        )
        .route(
            "/api/v1/networks/{network_id}/segment-grants",
            post(create_segment_grant_handler).get(list_segment_grants_handler),
        )
        .route(
            "/api/v1/networks/{network_id}/segment-grants/{grant_id}/apply",
            post(apply_segment_grant_handler),
        )
        .route(
            "/api/v1/networks/{network_id}/segment-grants/{grant_id}",
            delete(revoke_segment_grant_handler),
        )
}

async fn create_segment_handler(
    State(state): State<SharedAppState>,
    WriteUser(user_id): WriteUser,
    CsrfHeader: CsrfHeader,
    axum::extract::Path(network_id): axum::extract::Path<String>,
    Json(req): Json<crate::service::CreateSegmentRequest>,
) -> Result<(StatusCode, Json<crate::service::SegmentView>), crate::service::ServiceError> {
    let _persist = state.persist.lock().await;
    let (view, segment, revision, route_seq, staged) = {
        let guard = state.mesh.lock().unwrap();
        let mut staged = guard.clone();
        let view = crate::service::create_segment(&mut staged, &network_id, req)?;
        let segment = staged
            .segments(&network_id)
            .iter()
            .find(|candidate| candidate.id.to_string() == view.id)
            .expect("just created")
            .clone();
        let revision = staged
            .ledger
            .get(
                &meshlet_domain::NetworkId(network_id.clone()),
                view.revision_id,
            )
            .expect("just recorded")
            .clone();
        let route_seq = staged.route_seq();
        (view, segment, revision, route_seq, staged)
    };
    let audit = crate::persist::AuditDraft {
        actor_id: Some(&user_id.0),
        action: "segment.created",
        target_type: "segment",
        target_id: &view.id,
        detail: Some(serde_json::json!({ "network_id": network_id })),
    };
    crate::persist::commit_segment(state.auth.pool(), &segment, route_seq, &revision, &audit)
        .await
        .map_err(crate::persist::internal)?;
    *state.mesh.lock().unwrap() = staged;
    Ok((StatusCode::CREATED, Json(view)))
}

async fn list_segments_handler(
    State(state): State<SharedAppState>,
    AuthenticatedUser(_user): AuthenticatedUser,
    axum::extract::Path(network_id): axum::extract::Path<String>,
) -> Result<Json<Vec<crate::service::SegmentView>>, crate::service::ServiceError> {
    let guard = state.mesh.lock().unwrap();
    Ok(Json(crate::service::list_segments(&guard, &network_id)?))
}

async fn create_segment_grant_handler(
    State(state): State<SharedAppState>,
    WriteUser(user_id): WriteUser,
    CsrfHeader: CsrfHeader,
    axum::extract::Path(network_id): axum::extract::Path<String>,
    Json(req): Json<crate::service::CreateSegmentGrantRequest>,
) -> Result<(StatusCode, Json<crate::service::SegmentGrantView>), crate::service::ServiceError> {
    let _persist = state.persist.lock().await;
    let (view, grant, revision, route_seq, staged) = {
        let guard = state.mesh.lock().unwrap();
        let mut staged = guard.clone();
        let view = crate::service::create_segment_grant(&mut staged, &network_id, req)?;
        let grant = staged
            .segment_grants(&network_id)
            .iter()
            .find(|candidate| candidate.id.to_string() == view.id)
            .expect("just created")
            .clone();
        let revision = staged
            .ledger
            .get(
                &meshlet_domain::NetworkId(network_id.clone()),
                view.revision_id,
            )
            .expect("just recorded")
            .clone();
        let route_seq = staged.route_seq();
        (view, grant, revision, route_seq, staged)
    };
    let audit = crate::persist::AuditDraft {
        actor_id: Some(&user_id.0),
        action: "segment_grant.created",
        target_type: "segment_grant",
        target_id: &view.id,
        detail: Some(serde_json::json!({
            "network_id": network_id,
            "source_segment_id": view.source_segment_id,
            "destination_segment_id": view.destination_segment_id,
        })),
    };
    crate::persist::commit_segment_grant(state.auth.pool(), &grant, route_seq, &revision, &audit)
        .await
        .map_err(crate::persist::internal)?;
    *state.mesh.lock().unwrap() = staged;
    Ok((StatusCode::CREATED, Json(view)))
}

async fn list_segment_grants_handler(
    State(state): State<SharedAppState>,
    AuthenticatedUser(_user): AuthenticatedUser,
    axum::extract::Path(network_id): axum::extract::Path<String>,
) -> Result<Json<Vec<crate::service::SegmentGrantView>>, crate::service::ServiceError> {
    let guard = state.mesh.lock().unwrap();
    Ok(Json(crate::service::list_segment_grants(
        &guard,
        &network_id,
    )?))
}

async fn apply_segment_grant_handler(
    State(state): State<SharedAppState>,
    WriteUser(user_id): WriteUser,
    CsrfHeader: CsrfHeader,
    axum::extract::Path((network_id, grant_id)): axum::extract::Path<(String, String)>,
) -> Result<Json<crate::service::SegmentGrantView>, crate::service::ServiceError> {
    let _persist = state.persist.lock().await;
    let (view, grant, revision, staged) = {
        let guard = state.mesh.lock().unwrap();
        let mut staged = guard.clone();
        let view = crate::service::apply_segment_grant(&mut staged, &network_id, &grant_id)?;
        let grant = staged
            .segment_grants(&network_id)
            .iter()
            .find(|candidate| candidate.id.to_string() == view.id)
            .expect("just updated")
            .clone();
        let revision = staged
            .ledger
            .get(
                &meshlet_domain::NetworkId(network_id.clone()),
                view.revision_id,
            )
            .expect("just recorded")
            .clone();
        (view, grant, revision, staged)
    };
    let audit = crate::persist::AuditDraft {
        actor_id: Some(&user_id.0),
        action: "segment_grant.applied",
        target_type: "segment_grant",
        target_id: &grant_id,
        detail: Some(serde_json::json!({ "network_id": network_id })),
    };
    crate::persist::commit_segment_grant_status(state.auth.pool(), &grant, &revision, &audit)
        .await
        .map_err(crate::persist::internal)?;
    *state.mesh.lock().unwrap() = staged;
    Ok(Json(view))
}

async fn revoke_segment_grant_handler(
    State(state): State<SharedAppState>,
    WriteUser(user_id): WriteUser,
    CsrfHeader: CsrfHeader,
    axum::extract::Path((network_id, grant_id)): axum::extract::Path<(String, String)>,
) -> Result<StatusCode, crate::service::ServiceError> {
    let _persist = state.persist.lock().await;
    let (grant, revision, staged) = {
        let guard = state.mesh.lock().unwrap();
        let mut staged = guard.clone();
        crate::service::revoke_segment_grant(&mut staged, &network_id, &grant_id)?;
        let grant = staged
            .segment_grants(&network_id)
            .iter()
            .find(|candidate| candidate.id.to_string() == grant_id)
            .expect("just updated")
            .clone();
        let revision = staged
            .ledger
            .current(&meshlet_domain::NetworkId(network_id.clone()))
            .expect("revoke_segment_grant just recorded a revision")
            .clone();
        (grant, revision, staged)
    };
    let audit = crate::persist::AuditDraft {
        actor_id: Some(&user_id.0),
        action: "segment_grant.revoked",
        target_type: "segment_grant",
        target_id: &grant_id,
        detail: Some(serde_json::json!({ "network_id": network_id })),
    };
    crate::persist::commit_segment_grant_status(state.auth.pool(), &grant, &revision, &audit)
        .await
        .map_err(crate::persist::internal)?;
    *state.mesh.lock().unwrap() = staged;
    Ok(StatusCode::NO_CONTENT)
}
