//! host-forward（域名→LAN 路由别名）端点：建/列/删；冲突计数与路由同口径。

use crate::auth::{AuthenticatedUser, CsrfHeader, SharedAppState, WriteUser};
use crate::record_route_conflict;
use crate::service;
use crate::service::{create_host_forward, delete_host_forward, list_host_forwards};
use axum::extract::State;
use axum::http::StatusCode;
use axum::Json;

pub(crate) async fn create_host_forward_handler(
    State(state): State<SharedAppState>,
    WriteUser(user_id): WriteUser,
    CsrfHeader: CsrfHeader,
    axum::extract::Path(network_id): axum::extract::Path<String>,
    Json(req): Json<service::CreateHostForwardRequest>,
) -> Result<(StatusCode, Json<service::HostForwardView>), service::ServiceError> {
    let _persist = state.persist.lock().await;
    let (view, route, alias, revision, route_seq, staged) = {
        let guard = state.mesh.lock().unwrap();
        let mut staged = guard.clone();
        match create_host_forward(&mut staged, &network_id, req) {
            Ok(view) => {
                let alias = staged
                    .aliases
                    .get(&network_id)
                    .and_then(|aliases| aliases.iter().find(|item| item.id.to_string() == view.id))
                    .expect("host forward alias just created")
                    .clone();
                let route = staged
                    .lan_routes
                    .get(&network_id)
                    .and_then(|routes| routes.iter().find(|item| item.id == alias.lan_route_id))
                    .expect("host forward route just created")
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
                (view, route, alias, revision, route_seq, staged)
            }
            Err(e) => {
                if matches!(e, service::ServiceError::RouteConflict(_)) {
                    record_route_conflict(&state);
                }
                crate::op_log!(
                    warn,
                    "host_forward",
                    "create_host_forward",
                    &network_id,
                    crate::telemetry::NOT_APPLICABLE,
                    crate::telemetry::NOT_APPLICABLE,
                    crate::telemetry::ErrorCategory::from(&e).as_str(),
                    crate::telemetry::RESULT_ERROR
                );
                return Err(e);
            }
        }
    };
    let audit = crate::persist::AuditDraft {
        actor_id: Some(&user_id.0),
        action: "host_forward.created",
        target_type: "host_forward",
        target_id: &view.id,
        detail: Some(serde_json::json!({ "network_id": network_id })),
    };
    crate::persist::commit_host_forward(
        state.auth.pool(),
        &route,
        &alias,
        route_seq,
        &revision,
        &audit,
    )
    .await
    .map_err(crate::persist::internal)?;
    *state.mesh.lock().unwrap() = staged;
    crate::op_log!(
        info,
        "host_forward",
        "create_host_forward",
        &network_id,
        crate::telemetry::NOT_APPLICABLE,
        &view.revision_id.to_string(),
        crate::telemetry::ErrorCategory::None.as_str(),
        crate::telemetry::RESULT_OK
    );
    Ok((StatusCode::CREATED, Json(view)))
}

pub(crate) async fn delete_host_forward_handler(
    State(state): State<SharedAppState>,
    WriteUser(user_id): WriteUser,
    CsrfHeader: CsrfHeader,
    axum::extract::Path((network_id, alias_id)): axum::extract::Path<(String, String)>,
) -> Result<StatusCode, service::ServiceError> {
    let _persist = state.persist.lock().await;
    let (route_id, revision, staged) = {
        let guard = state.mesh.lock().unwrap();
        let mut staged = guard.clone();
        let (_, route_id) = delete_host_forward(&mut staged, &network_id, &alias_id)?;
        let revision = staged
            .ledger
            .current(&meshlet_domain::NetworkId(network_id.clone()))
            .expect("delete_host_forward just recorded a revision")
            .clone();
        (route_id, revision, staged)
    };
    let audit = crate::persist::AuditDraft {
        actor_id: Some(&user_id.0),
        action: "host_forward.deleted",
        target_type: "host_forward",
        target_id: &alias_id,
        detail: Some(serde_json::json!({ "network_id": network_id, "route_id": route_id })),
    };
    crate::persist::commit_route_delete(state.auth.pool(), &route_id, &revision, &audit)
        .await
        .map_err(crate::persist::internal)?;
    *state.mesh.lock().unwrap() = staged;
    crate::op_log!(
        info,
        "host_forward",
        "delete_host_forward",
        &network_id,
        crate::telemetry::NOT_APPLICABLE,
        crate::telemetry::NOT_APPLICABLE,
        crate::telemetry::ErrorCategory::None.as_str(),
        crate::telemetry::RESULT_OK
    );
    Ok(StatusCode::NO_CONTENT)
}

pub(crate) async fn list_host_forwards_handler(
    State(state): State<SharedAppState>,
    AuthenticatedUser(_user): AuthenticatedUser,
    axum::extract::Path(network_id): axum::extract::Path<String>,
) -> Result<Json<Vec<service::HostForwardView>>, service::ServiceError> {
    let guard = state.mesh.lock().unwrap();
    Ok(Json(list_host_forwards(&guard, &network_id)?))
}
