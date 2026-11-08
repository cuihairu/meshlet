//! LAN 路由端点：建/列/查/删；路由冲突单独计数（§17.2，经根模块的
//! `record_route_conflict`，alias.rs 同用）。

use crate::auth::{AuthenticatedUser, CsrfHeader, SharedAppState, WriteUser};
use crate::record_route_conflict;
use crate::service;
use crate::service::{create_route, delete_route, get_route, list_routes};
use axum::extract::State;
use axum::http::StatusCode;
use axum::Json;

pub(crate) async fn create_route_handler(
    State(state): State<SharedAppState>,
    WriteUser(user_id): WriteUser,
    CsrfHeader: CsrfHeader,
    axum::extract::Path(network_id): axum::extract::Path<String>,
    Json(req): Json<service::CreateRouteRequest>,
) -> Result<(StatusCode, Json<service::RouteView>), service::ServiceError> {
    let _persist = state.persist.lock().await;
    let (view, route, revision, route_seq, staged) = {
        let guard = state.mesh.lock().unwrap();
        let mut staged = guard.clone();
        match create_route(&mut staged, &network_id, req) {
            Ok(view) => {
                let route = staged
                    .lan_routes
                    .get(&network_id)
                    .and_then(|routes| routes.iter().find(|r| r.id.to_string() == view.id))
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
                (view, route, revision, route_seq, staged)
            }
            Err(e) => {
                // 路由冲突单独计数（§17.2「路由冲突数」）；错误类别随领域事件留痕。
                if matches!(e, service::ServiceError::RouteConflict(_)) {
                    record_route_conflict(&state);
                }
                crate::op_log!(
                    warn,
                    "route",
                    "create_route",
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
        action: "route.created",
        target_type: "route",
        target_id: &view.id,
        detail: Some(serde_json::json!({ "network_id": network_id })),
    };
    crate::persist::commit_route(state.auth.pool(), &route, route_seq, &revision, &audit)
        .await
        .map_err(crate::persist::internal)?;
    *state.mesh.lock().unwrap() = staged;
    crate::op_log!(
        info,
        "route",
        "create_route",
        &network_id,
        crate::telemetry::NOT_APPLICABLE,
        &view.revision_id.to_string(),
        crate::telemetry::ErrorCategory::None.as_str(),
        crate::telemetry::RESULT_OK
    );
    Ok((StatusCode::CREATED, Json(view)))
}

pub(crate) async fn list_routes_handler(
    State(state): State<SharedAppState>,
    AuthenticatedUser(_user): AuthenticatedUser,
    axum::extract::Path(network_id): axum::extract::Path<String>,
) -> Result<Json<Vec<service::RouteView>>, service::ServiceError> {
    let guard = state.mesh.lock().unwrap();
    Ok(Json(list_routes(&guard, &network_id)?))
}

pub(crate) async fn get_route_handler(
    State(state): State<SharedAppState>,
    AuthenticatedUser(_user): AuthenticatedUser,
    axum::extract::Path((network_id, route_id)): axum::extract::Path<(String, String)>,
) -> Result<Json<service::RouteView>, service::ServiceError> {
    let guard = state.mesh.lock().unwrap();
    Ok(Json(get_route(&guard, &network_id, &route_id)?))
}

pub(crate) async fn delete_route_handler(
    State(state): State<SharedAppState>,
    WriteUser(user_id): WriteUser,
    CsrfHeader: CsrfHeader,
    axum::extract::Path((network_id, route_id)): axum::extract::Path<(String, String)>,
) -> Result<StatusCode, service::ServiceError> {
    let _persist = state.persist.lock().await;
    let (revision, staged) = {
        let guard = state.mesh.lock().unwrap();
        let mut staged = guard.clone();
        delete_route(&mut staged, &network_id, &route_id)?;
        // 删除记录了新修订（当前最新）：取出以镜像落库。
        let revision = staged
            .ledger
            .current(&meshlet_domain::NetworkId(network_id.clone()))
            .expect("delete_route just recorded a revision")
            .clone();
        (revision, staged)
    };
    let audit = crate::persist::AuditDraft {
        actor_id: Some(&user_id.0),
        action: "route.deleted",
        target_type: "route",
        target_id: &route_id,
        detail: Some(serde_json::json!({ "network_id": network_id })),
    };
    crate::persist::commit_route_delete(state.auth.pool(), &route_id, &revision, &audit)
        .await
        .map_err(crate::persist::internal)?;
    *state.mesh.lock().unwrap() = staged;
    crate::op_log!(
        info,
        "route",
        "delete_route",
        &network_id,
        crate::telemetry::NOT_APPLICABLE,
        crate::telemetry::NOT_APPLICABLE,
        crate::telemetry::ErrorCategory::None.as_str(),
        crate::telemetry::RESULT_OK
    );
    Ok(StatusCode::NO_CONTENT)
}
