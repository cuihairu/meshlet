//! Write paths for Alias mappings (§12.6 / ADR-006, archive §12 "Alias page"):
//! - `POST /networks/{id}/aliases`: create (binds an alias-mode route, target
//!   derived server-side, a conflict rejection happens before any state change);
//! - `GET /networks/{id}/aliases`, `GET …/{alias_id}`: list/detail;
//! - `DELETE /networks/{id}/aliases/{alias_id}`: delete = whole-unit cleanup
//!   (mapping + bound route in one revision, the kernel-side NAT rules are
//!   handed to the backend as part of the revision apply, §10.3).
//!
//! Conflict metric (§17.2): prefix-overlap rejections count towards
//! `meshlet_route_conflicts_total`. (Data-plane NAT execution awaits ADR-007;
//! this module is the control-plane desired state.)

use axum::extract::State;
use axum::http::StatusCode;
use axum::routing::{get, post};
use axum::{Json, Router};

use crate::auth::{AuthenticatedUser, CsrfHeader, SharedAppState, WriteUser};

pub fn routes() -> Router<SharedAppState> {
    Router::new()
        .route(
            "/api/v1/networks/{network_id}/aliases",
            post(create_alias_handler).get(list_aliases_handler),
        )
        .route(
            "/api/v1/networks/{network_id}/aliases/{alias_id}",
            get(get_alias_handler).delete(delete_alias_handler),
        )
}

async fn create_alias_handler(
    State(state): State<SharedAppState>,
    WriteUser(user_id): WriteUser,
    CsrfHeader: CsrfHeader,
    axum::extract::Path(network_id): axum::extract::Path<String>,
    Json(req): Json<crate::service::CreateAliasRequest>,
) -> Result<(StatusCode, Json<crate::service::AliasView>), crate::service::ServiceError> {
    let _persist = state.persist.lock().await;
    let (view, alias, revision, route_seq, staged) = {
        let guard = state.mesh.lock().unwrap();
        let mut staged = guard.clone();
        match crate::service::create_alias(&mut staged, &network_id, req) {
            Ok(view) => {
                let alias = staged
                    .aliases
                    .get(&network_id)
                    .and_then(|aliases| aliases.iter().find(|a| a.id.to_string() == view.id))
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
                (view, alias, revision, route_seq, staged)
            }
            Err(e) => {
                // Prefix-overlap conflicts share the route conflict metric (§17.2);
                // other 409s are not counted.
                if matches!(e, crate::service::ServiceError::RouteConflict(_)) {
                    crate::record_route_conflict(&state);
                }
                crate::op_log!(
                    warn,
                    "alias",
                    "create_alias",
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
        action: "alias.created",
        target_type: "alias",
        target_id: &view.id,
        detail: Some(
            serde_json::json!({ "network_id": network_id, "lan_route_id": view.lan_route_id }),
        ),
    };
    crate::persist::commit_alias(state.auth.pool(), &alias, route_seq, &revision, &audit)
        .await
        .map_err(crate::persist::internal)?;
    *state.mesh.lock().unwrap() = staged;
    crate::op_log!(
        info,
        "alias",
        "create_alias",
        &network_id,
        crate::telemetry::NOT_APPLICABLE,
        &view.revision_id.to_string(),
        crate::telemetry::ErrorCategory::None.as_str(),
        crate::telemetry::RESULT_OK
    );
    Ok((StatusCode::CREATED, Json(view)))
}

async fn list_aliases_handler(
    State(state): State<SharedAppState>,
    AuthenticatedUser(_user): AuthenticatedUser,
    axum::extract::Path(network_id): axum::extract::Path<String>,
) -> Result<Json<Vec<crate::service::AliasView>>, crate::service::ServiceError> {
    let guard = state.mesh.lock().unwrap();
    Ok(Json(crate::service::list_aliases(&guard, &network_id)?))
}

async fn get_alias_handler(
    State(state): State<SharedAppState>,
    AuthenticatedUser(_user): AuthenticatedUser,
    axum::extract::Path((network_id, alias_id)): axum::extract::Path<(String, String)>,
) -> Result<Json<crate::service::AliasView>, crate::service::ServiceError> {
    let guard = state.mesh.lock().unwrap();
    Ok(Json(crate::service::get_alias(
        &guard,
        &network_id,
        &alias_id,
    )?))
}

async fn delete_alias_handler(
    State(state): State<SharedAppState>,
    WriteUser(user_id): WriteUser,
    CsrfHeader: CsrfHeader,
    axum::extract::Path((network_id, alias_id)): axum::extract::Path<(String, String)>,
) -> Result<StatusCode, crate::service::ServiceError> {
    let _persist = state.persist.lock().await;
    let (route_id, revision, staged) = {
        let guard = state.mesh.lock().unwrap();
        let mut staged = guard.clone();
        // Delete = whole unit: the return value carries the bound route id,
        // cleaned up under the same revision.
        let (_, route_id) = crate::service::delete_alias(&mut staged, &network_id, &alias_id)?;
        let revision = staged
            .ledger
            .current(&meshlet_domain::NetworkId(network_id.clone()))
            .expect("delete_alias just recorded a revision")
            .clone();
        (route_id, revision, staged)
    };
    let audit = crate::persist::AuditDraft {
        actor_id: Some(&user_id.0),
        action: "alias.deleted",
        target_type: "alias",
        target_id: &alias_id,
        detail: Some(serde_json::json!({ "network_id": network_id, "route_id": route_id })),
    };
    crate::persist::commit_route_delete(state.auth.pool(), &route_id, &revision, &audit)
        .await
        .map_err(crate::persist::internal)?;
    *state.mesh.lock().unwrap() = staged;
    crate::op_log!(
        info,
        "alias",
        "delete_alias",
        &network_id,
        crate::telemetry::NOT_APPLICABLE,
        crate::telemetry::NOT_APPLICABLE,
        crate::telemetry::ErrorCategory::None.as_str(),
        crate::telemetry::RESULT_OK
    );
    Ok(StatusCode::NO_CONTENT)
}
