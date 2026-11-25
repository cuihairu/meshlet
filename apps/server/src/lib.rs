//! meshlet-server library entry point: the router construction is reusable by integration tests.
//!
//! Control-plane routes (contract: docs/architecture/api-contract.md):
//! status / networks / invites / device enrollment / console authentication ([ADR-010](../../docs/decisions/adr-010-console-auth-enrollment.md)).
//!
//! Route tiers:
//! - Public: `/system/status`, `/enroll` (carries its own invite Token authentication), `/auth/bootstrap|login`;
//! - Admin (`AuthenticatedUser`: a cookie session or an `mlt_` API Token; write requests additionally require
//!   `WriteUser` + `CsrfHeader`): `/auth/tokens*`, `/networks*`,
//!   `/networks/{id}/invites*`, `/networks/{id}/devices`, `/networks/{id}/revisions*`,
//!   `/networks/{id}/routes*`, `/networks/{id}/aliases*` (§12.6, deletion cleans up the whole unit),
//!   `/networks/{id}/diagnostics` (the thirteen §12.7 items, POST triggers and GET reads the latest snapshot),
//!   `/system/backup` (§17.4, 503 when the directory is not configured).

pub mod agent;
pub mod alias;
pub mod api_token;
pub mod audit;
pub mod auth;
pub mod backup;
pub mod convergence;
pub mod device_plan;
pub mod diagnostics;
pub mod instance_lock;
pub mod metrics;
pub mod persist;
pub mod presence_watch;
pub mod publish;
pub mod publish_check;
pub mod revision;
pub mod segment;
pub mod service;
pub mod store;
pub mod task;
pub mod telemetry;

// HTTP handlers grouped by resource family (private submodule; the public API is unchanged).
mod handlers;

use crate::auth::SharedAppState;
use crate::handlers::*;

use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::{delete, get, post};
use axum::{Json, Router};
use serde::Serialize;

/// Response of `GET /api/v1/system/status` (contract: docs/architecture/api-contract.md).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SystemStatus {
    pub status: String,
    pub version: String,
}

/// Public update descriptor. Artifact URL and digest are release-provided;
/// no device credential is required to read this descriptor.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct UpdateManifest {
    pub version: String,
    pub url: String,
    pub sha256: String,
}

pub fn update_manifest(url: impl Into<String>, sha256: impl Into<String>) -> UpdateManifest {
    UpdateManifest {
        version: env!("CARGO_PKG_VERSION").into(),
        url: url.into(),
        sha256: sha256.into(),
    }
}

pub fn system_status() -> SystemStatus {
    SystemStatus {
        status: "ok".into(),
        version: env!("CARGO_PKG_VERSION").into(),
    }
}

/// Record a route-conflict rejection (the §17.2 "route conflict count" metric): only "destination segment overlap" conflicts
/// (`ServiceError::RouteConflict`) are counted; other 409s such as an inactive device are not.
pub(crate) fn record_route_conflict(state: &SharedAppState) {
    state.metrics.record_route_conflict();
}

/// Build the full route table.
pub fn router(state: SharedAppState) -> Router {
    Router::new()
        .merge(alias::routes())
        .merge(api_token::routes())
        .merge(audit::routes())
        .merge(backup::routes())
        .merge(diagnostics::routes())
        .merge(metrics::routes())
        .merge(revision::routes())
        .merge(publish::routes())
        .merge(task::console_routes())
        .merge(segment::routes())
        .route("/api/v1/system/status", get(status_handler))
        .route("/api/v1/update-manifest", get(update_manifest_handler))
        .route("/api/v1/enroll", post(enroll_handler))
        .route(
            "/api/v1/device-registrations",
            post(register_device_handler),
        )
        .route("/api/v1/auth/bootstrap", post(auth::bootstrap_handler))
        .route("/api/v1/auth/login", post(auth::login_handler))
        .route("/api/v1/auth/logout", post(auth::logout_handler))
        .route("/api/v1/auth/me", get(auth::me_handler))
        .route(
            "/api/v1/auth/2fa/status",
            get(auth::two_factor_status_handler),
        )
        .route(
            "/api/v1/auth/2fa/enroll",
            post(auth::two_factor_enroll_handler),
        )
        .route(
            "/api/v1/auth/2fa/activate",
            post(auth::two_factor_activate_handler),
        )
        .route(
            "/api/v1/auth/2fa/disable",
            post(auth::two_factor_disable_handler),
        )
        .route(
            "/api/v1/networks",
            post(create_network_handler).get(list_networks_handler),
        )
        .route(
            "/api/v1/networks/{network_id}/invites",
            post(create_invite_handler),
        )
        .route(
            "/api/v1/networks/{network_id}/routes",
            post(create_route_handler).get(list_routes_handler),
        )
        .route(
            "/api/v1/networks/{network_id}/routes/{route_id}",
            get(get_route_handler).delete(delete_route_handler),
        )
        .route(
            "/api/v1/networks/{network_id}/host-forwards",
            post(create_host_forward_handler).get(list_host_forwards_handler),
        )
        .route(
            "/api/v1/networks/{network_id}/host-forwards/{alias_id}",
            delete(delete_host_forward_handler),
        )
        .route(
            "/api/v1/networks/{network_id}/devices/{device_id}/revoke",
            post(revoke_device_handler),
        )
        .route(
            "/api/v1/networks/{network_id}/invites/{invite_id}",
            delete(revoke_invite_handler),
        )
        .route(
            "/api/v1/networks/{network_id}/devices",
            get(list_devices_handler),
        )
        .route(
            "/api/v1/networks/{network_id}/devices/{device_id}/approve",
            post(approve_registration_handler),
        )
        .route(
            "/api/v1/networks/{network_id}/devices/{device_id}/labels",
            post(set_device_labels_handler),
        )
        .route(
            "/api/v1/networks/{network_id}/devices/{device_id}/deny",
            post(deny_registration_handler),
        )
        .route(
            "/api/v1/networks/{network_id}/registrations",
            get(list_registrations_handler),
        )
        .route(
            "/api/v1/networks/{network_id}/bootstrap-tokens",
            post(create_bootstrap_token_handler).get(list_bootstrap_tokens_handler),
        )
        .route(
            "/api/v1/networks/{network_id}/bootstrap-tokens/{token_id}",
            delete(revoke_bootstrap_token_handler),
        )
        .route(
            "/api/v1/agent/device/applied",
            post(convergence::receipt_handler),
        )
        .route("/api/v1/agent/heartbeat", post(agent::heartbeat_handler))
        .route(
            "/api/v1/publish/routes/check",
            post(publish_check::publish_check_handler),
        )
        .route(
            "/api/v1/agent/device/desired",
            get(agent::desired_device_plan_handler),
        )
        .route(
            "/api/v1/agent/device/peers/endpoints",
            get(agent::agent_peers_endpoints_handler),
        )
        // MT-002 task channel: agent-side pull/ack/receipt (AuthorizedAgent authentication).
        .route("/api/v1/agent/tasks/pending", get(task::pending_handler))
        .route("/api/v1/agent/tasks/{id}/ack", post(task::ack_handler))
        .route(
            "/api/v1/agent/tasks/{id}/result",
            post(task::result_handler),
        )
        .route(
            "/api/v1/networks/{network_id}/peers/endpoints",
            get(agent::peers_endpoints_handler),
        )
        // Access log (§17.1) + HTTP metric counting (§17.2): at route-template level, not crossing the static fallback.
        .layer(axum::middleware::from_fn_with_state(
            state.clone(),
            telemetry::request_log,
        ))
        .with_state(state)
}

/// Build the full router with console static hosting: `console_dir`
/// (usually `console/dist`) serves as the fallback file service for
/// non-`/api` paths (`/api/v1/*` route priority is unaffected).
pub fn router_with_console(state: SharedAppState, console_dir: &str) -> Router {
    router(state).fallback_service(tower_http::services::ServeDir::new(console_dir))
}

impl IntoResponse for service::ServiceError {
    fn into_response(self) -> Response {
        let status = match &self {
            service::ServiceError::NetworkNotFound(_)
            | service::ServiceError::InviteNotFound(_)
            | service::ServiceError::BootstrapTokenNotFound(_)
            | service::ServiceError::DeviceNotFound(_)
            | service::ServiceError::RouteNotFound(_)
            | service::ServiceError::AliasNotFound(_)
            | service::ServiceError::PublishNotFound(_)
            | service::ServiceError::SegmentNotFound(_)
            | service::ServiceError::SegmentGrantNotFound(_)
            | service::ServiceError::RevisionNotFound(_)
            | service::ServiceError::TaskNotFound(_)
            | service::ServiceError::DiagnosticsNotRun(_)
            | service::ServiceError::InvalidInviteToken => StatusCode::NOT_FOUND,
            service::ServiceError::InvalidBootstrapToken => StatusCode::UNAUTHORIZED,
            service::ServiceError::InvalidCidr(_) | service::ServiceError::InvalidInput(_) => {
                StatusCode::BAD_REQUEST
            }
            service::ServiceError::Conflict(_) | service::ServiceError::RouteConflict(_) => {
                StatusCode::CONFLICT
            }
            service::ServiceError::Internal(_) => StatusCode::INTERNAL_SERVER_ERROR,
        };
        (status, Json(self.into_response())).into_response()
    }
}
