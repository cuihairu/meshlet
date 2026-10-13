//! meshlet-server 库入口：路由构建可供集成测试复用。
//!
//! 控制平面路由（契约见 docs/architecture/api-contract.md）：
//! 状态/网络/邀请/设备加入（[ADR-010](../../docs/decisions/adr-010-console-auth-enrollment.md)）。

pub mod service;
pub mod store;

use axum::extract::State;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::{delete, get, post};
use axum::{Json, Router};
use serde::Serialize;

use crate::service::{
    create_invite, create_network, enroll, list_devices, list_networks, revoke_invite, SharedState,
};

/// `GET /api/v1/system/status` 响应（契约见 docs/architecture/api-contract.md）。
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SystemStatus {
    pub status: String,
    pub version: String,
}

pub fn system_status() -> SystemStatus {
    SystemStatus {
        status: "ok".into(),
        version: env!("CARGO_PKG_VERSION").into(),
    }
}

async fn status_handler() -> Json<SystemStatus> {
    Json(system_status())
}

async fn create_network_handler(
    State(state): State<SharedState>,
    Json(req): Json<service::CreateNetworkRequest>,
) -> Result<(StatusCode, Json<service::NetworkView>), service::ServiceError> {
    let mut guard = state.lock().unwrap();
    Ok((StatusCode::CREATED, Json(create_network(&mut guard, req)?)))
}

async fn list_networks_handler(
    State(state): State<SharedState>,
) -> Result<Json<Vec<service::NetworkView>>, service::ServiceError> {
    let guard = state.lock().unwrap();
    Ok(Json(list_networks(&guard)))
}

async fn create_invite_handler(
    State(state): State<SharedState>,
    axum::extract::Path(network_id): axum::extract::Path<String>,
    Json(req): Json<service::CreateInviteRequest>,
) -> Result<(StatusCode, Json<service::CreateInviteResponse>), service::ServiceError> {
    let mut guard = state.lock().unwrap();
    Ok((
        StatusCode::CREATED,
        Json(create_invite(&mut guard, &network_id, req)?),
    ))
}

async fn revoke_invite_handler(
    State(state): State<SharedState>,
    axum::extract::Path((network_id, invite_id)): axum::extract::Path<(String, String)>,
) -> Result<StatusCode, service::ServiceError> {
    let mut guard = state.lock().unwrap();
    revoke_invite(&mut guard, &network_id, &invite_id)?;
    Ok(StatusCode::NO_CONTENT)
}

async fn list_devices_handler(
    State(state): State<SharedState>,
    axum::extract::Path(network_id): axum::extract::Path<String>,
) -> Result<Json<Vec<service::DeviceView>>, service::ServiceError> {
    let guard = state.lock().unwrap();
    Ok(Json(list_devices(&guard, &network_id)?))
}

async fn enroll_handler(
    State(state): State<SharedState>,
    Json(req): Json<service::EnrollRequest>,
) -> Result<(StatusCode, Json<service::EnrollResponse>), service::ServiceError> {
    let mut guard = state.lock().unwrap();
    Ok((StatusCode::CREATED, Json(enroll(&mut guard, req)?)))
}

pub fn router(state: SharedState) -> Router {
    Router::new()
        .route("/api/v1/system/status", get(status_handler))
        .route(
            "/api/v1/networks",
            post(create_network_handler).get(list_networks_handler),
        )
        .route(
            "/api/v1/networks/{network_id}/invites",
            post(create_invite_handler),
        )
        .route(
            "/api/v1/networks/{network_id}/invites/{invite_id}",
            delete(revoke_invite_handler),
        )
        .route(
            "/api/v1/networks/{network_id}/devices",
            get(list_devices_handler),
        )
        .route("/api/v1/enroll", post(enroll_handler))
        .with_state(state)
}

impl IntoResponse for service::ServiceError {
    fn into_response(self) -> Response {
        let status = match &self {
            service::ServiceError::NetworkNotFound(_)
            | service::ServiceError::InviteNotFound(_)
            | service::ServiceError::InvalidInviteToken => StatusCode::NOT_FOUND,
            service::ServiceError::InvalidCidr(_) | service::ServiceError::InvalidInput(_) => {
                StatusCode::BAD_REQUEST
            }
            service::ServiceError::Conflict(_) => StatusCode::CONFLICT,
            service::ServiceError::Internal(_) => StatusCode::INTERNAL_SERVER_ERROR,
        };
        (status, Json(self.into_response())).into_response()
    }
}
