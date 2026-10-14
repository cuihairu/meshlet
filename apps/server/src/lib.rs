//! meshlet-server 库入口：路由构建可供集成测试复用。
//!
//! 控制平面路由（契约见 docs/architecture/api-contract.md）：
//! 状态/网络/邀请/设备加入/控制台认证（[ADR-010](../../docs/decisions/adr-010-console-auth-enrollment.md)）。
//!
//! 路由分层：
//! - 公开：`/system/status`、`/enroll`（自带邀请 Token 鉴权）、`/auth/bootstrap|login`；
//! - 管理（`AuthenticatedUser`：Cookie 会话或 `mlt_` API Token；写请求另挂
//!   `WriteUser` + `CsrfHeader`）：`/auth/tokens*`、`/networks*`、
//!   `/networks/{id}/invites*`、`/networks/{id}/devices`、`/networks/{id}/revisions*`。

pub mod agent;
pub mod api_token;
pub mod auth;
pub mod revision;
pub mod service;
pub mod store;

use axum::extract::State;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::{delete, get, post};
use axum::{Json, Router};
use serde::Serialize;

use crate::auth::{AuthenticatedUser, CsrfHeader, SharedAppState, WriteUser};
use crate::service::{
    create_invite, create_network, create_route, delete_route, enroll, get_route, list_devices,
    list_networks, list_routes, revoke_device, revoke_invite,
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
    State(state): State<SharedAppState>,
    WriteUser(_user): WriteUser,
    CsrfHeader: CsrfHeader,
    Json(req): Json<service::CreateNetworkRequest>,
) -> Result<(StatusCode, Json<service::NetworkView>), service::ServiceError> {
    let mut guard = state.mesh.lock().unwrap();
    Ok((StatusCode::CREATED, Json(create_network(&mut guard, req)?)))
}

async fn list_networks_handler(
    State(state): State<SharedAppState>,
    AuthenticatedUser(_user): AuthenticatedUser,
) -> Result<Json<Vec<service::NetworkView>>, service::ServiceError> {
    let guard = state.mesh.lock().unwrap();
    Ok(Json(list_networks(&guard)))
}

async fn create_invite_handler(
    State(state): State<SharedAppState>,
    WriteUser(_user): WriteUser,
    CsrfHeader: CsrfHeader,
    axum::extract::Path(network_id): axum::extract::Path<String>,
    Json(req): Json<service::CreateInviteRequest>,
) -> Result<(StatusCode, Json<service::CreateInviteResponse>), service::ServiceError> {
    let mut guard = state.mesh.lock().unwrap();
    Ok((
        StatusCode::CREATED,
        Json(create_invite(&mut guard, &network_id, req)?),
    ))
}

async fn revoke_invite_handler(
    State(state): State<SharedAppState>,
    WriteUser(_user): WriteUser,
    CsrfHeader: CsrfHeader,
    axum::extract::Path((network_id, invite_id)): axum::extract::Path<(String, String)>,
) -> Result<StatusCode, service::ServiceError> {
    let mut guard = state.mesh.lock().unwrap();
    revoke_invite(&mut guard, &network_id, &invite_id)?;
    Ok(StatusCode::NO_CONTENT)
}

async fn list_devices_handler(
    State(state): State<SharedAppState>,
    AuthenticatedUser(_user): AuthenticatedUser,
    axum::extract::Path(network_id): axum::extract::Path<String>,
) -> Result<Json<Vec<service::DeviceView>>, service::ServiceError> {
    let guard = state.mesh.lock().unwrap();
    Ok(Json(list_devices(&guard, &network_id)?))
}

async fn create_route_handler(
    State(state): State<SharedAppState>,
    WriteUser(_user): WriteUser,
    CsrfHeader: CsrfHeader,
    axum::extract::Path(network_id): axum::extract::Path<String>,
    Json(req): Json<service::CreateRouteRequest>,
) -> Result<(StatusCode, Json<service::RouteView>), service::ServiceError> {
    let mut guard = state.mesh.lock().unwrap();
    Ok((
        StatusCode::CREATED,
        Json(create_route(&mut guard, &network_id, req)?),
    ))
}

async fn list_routes_handler(
    State(state): State<SharedAppState>,
    AuthenticatedUser(_user): AuthenticatedUser,
    axum::extract::Path(network_id): axum::extract::Path<String>,
) -> Result<Json<Vec<service::RouteView>>, service::ServiceError> {
    let guard = state.mesh.lock().unwrap();
    Ok(Json(list_routes(&guard, &network_id)?))
}

async fn get_route_handler(
    State(state): State<SharedAppState>,
    AuthenticatedUser(_user): AuthenticatedUser,
    axum::extract::Path((network_id, route_id)): axum::extract::Path<(String, String)>,
) -> Result<Json<service::RouteView>, service::ServiceError> {
    let guard = state.mesh.lock().unwrap();
    Ok(Json(get_route(&guard, &network_id, &route_id)?))
}

async fn delete_route_handler(
    State(state): State<SharedAppState>,
    WriteUser(_user): WriteUser,
    CsrfHeader: CsrfHeader,
    axum::extract::Path((network_id, route_id)): axum::extract::Path<(String, String)>,
) -> Result<StatusCode, service::ServiceError> {
    let mut guard = state.mesh.lock().unwrap();
    delete_route(&mut guard, &network_id, &route_id)?;
    Ok(StatusCode::NO_CONTENT)
}

async fn revoke_device_handler(
    State(state): State<SharedAppState>,
    WriteUser(_user): WriteUser,
    CsrfHeader: CsrfHeader,
    axum::extract::Path((network_id, device_id)): axum::extract::Path<(String, String)>,
) -> Result<(StatusCode, Json<service::RevisionRef>), service::ServiceError> {
    // 先完成撤销 + 修订簿记（内存操作），再在锁外失效 agent 凭证。
    let rev = {
        let mut guard = state.mesh.lock().unwrap();
        revoke_device(&mut guard, &network_id, &device_id)?
    };
    state
        .agent_tokens
        .revoke_for_device(&meshlet_domain::DeviceId(device_id), &crate::service::now())
        .await
        .map_err(|e| service::ServiceError::Internal(e.to_string()))?;
    Ok((StatusCode::ACCEPTED, Json(rev)))
}

async fn enroll_handler(
    State(state): State<SharedAppState>,
    Json(req): Json<service::EnrollRequest>,
) -> Result<(StatusCode, Json<service::EnrollResponse>), service::ServiceError> {
    // 先完成加入（内存操作），再签发 agent 凭证——锁不跨 await（future 须 Send）。
    let mut resp = {
        let mut guard = state.mesh.lock().unwrap();
        enroll(&mut guard, req)?
    };
    let device_id = meshlet_domain::DeviceId(resp.device_id.clone());
    let (raw, _hash) = state
        .agent_tokens
        .issue(&device_id, service::now())
        .await
        .map_err(|e| service::ServiceError::Internal(e.to_string()))?;
    resp.agent_token = raw;
    Ok((StatusCode::CREATED, Json(resp)))
}

/// 构建完整路由。
pub fn router(state: SharedAppState) -> Router {
    Router::new()
        .merge(api_token::routes())
        .merge(revision::routes())
        .route("/api/v1/system/status", get(status_handler))
        .route("/api/v1/enroll", post(enroll_handler))
        .route("/api/v1/auth/bootstrap", post(auth::bootstrap_handler))
        .route("/api/v1/auth/login", post(auth::login_handler))
        .route("/api/v1/auth/logout", post(auth::logout_handler))
        .route("/api/v1/auth/me", get(auth::me_handler))
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
        .route("/api/v1/agent/heartbeat", post(agent::heartbeat_handler))
        .with_state(state)
}

/// 构建带控制台静态托管的完整路由：`console_dir`（通常是 `console/dist`）
/// 作为非 `/api` 路径的回落文件服务（`/api/v1/*` 路由优先级不受影响）。
pub fn router_with_console(state: SharedAppState, console_dir: &str) -> Router {
    router(state).fallback_service(tower_http::services::ServeDir::new(console_dir))
}

impl IntoResponse for service::ServiceError {
    fn into_response(self) -> Response {
        let status = match &self {
            service::ServiceError::NetworkNotFound(_)
            | service::ServiceError::InviteNotFound(_)
            | service::ServiceError::DeviceNotFound(_)
            | service::ServiceError::RouteNotFound(_)
            | service::ServiceError::RevisionNotFound(_)
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
