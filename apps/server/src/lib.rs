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
pub mod audit;
pub mod auth;
pub mod metrics;
pub mod revision;
pub mod service;
pub mod store;
pub mod telemetry;

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
    WriteUser(user_id): WriteUser,
    CsrfHeader: CsrfHeader,
    Json(req): Json<service::CreateNetworkRequest>,
) -> Result<(StatusCode, Json<service::NetworkView>), service::ServiceError> {
    let view = {
        let mut guard = state.mesh.lock().unwrap();
        create_network(&mut guard, req)?
    };
    crate::audit::record_or_fail(
        &state,
        Some(&user_id.0),
        "network.created",
        "network",
        Some(&view.id),
        None,
    )
    .await?;
    crate::op_log!(
        info,
        "network",
        "create_network",
        &view.id,
        crate::telemetry::NOT_APPLICABLE,
        &view.revision_id.to_string(),
        crate::telemetry::ErrorCategory::None.as_str(),
        crate::telemetry::RESULT_OK
    );
    Ok((StatusCode::CREATED, Json(view)))
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
    WriteUser(user_id): WriteUser,
    CsrfHeader: CsrfHeader,
    axum::extract::Path(network_id): axum::extract::Path<String>,
    Json(req): Json<service::CreateInviteRequest>,
) -> Result<(StatusCode, Json<service::CreateInviteResponse>), service::ServiceError> {
    let resp = {
        let mut guard = state.mesh.lock().unwrap();
        create_invite(&mut guard, &network_id, req)?
    };
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

async fn revoke_invite_handler(
    State(state): State<SharedAppState>,
    WriteUser(user_id): WriteUser,
    CsrfHeader: CsrfHeader,
    axum::extract::Path((network_id, invite_id)): axum::extract::Path<(String, String)>,
) -> Result<StatusCode, service::ServiceError> {
    {
        let mut guard = state.mesh.lock().unwrap();
        revoke_invite(&mut guard, &network_id, &invite_id)?;
    }
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
    WriteUser(user_id): WriteUser,
    CsrfHeader: CsrfHeader,
    axum::extract::Path(network_id): axum::extract::Path<String>,
    Json(req): Json<service::CreateRouteRequest>,
) -> Result<(StatusCode, Json<service::RouteView>), service::ServiceError> {
    let view = {
        let mut guard = state.mesh.lock().unwrap();
        match create_route(&mut guard, &network_id, req) {
            Ok(view) => view,
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
    crate::audit::record_or_fail(
        &state,
        Some(&user_id.0),
        "route.created",
        "route",
        Some(&view.id),
        Some(serde_json::json!({ "network_id": network_id })),
    )
    .await?;
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

/// 路由冲突拒绝（§17.2「路由冲突数」指标）：仅计「目的网段重叠」类冲突
/// （`ServiceError::RouteConflict`）；设备未激活等其它 409 不计。
fn record_route_conflict(state: &SharedAppState) {
    state.metrics.record_route_conflict();
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
    WriteUser(user_id): WriteUser,
    CsrfHeader: CsrfHeader,
    axum::extract::Path((network_id, route_id)): axum::extract::Path<(String, String)>,
) -> Result<StatusCode, service::ServiceError> {
    {
        let mut guard = state.mesh.lock().unwrap();
        delete_route(&mut guard, &network_id, &route_id)?;
    }
    crate::audit::record_or_fail(
        &state,
        Some(&user_id.0),
        "route.deleted",
        "route",
        Some(&route_id),
        Some(serde_json::json!({ "network_id": network_id })),
    )
    .await?;
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

async fn revoke_device_handler(
    State(state): State<SharedAppState>,
    WriteUser(user_id): WriteUser,
    CsrfHeader: CsrfHeader,
    axum::extract::Path((network_id, device_id)): axum::extract::Path<(String, String)>,
) -> Result<(StatusCode, Json<service::RevisionRef>), service::ServiceError> {
    // 先完成撤销 + 修订簿记（内存操作），再在锁外失效 agent 凭证并留痕。
    let rev = {
        let mut guard = state.mesh.lock().unwrap();
        revoke_device(&mut guard, &network_id, &device_id)?
    };
    state
        .agent_tokens
        .revoke_for_device(
            &meshlet_domain::DeviceId(device_id.clone()),
            &crate::service::now(),
        )
        .await
        .map_err(|e| service::ServiceError::Internal(e.to_string()))?;
    crate::audit::record_or_fail(
        &state,
        Some(&user_id.0),
        "device.revoked",
        "device",
        Some(&device_id),
        Some(serde_json::json!({ "network_id": network_id })),
    )
    .await?;
    crate::op_log!(
        info,
        "device",
        "revoke_device",
        &network_id,
        &device_id,
        &rev.revision_id.to_string(),
        crate::telemetry::ErrorCategory::None.as_str(),
        crate::telemetry::RESULT_OK
    );
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
    // 加入者经邀请 Token 而来，无用户 actor（actor=None）；agent Token 原始
    // 材料不进审计（§16.5）。
    crate::audit::record_or_fail(
        &state,
        None,
        "device.enrolled",
        "device",
        Some(&resp.device_id),
        Some(serde_json::json!({ "network_id": resp.network_id })),
    )
    .await?;
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

/// 构建完整路由。
pub fn router(state: SharedAppState) -> Router {
    Router::new()
        .merge(api_token::routes())
        .merge(audit::routes())
        .merge(metrics::routes())
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
        // 访问日志（§17.1）+ HTTP 指标计数（§17.2）：路由模板级，不跨静态回落。
        .layer(axum::middleware::from_fn_with_state(
            state.clone(),
            telemetry::request_log,
        ))
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
            service::ServiceError::Conflict(_) | service::ServiceError::RouteConflict(_) => {
                StatusCode::CONFLICT
            }
            service::ServiceError::Internal(_) => StatusCode::INTERNAL_SERVER_ERROR,
        };
        (status, Json(self.into_response())).into_response()
    }
}
