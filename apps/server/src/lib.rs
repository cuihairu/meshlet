//! meshlet-server 库入口：路由构建可供集成测试复用。
//!
//! 控制平面路由（契约见 docs/architecture/api-contract.md）：
//! 状态/网络/邀请/设备加入/控制台认证（[ADR-010](../../docs/decisions/adr-010-console-auth-enrollment.md)）。
//!
//! 路由分层：
//! - 公开：`/system/status`、`/enroll`（自带邀请 Token 鉴权）、`/auth/bootstrap|login`；
//! - 管理（`AuthenticatedUser`：Cookie 会话或 `mlt_` API Token；写请求另挂
//!   `WriteUser` + `CsrfHeader`）：`/auth/tokens*`、`/networks*`、
//!   `/networks/{id}/invites*`、`/networks/{id}/devices`、`/networks/{id}/revisions*`、
//!   `/networks/{id}/routes*`、`/networks/{id}/aliases*`（§12.6，删除即整单元清理）、
//!   `/networks/{id}/diagnostics`（§12.7 十三项，POST 触发、GET 读最近快照）、
//!   `/system/backup`（§17.4，目录未配置时 503）。

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

// HTTP handler 按资源族分组（private 子模块，公开 API 不变）。
mod handlers;

use crate::auth::SharedAppState;
use crate::handlers::*;

use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::{delete, get, post};
use axum::{Json, Router};
use serde::Serialize;

/// `GET /api/v1/system/status` 响应（契约见 docs/architecture/api-contract.md）。
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

/// 路由冲突拒绝（§17.2「路由冲突数」指标）：仅计「目的网段重叠」类冲突
/// （`ServiceError::RouteConflict`）；设备未激活等其它 409 不计。
pub(crate) fn record_route_conflict(state: &SharedAppState) {
    state.metrics.record_route_conflict();
}

/// 构建完整路由。
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
        // MT-002 任务通道：agent 侧拉取/确认/回执（AuthorizedAgent 认证）。
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
