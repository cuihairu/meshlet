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
pub mod diagnostics;
pub mod metrics;
pub mod persist;
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
    // 变更 + 落库同一互斥段（§17.3）：DB 镜像与内存变更序一致。
    let _persist = state.persist.lock().await;
    let (view, network, revision) = {
        let mut guard = state.mesh.lock().unwrap();
        let view = create_network(&mut guard, req)?;
        let network = guard.network_row(&view.id).expect("just created").clone();
        let revision = guard
            .ledger
            .get(
                &meshlet_domain::NetworkId(view.id.clone()),
                view.revision_id,
            )
            .expect("just recorded")
            .clone();
        (view, network, revision)
    };
    // 落库失败即请求失败（「不落库不放行」）；审计随后留痕。
    crate::persist::insert_network(state.auth.pool(), &network)
        .await
        .map_err(crate::persist::internal)?;
    crate::persist::insert_revision(state.auth.pool(), &revision)
        .await
        .map_err(crate::persist::internal)?;
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
    let _persist = state.persist.lock().await;
    let (resp, invite) = {
        let mut guard = state.mesh.lock().unwrap();
        let resp = create_invite(&mut guard, &network_id, req)?;
        let invite = guard
            .invite_by_hash(&meshlet_domain::token_hash(&resp.token))
            .expect("just created")
            .clone();
        (resp, invite)
    };
    crate::persist::save_invite(state.auth.pool(), &invite)
        .await
        .map_err(crate::persist::internal)?;
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
    let _persist = state.persist.lock().await;
    let invite = {
        let mut guard = state.mesh.lock().unwrap();
        revoke_invite(&mut guard, &network_id, &invite_id)?;
        // 撤销落在内存后取回整份邀请（摘要索引），回写撤销时刻。
        let invite = guard
            .invites()
            .find(|i| i.id.to_string() == invite_id)
            .expect("just revoked")
            .clone();
        invite
    };
    crate::persist::save_invite(state.auth.pool(), &invite)
        .await
        .map_err(crate::persist::internal)?;
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
    let _persist = state.persist.lock().await;
    let (view, route, revision, route_seq) = {
        let mut guard = state.mesh.lock().unwrap();
        match create_route(&mut guard, &network_id, req) {
            Ok(view) => {
                let route = guard
                    .lan_routes
                    .get(&network_id)
                    .and_then(|routes| routes.iter().find(|r| r.id.to_string() == view.id))
                    .expect("just created")
                    .clone();
                let revision = guard
                    .ledger
                    .get(
                        &meshlet_domain::NetworkId(network_id.clone()),
                        view.revision_id,
                    )
                    .expect("just recorded")
                    .clone();
                (view, route, revision, guard.route_seq())
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
    crate::persist::insert_route(state.auth.pool(), &route, route_seq)
        .await
        .map_err(crate::persist::internal)?;
    crate::persist::insert_revision(state.auth.pool(), &revision)
        .await
        .map_err(crate::persist::internal)?;
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
pub(crate) fn record_route_conflict(state: &SharedAppState) {
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
    let _persist = state.persist.lock().await;
    let revision = {
        let mut guard = state.mesh.lock().unwrap();
        delete_route(&mut guard, &network_id, &route_id)?;
        // 删除记录了新修订（当前最新）：取出以镜像落库。
        guard
            .ledger
            .current(&meshlet_domain::NetworkId(network_id.clone()))
            .expect("delete_route just recorded a revision")
            .clone()
    };
    // 删除 + 新修订落库；路由 id 序列不回退（重启不重发已删 id）。
    crate::persist::delete_route(state.auth.pool(), &route_id)
        .await
        .map_err(crate::persist::internal)?;
    crate::persist::insert_revision(state.auth.pool(), &revision)
        .await
        .map_err(crate::persist::internal)?;
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
    // 先完成撤销 + 修订簿记 + 落库（同一互斥段），再在锁外失效 agent 凭证并留痕。
    let _persist = state.persist.lock().await;
    let (rev, device, revision) = {
        let mut guard = state.mesh.lock().unwrap();
        let rev = revoke_device(&mut guard, &network_id, &device_id)?;
        let device = guard
            .registry
            .find_by_id(&meshlet_domain::DeviceId(device_id.clone()))
            .expect("just revoked")
            .clone();
        let revision = guard
            .ledger
            .get(
                &meshlet_domain::NetworkId(network_id.clone()),
                rev.revision_id,
            )
            .expect("just recorded")
            .clone();
        (rev, device, revision)
    };
    // §11.5：撤销设备状态 + 其发布的全部 LAN 路由 + 新修订一并落库。
    crate::persist::update_device_status(state.auth.pool(), &device)
        .await
        .map_err(crate::persist::internal)?;
    crate::persist::delete_routes_of_device(state.auth.pool(), &device_id)
        .await
        .map_err(crate::persist::internal)?;
    crate::persist::insert_revision(state.auth.pool(), &revision)
        .await
        .map_err(crate::persist::internal)?;
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
    // 先完成加入（内存变更 + 落库同一互斥段），再签发 agent 凭证——锁不跨
    // mesh 锁的 await（future 须 Send）。
    let _persist = state.persist.lock().await;
    let invite_token = req.invite_token.clone();
    let (mut resp, device, revision, invite) = {
        let mut guard = state.mesh.lock().unwrap();
        let resp = enroll(&mut guard, req)?;
        let device = guard
            .registry
            .find_by_id(&meshlet_domain::DeviceId(resp.device_id.clone()))
            .expect("just enrolled")
            .clone();
        let revision = guard
            .ledger
            .get(
                &meshlet_domain::NetworkId(resp.network_id.clone()),
                resp.revision_id,
            )
            .expect("just recorded")
            .clone();
        let invite = guard
            .invite_by_hash(&meshlet_domain::token_hash(&invite_token))
            .expect("invite just redeemed")
            .clone();
        (resp, device, revision, invite)
    };
    // 设备行 + 新修订 + 邀请兑换计数落库（§17.3：重启后设备与 IP 保留）。
    crate::persist::insert_device(state.auth.pool(), &device)
        .await
        .map_err(crate::persist::internal)?;
    crate::persist::insert_revision(state.auth.pool(), &revision)
        .await
        .map_err(crate::persist::internal)?;
    crate::persist::save_invite(state.auth.pool(), &invite)
        .await
        .map_err(crate::persist::internal)?;
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
        .merge(alias::routes())
        .merge(api_token::routes())
        .merge(audit::routes())
        .merge(backup::routes())
        .merge(diagnostics::routes())
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
            | service::ServiceError::AliasNotFound(_)
            | service::ServiceError::RevisionNotFound(_)
            | service::ServiceError::DiagnosticsNotRun(_)
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
