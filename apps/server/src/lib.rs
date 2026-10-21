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
pub mod metrics;
pub mod persist;
pub mod revision;
pub mod segment;
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
    approve_registration, create_bootstrap_token, create_host_forward, create_invite,
    create_network, create_route, delete_host_forward, delete_route, deny_registration, enroll,
    get_route, list_bootstrap_tokens, list_devices, list_host_forwards, list_networks,
    list_registrations, list_routes, register_device, revoke_bootstrap_token, revoke_device,
    revoke_invite,
};

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

async fn status_handler() -> Json<SystemStatus> {
    Json(system_status())
}

async fn update_manifest_handler() -> Json<UpdateManifest> {
    Json(update_manifest(
        "https://releases.meshlet.dev/meshlet-agent",
        "0000000000000000000000000000000000000000000000000000000000000000",
    ))
}

async fn create_network_handler(
    State(state): State<SharedAppState>,
    WriteUser(user_id): WriteUser,
    CsrfHeader: CsrfHeader,
    Json(req): Json<service::CreateNetworkRequest>,
) -> Result<(StatusCode, Json<service::NetworkView>), service::ServiceError> {
    // 变更 + 落库同一互斥段（§17.3）：DB 镜像与内存变更序一致。
    let _persist = state.persist.lock().await;
    let (view, network, revision, staged) = {
        let guard = state.mesh.lock().unwrap();
        let mut staged = guard.clone();
        crate::revision::network_dataplane(
            &state.dataplane,
            &format!("net-{}", guard.network_count() + 1),
        )
        .map_err(service::ServiceError::InvalidInput)?;
        let view = create_network(&mut staged, req)?;
        let network = staged.network_row(&view.id).expect("just created").clone();
        let revision = staged
            .ledger
            .get(
                &meshlet_domain::NetworkId(view.id.clone()),
                view.revision_id,
            )
            .expect("just recorded")
            .clone();
        (view, network, revision, staged)
    };
    let audit = crate::persist::AuditDraft {
        actor_id: Some(&user_id.0),
        action: "network.created",
        target_type: "network",
        target_id: &view.id,
        detail: None,
    };
    crate::persist::commit_network(state.auth.pool(), &network, &revision, &audit)
        .await
        .map_err(crate::persist::internal)?;
    *state.mesh.lock().unwrap() = staged;
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

async fn create_host_forward_handler(
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

async fn delete_host_forward_handler(
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

async fn list_host_forwards_handler(
    State(state): State<SharedAppState>,
    AuthenticatedUser(_user): AuthenticatedUser,
    axum::extract::Path(network_id): axum::extract::Path<String>,
) -> Result<Json<Vec<service::HostForwardView>>, service::ServiceError> {
    let guard = state.mesh.lock().unwrap();
    Ok(Json(list_host_forwards(&guard, &network_id)?))
}

async fn revoke_device_handler(
    State(state): State<SharedAppState>,
    WriteUser(user_id): WriteUser,
    CsrfHeader: CsrfHeader,
    axum::extract::Path((network_id, device_id)): axum::extract::Path<(String, String)>,
) -> Result<(StatusCode, Json<service::RevisionRef>), service::ServiceError> {
    // 先完成撤销 + 修订簿记 + 落库（同一互斥段），再在锁外失效 agent 凭证并留痕。
    let _persist = state.persist.lock().await;
    let (rev, device, revision, staged) = {
        let guard = state.mesh.lock().unwrap();
        let mut staged = guard.clone();
        let rev = revoke_device(&mut staged, &network_id, &device_id)?;
        let device = staged
            .registry
            .find_by_id(&meshlet_domain::DeviceId(device_id.clone()))
            .expect("just revoked")
            .clone();
        let revision = staged
            .ledger
            .get(
                &meshlet_domain::NetworkId(network_id.clone()),
                rev.revision_id,
            )
            .expect("just recorded")
            .clone();
        (rev, device, revision, staged)
    };
    let audit = crate::persist::AuditDraft {
        actor_id: Some(&user_id.0),
        action: "device.revoked",
        target_type: "device",
        target_id: &device_id,
        detail: Some(serde_json::json!({ "network_id": network_id })),
    };
    crate::persist::commit_revoke_device(state.auth.pool(), &device, &revision, &audit)
        .await
        .map_err(crate::persist::internal)?;
    *state.mesh.lock().unwrap() = staged;
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
    let (mut resp, device, revision, invite, staged) = {
        let guard = state.mesh.lock().unwrap();
        let mut staged = guard.clone();
        let resp = enroll(&mut staged, req)?;
        let device = staged
            .registry
            .find_by_id(&meshlet_domain::DeviceId(resp.device_id.clone()))
            .expect("just enrolled")
            .clone();
        let revision = staged
            .ledger
            .get(
                &meshlet_domain::NetworkId(resp.network_id.clone()),
                resp.revision_id,
            )
            .expect("just recorded")
            .clone();
        let invite = staged
            .invite_by_hash(&meshlet_domain::token_hash(&invite_token))
            .expect("invite just redeemed")
            .clone();
        (resp, device, revision, invite, staged)
    };
    let audit = crate::persist::AuditDraft {
        actor_id: None,
        action: "device.enrolled",
        target_type: "device",
        target_id: &resp.device_id,
        detail: Some(serde_json::json!({ "network_id": resp.network_id })),
    };
    let raw_agent_token =
        crate::persist::commit_enrollment(state.auth.pool(), &device, &revision, &invite, &audit)
            .await
            .map_err(crate::persist::internal)?;
    resp.agent_token = raw_agent_token;
    *state.mesh.lock().unwrap() = staged;
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

// ---------------------------------------------------------------------------
// 设备自举注册（ZeroTier 式：自举码注册 → Pending → 控制中心审批/拒绝）
// ---------------------------------------------------------------------------

async fn create_bootstrap_token_handler(
    State(state): State<SharedAppState>,
    WriteUser(user_id): WriteUser,
    CsrfHeader: CsrfHeader,
    axum::extract::Path(network_id): axum::extract::Path<String>,
    Json(req): Json<service::CreateBootstrapTokenRequest>,
) -> Result<(StatusCode, Json<service::CreateBootstrapTokenResponse>), service::ServiceError> {
    let _persist = state.persist.lock().await;
    let (resp, token, seq) = {
        let mut guard = state.mesh.lock().unwrap();
        let resp = create_bootstrap_token(&mut guard, &network_id, req)?;
        let token = guard
            .bootstrap_tokens
            .get(&meshlet_domain::token_hash(&resp.token))
            .expect("just created")
            .clone();
        (resp, token, guard.bootstrap_seq())
    };
    // 摘要 + 序列落库（§17.3：重启后自举码继续可用，`bt-N` 不重号）。
    crate::persist::save_bootstrap_token(state.auth.pool(), &token, seq)
        .await
        .map_err(crate::persist::internal)?;
    // 原始自举码不进审计（§16.5，同邀请 Token 纪律）。
    crate::audit::record_or_fail(
        &state,
        Some(&user_id.0),
        "bootstrap_token.created",
        "bootstrap_token",
        Some(&resp.token_id),
        Some(serde_json::json!({
            "network_id": network_id,
            "max_uses": resp.max_uses,
        })),
    )
    .await?;
    crate::op_log!(
        info,
        "network",
        "create_bootstrap_token",
        &network_id,
        crate::telemetry::NOT_APPLICABLE,
        crate::telemetry::NOT_APPLICABLE,
        crate::telemetry::ErrorCategory::None.as_str(),
        crate::telemetry::RESULT_OK
    );
    Ok((StatusCode::CREATED, Json(resp)))
}

async fn list_bootstrap_tokens_handler(
    State(state): State<SharedAppState>,
    AuthenticatedUser(_user): AuthenticatedUser,
    axum::extract::Path(network_id): axum::extract::Path<String>,
) -> Result<Json<Vec<service::BootstrapTokenView>>, service::ServiceError> {
    let guard = state.mesh.lock().unwrap();
    Ok(Json(list_bootstrap_tokens(&guard, &network_id)?))
}

async fn revoke_bootstrap_token_handler(
    State(state): State<SharedAppState>,
    WriteUser(user_id): WriteUser,
    CsrfHeader: CsrfHeader,
    axum::extract::Path((network_id, token_id)): axum::extract::Path<(String, String)>,
) -> Result<StatusCode, service::ServiceError> {
    let _persist = state.persist.lock().await;
    let revoked_at = {
        let mut guard = state.mesh.lock().unwrap();
        revoke_bootstrap_token(&mut guard, &network_id, &token_id)?
    };
    crate::persist::revoke_bootstrap_token_db(
        state.auth.pool(),
        &meshlet_domain::BootstrapTokenId(token_id.clone()),
        &revoked_at,
    )
    .await
    .map_err(crate::persist::internal)?;
    crate::audit::record_or_fail(
        &state,
        Some(&user_id.0),
        "bootstrap_token.revoked",
        "bootstrap_token",
        Some(token_id.as_str()),
        Some(serde_json::json!({ "network_id": network_id })),
    )
    .await?;
    crate::op_log!(
        info,
        "network",
        "revoke_bootstrap_token",
        &network_id,
        crate::telemetry::NOT_APPLICABLE,
        crate::telemetry::NOT_APPLICABLE,
        crate::telemetry::ErrorCategory::None.as_str(),
        crate::telemetry::RESULT_OK
    );
    Ok(StatusCode::NO_CONTENT)
}

/// 设备自举注册（公开端点，设备凭自举码而来，无用户会话）。落 Pending
/// 申请并签发 agent 凭证——凭证**仅此一次**返回（§11.3）。
async fn register_device_handler(
    State(state): State<SharedAppState>,
    Json(req): Json<service::RegisterDeviceRequest>,
) -> Result<(StatusCode, Json<service::RegisterDeviceResponse>), service::ServiceError> {
    let _persist = state.persist.lock().await;
    // 摘要先行：req 被 service 消费后仍需定位刚被递增的自举码以落库。
    let token_hash = meshlet_domain::token_hash(&req.bootstrap_token);
    let (mut resp, registration, seq, token, bootstrap_seq) = {
        let mut guard = state.mesh.lock().unwrap();
        let resp = register_device(&mut guard, req)?;
        let registration = guard
            .registry
            .find_registration(&meshlet_domain::DeviceId(resp.device_id.clone()))
            .expect("just registered")
            .clone();
        // 使用次数随注册递增，同步落库——否则重启后计数回退，max_uses
        // 限制可被重启绕过。
        let token = guard
            .bootstrap_tokens
            .get(&token_hash)
            .expect("token validated by service")
            .clone();
        (
            resp,
            registration,
            guard.registration_seq(),
            token,
            guard.bootstrap_seq(),
        )
    };
    crate::persist::insert_registration(state.auth.pool(), &registration, seq)
        .await
        .map_err(crate::persist::internal)?;
    crate::persist::save_bootstrap_token(state.auth.pool(), &token, bootstrap_seq)
        .await
        .map_err(crate::persist::internal)?;
    let device_id = meshlet_domain::DeviceId(resp.device_id.clone());
    let (raw, _hash) = state
        .agent_tokens
        .issue(&device_id, service::now())
        .await
        .map_err(|e| service::ServiceError::Internal(e.to_string()))?;
    resp.agent_token = raw;
    // 注册者凭自举码而来，无用户 actor；agent 凭证原始材料不进审计（§16.5）。
    crate::audit::record_or_fail(
        &state,
        None,
        "device.registered",
        "device",
        Some(&resp.device_id),
        Some(serde_json::json!({
            "network_id": resp.network_id,
            "name": registration.name,
        })),
    )
    .await?;
    crate::op_log!(
        info,
        "device",
        "register",
        &resp.network_id,
        &resp.device_id,
        crate::telemetry::NOT_APPLICABLE,
        crate::telemetry::ErrorCategory::None.as_str(),
        crate::telemetry::RESULT_OK
    );
    Ok((StatusCode::CREATED, Json(resp)))
}

async fn list_registrations_handler(
    State(state): State<SharedAppState>,
    AuthenticatedUser(_user): AuthenticatedUser,
    axum::extract::Path(network_id): axum::extract::Path<String>,
) -> Result<Json<Vec<service::RegistrationView>>, service::ServiceError> {
    let guard = state.mesh.lock().unwrap();
    Ok(Json(list_registrations(&guard, &network_id)?))
}

/// 批准注册：Pending 申请转正为设备（此刻才分配 overlay 地址），新修订
/// 随期望配置下发；Pending 凭证作废并换发新凭证（仅此一次返回）。
async fn approve_registration_handler(
    State(state): State<SharedAppState>,
    WriteUser(user_id): WriteUser,
    CsrfHeader: CsrfHeader,
    axum::extract::Path((network_id, device_id)): axum::extract::Path<(String, String)>,
) -> Result<(StatusCode, Json<service::ApproveRegistrationResponse>), service::ServiceError> {
    let _persist = state.persist.lock().await;
    let (registration, device, revision, revision_id, approved_at, audit_detail, staged) = {
        let guard = state.mesh.lock().unwrap();
        let mut staged = guard.clone();
        let (registration, device, revision_id) =
            approve_registration(&mut staged, &network_id, &device_id)?;
        let revision = staged
            .ledger
            .get(&meshlet_domain::NetworkId(network_id.clone()), revision_id)
            .expect("just recorded")
            .clone();
        let approved_at = device.approved_at.clone().expect("just approved");
        let audit_detail = serde_json::json!({
            "network_id": network_id,
            "virtual_ipv4": device.virtual_ipv4.to_string(),
            "revision_id": revision_id,
        });
        (
            registration,
            device,
            revision,
            revision_id,
            approved_at,
            audit_detail,
            staged,
        )
    };
    let audit = crate::persist::AuditDraft {
        actor_id: Some(&user_id.0),
        action: "device.approved",
        target_type: "device",
        target_id: &device.id.to_string(),
        detail: Some(audit_detail.clone()),
    };
    crate::persist::commit_approve_registration(
        state.auth.pool(),
        &registration,
        &device,
        &revision,
        &audit,
    )
    .await
    .map_err(crate::persist::internal)?;
    *state.mesh.lock().unwrap() = staged;
    let resp = service::ApproveRegistrationResponse {
        device_id: device.id.to_string(),
        network_id: device.network_id.to_string(),
        virtual_ipv4: device.virtual_ipv4,
        fingerprint: crate::service::fingerprint_of(&device.public_key),
        revision_id,
        apply_status: meshlet_domain::ApplyStatus::Pending.as_str().to_string(),
        approved_at,
    };
    crate::op_log!(
        info,
        "device",
        "approve_registration",
        &network_id,
        &resp.device_id,
        &revision_id.to_string(),
        crate::telemetry::ErrorCategory::None.as_str(),
        crate::telemetry::RESULT_OK
    );
    Ok((StatusCode::CREATED, Json(resp)))
}

/// 拒绝注册：申请摘除、Pending 凭证作废。不记修订（期望配置从未包含过
/// Pending 申请）。
async fn deny_registration_handler(
    State(state): State<SharedAppState>,
    WriteUser(user_id): WriteUser,
    CsrfHeader: CsrfHeader,
    axum::extract::Path((network_id, device_id)): axum::extract::Path<(String, String)>,
) -> Result<StatusCode, service::ServiceError> {
    let _persist = state.persist.lock().await;
    let registration = {
        let mut guard = state.mesh.lock().unwrap();
        deny_registration(&mut guard, &network_id, &device_id)?
    };
    // 申请行 + Pending 凭证同一事务清理（persist::delete_registration_db）。
    crate::persist::delete_registration_db(state.auth.pool(), &registration.id)
        .await
        .map_err(crate::persist::internal)?;
    crate::audit::record_or_fail(
        &state,
        Some(&user_id.0),
        "device.denied",
        "device",
        Some(&registration.id.to_string()),
        Some(serde_json::json!({
            "network_id": network_id,
            "name": registration.name,
        })),
    )
    .await?;
    crate::op_log!(
        info,
        "device",
        "deny_registration",
        &network_id,
        &registration.id.to_string(),
        crate::telemetry::NOT_APPLICABLE,
        crate::telemetry::ErrorCategory::None.as_str(),
        crate::telemetry::RESULT_OK
    );
    Ok(StatusCode::NO_CONTENT)
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
            "/api/v1/agent/device/desired",
            get(agent::desired_device_plan_handler),
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
            | service::ServiceError::SegmentNotFound(_)
            | service::ServiceError::SegmentGrantNotFound(_)
            | service::ServiceError::RevisionNotFound(_)
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
