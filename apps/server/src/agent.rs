//! Agent 心跳/状态上报（[存档 §14.1](../../docs/review/chatgpt-2026-10-13.md)、
//! [§12.4](../../docs/review/chatgpt-2026-10-13.md)）。
//!
//! - Agent 凭证（`agent_tokens` 表，migration 003）与邀请/会话同一纪律：
//!   只存 SHA-256 摘要，原始 Token 仅在加入响应里出现一次；
//! - 心跳端点 `POST /api/v1/agent/heartbeat` 是 **agent API**（Bearer 凭证），
//!   与管理 API（Cookie 会话 + CSRF）认证边界清晰（§13.5）；
//! - 心跳携带 agent 本地读到的 `wg show` 握手时间（`last_handshake_at`），
//!   服务端据此 + 上报时间做在线判定（[presence] 域层）。

use axum::extract::{ConnectInfo, FromRequestParts, Path, State};
use axum::http::request::Parts;
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use meshlet_api_types::{ErrorCode, ErrorResponse};
use meshlet_domain::{
    generate_token, token_hash, DataplaneEvidence, DeviceId, DirectEndpointReport,
    DirectLinkStatus, PeerEndpoints, Timestamp,
};
use serde::{Deserialize, Serialize};
use sqlx::SqlitePool;
use std::net::SocketAddr;

use crate::auth::SharedAppState;
use crate::service;

/// Agent 凭证存储（SQLite，migration 003）。
#[derive(Clone)]
pub struct AgentTokenStore {
    pool: SqlitePool,
}

impl AgentTokenStore {
    pub fn new(pool: SqlitePool) -> Self {
        Self { pool }
    }

    /// 签发：返回 (`raw_token`, `token_hash`)。原始 Token 只在此出现一次。
    pub async fn issue(
        &self,
        device_id: &DeviceId,
        now: Timestamp,
    ) -> Result<(String, String), sqlx::Error> {
        let raw = generate_token();
        let hash = token_hash(&raw);
        sqlx::query(
            "INSERT INTO agent_tokens (token_hash, device_id, created_at)
             VALUES (?, ?, ?)",
        )
        .bind(&hash)
        .bind(&device_id.0)
        .bind(now.as_str())
        .execute(&self.pool)
        .await?;
        Ok((raw, hash))
    }

    /// 校验：存在且未撤销 → 设备 ID。
    pub async fn validate(&self, raw_token: &str) -> Result<Option<DeviceId>, sqlx::Error> {
        let row = sqlx::query_as::<_, (String, Option<String>)>(
            "SELECT device_id, revoked_at FROM agent_tokens WHERE token_hash = ?",
        )
        .bind(token_hash(raw_token))
        .fetch_optional(&self.pool)
        .await?;
        Ok(row.and_then(|(device_id, revoked_at)| {
            if revoked_at.is_none() {
                Some(DeviceId(device_id))
            } else {
                None
            }
        }))
    }

    pub async fn revoke(&self, raw_token: &str, at: &Timestamp) -> Result<(), sqlx::Error> {
        sqlx::query("UPDATE agent_tokens SET revoked_at = ? WHERE token_hash = ?")
            .bind(at.as_str())
            .bind(token_hash(raw_token))
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    /// 撤销某设备的全部 agent 凭证（设备撤销链路，§11.5）：返回失效的凭证数。
    pub async fn revoke_for_device(
        &self,
        device_id: &DeviceId,
        at: &Timestamp,
    ) -> Result<u64, sqlx::Error> {
        let result = sqlx::query(
            "UPDATE agent_tokens SET revoked_at = ? WHERE device_id = ? AND revoked_at IS NULL",
        )
        .bind(at.as_str())
        .bind(&device_id.0)
        .execute(&self.pool)
        .await?;
        Ok(result.rows_affected())
    }
}

/// 解析 `Authorization: Bearer <token>`（scheme 大小写不敏感）。
pub fn bearer_token_from_headers(headers: &HeaderMap) -> Option<String> {
    let raw = headers.get(header::AUTHORIZATION)?.to_str().ok()?;
    let (scheme, value) = raw.split_once(' ')?;
    if !scheme.eq_ignore_ascii_case("bearer") || value.is_empty() {
        return None;
    }
    Some(value.to_string())
}

/// §12 P2P：观测源地址 → 公网候选 IP。连接来自 IPv6（无 IPv4 地址）或
/// 无地址时返回 `None`——meshlet 是 IPv4 overlay，v6 观测不构成 IPv4 公网候选。
fn direct_observed_ip(addr: &SocketAddr) -> Option<std::net::Ipv4Addr> {
    match addr.ip() {
        std::net::IpAddr::V4(ip) => Some(ip),
        std::net::IpAddr::V6(_) => None,
    }
}

// ---------------------------------------------------------------------------
// 错误
// ---------------------------------------------------------------------------

#[derive(Debug)]
pub enum AgentApiError {
    Unauthorized,
    InvalidInput(String),
    NotFound(String),
    /// 服务端 `[dataplane] enabled = false`：不向 agent 下发数据面计划
    /// （503，可重试——管理员开启后计划即可用）。
    DataplaneNotConfigured(String),
    Internal(String),
}

impl IntoResponse for AgentApiError {
    fn into_response(self) -> Response {
        let (status, code, message) = match self {
            AgentApiError::Unauthorized => (
                StatusCode::UNAUTHORIZED,
                ErrorCode::Unauthorized,
                "valid agent token required".into(),
            ),
            AgentApiError::InvalidInput(m) => {
                (StatusCode::BAD_REQUEST, ErrorCode::ValidationFailed, m)
            }
            AgentApiError::NotFound(m) => (StatusCode::NOT_FOUND, ErrorCode::NotFound, m),
            AgentApiError::DataplaneNotConfigured(m) => (
                StatusCode::SERVICE_UNAVAILABLE,
                ErrorCode::DataplaneNotConfigured,
                m,
            ),
            AgentApiError::Internal(m) => {
                (StatusCode::INTERNAL_SERVER_ERROR, ErrorCode::Internal, m)
            }
        };
        (status, Json(ErrorResponse::new(code, message))).into_response()
    }
}

// ---------------------------------------------------------------------------
// 提取器（只在命中路由上运行；未知路径保持 404）
// ---------------------------------------------------------------------------

/// Agent API 认证提取器：`Authorization: Bearer <agent_token>` 无效一律 401。
#[derive(Debug, Clone)]
pub struct AuthorizedAgent(pub DeviceId);

impl FromRequestParts<SharedAppState> for AuthorizedAgent {
    type Rejection = AgentApiError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &SharedAppState,
    ) -> Result<Self, Self::Rejection> {
        let Some(token) = bearer_token_from_headers(&parts.headers) else {
            return Err(AgentApiError::Unauthorized);
        };
        match state.agent_tokens.validate(&token).await {
            Ok(Some(device_id)) => Ok(AuthorizedAgent(device_id)),
            Ok(None) => Err(AgentApiError::Unauthorized),
            Err(e) => Err(AgentApiError::Internal(e.to_string())),
        }
    }
}

// ---------------------------------------------------------------------------
// 端点
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HeartbeatRequest {
    /// agent 本地 `wg show` 读到的最近握手时间（ISO-8601）；缺省表示未取到。
    pub last_handshake_at: Option<String>,
    /// 设备侧数据面实测证据（内核读数 + 大包探测，§7.5）；缺省表示未上报。
    #[serde(default)]
    pub dataplane: Option<DataplaneEvidence>,
    /// §12 P2P 直连候选端点（监听端口 + LAN 地址）；缺省表示未上报/已关闭直连。
    #[serde(default)]
    pub direct: Option<DirectEndpointReport>,
    /// §12.3 链路状态上报：本设备对各对端的直连链路（direct / direct_pending）。
    /// 空缺省 = 全中继/旧版未上报；hub 仅存内存，供控制台展示 P2P/中继。
    #[serde(default)]
    pub direct_links: Vec<DirectLinkStatus>,
}

#[derive(Debug, Clone, Serialize)]
pub struct HeartbeatResponse {
    pub online_state: String,
    pub presence_source: String,
    pub last_seen_at: Option<String>,
}

/// `POST /api/v1/agent/heartbeat`：记录一次 agent 上报（+ 可选握手时间 +
/// §12 P2P 直连候选端点），返回当前在线判定（状态 + 数据来源 + 最后证据时间）。
///
/// 观测源地址（公网候选）来自连接 socket（[ConnectInfo]，serve 侧装配；
/// 测试经 `request.extensions_mut().insert(ConnectInfo(..))` 注入）；请求里
/// 上报的 LAN 地址是 agent 自己枚举的。候选是临时性咨询数据，仅存内存。
pub async fn heartbeat_handler(
    State(state): State<SharedAppState>,
    AuthorizedAgent(device_id): AuthorizedAgent,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    Json(req): Json<HeartbeatRequest>,
) -> Result<Json<HeartbeatResponse>, AgentApiError> {
    if let Some(ts) = &req.last_handshake_at {
        if chrono::DateTime::parse_from_rfc3339(ts).is_err() {
            return Err(AgentApiError::InvalidInput(format!(
                "last_handshake_at {ts:?} is not an RFC 3339 timestamp"
            )));
        }
    }
    let now: Timestamp = service::now();
    // 心跳证据时间戳同样落库（§17.3）：重启后 presence 按原证据判定，
    // 不虚构在线（§12.4）。Pending 注册申请的心跳走 `device_registrations`
    // 证据通道（批准前无 devices 行，§7.5 证据不丢）。
    let _persist = state.persist.lock().await;
    let (presence, network_id, device) = {
        let mut guard = state.mesh.lock().unwrap();
        match service::record_agent_report(
            &mut guard,
            &device_id,
            req.last_handshake_at.clone(),
            req.dataplane.clone(),
            now.clone(),
        ) {
            Ok(presence) => {
                let device = guard
                    .registry
                    .find_by_id(&device_id)
                    .expect("report just recorded")
                    .clone();
                let network_id = device.network_id.to_string();
                // §12：直连候选只对已注册设备记录（Pending 无隧道、不参与数据面）。
                service::record_direct_state(
                    &mut guard,
                    &device_id,
                    direct_observed_ip(&addr),
                    req.direct.clone(),
                    req.direct_links.clone(),
                );
                (Some(presence), network_id, Some(device))
            }
            Err(service::ServiceError::DeviceNotFound(_)) => {
                service::record_pending_agent_report(
                    &mut guard,
                    &device_id,
                    req.dataplane.clone(),
                    now.clone(),
                )
                .map_err(|e| match e {
                    service::ServiceError::DeviceNotFound(id) => AgentApiError::NotFound(id),
                    other => AgentApiError::Internal(other.to_string()),
                })?;
                let network_id = guard
                    .registry
                    .find_registration(&device_id)
                    .expect("just reported")
                    .network_id
                    .to_string();
                (None, network_id, None)
            }
            Err(other) => return Err(AgentApiError::Internal(other.to_string())),
        }
    };
    if let Some(device) = &device {
        crate::persist::update_device_presence(state.auth.pool(), device)
            .await
            .map_err(|e| AgentApiError::Internal(e.to_string()))?;
    } else {
        // Pending 申请：证据落 device_registrations（approval 前唯一证据通道）。
        let evidence = req
            .dataplane
            .as_ref()
            .map(serde_json::to_string)
            .transpose()
            .map_err(|e| AgentApiError::Internal(e.to_string()))?;
        crate::persist::update_registration_report(
            state.auth.pool(),
            &device_id,
            &now,
            evidence.as_deref(),
        )
        .await
        .map_err(|e| AgentApiError::Internal(e.to_string()))?;
    }
    // 指标（§17.2 agent 心跳计数）+ 结构化日志（§17.1：device 组件事件）。
    state.metrics.record_agent_heartbeat();
    crate::op_log!(
        info,
        "agent",
        "heartbeat",
        &network_id,
        &device_id.0,
        crate::telemetry::NOT_APPLICABLE,
        crate::telemetry::ErrorCategory::None.as_str(),
        crate::telemetry::RESULT_OK
    );
    // Pending 申请无隧道、不参与数据面：`pending` 明确区别于在线三态，
    // agent 据此保持退避重试而不是当隧道故障。
    let (online_state, presence_source) = match presence {
        Some(presence) => (
            presence.state.as_str().to_string(),
            presence.source.as_str().to_string(),
        ),
        None => ("pending".to_string(), "registration".to_string()),
    };
    Ok(Json(HeartbeatResponse {
        online_state,
        presence_source,
        last_seen_at: Some(now),
    }))
}

/// `GET /api/v1/agent/device/desired`：本设备的期望数据面计划。
///
/// 返回 [`meshlet_network::DevicePlan`]——**结构化配置对象**（§16.4）：类型化
/// 的隧道/路由/NAT 计划 + `desired_config_hash`。服务端**从不**下发 Shell
/// 命令；agent 只消费类型化对象并按需重放本地后端。计划里的 `private_key` 恒为
/// `null`（ADR-010：私钥不出设备，agent 本地注入）。
///
/// 服务端 `[dataplane] enabled = false` 时返回 503（管理员开启后计划即可用，
/// agent 可重试），不返回空计划——避免 agent 把「未配置」误当成「已生效」。
pub async fn desired_device_plan_handler(
    State(state): State<SharedAppState>,
    AuthorizedAgent(device_id): AuthorizedAgent,
) -> Result<Json<meshlet_network::DevicePlan>, AgentApiError> {
    let _persist = state.persist.lock().await;
    // 身份判定先于全局数据面开关：待审批的注册申请永远 404「pending approval」，
    // 否则数据面关闭时该信号被 503 掩盖，agent 与管理员都读不到真实状态。
    let (plan, network_id) = {
        let guard = state.mesh.lock().unwrap();
        let Some(device) = guard.registry.find_by_id(&device_id) else {
            // 待审批的注册申请（ZeroTier 式自举流）：404 语义同「计划不存在」
            // ——批准前不进期望配置（migration 008 取舍），agent 退避重试，
            // 批准后本端点即返回计划。
            if guard.registry.find_registration(&device_id).is_some() {
                return Err(AgentApiError::NotFound(format!(
                    "device {device_id} is pending approval: no desired plan until an operator \
                     approves the registration"
                )));
            }
            return Err(AgentApiError::NotFound(format!(
                "device {device_id} not found"
            )));
        };
        let network_id = device.network_id.to_string();
        if !state.dataplane.enabled {
            return Err(AgentApiError::DataplaneNotConfigured(
                "server dataplane is disabled: set [dataplane] enabled = true to distribute \
                 device plans"
                    .into(),
            ));
        }
        if !device.is_active() {
            return Err(AgentApiError::Unauthorized);
        }
        if !guard
            .ledger
            .current(&device.network_id)
            .is_some_and(|r| r.apply_status == meshlet_domain::ApplyStatus::Applied)
        {
            return Err(AgentApiError::DataplaneNotConfigured(
                "hub desired revision has not been applied".into(),
            ));
        }
        if !guard.deployments.contains_key(&network_id) {
            return Err(AgentApiError::DataplaneNotConfigured(
                "hub recovery has not yet confirmed this network".into(),
            ));
        }
        let hub_public_key = crate::device_plan::hub_public_key(&state.dataplane)
            .map_err(AgentApiError::Internal)?;
        let plan = crate::device_plan::build_device_plan(
            &guard,
            &network_id,
            &device_id,
            &state.dataplane,
            state.tunnel_mtu,
            &hub_public_key,
        )
        .map_err(AgentApiError::Internal)?;
        (plan, network_id)
    };
    crate::op_log!(
        info,
        "agent",
        "desired_plan",
        &network_id,
        &device_id.0,
        crate::telemetry::NOT_APPLICABLE,
        crate::telemetry::ErrorCategory::None.as_str(),
        crate::telemetry::RESULT_OK
    );
    Ok(Json(plan))
}

/// `GET /api/v1/networks/{network_id}/peers/endpoints`：本设备可直连的 peer
/// 候选端点列表（§12 P2P）。
///
/// - 凭证：agent 设备 Bearer（与心跳/计划同一认证边界）；
/// - 返回 [`meshlet_domain::peer_endpoints_for`] 结果：排除自身/非 Active/
///   未上报候选/超出本设备可路由网段，按 device_id 确定性排序；
/// - 与 peer AllowedIPs 同一段口径：分段网络取所属段前缀，单段网络取整个
///   overlay（`device_plan::segment_for` 复用）。
pub async fn peers_endpoints_handler(
    State(state): State<SharedAppState>,
    AuthorizedAgent(device_id): AuthorizedAgent,
    Path(network_id): Path<String>,
) -> Result<Json<Vec<PeerEndpoints>>, AgentApiError> {
    let _persist = state.persist.lock().await;
    let guard = state.mesh.lock().unwrap();
    let Some(device) = guard.registry.find_by_id(&device_id) else {
        // 待审批注册申请：批准前无端点（无隧道、不参与数据面）。
        if guard.registry.find_registration(&device_id).is_some() {
            return Err(AgentApiError::NotFound(format!(
                "device {device_id} is pending approval: no endpoints until approved"
            )));
        }
        return Err(AgentApiError::NotFound(format!(
            "device {device_id} not found"
        )));
    };
    if device.network_id.to_string() != network_id {
        return Err(AgentApiError::NotFound(format!(
            "network {network_id} does not own device {device_id}"
        )));
    }
    if !device.is_active() {
        return Err(AgentApiError::NotFound(format!(
            "device {device_id} is not active"
        )));
    }
    let Some(source_segment) = crate::device_plan::segment_for(&guard, &network_id, device) else {
        return Err(AgentApiError::Internal(format!(
            "device {device_id} has no segment assignment"
        )));
    };
    let peers = meshlet_domain::peer_endpoints_for(
        source_segment.cidr,
        &device_id,
        guard.registry.devices(),
        &guard.direct_states,
    );
    Ok(Json(peers))
}

/// `GET /api/v1/agent/device/peers/endpoints`：本设备可直连的 peer 候选端点
/// 列表（§12 P2P，agent 视角）。
///
/// 与 [`peers_endpoints_handler`] 同一聚合，但无需网络 ID 路径参数——agent
/// 凭证本身即身份，网络从设备记录解析（与 `desired_device_plan_handler`
/// 同一口径）。agent 因此无需知道网络 ID 就能拉取候选。
pub async fn agent_peers_endpoints_handler(
    State(state): State<SharedAppState>,
    AuthorizedAgent(device_id): AuthorizedAgent,
) -> Result<Json<Vec<PeerEndpoints>>, AgentApiError> {
    let guard = state.mesh.lock().unwrap();
    let Some(device) = guard.registry.find_by_id(&device_id) else {
        if guard.registry.find_registration(&device_id).is_some() {
            return Err(AgentApiError::NotFound(format!(
                "device {device_id} is pending approval: no endpoints until approved"
            )));
        }
        return Err(AgentApiError::NotFound(format!(
            "device {device_id} not found"
        )));
    };
    if !device.is_active() {
        return Err(AgentApiError::NotFound(format!(
            "device {device_id} is not active"
        )));
    }
    let network_id = device.network_id.to_string();
    let Some(source_segment) = crate::device_plan::segment_for(&guard, &network_id, device) else {
        return Err(AgentApiError::Internal(format!(
            "device {device_id} has no segment assignment"
        )));
    };
    let peers = meshlet_domain::peer_endpoints_for(
        source_segment.cidr,
        &device_id,
        guard.registry.devices(),
        &guard.direct_states,
    );
    Ok(Json(peers))
}
