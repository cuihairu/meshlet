//! Agent 心跳/状态上报（[存档 §14.1](../../docs/review/chatgpt-2026-10-13.md)、
//! [§12.4](../../docs/review/chatgpt-2026-10-13.md)）。
//!
//! - Agent 凭证（`agent_tokens` 表，migration 003）与邀请/会话同一纪律：
//!   只存 SHA-256 摘要，原始 Token 仅在加入响应里出现一次；
//! - 心跳端点 `POST /api/v1/agent/heartbeat` 是 **agent API**（Bearer 凭证），
//!   与管理 API（Cookie 会话 + CSRF）认证边界清晰（§13.5）；
//! - 心跳携带 agent 本地读到的 `wg show` 握手时间（`last_handshake_at`），
//!   服务端据此 + 上报时间做在线判定（[presence] 域层）。

use axum::extract::{FromRequestParts, State};
use axum::http::request::Parts;
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use meshlet_api_types::{ErrorCode, ErrorResponse};
use meshlet_domain::{generate_token, token_hash, DeviceId, Timestamp};
use serde::{Deserialize, Serialize};
use sqlx::SqlitePool;

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

// ---------------------------------------------------------------------------
// 错误
// ---------------------------------------------------------------------------

#[derive(Debug)]
pub enum AgentApiError {
    Unauthorized,
    InvalidInput(String),
    NotFound(String),
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
}

#[derive(Debug, Clone, Serialize)]
pub struct HeartbeatResponse {
    pub online_state: String,
    pub presence_source: String,
    pub last_seen_at: Option<String>,
}

/// `POST /api/v1/agent/heartbeat`：记录一次 agent 上报（+ 可选握手时间），
/// 返回当前在线判定（状态 + 数据来源 + 最后证据时间）。
pub async fn heartbeat_handler(
    State(state): State<SharedAppState>,
    AuthorizedAgent(device_id): AuthorizedAgent,
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
    let presence = {
        let mut guard = state.mesh.lock().unwrap();
        service::record_agent_report(
            &mut guard,
            &device_id,
            req.last_handshake_at.clone(),
            now.clone(),
        )
        .map_err(|e| match e {
            service::ServiceError::DeviceNotFound(id) => AgentApiError::NotFound(id),
            other => AgentApiError::Internal(other.to_string()),
        })?
    };
    Ok(Json(HeartbeatResponse {
        online_state: presence.state.as_str().to_string(),
        presence_source: presence.source.as_str().to_string(),
        last_seen_at: Some(now),
    }))
}
