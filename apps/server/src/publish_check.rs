//! 发布检查接线：把 meshlet-publish 的授权判断暴露成 server 路由。

use axum::{extract::State, http::StatusCode, Json};
use meshlet_publish::{AuthorizationDecision, AuthorizationPolicy, AuthorizedClient};

use crate::auth::{CsrfHeader, SharedAppState, WriteUser};

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct PublishCheckRequest {
    pub remote: std::net::SocketAddr,
    #[serde(default)]
    pub auth_header: Option<String>,
    #[serde(default)]
    pub policy: AuthorizationPolicy,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct PublishCheckResponse {
    pub allowed: bool,
    pub reason: String,
}

pub async fn publish_check_handler(
    State(_state): State<SharedAppState>,
    WriteUser(_user_id): WriteUser,
    CsrfHeader: CsrfHeader,
    Json(req): Json<PublishCheckRequest>,
) -> Result<Json<PublishCheckResponse>, StatusCode> {
    let mut client = AuthorizedClient::from_socket(req.remote);
    if let Some(auth_header) = req.auth_header {
        client = client.with_auth_header(auth_header);
    }
    let allowed = req.policy.authorize(&client) == AuthorizationDecision::Allowed;
    let reason = if allowed {
        "authorized"
    } else {
        "source or bearer token not authorized"
    };
    Ok(Json(PublishCheckResponse {
        allowed,
        reason: reason.to_owned(),
    }))
}
