use super::{AuthApiError, SharedAppState};
use axum::extract::FromRequestParts;
use axum::http::request::Parts;
use axum::http::{header, HeaderMap};
use meshlet_domain::auth::{SESSION_COOKIE_NAME, SESSION_TTL_SECS};
use meshlet_domain::{Timestamp, UserId};

use crate::service;

// ---------------------------------------------------------------------------
// Cookie / 请求头
// ---------------------------------------------------------------------------

pub(super) fn session_token_from_headers(headers: &HeaderMap) -> Option<String> {
    let raw = headers.get(header::COOKIE)?.to_str().ok()?;
    for pair in raw.split(';') {
        let pair = pair.trim();
        if let Some(value) = pair.strip_prefix(SESSION_COOKIE_NAME) {
            let value = value.strip_prefix('=')?;
            if !value.is_empty() {
                return Some(value.to_string());
            }
        }
    }
    None
}

fn build_session_cookie(token: &str, max_age: i64, secure: bool) -> String {
    format!(
        "{SESSION_COOKIE_NAME}={token}; HttpOnly; SameSite=Strict; Max-Age={max_age}; Path=/api/v1{}",
        if secure { "; Secure" } else { "" }
    )
}

pub(super) fn session_cookie_header(token: &str, secure: bool) -> HeaderMap {
    let mut headers = HeaderMap::new();
    if let Ok(value) = build_session_cookie(token, SESSION_TTL_SECS as i64, secure).parse() {
        headers.insert(header::SET_COOKIE, value);
    }
    headers
}

pub(super) fn clear_cookie_header(secure: bool) -> HeaderMap {
    let mut headers = HeaderMap::new();
    if let Ok(value) = build_session_cookie("", 0, secure).parse() {
        headers.insert(header::SET_COOKIE, value);
    }
    headers
}

// ---------------------------------------------------------------------------
// 提取器（只在匹配到的路由上运行；未知路径仍走 404 fallback）
// ---------------------------------------------------------------------------

/// 认证结果：浏览器会话（恒全部权限）或 API Token（携带 scope）。
enum Credentials {
    Session(UserId),
    ApiToken(UserId, crate::api_token::TokenScope),
}

impl Credentials {
    fn user_id(&self) -> UserId {
        match self {
            Credentials::Session(id) => id.clone(),
            Credentials::ApiToken(id, _) => id.clone(),
        }
    }
}

/// 会话优先、Bearer 兜底的统一认证（仅供管理 API 提取器使用）。
///
/// 会话头存在但无效 → 401（不回退到 Bearer，避免静默降级）；
/// 无会话头 → 接受 `Authorization: Bearer mlt_…`（API Token 与 agent token 是
/// 两个独立边界：agent token 不在 api_tokens 表中，反之亦然）。
async fn authenticate(
    state: &SharedAppState,
    parts: &mut Parts,
) -> Result<Credentials, AuthApiError> {
    if let Some(token) = session_token_from_headers(&parts.headers) {
        let now: Timestamp = service::now();
        return match state.auth.validate_session(&token, &now).await {
            Ok(Some(user_id)) => Ok(Credentials::Session(user_id)),
            Ok(None) => Err(AuthApiError::Unauthorized),
            Err(e) => Err(AuthApiError::Internal(e.to_string())),
        };
    }
    if let Some(raw) = crate::agent::bearer_token_from_headers(&parts.headers) {
        let now: Timestamp = service::now();
        return match state.api_tokens.validate(&raw, &now).await {
            Ok(Some((user_id, scope))) => Ok(Credentials::ApiToken(user_id, scope)),
            Ok(None) => Err(AuthApiError::Unauthorized),
            Err(e) => Err(AuthApiError::Internal(e.to_string())),
        };
    }
    Err(AuthApiError::Unauthorized)
}

/// 管理 API 认证提取器：Cookie 会话或 API Token Bearer，无效一律 401。
///
/// 不用全局 middleware——middleware 会作用于 fallback，把未知路径变成 401；
/// 提取器只在命中路由后求值，404 语义保持。
#[derive(Debug, Clone)]
pub struct AuthenticatedUser(pub UserId);

impl FromRequestParts<SharedAppState> for AuthenticatedUser {
    type Rejection = AuthApiError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &SharedAppState,
    ) -> Result<Self, Self::Rejection> {
        Ok(AuthenticatedUser(
            authenticate(state, parts).await?.user_id(),
        ))
    }
}

/// 写端点提取器：会话恒放行；API Token 必须持 `write` scope，否则 403。
#[derive(Debug, Clone)]
pub struct WriteUser(pub UserId);

impl FromRequestParts<SharedAppState> for WriteUser {
    type Rejection = AuthApiError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &SharedAppState,
    ) -> Result<Self, Self::Rejection> {
        match authenticate(state, parts).await? {
            Credentials::Session(user_id) => Ok(WriteUser(user_id)),
            Credentials::ApiToken(user_id, scope) => {
                if scope.allows(crate::api_token::TokenScope::Write) {
                    Ok(WriteUser(user_id))
                } else {
                    Err(AuthApiError::ForbiddenScopes)
                }
            }
        }
    }
}

/// CSRF 提取器：管理端写请求必须带 `X-Requested-With: XMLHttpRequest`
/// （Console 前端约定），配合 SameSite=Strict 构成双重防线。
#[derive(Debug, Clone)]
pub struct CsrfHeader;

impl FromRequestParts<SharedAppState> for CsrfHeader {
    type Rejection = AuthApiError;

    async fn from_request_parts(
        parts: &mut Parts,
        _state: &SharedAppState,
    ) -> Result<Self, Self::Rejection> {
        let ok = parts
            .headers
            .get("x-requested-with")
            .and_then(|v| v.to_str().ok())
            .is_some_and(|v| v.eq_ignore_ascii_case("xmlhttprequest"));
        if ok {
            Ok(CsrfHeader)
        } else {
            Err(AuthApiError::ForbiddenCsrf)
        }
    }
}

/// 审计留痕（§16.5）：复用 [`crate::audit::record_or_fail`]，失败映射本模块
/// 错误（不留痕不放行）。
pub(super) async fn record_audit(
    state: &SharedAppState,
    actor: Option<&str>,
    action: &str,
    target_id: Option<&str>,
    detail: Option<serde_json::Value>,
) -> Result<(), AuthApiError> {
    crate::audit::record_or_fail(state, actor, action, "user", target_id, detail)
        .await
        .map_err(|e| AuthApiError::Internal(e.to_string()))
}
