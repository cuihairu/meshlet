use super::{AuthApiError, SharedAppState};
use axum::extract::FromRequestParts;
use axum::http::request::Parts;
use axum::http::{header, HeaderMap};
use meshlet_domain::auth::{SESSION_COOKIE_NAME, SESSION_TTL_SECS};
use meshlet_domain::{Timestamp, UserId};

use crate::service;

// ---------------------------------------------------------------------------
// Cookie / request headers
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
// Extractors (only run on matched routes; unknown paths still hit the 404 fallback)
// ---------------------------------------------------------------------------

/// Authentication result: a browser session (always full permissions) or an
/// API Token (carrying a scope).
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

/// Unified authentication that prefers the session with Bearer as fallback
/// (only for the admin API extractors).
///
/// Session header present but invalid → 401 (no Bearer fallback, avoiding a
/// silent downgrade); no session header → accept `Authorization: Bearer mlt_…`
/// (API Token and agent token are two independent boundaries: agent tokens are
/// not in the api_tokens table, and vice versa).
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

/// Admin API authentication extractor: cookie session or API Token Bearer;
/// anything invalid is always a 401.
///
/// No global middleware — middleware would also apply to the fallback, turning
/// unknown paths into 401s; the extractor is only evaluated after a route is
/// matched, preserving 404 semantics.
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

/// Write-endpoint extractor: sessions always pass; an API Token must carry
/// the `write` scope, otherwise 403.
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

/// CSRF extractor: admin write requests must carry `X-Requested-With: XMLHttpRequest`
/// (a Console frontend convention), which together with SameSite=Strict forms
/// a double line of defense.
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

/// Audit trail (§16.5): reuses [`crate::audit::record_or_fail`], mapping
/// failures to this module's error (no audit record, no pass-through).
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
