//! 控制台认证：会话存储 + 认证/CSRF 提取器 + 登录/引导端点
//! （[存档 §11.4](../../docs/review/chatgpt-2026-10-13.md)、
//! [ADR-010](../../docs/decisions/adr-010-console-auth-enrollment.md)）。
//!
//! - 管理 API（网络/邀请/设备）handler 一律挂 `AuthenticatedUser`（Cookie 会话）
//!   与写请求的 `CsrfHeader` 提取器；提取器只在命中路由后求值，未知路径保持 404；
//! - `/api/v1/enroll` 与 `/api/v1/system/status` 保持公开（enroll 自带邀请 Token 鉴权）；
//! - Cookie：HttpOnly + SameSite=Strict + Max-Age=会话 TTL；`Secure` 由配置决定
//!   （生产部署在 HTTPS 反代后置 true）；
//! - CSRF：Cookie 认证的管理端「写」请求必须携带 `X-Requested-With: XMLHttpRequest`
//!   （Console 前端约定），配合 SameSite=Strict 构成双重防线；
//! - 登录限流：进程内固定窗口（按 email 维度），成功登录即清零；
//! - **无默认管理员密码**：首个管理员只能经「空库 bootstrap」创建。

use axum::extract::{FromRequestParts, State};
use axum::http::request::Parts;
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use meshlet_api_types::{ErrorCode, ErrorResponse};
use meshlet_domain::auth::{
    validate_email, validate_password, RateLimiter, Session, User, SESSION_COOKIE_NAME,
    SESSION_TTL_SECS,
};
use meshlet_domain::{generate_token, token_hash, Timestamp, UserId};
use serde::{Deserialize, Serialize};
use sqlx::SqlitePool;
use std::sync::Arc;
use std::time::{Duration, Instant};

use crate::service;

/// 登录限流参数：每 email 每窗口最多 5 次失败尝试，窗口 15 分钟。
pub const LOGIN_MAX_ATTEMPTS: u32 = 5;
pub const LOGIN_WINDOW: Duration = Duration::from_secs(15 * 60);

/// 未知 email 的恒时校验目标（消除「用户不存在」的时间侧信道）。
/// 内容为 Argon2id PHC 格式的无效哈希——校验必然失败，但耗时与真哈希一致。
const DUMMY_HASH: &str = "$argon2id$v=19$m=32768,t=2,p=4$AAAAAAAAAAAAAAAAAAAAAA$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";

/// 应用状态：内存 Mesh 状态 + SQLite 用户/会话 + 登录限流器。
#[derive(Clone)]
pub struct AppState {
    pub mesh: service::SharedState,
    pub auth: AuthStore,
    pub login_limiter: Arc<RateLimiter>,
    pub cookie_secure: bool,
}

pub type SharedAppState = Arc<AppState>;

impl AppState {
    pub fn new(mesh: service::SharedState, auth: AuthStore, cookie_secure: bool) -> Self {
        Self {
            mesh,
            auth,
            login_limiter: Arc::new(RateLimiter::new(LOGIN_MAX_ATTEMPTS, LOGIN_WINDOW)),
            cookie_secure,
        }
    }
}

// ---------------------------------------------------------------------------
// 存储
// ---------------------------------------------------------------------------

/// 用户/会话存储（SQLite，migrations 001/002）。
#[derive(Clone)]
pub struct AuthStore {
    pool: SqlitePool,
}

/// 查询到的用户行（含哈希；仅在登录路径内部使用，不序列化出站）。
pub struct UserRecord {
    pub id: UserId,
    pub email: String,
    pub password_hash: String,
}

impl AuthStore {
    pub fn new(pool: SqlitePool) -> Self {
        Self { pool }
    }

    pub async fn user_count(&self) -> Result<i64, sqlx::Error> {
        sqlx::query_scalar("SELECT COUNT(*) FROM users")
            .fetch_one(&self.pool)
            .await
    }

    pub async fn insert_user(&self, user: &User) -> Result<(), sqlx::Error> {
        sqlx::query(
            "INSERT INTO users (id, email, password_hash, created_at)
             VALUES (?, ?, ?, ?)",
        )
        .bind(&user.id.0)
        .bind(&user.email)
        .bind(&user.password_hash)
        .bind(user.created_at.as_str())
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn find_user_by_email(&self, email: &str) -> Result<Option<UserRecord>, sqlx::Error> {
        Self::find_user_by(
            &self.pool,
            "SELECT id, email, password_hash FROM users WHERE email = ?",
            email,
        )
        .await
    }

    pub async fn find_user_by_id(&self, id: &UserId) -> Result<Option<UserRecord>, sqlx::Error> {
        Self::find_user_by(
            &self.pool,
            "SELECT id, email, password_hash FROM users WHERE id = ?",
            &id.0,
        )
        .await
    }

    async fn find_user_by(
        pool: &SqlitePool,
        sql: &'static str,
        key: &str,
    ) -> Result<Option<UserRecord>, sqlx::Error> {
        let row = sqlx::query_as::<_, (String, String, String)>(sql)
            .bind(key)
            .fetch_optional(pool)
            .await?;
        Ok(row.map(|(id, email, password_hash)| UserRecord {
            id: UserId(id),
            email,
            password_hash,
        }))
    }

    pub async fn insert_session(&self, session: &Session) -> Result<(), sqlx::Error> {
        sqlx::query(
            "INSERT INTO sessions (token_hash, user_id, created_at, expires_at)
             VALUES (?, ?, ?, ?)",
        )
        .bind(&session.token_hash)
        .bind(&session.user_id.0)
        .bind(session.created_at.as_str())
        .bind(session.expires_at.as_str())
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// 校验会话：存在、未撤销、未过期 → 用户 ID。
    pub async fn validate_session(
        &self,
        raw_token: &str,
        now: &Timestamp,
    ) -> Result<Option<UserId>, sqlx::Error> {
        let row = sqlx::query_as::<_, (String, String, Option<String>)>(
            "SELECT user_id, expires_at, revoked_at FROM sessions WHERE token_hash = ?",
        )
        .bind(token_hash(raw_token))
        .fetch_optional(&self.pool)
        .await?;
        match row {
            Some((user_id, expires_at, revoked_at)) => {
                if revoked_at.is_none() && expires_at.as_str() > now.as_str() {
                    Ok(Some(UserId(user_id)))
                } else {
                    Ok(None)
                }
            }
            None => Ok(None),
        }
    }

    pub async fn revoke_session(&self, raw_token: &str, at: &Timestamp) -> Result<(), sqlx::Error> {
        sqlx::query("UPDATE sessions SET revoked_at = ? WHERE token_hash = ?")
            .bind(at.as_str())
            .bind(token_hash(raw_token))
            .execute(&self.pool)
            .await?;
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// 错误
// ---------------------------------------------------------------------------

#[derive(Debug)]
pub enum AuthApiError {
    Unauthorized,
    ForbiddenCsrf,
    InvalidInput(String),
    AlreadyBootstrapped,
    RateLimited,
    Internal(String),
}

impl IntoResponse for AuthApiError {
    fn into_response(self) -> Response {
        let (status, code, message) = match self {
            AuthApiError::Unauthorized => (
                StatusCode::UNAUTHORIZED,
                ErrorCode::Unauthorized,
                "invalid credentials or authentication required".into(),
            ),
            AuthApiError::ForbiddenCsrf => (
                StatusCode::FORBIDDEN,
                ErrorCode::Forbidden,
                "mutating console requests must set X-Requested-With".into(),
            ),
            AuthApiError::InvalidInput(m) => {
                (StatusCode::BAD_REQUEST, ErrorCode::ValidationFailed, m)
            }
            AuthApiError::AlreadyBootstrapped => (
                StatusCode::CONFLICT,
                ErrorCode::Conflict,
                "admin user already exists; bootstrap is closed".into(),
            ),
            AuthApiError::RateLimited => (
                StatusCode::TOO_MANY_REQUESTS,
                ErrorCode::TooManyRequests,
                "login rate limit exceeded; retry later".into(),
            ),
            AuthApiError::Internal(m) => {
                (StatusCode::INTERNAL_SERVER_ERROR, ErrorCode::Internal, m)
            }
        };
        (status, Json(ErrorResponse::new(code, message))).into_response()
    }
}

// ---------------------------------------------------------------------------
// Cookie / 请求头
// ---------------------------------------------------------------------------

fn session_token_from_headers(headers: &HeaderMap) -> Option<String> {
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

fn session_cookie_header(token: &str, secure: bool) -> HeaderMap {
    let mut headers = HeaderMap::new();
    if let Ok(value) = build_session_cookie(token, SESSION_TTL_SECS as i64, secure).parse() {
        headers.insert(header::SET_COOKIE, value);
    }
    headers
}

fn clear_cookie_header(secure: bool) -> HeaderMap {
    let mut headers = HeaderMap::new();
    if let Ok(value) = build_session_cookie("", 0, secure).parse() {
        headers.insert(header::SET_COOKIE, value);
    }
    headers
}

// ---------------------------------------------------------------------------
// 提取器（只在匹配到的路由上运行；未知路径仍走 404 fallback）
// ---------------------------------------------------------------------------

/// 管理 API 认证提取器：Cookie 会话无效一律 401。
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
        let Some(token) = session_token_from_headers(&parts.headers) else {
            return Err(AuthApiError::Unauthorized);
        };
        let now: Timestamp = service::now();
        match state.auth.validate_session(&token, &now).await {
            Ok(Some(user_id)) => Ok(AuthenticatedUser(user_id)),
            Ok(None) => Err(AuthApiError::Unauthorized),
            Err(e) => Err(AuthApiError::Internal(e.to_string())),
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

// ---------------------------------------------------------------------------
// 端点
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CredentialsRequest {
    pub email: String,
    pub password: String,
}

#[derive(Debug, Serialize)]
pub struct SessionResponse {
    pub user_id: String,
    pub email: String,
}

/// 建会话 + 种 Cookie。
async fn open_session(state: &AppState, user_id: &UserId) -> Result<HeaderMap, AuthApiError> {
    let (raw_token, session) = Session::generate(user_id.clone(), service::now());
    state
        .auth
        .insert_session(&session)
        .await
        .map_err(|e| AuthApiError::Internal(e.to_string()))?;
    Ok(session_cookie_header(&raw_token, state.cookie_secure))
}

/// `POST /api/v1/auth/bootstrap`：仅空库可用，创建首个管理员并直接登录。
pub async fn bootstrap_handler(
    State(state): State<SharedAppState>,
    Json(req): Json<CredentialsRequest>,
) -> Result<Response, AuthApiError> {
    let count = state
        .auth
        .user_count()
        .await
        .map_err(|e| AuthApiError::Internal(e.to_string()))?;
    if count > 0 {
        return Err(AuthApiError::AlreadyBootstrapped);
    }
    validate_email(&req.email).map_err(|e| AuthApiError::InvalidInput(e.to_string()))?;
    validate_password(&req.password).map_err(|e| AuthApiError::InvalidInput(e.to_string()))?;

    let user = User::new(
        UserId(generate_token()),
        req.email,
        &req.password,
        service::now(),
    )
    .map_err(|e| AuthApiError::InvalidInput(e.to_string()))?;
    let (user_id, email) = (user.id.clone(), user.email.clone());
    state
        .auth
        .insert_user(&user)
        .await
        .map_err(|e| AuthApiError::Internal(e.to_string()))?;

    let headers = open_session(&state, &user_id).await?;
    Ok((
        StatusCode::CREATED,
        headers,
        Json(SessionResponse {
            user_id: user_id.0,
            email,
        }),
    )
        .into_response())
}

/// `POST /api/v1/auth/login`：校验密码，成功发会话 Cookie。
/// 不区分「用户不存在」与「密码错误」（统一 401 + 恒时校验）。
pub async fn login_handler(
    State(state): State<SharedAppState>,
    Json(req): Json<CredentialsRequest>,
) -> Result<Response, AuthApiError> {
    let key = format!("login:{}", req.email.to_lowercase());
    if !state.login_limiter.check(&key, Instant::now()) {
        return Err(AuthApiError::RateLimited);
    }

    let record = state
        .auth
        .find_user_by_email(&req.email)
        .await
        .map_err(|e| AuthApiError::Internal(e.to_string()))?;
    let Some(record) = record else {
        // 恒时：对固定哈希跑一次校验再拒绝。
        let _ = meshlet_domain::auth::verify_password(&req.password, DUMMY_HASH);
        return Err(AuthApiError::Unauthorized);
    };
    let user_id = record.id.clone();
    let email = record.email;
    if !meshlet_domain::auth::verify_password(&req.password, &record.password_hash) {
        return Err(AuthApiError::Unauthorized);
    }
    state.login_limiter.reset(&key);

    let headers = open_session(&state, &user_id).await?;
    Ok((
        StatusCode::OK,
        headers,
        Json(SessionResponse {
            user_id: user_id.0,
            email,
        }),
    )
        .into_response())
}

/// `POST /api/v1/auth/logout`：撤销会话并清 Cookie。
pub async fn logout_handler(
    State(state): State<SharedAppState>,
    req: axum::extract::Request,
) -> Response {
    if let Some(token) = session_token_from_headers(req.headers()) {
        let now: Timestamp = service::now();
        if let Err(e) = state.auth.revoke_session(&token, &now).await {
            return AuthApiError::Internal(e.to_string()).into_response();
        }
    }
    (
        StatusCode::NO_CONTENT,
        clear_cookie_header(state.cookie_secure),
    )
        .into_response()
}

/// `GET /api/v1/auth/me`：返回当前会话用户。
pub async fn me_handler(
    State(state): State<SharedAppState>,
    AuthenticatedUser(user_id): AuthenticatedUser,
) -> Result<Json<SessionResponse>, AuthApiError> {
    // 会话有效 ≠ 用户仍存在；再核一次。
    let record = state
        .auth
        .find_user_by_id(&user_id)
        .await
        .map_err(|e| AuthApiError::Internal(e.to_string()))?
        .ok_or(AuthApiError::Unauthorized)?;
    Ok(Json(SessionResponse {
        user_id: record.id.0,
        email: record.email,
    }))
}
