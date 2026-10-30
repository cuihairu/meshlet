//! 控制台认证：会话存储 + 认证/CSRF 提取器 + 登录/引导端点
//! （[存档 §11.4](../../docs/review/chatgpt-2026-10-13.md)、
//! [ADR-010](../../docs/decisions/adr-010-console-auth-enrollment.md)）。
//!
//! - 管理 API（网络/邀请/设备）handler 一律挂 `AuthenticatedUser`（Cookie 会话
//!   或 `mlt_` API Token Bearer，见 api_token.rs）与写请求的 `CsrfHeader` +
//!   `WriteUser`（会话恒放行；token 需 `write` scope）提取器；提取器只在命中
//!   路由后求值，未知路径保持 404；
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
use meshlet_domain::totp;
use meshlet_domain::{generate_token, token_hash, Timestamp, UserId};
use serde::{Deserialize, Serialize};
use sqlx::SqlitePool;
use std::collections::HashMap;
use std::sync::Arc;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use crate::service;

/// 登录限流参数：每 email 每窗口最多 5 次失败尝试，窗口 15 分钟。
pub const LOGIN_MAX_ATTEMPTS: u32 = 5;
pub const LOGIN_WINDOW: Duration = Duration::from_secs(15 * 60);

/// Argon2 阻塞任务上限：限制 CPU 密集哈希/校验同时占满 worker。
pub const AUTH_BLOCKING_CONCURRENCY: usize = 4;

/// 未知 email 的恒时校验目标（消除「用户不存在」的时间侧信道）。
/// 内容为 Argon2id PHC 格式的无效哈希——校验必然失败，但耗时与真哈希一致。
const DUMMY_HASH: &str = "$argon2id$v=19$m=32768,t=2,p=4$AAAAAAAAAAAAAAAAAAAAAA$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";

/// 应用状态：内存 Mesh 状态 + SQLite 用户/会话/agent/API token + 登录限流器。
#[derive(Clone)]
pub struct AppState {
    pub mesh: service::SharedState,
    pub auth: AuthStore,
    pub agent_tokens: crate::agent::AgentTokenStore,
    pub api_tokens: crate::api_token::ApiTokenStore,
    /// 审计日志（存档 §16.5）：与凭证同库。
    pub audit: crate::audit::AuditStore,
    pub login_limiter: Arc<RateLimiter>,
    pub cookie_secure: bool,
    /// 配置应用/回滚 backend 工厂（§10.3 幂等、§10.4 回滚边界）；默认数据面
    /// 未接入（显式失败），测试可注入计数 backend 验证幂等与串行化。
    pub apply_backend: crate::revision::BackendFactory,
    /// 运行指标（§17.2）：进程内计数 + 抓取时现算量规；`GET /api/v1/system/metrics`。
    pub metrics: crate::metrics::Metrics,
    /// Mesh 持久化互斥（§17.3）：变更 + 落库在同一个互斥段内完成，任何并发
    /// 交错都不会让旧行快照覆盖新行（请求路径 DB 镜像的写序保证）。
    pub persist: Arc<tokio::sync::Mutex<()>>,
    /// 备份目录（§17.4）：`None` = 备份未配置（`POST /system/backup` 503）。
    pub backup_dir: Option<std::path::PathBuf>,
    /// 计划隧道 MTU（§7.5「MTU 可配置」）：`None` = 未显式配置，诊断按
    /// WireGuard 默认 1420 解释大包/分片风险；诊断第 13 项据此判读。
    pub tunnel_mtu: Option<u32>,
    /// 服务端 `[dataplane]` 配置（设备计划下发用：接口名/私钥文件）；
    /// `enabled = false` 时 `GET /agent/device/desired` 返回 503。
    pub dataplane: meshlet_config::DataPlaneConfig,
    /// 同一网络的 apply/rollback 串行门（§10.4）；不同网络仍可并行执行。
    pub revision_locks: Arc<Mutex<HashMap<String, Arc<tokio::sync::Mutex<()>>>>>,
    /// 密码哈希/校验阻塞任务并发上限（§11.4）。
    pub auth_blocking: Arc<tokio::sync::Semaphore>,
}

pub type SharedAppState = Arc<AppState>;

impl AppState {
    pub fn new(
        mesh: service::SharedState,
        auth: AuthStore,
        agent_tokens: crate::agent::AgentTokenStore,
        api_tokens: crate::api_token::ApiTokenStore,
        cookie_secure: bool,
    ) -> Self {
        // 审计与凭证同库；克隆池句柄而非共享借用（下方 auth 会被移动进 Self）。
        let audit = crate::audit::AuditStore::new(auth.pool().clone());
        Self {
            mesh,
            auth,
            agent_tokens,
            api_tokens,
            audit,
            login_limiter: Arc::new(RateLimiter::new(LOGIN_MAX_ATTEMPTS, LOGIN_WINDOW)),
            cookie_secure,
            apply_backend: crate::revision::unconfigured_backend_factory(),
            metrics: crate::metrics::Metrics::new(),
            persist: Arc::new(tokio::sync::Mutex::new(())),
            revision_locks: Arc::new(Mutex::new(HashMap::new())),
            auth_blocking: Arc::new(tokio::sync::Semaphore::new(AUTH_BLOCKING_CONCURRENCY)),
            backup_dir: None,
            tunnel_mtu: None,
            dataplane: meshlet_config::DataPlaneConfig::default(),
        }
    }

    /// 注入自定义配置应用 backend（数据面接入 / 集成测试）。
    pub fn with_apply_backend(mut self, factory: crate::revision::BackendFactory) -> Self {
        self.apply_backend = factory;
        self
    }

    /// 注入备份目录（§17.4；生产来自 `[backup] dir`，测试注入临时目录）。
    pub fn with_backup_dir(mut self, dir: Option<std::path::PathBuf>) -> Self {
        self.backup_dir = dir;
        self
    }

    /// 注入计划隧道 MTU（§7.5；生产来自 `tunnel_mtu`，测试注入以验证诊断分支）。
    pub fn with_tunnel_mtu(mut self, mtu: Option<u32>) -> Self {
        self.tunnel_mtu = mtu;
        self
    }

    /// 注入服务端 `[dataplane]` 配置（生产来自 `config.dataplane`；测试注入以
    /// 验证设备计划下发与未配置分支）。
    pub fn with_dataplane(mut self, dataplane: meshlet_config::DataPlaneConfig) -> Self {
        self.dataplane = dataplane;
        self
    }

    /// 注入指标注册表（集成测试断言计数用；生产走 `AppState::new` 默认值）。
    pub fn with_metrics(mut self, metrics: crate::metrics::Metrics) -> Self {
        self.metrics = metrics;
        self
    }

    /// 注入认证阻塞并发上限（生产保持默认，测试验证限并发）。
    pub fn with_auth_blocking_concurrency(mut self, concurrency: usize) -> Self {
        self.auth_blocking = Arc::new(tokio::sync::Semaphore::new(concurrency));
        self
    }

    /// 取某网络的 apply/rollback 串行门；其他网络不被这条配置操作阻塞。
    pub fn revision_lock(&self, network_id: &str) -> Arc<tokio::sync::Mutex<()>> {
        let mut guard = self.revision_locks.lock().unwrap();
        Arc::clone(
            guard
                .entry(network_id.to_string())
                .or_insert_with(|| Arc::new(tokio::sync::Mutex::new(()))),
        )
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
    /// TOTP base32 密钥；`None` = 未发起绑定。
    pub totp_secret: Option<String>,
    /// TOTP 已激活（登录需第二步校验）。
    pub totp_enabled: bool,
}

impl AuthStore {
    pub fn new(pool: SqlitePool) -> Self {
        Self { pool }
    }

    /// 池句柄（克隆后供审计存储与其他 store 共用同一库）。
    pub fn pool(&self) -> &SqlitePool {
        &self.pool
    }

    pub async fn user_count(&self) -> Result<i64, sqlx::Error> {
        sqlx::query_scalar("SELECT COUNT(*) FROM users")
            .fetch_one(&self.pool)
            .await
    }

    pub async fn insert_first_user(&self, user: &User) -> Result<bool, sqlx::Error> {
        let result = sqlx::query("INSERT INTO users(id,email,password_hash,created_at) SELECT ?,?,?,? WHERE NOT EXISTS(SELECT 1 FROM users)")
            .bind(&user.id.0).bind(&user.email).bind(&user.password_hash).bind(&user.created_at).execute(&self.pool).await?;
        Ok(result.rows_affected() == 1)
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
            "SELECT id, email, password_hash, totp_secret, totp_enabled FROM users WHERE email = ?",
            email,
        )
        .await
    }

    pub async fn find_user_by_id(&self, id: &UserId) -> Result<Option<UserRecord>, sqlx::Error> {
        Self::find_user_by(
            &self.pool,
            "SELECT id, email, password_hash, totp_secret, totp_enabled FROM users WHERE id = ?",
            &id.0,
        )
        .await
    }

    async fn find_user_by(
        pool: &SqlitePool,
        sql: &'static str,
        key: &str,
    ) -> Result<Option<UserRecord>, sqlx::Error> {
        let row = sqlx::query_as::<_, (String, String, String, Option<String>, i64)>(sql)
            .bind(key)
            .fetch_optional(pool)
            .await?;
        Ok(row.map(|(id, email, password_hash, totp_secret, totp_enabled)| UserRecord {
            id: UserId(id),
            email,
            password_hash,
            totp_secret,
            totp_enabled: totp_enabled != 0,
        }))
    }

    /// 管理员重置密码（离线维护 CLI；登录恒重读库，运行中生效）。
    pub async fn set_password(&self, id: &UserId, new_hash: &str) -> Result<(), sqlx::Error> {
        sqlx::query("UPDATE users SET password_hash = ? WHERE id = ?")
            .bind(new_hash)
            .bind(&id.0)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    /// 写入/清除 TOTP 密钥（`None` = 清除并关停）。
    pub async fn set_totp_secret(
        &self,
        id: &UserId,
        secret: Option<&str>,
    ) -> Result<(), sqlx::Error> {
        sqlx::query("UPDATE users SET totp_secret = ? WHERE id = ?")
            .bind(secret)
            .bind(&id.0)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    /// 激活/关停 TOTP 登录第二步。
    pub async fn set_totp_enabled(&self, id: &UserId, enabled: bool) -> Result<(), sqlx::Error> {
        sqlx::query("UPDATE users SET totp_enabled = ? WHERE id = ?")
            .bind(if enabled { 1i64 } else { 0i64 })
            .bind(&id.0)
            .execute(&self.pool)
            .await?;
        Ok(())
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
    ForbiddenScopes,
    NotFound(String),
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
            AuthApiError::ForbiddenScopes => (
                StatusCode::FORBIDDEN,
                ErrorCode::Forbidden,
                "api token lacks write scope".into(),
            ),
            AuthApiError::NotFound(m) => (StatusCode::NOT_FOUND, ErrorCode::NotFound, m),
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

// ---------------------------------------------------------------------------
// 端点
// ---------------------------------------------------------------------------

/// 审计留痕（§16.5）：复用 [`crate::audit::record_or_fail`]，失败映射本模块
/// 错误（不留痕不放行）。
async fn record_audit(
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

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CredentialsRequest {
    pub email: String,
    pub password: String,
    /// TOTP 验证码（第二步）。该用户已启用 2FA 时提供；未启用则忽略。
    #[serde(default)]
    pub code: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct SessionResponse {
    pub user_id: String,
    pub email: String,
    /// 本次登录尚缺 TOTP 第二步（响应未种会话 Cookie；客户端应提示输入验证码）。
    pub two_factor_required: bool,
    /// 该用户已启用 TOTP（客户端据此决定是否显示绑定引导）。
    pub two_factor_enabled: bool,
}

/// TOTP 绑定/激活/关停请求体。
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TotpCodeRequest {
    pub code: String,
}

/// `GET /api/v1/auth/2fa/status` 响应。
#[derive(Debug, Serialize)]
pub struct TotpStatusResponse {
    /// 已激活（登录需第二步）。
    pub enabled: bool,
    /// 已生成密钥、待验证码激活（绑定引导进行中）。
    pub pending: bool,
}

/// `POST /api/v1/auth/2fa/enroll` 响应。
#[derive(Debug, Serialize)]
pub struct TotpEnrollResponse {
    /// 认证器扫码导入的 otpauth:// URI。仅此 URI 承载 base32 密钥——这是认证器
    /// 导入的标准材料；响应不含密钥原文的其他表示形式。
    pub otpauth_uri: String,
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
    let _bootstrap = state.persist.lock().await;
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

    let password = req.password;
    let user = {
        let email = req.email;
        let _permit = state.auth_blocking.acquire().await;
        tokio::task::spawn_blocking(move || {
            User::new(UserId(generate_token()), email, &password, service::now())
        })
        .await
        .map_err(|e| AuthApiError::Internal(e.to_string()))?
        .map_err(|e| AuthApiError::InvalidInput(e.to_string()))?
    };
    let (user_id, email) = (user.id.clone(), user.email.clone());
    if !state
        .auth
        .insert_first_user(&user)
        .await
        .map_err(|e| AuthApiError::Internal(e.to_string()))?
    {
        return Err(AuthApiError::AlreadyBootstrapped);
    }

    let headers = open_session(&state, &user_id).await?;
    record_audit(
        &state,
        Some(&user_id.0),
        "user.bootstrap",
        Some(&user_id.0),
        None,
    )
    .await?;
    crate::op_log!(
        info,
        "auth",
        "bootstrap",
        crate::telemetry::NOT_APPLICABLE,
        crate::telemetry::NOT_APPLICABLE,
        crate::telemetry::NOT_APPLICABLE,
        crate::telemetry::ErrorCategory::None.as_str(),
        crate::telemetry::RESULT_OK
    );
    Ok((
        StatusCode::CREATED,
        headers,
        Json(SessionResponse {
            user_id: user_id.0,
            email,
            two_factor_required: false,
            two_factor_enabled: false,
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
        let password = req.password;
        let _permit = state.auth_blocking.acquire().await;
        let _ = tokio::task::spawn_blocking(move || {
            meshlet_domain::auth::verify_password(&password, DUMMY_HASH)
        })
        .await
        .map_err(|e| AuthApiError::Internal(e.to_string()));
        // 失败也要留痕（§16.5：登录失败必记录）；email 非秘密字段，有助
        // 暴破诊断。不记录密码本身。
        record_audit(
            &state,
            None,
            "user.login_failed",
            None,
            Some(serde_json::json!({ "email": req.email, "reason": "unknown_user" })),
        )
        .await?;
        crate::op_log!(
            warn,
            "auth",
            "login",
            crate::telemetry::NOT_APPLICABLE,
            crate::telemetry::NOT_APPLICABLE,
            crate::telemetry::NOT_APPLICABLE,
            crate::telemetry::ErrorCategory::Unauthorized.as_str(),
            crate::telemetry::RESULT_ERROR
        );
        return Err(AuthApiError::Unauthorized);
    };
    let user_id = record.id.clone();
    let email = record.email;
    let password = req.password;
    let _permit = state.auth_blocking.acquire().await;
    let valid = tokio::task::spawn_blocking(move || {
        meshlet_domain::auth::verify_password(&password, &record.password_hash)
    })
    .await
    .map_err(|e| AuthApiError::Internal(e.to_string()))?;
    if !valid {
        record_audit(
            &state,
            None,
            "user.login_failed",
            None,
            Some(serde_json::json!({ "email": email, "reason": "bad_password" })),
        )
        .await?;
        crate::op_log!(
            warn,
            "auth",
            "login",
            crate::telemetry::NOT_APPLICABLE,
            crate::telemetry::NOT_APPLICABLE,
            crate::telemetry::NOT_APPLICABLE,
            crate::telemetry::ErrorCategory::Unauthorized.as_str(),
            crate::telemetry::RESULT_ERROR
        );
        return Err(AuthApiError::Unauthorized);
    }

    // 第二步（TOTP）：已启用 2FA 时，缺码→提示补码（不种会话）；错码→401。
    if record.totp_enabled {
        let secret = record.totp_secret.clone().unwrap_or_default();
        let provided = req.code.clone();
        let now = service::now_unix() as u64;
        let ok = provided
            .as_deref()
            .map(|c| totp::verify_code(&secret, c, now))
            .unwrap_or(false);
        if provided.is_none() {
            // 客户端据此提示输入验证码；本响应不带 Set-Cookie。
            return Ok((
                StatusCode::OK,
                Json(SessionResponse {
                    user_id: user_id.0,
                    email,
                    two_factor_required: true,
                    two_factor_enabled: true,
                }),
            )
                .into_response());
        }
        if !ok {
            record_audit(
                &state,
                None,
                "user.login_failed",
                None,
                Some(serde_json::json!({ "email": email, "reason": "bad_totp_code" })),
            )
            .await?;
            crate::op_log!(
                warn,
                "auth",
                "login",
                crate::telemetry::NOT_APPLICABLE,
                crate::telemetry::NOT_APPLICABLE,
                crate::telemetry::NOT_APPLICABLE,
                crate::telemetry::ErrorCategory::Unauthorized.as_str(),
                crate::telemetry::RESULT_ERROR
            );
            return Err(AuthApiError::Unauthorized);
        }
    }
    state.login_limiter.reset(&key);

    let headers = open_session(&state, &user_id).await?;
    record_audit(
        &state,
        Some(&user_id.0),
        "user.login",
        Some(&user_id.0),
        None,
    )
    .await?;
    crate::op_log!(
        info,
        "auth",
        "login",
        crate::telemetry::NOT_APPLICABLE,
        crate::telemetry::NOT_APPLICABLE,
        crate::telemetry::NOT_APPLICABLE,
        crate::telemetry::ErrorCategory::None.as_str(),
        crate::telemetry::RESULT_OK
    );
    Ok((
        StatusCode::OK,
        headers,
        Json(SessionResponse {
            user_id: user_id.0,
            email,
            two_factor_required: false,
            two_factor_enabled: record.totp_enabled,
        }),
    )
        .into_response())
}

/// `GET /api/v1/auth/2fa/status`：当前用户的 TOTP 绑定状态。
pub async fn two_factor_status_handler(
    State(state): State<SharedAppState>,
    AuthenticatedUser(user_id): AuthenticatedUser,
) -> Result<Json<TotpStatusResponse>, AuthApiError> {
    let record = state
        .auth
        .find_user_by_id(&user_id)
        .await
        .map_err(|e| AuthApiError::Internal(e.to_string()))?
        .ok_or(AuthApiError::Unauthorized)?;
    Ok(Json(TotpStatusResponse {
        enabled: record.totp_enabled,
        pending: record.totp_secret.is_some() && !record.totp_enabled,
    }))
}

/// `POST /api/v1/auth/2fa/enroll`：生成新 TOTP 密钥（服务端持有，待激活），
/// 返回扫码导入 URI。已激活则先关停旧绑定再重建（重新绑定）。
pub async fn two_factor_enroll_handler(
    State(state): State<SharedAppState>,
    AuthenticatedUser(user_id): AuthenticatedUser,
) -> Result<Json<TotpEnrollResponse>, AuthApiError> {
    let record = state
        .auth
        .find_user_by_id(&user_id)
        .await
        .map_err(|e| AuthApiError::Internal(e.to_string()))?
        .ok_or(AuthApiError::Unauthorized)?;
    let secret = totp::generate_secret();
    state
        .auth
        .set_totp_secret(&user_id, Some(&secret))
        .await
        .map_err(|e| AuthApiError::Internal(e.to_string()))?;
    state
        .auth
        .set_totp_enabled(&user_id, false)
        .await
        .map_err(|e| AuthApiError::Internal(e.to_string()))?;
    let uri = totp::otpauth_uri(totp::OTPAUTH_ISSUER, &record.email, &secret);
    record_audit(
        &state,
        Some(&user_id.0),
        "user.totp_enroll",
        Some(&user_id.0),
        None,
    )
    .await?;
    Ok(Json(TotpEnrollResponse { otpauth_uri: uri }))
}

/// `POST /api/v1/auth/2fa/activate`：以验证码确认并激活 TOTP（绑定引导收尾）。
pub async fn two_factor_activate_handler(
    State(state): State<SharedAppState>,
    AuthenticatedUser(user_id): AuthenticatedUser,
    Json(req): Json<TotpCodeRequest>,
) -> Result<Json<TotpStatusResponse>, AuthApiError> {
    let record = state
        .auth
        .find_user_by_id(&user_id)
        .await
        .map_err(|e| AuthApiError::Internal(e.to_string()))?
        .ok_or(AuthApiError::Unauthorized)?;
    let secret = record
        .totp_secret
        .as_deref()
        .ok_or_else(|| AuthApiError::InvalidInput("no pending totp secret; enroll first".into()))?;
    let now = service::now_unix() as u64;
    if !totp::verify_code(secret, &req.code, now) {
        return Err(AuthApiError::InvalidInput("totp code mismatch".into()));
    }
    state
        .auth
        .set_totp_enabled(&user_id, true)
        .await
        .map_err(|e| AuthApiError::Internal(e.to_string()))?;
    record_audit(
        &state,
        Some(&user_id.0),
        "user.totp_activate",
        Some(&user_id.0),
        None,
    )
    .await?;
    Ok(Json(TotpStatusResponse {
        enabled: true,
        pending: false,
    }))
}

/// `POST /api/v1/auth/2fa/disable`：以验证码确认后关停并清除 TOTP 绑定。
pub async fn two_factor_disable_handler(
    State(state): State<SharedAppState>,
    AuthenticatedUser(user_id): AuthenticatedUser,
    Json(req): Json<TotpCodeRequest>,
) -> Result<Json<TotpStatusResponse>, AuthApiError> {
    let record = state
        .auth
        .find_user_by_id(&user_id)
        .await
        .map_err(|e| AuthApiError::Internal(e.to_string()))?
        .ok_or(AuthApiError::Unauthorized)?;
    let secret = record
        .totp_secret
        .as_deref()
        .ok_or_else(|| AuthApiError::InvalidInput("no totp binding to disable".into()))?;
    let now = service::now_unix() as u64;
    if !totp::verify_code(secret, &req.code, now) {
        return Err(AuthApiError::InvalidInput("totp code mismatch".into()));
    }
    state
        .auth
        .set_totp_secret(&user_id, None)
        .await
        .map_err(|e| AuthApiError::Internal(e.to_string()))?;
    state
        .auth
        .set_totp_enabled(&user_id, false)
        .await
        .map_err(|e| AuthApiError::Internal(e.to_string()))?;
    record_audit(
        &state,
        Some(&user_id.0),
        "user.totp_disable",
        Some(&user_id.0),
        None,
    )
    .await?;
    Ok(Json(TotpStatusResponse {
        enabled: false,
        pending: false,
    }))
}

/// `POST /api/v1/auth/logout`：撤销会话并清 Cookie。
pub async fn logout_handler(
    State(state): State<SharedAppState>,
    req: axum::extract::Request,
) -> Response {
    if let Some(token) = session_token_from_headers(req.headers()) {
        let now: Timestamp = service::now();
        // 先取属主再撤销（撤销后查不到了），登出留痕归属到人。
        let actor = state
            .auth
            .validate_session(&token, &now)
            .await
            .ok()
            .flatten();
        if let Err(e) = state.auth.revoke_session(&token, &now).await {
            return AuthApiError::Internal(e.to_string()).into_response();
        }
        if let Err(e) = record_audit(
            &state,
            actor.as_ref().map(|u| u.0.as_str()),
            "user.logout",
            actor.as_ref().map(|u| u.0.as_str()),
            None,
        )
        .await
        {
            return e.into_response();
        }
        crate::op_log!(
            info,
            "auth",
            "logout",
            crate::telemetry::NOT_APPLICABLE,
            crate::telemetry::NOT_APPLICABLE,
            crate::telemetry::NOT_APPLICABLE,
            crate::telemetry::ErrorCategory::None.as_str(),
            crate::telemetry::RESULT_OK
        );
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
        two_factor_required: false,
        two_factor_enabled: record.totp_enabled,
    }))
}
