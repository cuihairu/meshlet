//! 外部机器凭据：API Token（2026-10-14 用户需求）。
//!
//! - **长期凭证**：外部系统（如 cockpit）经 `Authorization: Bearer mlt_…`
//!   调用管理 API，与浏览器 Cookie 会话并存（`AuthenticatedUser` 两种凭证
//!   皆可；写端点走 `WriteUser`，见 auth.rs）；
//! - **同一 Token 纪律**（§11.3）：服务端只存 SHA-256 摘要，原始 Token
//!   仅在创建响应中出现一次；`mlt_` 前缀使其与 agent token / 邀请 token
//!   在日志与泄漏排查中可一眼区分；
//! - **最小权限**：`read` / `write` 两级 scope（write 隐含 read）；会话恒有
//!   全部权限；
//! - **可撤销 + 审计归属**：token 归属创建它的 `user_id`，`last_used_at`
//!   节流记录使用时刻；撤销即失效；
//! - **CSRF 防线不削弱**：Cookie 认证的写请求仍必须携带 `X-Requested-With`。
//!   Bearer Token 不是浏览器会自动附带的凭据（跨站请求无法伪造），但为保持
//!   「管理端写请求必须带 CSRF 头」的统一语义，对 token 调用方同样要求。

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::routing::{delete, post};
use axum::{Json, Router};
use meshlet_domain::{generate_token, token_hash, Timestamp, UserId};
use serde::{Deserialize, Serialize};
use sqlx::SqlitePool;

use crate::auth::{AuthApiError, AuthenticatedUser, CsrfHeader, SharedAppState, WriteUser};
use crate::service;

/// API Token 原始形态前缀：`mlt_` + 64 hex（32 字节随机材料）。
pub const API_TOKEN_PREFIX: &str = "mlt_";

/// `last_used_at` 刷新节流：审计归属可观测，又不给每个读请求加一次写放大。
const LAST_USED_REFRESH_SECS: i64 = 60;

// ---------------------------------------------------------------------------
// Scope
// ---------------------------------------------------------------------------

/// Token 权限范围：`read`（只读）或 `write`（读写）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TokenScope {
    Read,
    Write,
}

impl TokenScope {
    pub fn as_str(self) -> &'static str {
        match self {
            TokenScope::Read => "read",
            TokenScope::Write => "write",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        match s.trim().to_ascii_lowercase().as_str() {
            "read" => Some(TokenScope::Read),
            "write" => Some(TokenScope::Write),
            _ => None,
        }
    }

    /// `write` 隐含 `read`。
    pub fn allows(self, needed: Self) -> bool {
        matches!(
            (self, needed),
            (TokenScope::Write, TokenScope::Read)
                | (TokenScope::Write, TokenScope::Write)
                | (TokenScope::Read, TokenScope::Read)
        )
    }
}

// ---------------------------------------------------------------------------
// 存储
// ---------------------------------------------------------------------------

/// 一条 API Token 记录（摘要之外不落地任何 Token 材料）。
#[derive(Debug, Clone)]
pub struct ApiTokenRecord {
    pub id: String,
    pub token_hash: String,
    pub user_id: UserId,
    pub name: String,
    pub scopes: TokenScope,
    pub created_at: Timestamp,
    pub last_used_at: Option<Timestamp>,
    pub revoked_at: Option<Timestamp>,
}

/// API Token 存储（SQLite，migration 004）。
#[derive(Clone)]
pub struct ApiTokenStore {
    pool: SqlitePool,
}

impl ApiTokenStore {
    pub fn new(pool: SqlitePool) -> Self {
        Self { pool }
    }

    /// 签发：返回 (`raw_token`, 记录)。原始 Token 只在此出现一次。
    pub async fn issue(
        &self,
        user_id: &UserId,
        name: &str,
        scopes: TokenScope,
        now: Timestamp,
    ) -> Result<(String, ApiTokenRecord), sqlx::Error> {
        let raw = format!("{API_TOKEN_PREFIX}{}", generate_token());
        let id = format!("tok-{}", &generate_token()[..16]);
        let record = ApiTokenRecord {
            id: id.clone(),
            token_hash: token_hash(&raw),
            user_id: user_id.clone(),
            name: name.to_string(),
            scopes,
            created_at: now.clone(),
            last_used_at: None,
            revoked_at: None,
        };
        sqlx::query(
            "INSERT INTO api_tokens (id, token_hash, user_id, name, scopes, created_at)
             VALUES (?, ?, ?, ?, ?, ?)",
        )
        .bind(&record.id)
        .bind(&record.token_hash)
        .bind(&record.user_id.0)
        .bind(&record.name)
        .bind(record.scopes.as_str())
        .bind(record.created_at.as_str())
        .execute(&self.pool)
        .await?;
        Ok((raw, record))
    }

    /// 某用户的全部 token（创建时间序；不含摘要列）。
    pub async fn list_for_user(
        &self,
        user_id: &UserId,
    ) -> Result<Vec<ApiTokenRecord>, sqlx::Error> {
        let rows = sqlx::query_as::<
            _,
            (
                String,
                String,
                String,
                String,
                Option<String>,
                Option<String>,
            ),
        >(
            "SELECT id, name, scopes, created_at, last_used_at, revoked_at
             FROM api_tokens WHERE user_id = ? ORDER BY created_at, id",
        )
        .bind(&user_id.0)
        .fetch_all(&self.pool)
        .await?;
        Ok(rows
            .into_iter()
            .map(
                |(id, name, scopes, created_at, last_used_at, revoked_at)| ApiTokenRecord {
                    id,
                    token_hash: String::new(), // 列表路径不取摘要
                    user_id: user_id.clone(),
                    name,
                    scopes: TokenScope::parse(&scopes).unwrap_or(TokenScope::Read),
                    created_at,
                    last_used_at,
                    revoked_at,
                },
            )
            .collect())
    }

    /// Bearer 校验：存在且未撤销 → (用户, scope)，并节流刷新 `last_used_at`。
    pub async fn validate(
        &self,
        raw_token: &str,
        now: &Timestamp,
    ) -> Result<Option<(UserId, TokenScope)>, sqlx::Error> {
        let row = sqlx::query_as::<_, (String, String, Option<String>, Option<String>)>(
            "SELECT user_id, scopes, revoked_at, last_used_at
             FROM api_tokens WHERE token_hash = ?",
        )
        .bind(token_hash(raw_token))
        .fetch_optional(&self.pool)
        .await?;
        let Some((user_id, scopes, revoked_at, last_used_at)) = row else {
            return Ok(None);
        };
        if revoked_at.is_some() {
            return Ok(None);
        }
        let Some(scope) = TokenScope::parse(&scopes) else {
            return Ok(None); // 损坏行按无效凭证处理
        };
        if last_used_at_is_stale(last_used_at.as_deref(), now) {
            sqlx::query("UPDATE api_tokens SET last_used_at = ? WHERE token_hash = ?")
                .bind(now.as_str())
                .bind(token_hash(raw_token))
                .execute(&self.pool)
                .await?;
        }
        Ok(Some((UserId(user_id), scope)))
    }

    /// 撤销（仅属主可撤）；返回是否确有此 token。
    pub async fn revoke(
        &self,
        user_id: &UserId,
        token_id: &str,
        at: &Timestamp,
    ) -> Result<bool, sqlx::Error> {
        let result =
            sqlx::query("UPDATE api_tokens SET revoked_at = ? WHERE id = ? AND user_id = ?")
                .bind(at.as_str())
                .bind(token_id)
                .bind(&user_id.0)
                .execute(&self.pool)
                .await?;
        Ok(result.rows_affected() > 0)
    }
}

fn last_used_at_is_stale(last_used_at: Option<&str>, now: &Timestamp) -> bool {
    let parse = |t: &str| chrono::DateTime::parse_from_rfc3339(t).ok();
    let now = parse(now.as_str());
    match (last_used_at.and_then(parse), now) {
        (Some(used), Some(now)) => {
            now.signed_duration_since(used).num_seconds() >= LAST_USED_REFRESH_SECS
        }
        _ => true, // 从未使用，或时间戳异常——直接刷新
    }
}

// ---------------------------------------------------------------------------
// 端点
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CreateTokenRequest {
    /// 便于人工识别的标签（如 `cockpit`、`ci-pipeline`）。
    pub name: String,
    /// `read` 或 `write`（write 隐含 read）。
    pub scopes: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct ApiTokenCreated {
    pub id: String,
    /// 原始 Token **仅此一次**返回（`mlt_` + 64 hex）。
    pub token: String,
    pub name: String,
    pub scopes: String,
    pub created_at: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct ApiTokenView {
    pub id: String,
    pub name: String,
    pub scopes: String,
    pub created_at: String,
    pub last_used_at: Option<String>,
    pub revoked_at: Option<String>,
}

fn to_view(r: &ApiTokenRecord) -> ApiTokenView {
    ApiTokenView {
        id: r.id.clone(),
        name: r.name.clone(),
        scopes: r.scopes.as_str().to_string(),
        created_at: r.created_at.clone(),
        last_used_at: r.last_used_at.clone(),
        revoked_at: r.revoked_at.clone(),
    }
}

/// API Token 路由（管理 API：与其它管理端点同一认证 + CSRF 防线）。
pub fn routes() -> Router<SharedAppState> {
    Router::new()
        .route(
            "/api/v1/auth/tokens",
            post(create_token_handler).get(list_tokens_handler),
        )
        .route(
            "/api/v1/auth/tokens/{token_id}",
            delete(revoke_token_handler),
        )
}

/// `POST /api/v1/auth/tokens`：签发机器凭据（原始 Token 仅此一次返回）。
pub async fn create_token_handler(
    State(state): State<SharedAppState>,
    WriteUser(user_id): WriteUser,
    CsrfHeader: CsrfHeader,
    Json(req): Json<CreateTokenRequest>,
) -> Result<(StatusCode, Json<ApiTokenCreated>), AuthApiError> {
    let name = req.name.trim().to_string();
    if name.is_empty() || name.chars().count() > 128 {
        return Err(AuthApiError::InvalidInput(
            "name must be 1-128 characters".into(),
        ));
    }
    let scopes = TokenScope::parse(&req.scopes).ok_or_else(|| {
        AuthApiError::InvalidInput(format!(
            "scopes must be \"read\" or \"write\", got {:?}",
            req.scopes
        ))
    })?;
    let (raw, record) = state
        .api_tokens
        .issue(&user_id, &name, scopes, service::now())
        .await
        .map_err(|e| AuthApiError::Internal(e.to_string()))?;
    Ok((
        StatusCode::CREATED,
        Json(ApiTokenCreated {
            id: record.id,
            token: raw,
            name: record.name,
            scopes: record.scopes.as_str().to_string(),
            created_at: record.created_at,
        }),
    ))
}

/// `GET /api/v1/auth/tokens`：当前用户的 token 列表（无任何 Token 材料）。
pub async fn list_tokens_handler(
    State(state): State<SharedAppState>,
    AuthenticatedUser(user_id): AuthenticatedUser,
) -> Result<Json<Vec<ApiTokenView>>, AuthApiError> {
    let list = state
        .api_tokens
        .list_for_user(&user_id)
        .await
        .map_err(|e| AuthApiError::Internal(e.to_string()))?;
    Ok(Json(list.iter().map(to_view).collect()))
}

/// `DELETE /api/v1/auth/tokens/{token_id}`：撤销（即失效；仅属主可撤）。
pub async fn revoke_token_handler(
    State(state): State<SharedAppState>,
    WriteUser(user_id): WriteUser,
    CsrfHeader: CsrfHeader,
    Path(token_id): Path<String>,
) -> Result<StatusCode, AuthApiError> {
    let revoked = state
        .api_tokens
        .revoke(&user_id, &token_id, &service::now())
        .await
        .map_err(|e| AuthApiError::Internal(e.to_string()))?;
    if revoked {
        Ok(StatusCode::NO_CONTENT)
    } else {
        Err(AuthApiError::NotFound(format!(
            "token {token_id} not found"
        )))
    }
}
