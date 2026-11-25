//! External machine credential: API Token (2026-10-14 user request).
//!
//! - **Long-lived credential**: external systems (e.g. cockpit) call the
//!   management API with `Authorization: Bearer mlt_...`, alongside browser
//!   Cookie sessions (`AuthenticatedUser` accepts either credential; write
//!   endpoints go through `WriteUser`, see auth.rs);
//! - **same-token discipline** (§11.3): the server stores only the SHA-256
//!   digest; the raw token appears exactly once, in the creation response;
//!   the `mlt_` prefix makes it instantly distinguishable from agent tokens /
//!   invite tokens in logs and leak investigations;
//! - **least privilege**: two scope tiers, `read` / `write` (write implies
//!   read); sessions always hold every permission;
//! - **revocable + attributable in the audit trail**: a token belongs to the
//!   `user_id` that created it, `last_used_at` records usage time in a
//!   throttled fashion; revocation takes effect immediately;
//! - **the CSRF defence is not weakened**: Cookie-authenticated write requests
//!   must still carry `X-Requested-With`. A Bearer token is not a credential
//!   a browser attaches automatically (cross-site requests cannot forge one),
//!   but to keep the uniform meaning that "management-side write requests must
//!   carry the CSRF header", the same requirement applies to token callers.

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::routing::{delete, post};
use axum::{Json, Router};
use meshlet_domain::{generate_token, token_hash, Timestamp, UserId};
use serde::{Deserialize, Serialize};
use sqlx::SqlitePool;

use crate::auth::{AuthApiError, AuthenticatedUser, CsrfHeader, SharedAppState, WriteUser};
use crate::service;

/// Raw form prefix of an API Token: `mlt_` + 64 hex (32 bytes of random
/// material).
pub const API_TOKEN_PREFIX: &str = "mlt_";

/// Throttle for refreshing `last_used_at`: keeps audit attribution observable
/// without adding one write amplification per read request.
const LAST_USED_REFRESH_SECS: i64 = 60;

// ---------------------------------------------------------------------------
// Scope
// ---------------------------------------------------------------------------

/// Permission scope of a token: `read` (read-only) or `write` (read + write).
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

    /// `write` implies `read`.
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
// Storage
// ---------------------------------------------------------------------------

/// An API Token record (no token material is persisted beyond the digest).
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

/// API Token storage (SQLite, migration 004).
#[derive(Clone)]
pub struct ApiTokenStore {
    pool: SqlitePool,
}

impl ApiTokenStore {
    pub fn new(pool: SqlitePool) -> Self {
        Self { pool }
    }

    /// Issue: returns (`raw_token`, record). The raw token appears only here,
    /// once.
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

    /// All of a user's tokens (creation-time order; the digest column excluded).
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
                    token_hash: String::new(), // the list path does not read the digest
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

    /// Bearer validation: exists and not revoked → (user, scope), and
    /// throttled-refreshes `last_used_at`.
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
            return Ok(None); // a corrupted row is treated as an invalid credential
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

    /// Revoke (only the owner can revoke); returns whether the token really
    /// existed.
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
        _ => true, // never used, or an anomalous timestamp -- refresh right away
    }
}

// ---------------------------------------------------------------------------
// Endpoints
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CreateTokenRequest {
    /// A label that makes the token recognizable to humans (e.g. `cockpit`,
    /// `ci-pipeline`).
    pub name: String,
    /// `read` or `write` (write implies read).
    pub scopes: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct ApiTokenCreated {
    pub id: String,
    /// The raw token, returned **this once only** (`mlt_` + 64 hex).
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

/// API Token routes (management API: the same authentication + CSRF defence
/// as the other management endpoints).
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

/// `POST /api/v1/auth/tokens`: issue a machine credential (the raw token is
/// returned this once only).
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
    // Only metadata (id/name/scope) is traced; the raw token never enters the
    // audit trail (§16.5).
    crate::audit::record_or_fail(
        &state,
        Some(&user_id.0),
        "api_token.created",
        "api_token",
        Some(&record.id),
        Some(serde_json::json!({ "name": name, "scopes": scopes.as_str() })),
    )
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

/// `GET /api/v1/auth/tokens`: the current user's token list (no token
/// material at all).
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

/// `DELETE /api/v1/auth/tokens/{token_id}`: revoke (takes effect at once;
/// only the owner can revoke).
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
        crate::audit::record_or_fail(
            &state,
            Some(&user_id.0),
            "api_token.revoked",
            "api_token",
            Some(&token_id),
            None,
        )
        .await
        .map_err(|e| AuthApiError::Internal(e.to_string()))?;
        Ok(StatusCode::NO_CONTENT)
    } else {
        Err(AuthApiError::NotFound(format!(
            "token {token_id} not found"
        )))
    }
}
