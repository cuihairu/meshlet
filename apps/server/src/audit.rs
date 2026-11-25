//! Audit log (archival, §16.5, ADR-010).
//!
//! Records sensitive operations: login success/failure, bootstrap, logout, network creation, invite issuance/revocation,
//! device enrollment/revocation, LAN Route add/remove, API Token issuance/revocation, config apply and rollback
//! (a failed apply always leaves a trace). Schema: `audit_events` in `migrations/001_init.sql`
//! (table created in Phase 1).
//!
//! **No plaintext secrets are recorded** (§16.5): `record` only accepts controlled fields (actor / action /
//! target_type / target_id / structured detail values) and never the raw request body — passwords,
//! private keys, invite Tokens, and raw agent/API Token material cannot reach the audit table by construction
//! (test assertion `no_secret_material_in_audit`).

use axum::extract::{Query, State};
use axum::routing::get;
use axum::{Json, Router};
use serde::{Deserialize, Serialize};
use sqlx::SqlitePool;

use crate::auth::{AuthenticatedUser, SharedAppState};
use crate::service;

/// Audit storage: the same database as credentials (the `audit_events` table, migration 001).
#[derive(Clone)]
pub struct AuditStore {
    pool: SqlitePool,
}

/// Audit event view (a list-response entry; no raw credential material).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AuditEvent {
    pub id: i64,
    pub created_at: String,
    pub actor_id: Option<String>,
    pub action: String,
    pub target_type: String,
    pub target_id: Option<String>,
    pub detail: Option<String>,
}

impl AuditStore {
    pub fn new(pool: SqlitePool) -> Self {
        Self { pool }
    }

    /// Record one audit event. `detail` accepts only controlled structured values (JSON stored in a TEXT column).
    pub async fn record(
        &self,
        actor: Option<&str>,
        action: &str,
        target_type: &str,
        target_id: Option<&str>,
        detail: Option<serde_json::Value>,
    ) -> Result<(), sqlx::Error> {
        let detail = detail.map(|v| v.to_string());
        sqlx::query(
            "INSERT INTO audit_events \
             (actor_id, action, target_type, target_id, detail, created_at) \
             VALUES (?, ?, ?, ?, ?, ?)",
        )
        .bind(actor)
        .bind(action)
        .bind(target_type)
        .bind(target_id)
        .bind(detail)
        .bind(service::now())
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// Newest first (id descending).
    pub async fn list(&self, limit: u32, offset: u64) -> Result<Vec<AuditEvent>, sqlx::Error> {
        Ok(sqlx::query_as::<
            _,
            (
                i64,
                String,
                Option<String>,
                String,
                String,
                Option<String>,
                Option<String>,
            ),
        >(
            "SELECT id, created_at, actor_id, action, target_type, target_id, detail \
             FROM audit_events ORDER BY id DESC LIMIT ? OFFSET ?",
        )
        .bind(limit as i64)
        .bind(offset as i64)
        .fetch_all(&self.pool)
        .await?
        .into_iter()
        .map(
            |(id, created_at, actor_id, action, target_type, target_id, detail)| AuditEvent {
                id,
                created_at,
                actor_id,
                action,
                target_type,
                target_id,
                detail,
            },
        )
        .collect())
    }

    pub async fn count(&self) -> Result<i64, sqlx::Error> {
        sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM audit_events")
            .fetch_one(&self.pool)
            .await
    }
}

#[derive(Debug, Deserialize)]
struct AuditQuery {
    limit: Option<u32>,
    offset: Option<u64>,
}

#[derive(Debug, Serialize)]
struct AuditPage {
    total: i64,
    events: Vec<AuditEvent>,
}

/// `GET /api/v1/audit?limit=&offset=`: the audit event list (newest first, paginated).
async fn list_audit_handler(
    State(state): State<SharedAppState>,
    AuthenticatedUser(_user): AuthenticatedUser,
    Query(query): Query<AuditQuery>,
) -> Result<Json<AuditPage>, service::ServiceError> {
    let limit = query.limit.unwrap_or(50).min(500);
    let offset = query.offset.unwrap_or(0);
    let total = state
        .audit
        .count()
        .await
        .map_err(|e| service::ServiceError::Internal(e.to_string()))?;
    let events = state
        .audit
        .list(limit, offset)
        .await
        .map_err(|e| service::ServiceError::Internal(e.to_string()))?;
    Ok(Json(AuditPage { total, events }))
}

pub fn routes() -> Router<SharedAppState> {
    Router::new().route("/api/v1/audit", get(list_audit_handler))
}

/// Helper for tracing sensitive operations: a write failure -> `Internal` (the operational form of §16.5's
/// "record all sensitive operations" — **no trace, no proceed**; audit and business data share one database, so an independent failure means the database is already broken).
pub(crate) async fn record_or_fail(
    state: &SharedAppState,
    actor: Option<&str>,
    action: &str,
    target_type: &str,
    target_id: Option<&str>,
    detail: Option<serde_json::Value>,
) -> Result<(), service::ServiceError> {
    state
        .audit
        .record(actor, action, target_type, target_id, detail)
        .await
        .map_err(|e| service::ServiceError::Internal(e.to_string()))
}
