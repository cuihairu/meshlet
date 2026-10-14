//! 审计日志（存档 §16.5、ADR-010）。
//!
//! 记录敏感操作：登录成功/失败、bootstrap、登出、网络创建、邀请签发/撤销、
//! 设备加入/撤销、LAN Route 增删、API Token 签发/撤销、配置应用与回滚
//! （应用失败必留痕）。schema 见 `migrations/001_init.sql` 的 `audit_events`
//! （Phase 1 已建表）。
//!
//! **不记录明文秘密**（§16.5）：`record` 只接受受控字段（actor / action /
//! target_type / target_id / detail 结构化值），不接收请求体原文——密码、
//! 私钥、邀请 Token、agent/API Token 原始材料在类型上就进不了审计表
//! （测试断言 `no_secret_material_in_audit`）。

use axum::extract::{Query, State};
use axum::routing::get;
use axum::{Json, Router};
use serde::{Deserialize, Serialize};
use sqlx::SqlitePool;

use crate::auth::{AuthenticatedUser, SharedAppState};
use crate::service;

/// 审计存储：与凭证同库（`audit_events` 表，migration 001）。
#[derive(Clone)]
pub struct AuditStore {
    pool: SqlitePool,
}

/// 审计事件视图（列表响应条目；无原始凭证材料）。
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

    /// 记录一条审计事件。`detail` 只接受受控结构化值（JSON 存 TEXT 列）。
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

    /// 最新在前（id 降序）。
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

/// `GET /api/v1/audit?limit=&offset=`：审计事件列表（最新在前，分页）。
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

/// 敏感操作留痕辅助：写入失败 → `Internal`（§16.5「敏感操作全记录」的
/// 落地口径——**不留痕不放行**；审计与业务同库，独立失败即库已坏）。
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
