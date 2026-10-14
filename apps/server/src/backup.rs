//! 一致性备份端点（存档 §17.4）：`POST /api/v1/system/backup`。
//!
//! - **本地快照，不是同步**：只写服务器上配置的备份目录
//!   （`[backup] dir`），无任何外发/云上传/遥测；目录未配置 → `503`
//!   `backup_not_configured`（默认部署不产生任何文件）；
//! - 一致性由 SQLite `VACUUM INTO` 快照保证（独立可打开、自洽）；
//! - 恢复不走 HTTP——活动库文件不能在被服务时替换：恢复是
//!   `meshlet-server restore <backup.db>` 离线子命令（`main.rs`），
//!   落 `system.restore` 审计事件后按 §17.3 语义重建。

use axum::extract::State;
use axum::response::{IntoResponse, Response};
use axum::routing::post;
use axum::{Json, Router};
use meshlet_api_types::{ErrorCode, ErrorResponse};
use std::path::Path;

use crate::auth::{CsrfHeader, SharedAppState, WriteUser};
use crate::persist::BackupError;
use crate::service;

/// `POST /api/v1/system/backup` 响应。
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct BackupResponse {
    pub path: String,
    pub created_at: String,
    pub bytes: u64,
    pub networks: usize,
    pub devices: usize,
    pub routes: usize,
    pub invites: usize,
    pub revisions: usize,
}

impl From<crate::persist::BackupReport> for BackupResponse {
    fn from(r: crate::persist::BackupReport) -> Self {
        Self {
            path: r.path,
            created_at: service::now(),
            bytes: r.bytes,
            networks: r.view.networks,
            devices: r.view.devices,
            routes: r.view.routes,
            invites: r.view.invites,
            revisions: r.view.revisions,
        }
    }
}

/// 备份端点错误（默认部署未配置目录 → 503，明确而非静默失败）。
#[derive(Debug)]
pub enum BackupApiError {
    NotConfigured,
    TargetExists(String),
    Internal(String),
}

impl IntoResponse for BackupApiError {
    fn into_response(self) -> Response {
        let (status, code, message) = match self {
            Self::NotConfigured => (
                axum::http::StatusCode::SERVICE_UNAVAILABLE,
                ErrorCode::BackupNotConfigured,
                "backup directory is not configured ([backup] dir in server config)".to_string(),
            ),
            Self::TargetExists(path) => (
                axum::http::StatusCode::CONFLICT,
                ErrorCode::Conflict,
                format!("backup target already exists: {path}"),
            ),
            Self::Internal(m) => (
                axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                ErrorCode::Internal,
                m,
            ),
        };
        (status, Json(ErrorResponse::new(code, message))).into_response()
    }
}

impl From<BackupError> for BackupApiError {
    fn from(e: BackupError) -> Self {
        match e {
            BackupError::TargetExists(path) => Self::TargetExists(path),
            BackupError::Locked(why) => Self::Internal(format!("database locked: {why}")),
            e => Self::Internal(e.to_string()),
        }
    }
}

async fn backup_handler(
    State(state): State<SharedAppState>,
    WriteUser(user_id): WriteUser,
    CsrfHeader: CsrfHeader,
) -> Result<Json<BackupResponse>, BackupApiError> {
    // 备份未配置即明确 503（「备份 ≠ 同步」：默认不写任何文件）。
    let dir = state
        .backup_dir
        .as_deref()
        .ok_or(BackupApiError::NotConfigured)?;
    let report = crate::persist::backup_once(state.auth.pool(), Path::new(dir), Some(&user_id.0))
        .await
        .map_err(BackupApiError::from)?;
    crate::op_log!(
        info,
        "system",
        "backup",
        crate::telemetry::NOT_APPLICABLE,
        crate::telemetry::NOT_APPLICABLE,
        crate::telemetry::NOT_APPLICABLE,
        crate::telemetry::ErrorCategory::None.as_str(),
        crate::telemetry::RESULT_OK
    );
    Ok(Json(BackupResponse::from(report)))
}

pub fn routes() -> Router<SharedAppState> {
    Router::new().route("/api/v1/system/backup", post(backup_handler))
}
