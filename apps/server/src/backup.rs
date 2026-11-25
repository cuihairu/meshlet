//! Consistent backup endpoint (archive §17.4): `POST /api/v1/system/backup`.
//!
//! - **A local snapshot, not sync**: it writes only to the backup directory
//!   configured on the server (`[backup] dir`), with no outbound transfer,
//!   cloud upload or telemetry; directory not configured → `503`
//!   `backup_not_configured` (a default deployment produces no files);
//! - Consistency is guaranteed by an SQLite `VACUUM INTO` snapshot
//!   (independently openable, self-contained);
//! - Restore does not go over HTTP — the live database file cannot be replaced
//!   while it is being served: restore is the offline
//!   `meshlet-server restore <backup.db>` subcommand (`main.rs`), which
//!   records a `system.restore` audit event and then rebuilds per §17.3 semantics.

use axum::extract::State;
use axum::response::{IntoResponse, Response};
use axum::routing::post;
use axum::{Json, Router};
use meshlet_api_types::{ErrorCode, ErrorResponse};
use std::path::Path;

use crate::auth::{CsrfHeader, SharedAppState, WriteUser};
use crate::persist::BackupError;
use crate::service;

/// Response of `POST /api/v1/system/backup`.
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

/// Backup endpoint error (directory not configured in a default deployment →
/// 503, an explicit failure rather than a silent one).
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
    // An unconfigured backup is an explicit 503 ("backup ≠ sync": by default no
    // file is written at all).
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
