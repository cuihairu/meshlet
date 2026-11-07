//! Agent 发布健康回报入口。

use crate::agent::{AgentApiError, AuthorizedAgent};
use crate::auth::SharedAppState;
use crate::service::ServiceError;
use axum::extract::State;
use axum::Json;

#[derive(Debug, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PublishHealthRequest {
    pub reports: Vec<meshlet_publish::ProbeReport>,
}

#[derive(Debug, serde::Serialize)]
pub struct PublishHealthResponse {
    pub accepted: usize,
}

/// `POST /api/v1/agent/publish-health`：agent 批量上报探针结果。内存与 DB
/// 镜像同事务更新；`publish_probe_reports` 按 probe 主键 upsert（每探针一条
/// 最新证据），且只接受归本设备的探针。
pub(crate) async fn publish_health_handler(
    State(state): State<SharedAppState>,
    AuthorizedAgent(device_id): AuthorizedAgent,
    Json(req): Json<PublishHealthRequest>,
) -> Result<Json<PublishHealthResponse>, AgentApiError> {
    if req.reports.len() > 256 {
        return Err(AgentApiError::InvalidInput(format!(
            "too many reports in one batch: {} > 256",
            req.reports.len()
        )));
    }
    let _persist = state.persist.lock().await;
    let staged_reports = {
        let mut guard = state.mesh.lock().unwrap();
        let network_id = match guard.registry.find_by_id(&device_id) {
            Some(device) => device.network_id.to_string(),
            None => return Err(AgentApiError::NotFound(device_id.to_string())),
        };
        for report in &req.reports {
            if let Err(e) = crate::publish::crud::record_probe_health(
                &mut guard,
                &network_id,
                &device_id.to_string(),
                &report.probe_id,
                report.clone(),
            ) {
                return Err(match e {
                    ServiceError::PublishNotFound(id) => AgentApiError::NotFound(id),
                    ServiceError::Conflict(m) => AgentApiError::InvalidInput(m),
                    other => AgentApiError::Internal(other.to_string()),
                });
            }
        }
        req.reports.clone()
    };
    super::persist::upsert_probe_reports(
        state.auth.pool(),
        &device_id.to_string(),
        &staged_reports,
    )
    .await
    .map_err(|e| AgentApiError::Internal(e.to_string()))?;
    Ok(Json(PublishHealthResponse {
        accepted: staged_reports.len(),
    }))
}

// ---------------------------------------------------------------------------
