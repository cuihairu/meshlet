//! Versioned device receipts and hub drift recovery.
use crate::{
    agent::{AgentApiError, AuthorizedAgent},
    auth::SharedAppState,
    service,
};
use axum::{extract::State, http::StatusCode, Json};
use meshlet_domain::{ApplyStatus, DesiredStateStatus, NetworkId};
use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ApplyReceipt {
    pub desired_revision: u64,
    pub plan_hash: String,
    pub error: Option<String>,
}

#[derive(Debug, Default, Serialize)]
pub struct Convergence {
    pub device_apply_status: String,
    pub pending_device_ids: Vec<String>,
    pub device_errors: std::collections::BTreeMap<String, String>,
    pub hub_recovery_error: Option<String>,
    pub business_health: String,
}

pub async fn status(
    state: &SharedAppState,
    network: &str,
) -> Result<Convergence, service::ServiceError> {
    let mut result = Convergence {
        device_apply_status: "pending".into(),
        business_health: "not_probed".into(),
        ..Default::default()
    };
    if !state.dataplane.enabled {
        result.device_apply_status = "not_configured".into();
        return Ok(result);
    }
    let key = match crate::device_plan::hub_public_key(&state.dataplane) {
        Ok(key) => key,
        Err(error) => {
            result.device_apply_status = "failed".into();
            result.hub_recovery_error = Some(error);
            return Ok(result);
        }
    };
    let (revision, hub_applied, journaled, expected) = {
        let mesh = state.mesh.lock().unwrap();
        service::require_network(&mesh, network)?;
        let current = mesh.ledger.current(&NetworkId(network.into()));
        let expected = mesh
            .registry
            .devices()
            .iter()
            .filter(|d| d.is_active() && d.network_id.0 == network)
            .map(|d| {
                crate::device_plan::build_device_plan(
                    &mesh,
                    network,
                    &d.id,
                    &state.dataplane,
                    state.tunnel_mtu,
                    &key,
                )
                .map(|p| (d.id.0.clone(), p.desired_config_hash))
            })
            .collect::<Result<Vec<_>, _>>()
            .map_err(service::ServiceError::Internal)?;
        (
            current.map(|r| r.revision).unwrap_or(0),
            current.is_some_and(|r| r.apply_status == ApplyStatus::Applied),
            mesh.deployments.contains_key(network),
            expected,
        )
    };
    let rows = sqlx::query_as::<_, (String, i64, String, Option<String>)>("SELECT device_id,revision,plan_hash,error FROM device_apply_receipts WHERE device_id IN (SELECT id FROM devices WHERE network_id=?)")
        .bind(network).fetch_all(state.auth.pool()).await.map_err(crate::persist::internal)?;
    for (device, hash) in expected {
        match rows
            .iter()
            .find(|r| r.0 == device && r.1 == revision as i64 && r.2 == hash)
        {
            Some((_, _, _, None)) => {}
            Some((_, _, _, Some(error))) => {
                result.device_errors.insert(device.clone(), error.clone());
                result.pending_device_ids.push(device);
            }
            None => result.pending_device_ids.push(device),
        }
    }
    result.pending_device_ids.sort();
    result.hub_recovery_error = sqlx::query_scalar::<_, Option<String>>(
        "SELECT recovery_error FROM hub_deployments WHERE network_id=?",
    )
    .bind(network)
    .fetch_optional(state.auth.pool())
    .await
    .map_err(crate::persist::internal)?
    .flatten();
    if hub_applied && !journaled {
        result.hub_recovery_error = sqlx::query_scalar::<_, Option<String>>(
            "SELECT error_summary FROM config_revisions WHERE network_id=? AND revision=?",
        )
        .bind(network)
        .bind(revision as i64)
        .fetch_optional(state.auth.pool())
        .await
        .map_err(crate::persist::internal)?
        .flatten()
        .or_else(|| Some("hub recovery has not yet confirmed the legacy configuration".into()));
    }
    if hub_applied && result.pending_device_ids.is_empty() && result.hub_recovery_error.is_none() {
        result.device_apply_status = "applied".into();
    } else if !result.device_errors.is_empty() {
        result.device_apply_status = "failed".into();
    }
    Ok(result)
}

pub async fn receipt_handler(
    State(state): State<SharedAppState>,
    AuthorizedAgent(id): AuthorizedAgent,
    Json(receipt): Json<ApplyReceipt>,
) -> Result<StatusCode, AgentApiError> {
    let _persist = state.persist.lock().await;
    if receipt.error.as_ref().is_some_and(|e| e.len() > 4096) {
        return Err(AgentApiError::InvalidInput(
            "apply error exceeds 4096 bytes".into(),
        ));
    }
    let network = {
        let mesh = state.mesh.lock().unwrap();
        let device = mesh
            .registry
            .find_by_id(&id)
            .filter(|d| d.is_active())
            .ok_or(AgentApiError::Unauthorized)?;
        let network = device.network_id.0.clone();
        let current = mesh
            .ledger
            .current(&device.network_id)
            .ok_or_else(|| AgentApiError::InvalidInput("no desired revision".into()))?;
        if current.apply_status != ApplyStatus::Applied
            || current.revision != receipt.desired_revision
        {
            return Err(AgentApiError::InvalidInput(
                "stale receipt or hub revision is not applied".into(),
            ));
        }
        let key = crate::device_plan::hub_public_key(&state.dataplane)
            .map_err(AgentApiError::Internal)?;
        let plan = crate::device_plan::build_device_plan(
            &mesh,
            &network,
            &id,
            &state.dataplane,
            state.tunnel_mtu,
            &key,
        )
        .map_err(AgentApiError::Internal)?;
        if plan.desired_config_hash != receipt.plan_hash {
            return Err(AgentApiError::InvalidInput(
                "receipt plan hash does not match desired plan".into(),
            ));
        }
        network
    };
    sqlx::query("INSERT INTO device_apply_receipts(device_id,revision,plan_hash,applied_at,error) VALUES(?,?,?,?,?) ON CONFLICT(device_id) DO UPDATE SET revision=excluded.revision,plan_hash=excluded.plan_hash,applied_at=excluded.applied_at,error=excluded.error")
        .bind(&id.0).bind(receipt.desired_revision as i64).bind(receipt.plan_hash).bind(service::now()).bind(receipt.error).execute(state.auth.pool()).await.map_err(|e| AgentApiError::Internal(e.to_string()))?;
    let convergence = status(&state, &network)
        .await
        .map_err(|e| AgentApiError::Internal(e.to_string()))?;
    let settle = {
        let mut mesh = state.mesh.lock().unwrap();
        service::settle_desired_with_status(
            &mut mesh,
            &network,
            if convergence.device_apply_status == "applied" {
                DesiredStateStatus::Applied
            } else {
                DesiredStateStatus::Pending
            },
        )
    };
    crate::persist::update_desired_status(state.auth.pool(), &settle)
        .await
        .map_err(|e| AgentApiError::Internal(e.to_string()))?;
    Ok(StatusCode::NO_CONTENT)
}

/// Inspect/recover once, using the same injected backend as production apply.
pub async fn recover_once(state: SharedAppState) -> Result<(), String> {
    tokio::task::spawn_blocking(move || recover_hubs(&state))
        .await
        .map_err(|e| e.to_string())
}

/// Run immediately at startup, then periodically. A saved Applied row never
/// substitutes for observing the kernel. Pending edits are not auto-published.
pub fn start_recovery(state: SharedAppState) {
    if !state.dataplane.enabled {
        return;
    }
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(std::time::Duration::from_secs(30));
        loop {
            ticker.tick().await;
            if let Err(error) = recover_once(state.clone()).await {
                tracing::error!(%error, "hub recovery task failed");
            }
        }
    });
}

fn recover_hubs(state: &SharedAppState) {
    let rt = tokio::runtime::Handle::current();
    let _persist = state.persist.blocking_lock();
    // Older databases have Applied revisions but no recovery journal. Confirm
    // their current public plan in the kernel before treating it as last-good.
    let legacy = {
        let mesh = state.mesh.lock().unwrap();
        service::list_networks(&mesh)
            .into_iter()
            .filter_map(|n| {
                let revision = mesh.ledger.current(&NetworkId(n.id.clone()))?;
                (revision.apply_status == ApplyStatus::Applied
                    && !mesh.deployments.contains_key(&n.id))
                .then(|| (n.id, revision.clone()))
            })
            .collect::<Vec<_>>()
    };
    for (id, mut revision) in legacy {
        let result = {
            let mesh = state.mesh.lock().unwrap();
            crate::revision::deployment(
                &mesh,
                &id,
                &state.dataplane,
                state.tunnel_mtu,
                revision.revision,
            )
            .and_then(|plan| {
                let mut backend = (state.apply_backend)(&mesh, &id);
                backend.apply(&revision).map(|()| plan)
            })
        };
        let settle = {
            let mut mesh = state.mesh.lock().unwrap();
            service::settle_desired_with_status(&mut mesh, &id, DesiredStateStatus::Pending)
        };
        match result {
            Ok(plan) => {
                revision.error_summary = None;
                match rt.block_on(crate::persist::commit_application(
                    state.auth.pool(),
                    &revision,
                    &settle,
                    Some(&plan),
                )) {
                    Ok(()) => {
                        state
                            .mesh
                            .lock()
                            .unwrap()
                            .deployments
                            .insert(id.clone(), plan);
                    }
                    Err(error) => {
                        tracing::error!(network_id=%id, %error, "persist legacy hub recovery failed")
                    }
                }
            }
            Err(error) => {
                tracing::error!(network_id=%id, %error, "legacy hub recovery failed");
                revision.error_summary = Some(format!("hub recovery: {error}"));
                if let Err(error) = rt.block_on(crate::persist::commit_application(
                    state.auth.pool(),
                    &revision,
                    &settle,
                    None,
                )) {
                    tracing::error!(network_id=%id, %error, "persist legacy recovery failure failed");
                }
            }
        }
    }
    let saved: Vec<_> = state
        .mesh
        .lock()
        .unwrap()
        .deployments
        .iter()
        .map(|(id, plan)| (id.clone(), plan.clone()))
        .collect();
    for (id, saved) in saved {
        let outcome = crate::revision::recover_deployment(state, &id, saved);
        let error = outcome.err();
        if let Some(error) = &error {
            tracing::error!(network_id=%id, %error, "hub recovery failed");
        }
        if let Err(error) = rt.block_on(
            sqlx::query(
                "UPDATE hub_deployments SET recovery_error=?,checked_at=? WHERE network_id=?",
            )
            .bind(error)
            .bind(service::now())
            .bind(&id)
            .execute(state.auth.pool()),
        ) {
            tracing::error!(%error, "persist hub recovery result failed");
        }
    }
}
