//! 网络端点：建网（变更 + 落库同一互斥段，§17.3）与列网。

use crate::auth::{AuthenticatedUser, CsrfHeader, SharedAppState, WriteUser};
use crate::service;
use crate::service::{create_network, list_networks};
use axum::extract::State;
use axum::http::StatusCode;
use axum::Json;

pub(crate) async fn create_network_handler(
    State(state): State<SharedAppState>,
    WriteUser(user_id): WriteUser,
    CsrfHeader: CsrfHeader,
    Json(req): Json<service::CreateNetworkRequest>,
) -> Result<(StatusCode, Json<service::NetworkView>), service::ServiceError> {
    // 变更 + 落库同一互斥段（§17.3）：DB 镜像与内存变更序一致。
    let _persist = state.persist.lock().await;
    let (view, network, revision, staged) = {
        let guard = state.mesh.lock().unwrap();
        let mut staged = guard.clone();
        crate::revision::network_dataplane(
            &state.dataplane,
            &format!("net-{}", guard.network_count() + 1),
        )
        .map_err(service::ServiceError::InvalidInput)?;
        let view = create_network(&mut staged, req)?;
        let network = staged.network_row(&view.id).expect("just created").clone();
        let revision = staged
            .ledger
            .get(
                &meshlet_domain::NetworkId(view.id.clone()),
                view.revision_id,
            )
            .expect("just recorded")
            .clone();
        (view, network, revision, staged)
    };
    let audit = crate::persist::AuditDraft {
        actor_id: Some(&user_id.0),
        action: "network.created",
        target_type: "network",
        target_id: &view.id,
        detail: None,
    };
    crate::persist::commit_network(state.auth.pool(), &network, &revision, &audit)
        .await
        .map_err(crate::persist::internal)?;
    *state.mesh.lock().unwrap() = staged;
    crate::op_log!(
        info,
        "network",
        "create_network",
        &view.id,
        crate::telemetry::NOT_APPLICABLE,
        &view.revision_id.to_string(),
        crate::telemetry::ErrorCategory::None.as_str(),
        crate::telemetry::RESULT_OK
    );
    Ok((StatusCode::CREATED, Json(view)))
}

pub(crate) async fn list_networks_handler(
    State(state): State<SharedAppState>,
    AuthenticatedUser(_user): AuthenticatedUser,
) -> Result<Json<Vec<service::NetworkView>>, service::ServiceError> {
    let guard = state.mesh.lock().unwrap();
    Ok(Json(list_networks(&guard)))
}
