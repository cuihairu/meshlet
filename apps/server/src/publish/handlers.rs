//! 网络范围内四类发布对象的 HTTP handlers。

use super::crud::{
    create_dns_record, create_forward, create_http_route, create_probe, delete_dns_record,
    delete_forward, delete_http_route, delete_probe, get_dns_record, get_forward, get_http_route,
    get_probe, list_dns_records, list_forwards, list_http_routes, list_probes,
};
use super::views::{
    CreatePublishDnsRecordRequest, CreatePublishForwardRequest, CreatePublishHttpRouteRequest,
    CreatePublishProbeRequest, PublishDnsRecordView, PublishForwardView, PublishHttpRouteView,
    PublishProbeView,
};
use crate::auth::{AuthenticatedUser, CsrfHeader, SharedAppState, WriteUser};
use crate::service::ServiceError;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::Json;

pub(super) async fn create_forward_handler(
    State(state): State<SharedAppState>,
    WriteUser(user_id): WriteUser,
    CsrfHeader: CsrfHeader,
    Path(network_id): Path<String>,
    Json(req): Json<CreatePublishForwardRequest>,
) -> Result<(StatusCode, Json<PublishForwardView>), ServiceError> {
    let _persist = state.persist.lock().await;
    let (view, forward, revision, publish_seq, staged) = {
        let guard = state.mesh.lock().unwrap();
        let mut staged = guard.clone();
        match create_forward(&mut staged, &network_id, req) {
            Ok(view) => {
                let forward = staged
                    .publishes
                    .get(&network_id)
                    .and_then(|c| c.forwards.iter().find(|f| f.id == view.id))
                    .expect("just created")
                    .clone();
                let revision = staged
                    .ledger
                    .current(&meshlet_domain::NetworkId(network_id.clone()))
                    .expect("create_forward just recorded a revision")
                    .clone();
                let publish_seq = staged.publish_seq();
                (view, forward, revision, publish_seq, staged)
            }
            Err(e) => {
                crate::op_log!(
                    warn,
                    "publish",
                    "create_forward",
                    &network_id,
                    crate::telemetry::NOT_APPLICABLE,
                    crate::telemetry::NOT_APPLICABLE,
                    crate::telemetry::ErrorCategory::from(&e).as_str(),
                    crate::telemetry::RESULT_ERROR
                );
                return Err(e);
            }
        }
    };
    let audit = crate::persist::AuditDraft {
        actor_id: Some(&user_id.0),
        action: "publish.forward_created",
        target_type: "publish_forward",
        target_id: &view.id,
        detail: Some(serde_json::json!({ "network_id": network_id })),
    };
    super::persist::commit_forward(state.auth.pool(), &forward, publish_seq, &revision, &audit)
        .await
        .map_err(crate::persist::internal)?;
    *state.mesh.lock().unwrap() = staged;
    crate::op_log!(
        info,
        "publish",
        "create_forward",
        &network_id,
        crate::telemetry::NOT_APPLICABLE,
        &view.revision_id.to_string(),
        crate::telemetry::ErrorCategory::None.as_str(),
        crate::telemetry::RESULT_OK
    );
    Ok((StatusCode::CREATED, Json(view)))
}

pub(super) async fn list_forwards_handler(
    State(state): State<SharedAppState>,
    AuthenticatedUser(_user): AuthenticatedUser,
    Path(network_id): Path<String>,
) -> Result<Json<Vec<PublishForwardView>>, ServiceError> {
    let guard = state.mesh.lock().unwrap();
    Ok(Json(list_forwards(&guard, &network_id)?))
}

pub(super) async fn get_forward_handler(
    State(state): State<SharedAppState>,
    AuthenticatedUser(_user): AuthenticatedUser,
    Path((network_id, forward_id)): Path<(String, String)>,
) -> Result<Json<PublishForwardView>, ServiceError> {
    let guard = state.mesh.lock().unwrap();
    Ok(Json(get_forward(&guard, &network_id, &forward_id)?))
}

pub(super) async fn delete_forward_handler(
    State(state): State<SharedAppState>,
    WriteUser(user_id): WriteUser,
    CsrfHeader: CsrfHeader,
    Path((network_id, forward_id)): Path<(String, String)>,
) -> Result<StatusCode, ServiceError> {
    let _persist = state.persist.lock().await;
    let (revision, publish_seq, staged) = {
        let guard = state.mesh.lock().unwrap();
        let mut staged = guard.clone();
        let _deleted = delete_forward(&mut staged, &network_id, &forward_id)?;
        let revision = staged
            .ledger
            .current(&meshlet_domain::NetworkId(network_id.clone()))
            .expect("delete_forward just recorded a revision")
            .clone();
        let publish_seq = staged.publish_seq();
        (revision, publish_seq, staged)
    };
    let audit = crate::persist::AuditDraft {
        actor_id: Some(&user_id.0),
        action: "publish.forward_deleted",
        target_type: "publish_forward",
        target_id: &forward_id,
        detail: Some(serde_json::json!({ "network_id": network_id })),
    };
    super::persist::commit_delete(
        state.auth.pool(),
        "publish_forwards",
        &forward_id,
        publish_seq,
        &revision,
        &audit,
    )
    .await
    .map_err(crate::persist::internal)?;
    *state.mesh.lock().unwrap() = staged;
    crate::op_log!(
        info,
        "publish",
        "delete_forward",
        &network_id,
        crate::telemetry::NOT_APPLICABLE,
        crate::telemetry::NOT_APPLICABLE,
        crate::telemetry::ErrorCategory::None.as_str(),
        crate::telemetry::RESULT_OK
    );
    Ok(StatusCode::NO_CONTENT)
}

pub(super) async fn create_http_route_handler(
    State(state): State<SharedAppState>,
    WriteUser(user_id): WriteUser,
    CsrfHeader: CsrfHeader,
    Path(network_id): Path<String>,
    Json(req): Json<CreatePublishHttpRouteRequest>,
) -> Result<(StatusCode, Json<PublishHttpRouteView>), ServiceError> {
    let _persist = state.persist.lock().await;
    let (view, route, revision, publish_seq, staged) = {
        let guard = state.mesh.lock().unwrap();
        let mut staged = guard.clone();
        match create_http_route(&mut staged, &network_id, req) {
            Ok(view) => {
                let route = staged
                    .publishes
                    .get(&network_id)
                    .and_then(|c| c.http_routes.iter().find(|r| r.id == view.id))
                    .expect("just created")
                    .clone();
                let revision = staged
                    .ledger
                    .current(&meshlet_domain::NetworkId(network_id.clone()))
                    .expect("create_http_route just recorded a revision")
                    .clone();
                let publish_seq = staged.publish_seq();
                (view, route, revision, publish_seq, staged)
            }
            Err(e) => {
                crate::op_log!(
                    warn,
                    "publish",
                    "create_http_route",
                    &network_id,
                    crate::telemetry::NOT_APPLICABLE,
                    crate::telemetry::NOT_APPLICABLE,
                    crate::telemetry::ErrorCategory::from(&e).as_str(),
                    crate::telemetry::RESULT_ERROR
                );
                return Err(e);
            }
        }
    };
    let audit = crate::persist::AuditDraft {
        actor_id: Some(&user_id.0),
        action: "publish.http_route_created",
        target_type: "publish_http_route",
        target_id: &view.id,
        detail: Some(serde_json::json!({ "network_id": network_id })),
    };
    super::persist::commit_http_route(state.auth.pool(), &route, publish_seq, &revision, &audit)
        .await
        .map_err(crate::persist::internal)?;
    *state.mesh.lock().unwrap() = staged;
    crate::op_log!(
        info,
        "publish",
        "create_http_route",
        &network_id,
        crate::telemetry::NOT_APPLICABLE,
        &view.revision_id.to_string(),
        crate::telemetry::ErrorCategory::None.as_str(),
        crate::telemetry::RESULT_OK
    );
    Ok((StatusCode::CREATED, Json(view)))
}

pub(super) async fn list_http_routes_handler(
    State(state): State<SharedAppState>,
    AuthenticatedUser(_user): AuthenticatedUser,
    Path(network_id): Path<String>,
) -> Result<Json<Vec<PublishHttpRouteView>>, ServiceError> {
    let guard = state.mesh.lock().unwrap();
    Ok(Json(list_http_routes(&guard, &network_id)?))
}

pub(super) async fn get_http_route_handler(
    State(state): State<SharedAppState>,
    AuthenticatedUser(_user): AuthenticatedUser,
    Path((network_id, route_id)): Path<(String, String)>,
) -> Result<Json<PublishHttpRouteView>, ServiceError> {
    let guard = state.mesh.lock().unwrap();
    Ok(Json(get_http_route(&guard, &network_id, &route_id)?))
}

pub(super) async fn delete_http_route_handler(
    State(state): State<SharedAppState>,
    WriteUser(user_id): WriteUser,
    CsrfHeader: CsrfHeader,
    Path((network_id, route_id)): Path<(String, String)>,
) -> Result<StatusCode, ServiceError> {
    let _persist = state.persist.lock().await;
    let (revision, publish_seq, staged) = {
        let guard = state.mesh.lock().unwrap();
        let mut staged = guard.clone();
        let _deleted = delete_http_route(&mut staged, &network_id, &route_id)?;
        let revision = staged
            .ledger
            .current(&meshlet_domain::NetworkId(network_id.clone()))
            .expect("delete_http_route just recorded a revision")
            .clone();
        let publish_seq = staged.publish_seq();
        (revision, publish_seq, staged)
    };
    let audit = crate::persist::AuditDraft {
        actor_id: Some(&user_id.0),
        action: "publish.http_route_deleted",
        target_type: "publish_http_route",
        target_id: &route_id,
        detail: Some(serde_json::json!({ "network_id": network_id })),
    };
    super::persist::commit_delete(
        state.auth.pool(),
        "publish_http_routes",
        &route_id,
        publish_seq,
        &revision,
        &audit,
    )
    .await
    .map_err(crate::persist::internal)?;
    *state.mesh.lock().unwrap() = staged;
    crate::op_log!(
        info,
        "publish",
        "delete_http_route",
        &network_id,
        crate::telemetry::NOT_APPLICABLE,
        crate::telemetry::NOT_APPLICABLE,
        crate::telemetry::ErrorCategory::None.as_str(),
        crate::telemetry::RESULT_OK
    );
    Ok(StatusCode::NO_CONTENT)
}

pub(super) async fn create_probe_handler(
    State(state): State<SharedAppState>,
    WriteUser(user_id): WriteUser,
    CsrfHeader: CsrfHeader,
    Path(network_id): Path<String>,
    Json(req): Json<CreatePublishProbeRequest>,
) -> Result<(StatusCode, Json<PublishProbeView>), ServiceError> {
    let _persist = state.persist.lock().await;
    let (view, probe, revision, publish_seq, staged) = {
        let guard = state.mesh.lock().unwrap();
        let mut staged = guard.clone();
        match create_probe(&mut staged, &network_id, req) {
            Ok(view) => {
                let probe = staged
                    .publishes
                    .get(&network_id)
                    .and_then(|c| c.probes.iter().find(|p| p.id == view.id))
                    .expect("just created")
                    .clone();
                let revision = staged
                    .ledger
                    .current(&meshlet_domain::NetworkId(network_id.clone()))
                    .expect("create_probe just recorded a revision")
                    .clone();
                let publish_seq = staged.publish_seq();
                (view, probe, revision, publish_seq, staged)
            }
            Err(e) => {
                crate::op_log!(
                    warn,
                    "publish",
                    "create_probe",
                    &network_id,
                    crate::telemetry::NOT_APPLICABLE,
                    crate::telemetry::NOT_APPLICABLE,
                    crate::telemetry::ErrorCategory::from(&e).as_str(),
                    crate::telemetry::RESULT_ERROR
                );
                return Err(e);
            }
        }
    };
    let audit = crate::persist::AuditDraft {
        actor_id: Some(&user_id.0),
        action: "publish.probe_created",
        target_type: "publish_probe",
        target_id: &view.id,
        detail: Some(serde_json::json!({ "network_id": network_id })),
    };
    super::persist::commit_probe(state.auth.pool(), &probe, publish_seq, &revision, &audit)
        .await
        .map_err(crate::persist::internal)?;
    *state.mesh.lock().unwrap() = staged;
    crate::op_log!(
        info,
        "publish",
        "create_probe",
        &network_id,
        crate::telemetry::NOT_APPLICABLE,
        &view.revision_id.to_string(),
        crate::telemetry::ErrorCategory::None.as_str(),
        crate::telemetry::RESULT_OK
    );
    Ok((StatusCode::CREATED, Json(view)))
}

pub(super) async fn list_probes_handler(
    State(state): State<SharedAppState>,
    AuthenticatedUser(_user): AuthenticatedUser,
    Path(network_id): Path<String>,
) -> Result<Json<Vec<PublishProbeView>>, ServiceError> {
    let guard = state.mesh.lock().unwrap();
    Ok(Json(list_probes(&guard, &network_id)?))
}

pub(super) async fn get_probe_handler(
    State(state): State<SharedAppState>,
    AuthenticatedUser(_user): AuthenticatedUser,
    Path((network_id, probe_id)): Path<(String, String)>,
) -> Result<Json<PublishProbeView>, ServiceError> {
    let guard = state.mesh.lock().unwrap();
    Ok(Json(get_probe(&guard, &network_id, &probe_id)?))
}

pub(super) async fn delete_probe_handler(
    State(state): State<SharedAppState>,
    WriteUser(user_id): WriteUser,
    CsrfHeader: CsrfHeader,
    Path((network_id, probe_id)): Path<(String, String)>,
) -> Result<StatusCode, ServiceError> {
    let _persist = state.persist.lock().await;
    let (revision, publish_seq, staged) = {
        let guard = state.mesh.lock().unwrap();
        let mut staged = guard.clone();
        let _deleted = delete_probe(&mut staged, &network_id, &probe_id)?;
        let revision = staged
            .ledger
            .current(&meshlet_domain::NetworkId(network_id.clone()))
            .expect("delete_probe just recorded a revision")
            .clone();
        let publish_seq = staged.publish_seq();
        (revision, publish_seq, staged)
    };
    let audit = crate::persist::AuditDraft {
        actor_id: Some(&user_id.0),
        action: "publish.probe_deleted",
        target_type: "publish_probe",
        target_id: &probe_id,
        detail: Some(serde_json::json!({ "network_id": network_id })),
    };
    // 探针删除连带清掉它的健康证据（证据不是配置，不悬挂）。
    super::persist::commit_probe_delete(
        state.auth.pool(),
        &probe_id,
        publish_seq,
        &revision,
        &audit,
    )
    .await
    .map_err(crate::persist::internal)?;
    *state.mesh.lock().unwrap() = staged;
    crate::op_log!(
        info,
        "publish",
        "delete_probe",
        &network_id,
        crate::telemetry::NOT_APPLICABLE,
        crate::telemetry::NOT_APPLICABLE,
        crate::telemetry::ErrorCategory::None.as_str(),
        crate::telemetry::RESULT_OK
    );
    Ok(StatusCode::NO_CONTENT)
}

pub(super) async fn create_dns_record_handler(
    State(state): State<SharedAppState>,
    WriteUser(user_id): WriteUser,
    CsrfHeader: CsrfHeader,
    Path(network_id): Path<String>,
    Json(req): Json<CreatePublishDnsRecordRequest>,
) -> Result<(StatusCode, Json<PublishDnsRecordView>), ServiceError> {
    let _persist = state.persist.lock().await;
    let (view, record, revision, publish_seq, staged) = {
        let guard = state.mesh.lock().unwrap();
        let mut staged = guard.clone();
        match create_dns_record(&mut staged, &network_id, req) {
            Ok(view) => {
                let record = staged
                    .publishes
                    .get(&network_id)
                    .and_then(|c| c.dns_records.iter().find(|r| r.id == view.id))
                    .expect("just created")
                    .clone();
                let revision = staged
                    .ledger
                    .current(&meshlet_domain::NetworkId(network_id.clone()))
                    .expect("create_dns_record just recorded a revision")
                    .clone();
                let publish_seq = staged.publish_seq();
                (view, record, revision, publish_seq, staged)
            }
            Err(e) => {
                crate::op_log!(
                    warn,
                    "publish",
                    "create_dns_record",
                    &network_id,
                    crate::telemetry::NOT_APPLICABLE,
                    crate::telemetry::NOT_APPLICABLE,
                    crate::telemetry::ErrorCategory::from(&e).as_str(),
                    crate::telemetry::RESULT_ERROR
                );
                return Err(e);
            }
        }
    };
    let audit = crate::persist::AuditDraft {
        actor_id: Some(&user_id.0),
        action: "publish.dns_record_created",
        target_type: "publish_dns_record",
        target_id: &view.id,
        detail: Some(serde_json::json!({ "network_id": network_id })),
    };
    super::persist::commit_dns_record(state.auth.pool(), &record, publish_seq, &revision, &audit)
        .await
        .map_err(crate::persist::internal)?;
    *state.mesh.lock().unwrap() = staged;
    crate::op_log!(
        info,
        "publish",
        "create_dns_record",
        &network_id,
        crate::telemetry::NOT_APPLICABLE,
        &view.revision_id.to_string(),
        crate::telemetry::ErrorCategory::None.as_str(),
        crate::telemetry::RESULT_OK
    );
    Ok((StatusCode::CREATED, Json(view)))
}

pub(super) async fn list_dns_records_handler(
    State(state): State<SharedAppState>,
    AuthenticatedUser(_user): AuthenticatedUser,
    Path(network_id): Path<String>,
) -> Result<Json<Vec<PublishDnsRecordView>>, ServiceError> {
    let guard = state.mesh.lock().unwrap();
    Ok(Json(list_dns_records(&guard, &network_id)?))
}

pub(super) async fn get_dns_record_handler(
    State(state): State<SharedAppState>,
    AuthenticatedUser(_user): AuthenticatedUser,
    Path((network_id, record_id)): Path<(String, String)>,
) -> Result<Json<PublishDnsRecordView>, ServiceError> {
    let guard = state.mesh.lock().unwrap();
    Ok(Json(get_dns_record(&guard, &network_id, &record_id)?))
}

pub(super) async fn delete_dns_record_handler(
    State(state): State<SharedAppState>,
    WriteUser(user_id): WriteUser,
    CsrfHeader: CsrfHeader,
    Path((network_id, record_id)): Path<(String, String)>,
) -> Result<StatusCode, ServiceError> {
    let _persist = state.persist.lock().await;
    let (revision, publish_seq, staged) = {
        let guard = state.mesh.lock().unwrap();
        let mut staged = guard.clone();
        let _deleted = delete_dns_record(&mut staged, &network_id, &record_id)?;
        let revision = staged
            .ledger
            .current(&meshlet_domain::NetworkId(network_id.clone()))
            .expect("delete_dns_record just recorded a revision")
            .clone();
        let publish_seq = staged.publish_seq();
        (revision, publish_seq, staged)
    };
    let audit = crate::persist::AuditDraft {
        actor_id: Some(&user_id.0),
        action: "publish.dns_record_deleted",
        target_type: "publish_dns_record",
        target_id: &record_id,
        detail: Some(serde_json::json!({ "network_id": network_id })),
    };
    super::persist::commit_delete(
        state.auth.pool(),
        "publish_dns_records",
        &record_id,
        publish_seq,
        &revision,
        &audit,
    )
    .await
    .map_err(crate::persist::internal)?;
    *state.mesh.lock().unwrap() = staged;
    crate::op_log!(
        info,
        "publish",
        "delete_dns_record",
        &network_id,
        crate::telemetry::NOT_APPLICABLE,
        crate::telemetry::NOT_APPLICABLE,
        crate::telemetry::ErrorCategory::None.as_str(),
        crate::telemetry::RESULT_OK
    );
    Ok(StatusCode::NO_CONTENT)
}
