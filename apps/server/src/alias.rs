//! Alias 映射写路径（§12.6 / ADR-006，存档 §12「Alias 页面」）：
//! - `POST /networks/{id}/aliases`：创建（绑定 alias 模式路由，target 服务端
//!   推导，冲突拒绝发生在任何状态变更前）；
//! - `GET /networks/{id}/aliases`、`GET …/{alias_id}`：列表/详情；
//! - `DELETE /networks/{id}/aliases/{alias_id}`：删除 = 整单元清理（映射 +
//!   绑定路由一个修订，内核侧 NAT 规则随修订 apply 交 backend，§10.3）。
//!
//! 冲突指标（§17.2）：前缀重叠类拒绝计入 `meshlet_route_conflicts_total`。
//! （数据面 NAT 执行待 ADR-007；本模块是控制面期望态。）

use axum::extract::State;
use axum::http::StatusCode;
use axum::routing::{get, post};
use axum::{Json, Router};

use crate::auth::{AuthenticatedUser, CsrfHeader, SharedAppState, WriteUser};

pub fn routes() -> Router<SharedAppState> {
    Router::new()
        .route(
            "/api/v1/networks/{network_id}/aliases",
            post(create_alias_handler).get(list_aliases_handler),
        )
        .route(
            "/api/v1/networks/{network_id}/aliases/{alias_id}",
            get(get_alias_handler).delete(delete_alias_handler),
        )
}

async fn create_alias_handler(
    State(state): State<SharedAppState>,
    WriteUser(user_id): WriteUser,
    CsrfHeader: CsrfHeader,
    axum::extract::Path(network_id): axum::extract::Path<String>,
    Json(req): Json<crate::service::CreateAliasRequest>,
) -> Result<(StatusCode, Json<crate::service::AliasView>), crate::service::ServiceError> {
    let _persist = state.persist.lock().await;
    let (view, alias, revision, route_seq) = {
        let mut guard = state.mesh.lock().unwrap();
        match crate::service::create_alias(&mut guard, &network_id, req) {
            Ok(view) => {
                let alias = guard
                    .aliases
                    .get(&network_id)
                    .and_then(|aliases| aliases.iter().find(|a| a.id.to_string() == view.id))
                    .expect("just created")
                    .clone();
                let revision = guard
                    .ledger
                    .get(
                        &meshlet_domain::NetworkId(network_id.clone()),
                        view.revision_id,
                    )
                    .expect("just recorded")
                    .clone();
                (view, alias, revision, guard.route_seq())
            }
            Err(e) => {
                // 前缀重叠类冲突与路由冲突同指标（§17.2）；其它 409 不计。
                if matches!(e, crate::service::ServiceError::RouteConflict(_)) {
                    crate::record_route_conflict(&state);
                }
                crate::op_log!(
                    warn,
                    "alias",
                    "create_alias",
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
    crate::persist::insert_alias(state.auth.pool(), &alias, route_seq)
        .await
        .map_err(crate::persist::internal)?;
    crate::persist::insert_revision(state.auth.pool(), &revision)
        .await
        .map_err(crate::persist::internal)?;
    crate::audit::record_or_fail(
        &state,
        Some(&user_id.0),
        "alias.created",
        "alias",
        Some(&view.id),
        Some(serde_json::json!({ "network_id": network_id, "lan_route_id": view.lan_route_id })),
    )
    .await?;
    crate::op_log!(
        info,
        "alias",
        "create_alias",
        &network_id,
        crate::telemetry::NOT_APPLICABLE,
        &view.revision_id.to_string(),
        crate::telemetry::ErrorCategory::None.as_str(),
        crate::telemetry::RESULT_OK
    );
    Ok((StatusCode::CREATED, Json(view)))
}

async fn list_aliases_handler(
    State(state): State<SharedAppState>,
    AuthenticatedUser(_user): AuthenticatedUser,
    axum::extract::Path(network_id): axum::extract::Path<String>,
) -> Result<Json<Vec<crate::service::AliasView>>, crate::service::ServiceError> {
    let guard = state.mesh.lock().unwrap();
    Ok(Json(crate::service::list_aliases(&guard, &network_id)?))
}

async fn get_alias_handler(
    State(state): State<SharedAppState>,
    AuthenticatedUser(_user): AuthenticatedUser,
    axum::extract::Path((network_id, alias_id)): axum::extract::Path<(String, String)>,
) -> Result<Json<crate::service::AliasView>, crate::service::ServiceError> {
    let guard = state.mesh.lock().unwrap();
    Ok(Json(crate::service::get_alias(
        &guard,
        &network_id,
        &alias_id,
    )?))
}

async fn delete_alias_handler(
    State(state): State<SharedAppState>,
    WriteUser(user_id): WriteUser,
    CsrfHeader: CsrfHeader,
    axum::extract::Path((network_id, alias_id)): axum::extract::Path<(String, String)>,
) -> Result<StatusCode, crate::service::ServiceError> {
    let _persist = state.persist.lock().await;
    let (route_id, revision) = {
        let mut guard = state.mesh.lock().unwrap();
        // 删除 = 整单元：返回值带上绑定路由 id，随同一修订清理。
        let (_, route_id) = crate::service::delete_alias(&mut guard, &network_id, &alias_id)?;
        let revision = guard
            .ledger
            .current(&meshlet_domain::NetworkId(network_id.clone()))
            .expect("delete_alias just recorded a revision")
            .clone();
        (route_id, revision)
    };
    // 落库也是整单元：persist::delete_route 级联清理 alias 行（§12.6）。
    crate::persist::delete_route(state.auth.pool(), &route_id)
        .await
        .map_err(crate::persist::internal)?;
    crate::persist::insert_revision(state.auth.pool(), &revision)
        .await
        .map_err(crate::persist::internal)?;
    crate::audit::record_or_fail(
        &state,
        Some(&user_id.0),
        "alias.deleted",
        "alias",
        Some(&alias_id),
        Some(serde_json::json!({ "network_id": network_id, "route_id": route_id })),
    )
    .await?;
    crate::op_log!(
        info,
        "alias",
        "delete_alias",
        &network_id,
        crate::telemetry::NOT_APPLICABLE,
        crate::telemetry::NOT_APPLICABLE,
        crate::telemetry::ErrorCategory::None.as_str(),
        crate::telemetry::RESULT_OK
    );
    Ok(StatusCode::NO_CONTENT)
}
