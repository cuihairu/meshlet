//! 配置版本与应用状态 API（[存档 §10](../../docs/review/chatgpt-2026-10-13.md)、
//! [ADR-009](../../docs/decisions/adr-009-config-revision-rollback.md)）。
//!
//! **DB 写入 ≠ 显示生效**（§10.1）：期望配置的每次变更只生成 `Pending` 修订；
//! 只有 backend 成功把配置应用到实际网络环境后才转为 `Applied`。应用失败
//! （**含结果不确定**）进入 `Failed` 并保留可诊断的 `error_summary`。
//!
//! 本进程当前没有数据面 backend——WireGuard/路由/NAT 的 OS 侧执行需要
//! CAP_NET_ADMIN（环境卡点见 TODO.md），因此显式 apply 会确定性失败并留下
//! 清晰错误：失败可见、状态可区分，正是「配置状态机」条目的验收口径。接入
//! 数据面 daemon 后替换 [`UnconfiguredBackend`]，API 语义不变。
//!
//! 并发语义（§10.4）：修订版本号网络内单调递增，同一网络的配置修改由
//! 「先记录修订、再应用修订」串行化；非法跃迁（如对失败修订原地重试）返回
//! 409，重试路径是记录新修订。

use axum::extract::{Path, State};
use axum::routing::{get, post};
use axum::{Json, Router};
use meshlet_domain::{ConfigApplyBackend, ConfigRevision};
use serde::Serialize;

use crate::auth::{AuthenticatedUser, CsrfHeader, SharedAppState};
use crate::service::{self, ServiceError};

/// 配置版本视图（`GET /config-revisions`、版本详情、apply/rollback 响应）。
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RevisionView {
    pub network_id: String,
    pub revision: u64,
    pub desired_config_hash: String,
    /// ADR-009 状态机：`pending`/`applying`/`applied`/`failed`/
    /// `rollback_pending`/`rolled_back`。
    pub apply_status: String,
    pub created_at: String,
    /// 成功应用时刻；`Failed`/`Pending` 恒为 `null`（不声称已生效）。
    pub applied_at: Option<String>,
    /// 失败诊断（§12.2：失败可见）；成功时为 `null`。
    pub error_summary: Option<String>,
}

pub fn to_revision_view(r: &ConfigRevision) -> RevisionView {
    RevisionView {
        network_id: r.network_id.to_string(),
        revision: r.revision,
        desired_config_hash: r.desired_config_hash.clone(),
        apply_status: r.apply_status.as_str().to_string(),
        created_at: r.created_at.clone(),
        applied_at: r.applied_at.clone(),
        error_summary: r.error_summary.clone(),
    }
}

/// 数据面未接入时的占位 backend：任何应用/回滚都**显式失败**（§10.3 不得假装
/// 成功）。错误文本刻意写明「已记录但未应用」，让调用方一眼看出 DB 写入与
/// 实际生效的差别。
pub struct UnconfiguredBackend;

impl ConfigApplyBackend for UnconfiguredBackend {
    fn apply(&mut self, _revision: &ConfigRevision) -> Result<(), String> {
        Err(
            "no network backend configured: desired config recorded but not applied to any \
             wireguard interface on this host"
                .to_string(),
        )
    }

    fn rollback(&mut self, _revision: &ConfigRevision) -> Result<(), String> {
        Err(
            "no network backend configured: no meshlet-managed objects on this host to \
             roll back"
                .to_string(),
        )
    }
}

/// 配置版本与应用状态路由（管理 API：会话认证 + 写请求 CSRF 头）。
pub fn routes() -> Router<SharedAppState> {
    Router::new()
        .route(
            "/api/v1/networks/{network_id}/config-revisions",
            get(list_revisions_handler),
        )
        .route(
            "/api/v1/networks/{network_id}/config-revisions/{revision}",
            get(get_revision_handler),
        )
        .route(
            "/api/v1/networks/{network_id}/config-revisions/{revision}/apply",
            post(apply_revision_handler),
        )
        .route(
            "/api/v1/networks/{network_id}/config-revisions/{revision}/rollback",
            post(rollback_revision_handler),
        )
}

fn network_id_of(id: &str) -> meshlet_domain::NetworkId {
    meshlet_domain::NetworkId(id.to_string())
}

/// `GET /api/v1/networks/{network_id}/config-revisions`：全部修订（升序）。
pub async fn list_revisions_handler(
    State(state): State<SharedAppState>,
    AuthenticatedUser(_user): AuthenticatedUser,
    Path(network_id): Path<String>,
) -> Result<Json<Vec<RevisionView>>, ServiceError> {
    let guard = state.mesh.lock().unwrap();
    service::require_network(&guard, &network_id)?;
    Ok(Json(
        guard
            .ledger
            .revisions(&network_id_of(&network_id))
            .iter()
            .map(to_revision_view)
            .collect(),
    ))
}

/// `GET /api/v1/networks/{network_id}/config-revisions/{revision}`：版本详情。
pub async fn get_revision_handler(
    State(state): State<SharedAppState>,
    AuthenticatedUser(_user): AuthenticatedUser,
    Path((network_id, revision)): Path<(String, u64)>,
) -> Result<Json<RevisionView>, ServiceError> {
    let guard = state.mesh.lock().unwrap();
    service::require_network(&guard, &network_id)?;
    let revision = guard
        .ledger
        .get(&network_id_of(&network_id), revision)
        .ok_or_else(|| {
            ServiceError::RevisionNotFound(format!("{revision} in network {network_id}"))
        })?;
    Ok(Json(to_revision_view(revision)))
}

/// `POST .../config-revisions/{revision}/apply`：把该修订应用到实际环境。
///
/// 返回该修订的当前视图——`apply_status` 是结论；backend 失败时同样 200，
/// 但状态为 `failed` 且 `error_summary` 说明原因（失败可见，不伪装成功）。
pub async fn apply_revision_handler(
    State(state): State<SharedAppState>,
    AuthenticatedUser(_user): AuthenticatedUser,
    CsrfHeader: CsrfHeader,
    Path((network_id, revision)): Path<(String, u64)>,
) -> Result<Json<RevisionView>, ServiceError> {
    let mut backend = UnconfiguredBackend;
    let mut guard = state.mesh.lock().unwrap();
    service::require_network(&guard, &network_id)?;
    let applied = guard
        .ledger
        .apply(
            &network_id_of(&network_id),
            revision,
            &mut backend,
            service::now(),
        )
        .map_err(ServiceError::from_ledger)?;
    Ok(Json(to_revision_view(&applied)))
}

/// `POST .../config-revisions/{revision}/rollback`：回滚一个 `Failed` 修订。
/// 回滚只允许动 Meshlet 自有对象（ADR-007），不得清空系统路由（§10.3）。
pub async fn rollback_revision_handler(
    State(state): State<SharedAppState>,
    AuthenticatedUser(_user): AuthenticatedUser,
    CsrfHeader: CsrfHeader,
    Path((network_id, revision)): Path<(String, u64)>,
) -> Result<Json<RevisionView>, ServiceError> {
    let mut backend = UnconfiguredBackend;
    let mut guard = state.mesh.lock().unwrap();
    service::require_network(&guard, &network_id)?;
    let rolled = guard
        .ledger
        .rollback(&network_id_of(&network_id), revision, &mut backend)
        .map_err(ServiceError::from_ledger)?;
    Ok(Json(to_revision_view(&rolled)))
}
