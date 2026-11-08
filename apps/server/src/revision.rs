//! 配置版本与应用状态 API（[存档 §10](../../docs/review/chatgpt-2026-10-13.md)、
//! [ADR-009](../../docs/decisions/adr-009-config-revision-rollback.md)）。
//!
//! **DB 写入 ≠ 显示生效**（§10.1）：期望配置的每次变更只生成 `Pending` 修订；
//! 只有 backend 成功把配置应用到实际网络环境后才转为 `Applied`。应用失败
//! （**含结果不确定**）进入 `Failed` 并保留可诊断的 `error_summary`。
//!
//! 数据面接线（ADR-007）：`[dataplane] enabled = true` 时 apply 走
//! [`HubDataPlaneBackend`]——按当前期望配置快照在本机执行 WireGuard/路由
//! （平台后端 [`meshlet_network::SystemBackend`]：Linux 真实内核执行；其他
//! 平台每个操作显式 `Unsupported`，ADR-008 Windows 后端待接入）。默认（未配置或
//! `enabled = false`）仍是 [`UnconfiguredBackend`] 显式失败：失败可见、状态
//! 可区分，升级不悄悄接管内核。网关侧 NAT（ADR-006）在网关设备上执行，随
//! agent 数据面交付（server 只下 hub 侧转发面）。
//!
//! apply / rollback 的结论同时收敛到每条期望项的 `status`
//! （[`service::settle_desired_state`]）：只有真下发到内核的路由与 Alias 映射
//! 才转 `applied`，其余转 `failed`——agent 数据面据此取计划（§10.1）。
//!
//! 并发语义（§10.4）：修订版本号网络内单调递增，同一网络的配置修改由
//! 「先记录修订、再应用修订」串行化；非法跃迁（如对失败修订原地重试）返回
//! 409，重试路径是记录新修订。

// 按职责分档：Hub 数据面 backend（backend，ADR-007 接线）/ API 端点与实现
// （handlers）；本文件保留视图转换、占位 backend、工厂类型与路由装配。
mod backend;
mod handlers;

pub(crate) use backend::{deployment, enforce_authorization, recover_deployment, Deployment};
pub use backend::{
    hub_backend_factory, hub_backend_factory_with, network_dataplane, HubDataPlaneBackend,
};
pub use handlers::{
    apply_revision_handler, get_revision_handler, list_revisions_handler, rollback_revision_handler,
};

use axum::routing::{get, post};
use axum::Router;
use meshlet_domain::{ConfigApplyBackend, ConfigRevision};
use serde::Serialize;
use std::sync::Arc;

use crate::auth::SharedAppState;
use crate::service::MeshState;

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
    #[serde(skip_serializing_if = "Option::is_none")]
    pub convergence: Option<serde_json::Value>,
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
        convergence: None,
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

/// 构造一次应用/回滚 backend 的工厂：按指定网络的当前期望配置取快照。
///
/// 每次请求构造独立实例（领域 trait 是 `&mut self`），但**必须在网络级互斥内
/// 调用**——§10.4 的「同一网络的配置修改串行化」由此保证：并发 apply 不会拿到
/// 各自的后端实例交叉改写 WireGuard Peer / 路由 / NAT。生产由 `[dataplane]`
/// 配置决定 [`hub_backend_factory`] 或 [`unconfigured_backend_factory`]；集成
/// 测试注入计数 backend，在 API 层验证幂等与回滚边界（§10.3 验收）。
pub type BackendFactory =
    Arc<dyn Fn(&MeshState, &str) -> Box<dyn ConfigApplyBackend + Send> + Send + Sync>;

/// 默认工厂：数据面未接入，显式失败。
pub fn unconfigured_backend_factory() -> BackendFactory {
    Arc::new(|_, _| Box::new(UnconfiguredBackend))
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
