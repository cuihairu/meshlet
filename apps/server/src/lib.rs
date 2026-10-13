//! meshlet-server 库入口：路由构建可供集成测试复用（Phase 1 spike，ADR-003/009 待接入持久化）。

use axum::routing::get;
use axum::{Json, Router};
use serde::Serialize;

/// `GET /api/v1/system/status` 响应（契约见 docs/architecture/api-contract.md）。
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SystemStatus {
    pub status: String,
    pub version: String,
}

pub fn system_status() -> SystemStatus {
    SystemStatus {
        status: "ok".into(),
        version: env!("CARGO_PKG_VERSION").into(),
    }
}

pub fn router() -> Router {
    Router::new().route(
        "/api/v1/system/status",
        get(|| async { Json(system_status()) }),
    )
}
