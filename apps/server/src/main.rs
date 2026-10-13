//! meshlet-server：控制平面服务。
//!
//! 暴露状态/网络/邀请/设备加入路由（契约见
//! [api-contract.md](../../docs/architecture/api-contract.md)）。
//! 持久化（SQLite/SQLx）随「核心实体 migrations」条目接入；
//! 当前状态存于内存（`MeshState`）。

use meshlet_config::ServerConfig;
use tracing::info;

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "meshlet_server=info,tower_http=info".into()),
        )
        .init();

    // 配置文件可选：`meshlet-server [path/to/meshlet.toml]`，缺省用内置默认值。
    let config = match std::env::args().nth(1) {
        Some(path) => {
            let raw = std::fs::read_to_string(&path)
                .unwrap_or_else(|e| panic!("read config {path}: {e}"));
            ServerConfig::from_toml(&raw).unwrap_or_else(|e| panic!("invalid config {path}: {e}"))
        }
        None => ServerConfig::default(),
    };

    info!(bind = %config.bind, overlay = %config.overlay_cidr, "starting meshlet-server");
    let listener = tokio::net::TcpListener::bind(&config.bind)
        .await
        .unwrap_or_else(|e| panic!("bind {}: {e}", config.bind));
    let state = meshlet_server::service::SharedState::default();
    axum::serve(listener, meshlet_server::router(state))
        .await
        .expect("server error");
}
