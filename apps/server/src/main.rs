//! meshlet-server：控制平面服务。
//!
//! 暴露状态/网络/邀请/设备加入/控制台认证路由（契约见
//! [api-contract.md](../../docs/architecture/api-contract.md)）。
//! 状态：Mesh 数据暂存内存（`MeshState`）；用户/会话持久化 SQLite（migrations 001/002）。

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

    let database_url = if config.database_path.starts_with("sqlite:") {
        config.database_path.clone()
    } else {
        format!("sqlite:{}", config.database_path)
    };
    let pool = meshlet_server::store::connect(&database_url)
        .await
        .unwrap_or_else(|e| panic!("database {}: {e}", config.database_path));
    let state = std::sync::Arc::new(meshlet_server::auth::AppState::new(
        meshlet_server::service::SharedState::default(),
        meshlet_server::auth::AuthStore::new(pool),
        config.cookie_secure,
    ));
    axum::serve(listener, meshlet_server::router(state))
        .await
        .expect("server error");
}
