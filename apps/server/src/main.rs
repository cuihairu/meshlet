//! meshlet-server：控制平面服务。
//!
//! 暴露状态/网络/邀请/设备加入/控制台认证路由（契约见
//! [api-contract.md](../../docs/architecture/api-contract.md)）。
//! 状态：Mesh 数据运行期存于内存（`MeshState`），每次变更镜像 SQLite，
//! 启动时从 DB 重建（§17.3 故障恢复）；用户/会话持久化 SQLite。

use meshlet_config::ServerConfig;
use tracing::info;

#[tokio::main]
async fn main() {
    // 结构化日志（§17.1）：JSON 行输出，八字段（time/component/operation/
    // network_id/device_id/config_revision/error_category/result）为顶层键，
    // 由 telemetry 模块的 op_log! 与 request_log 中间件统一发出。
    tracing_subscriber::fmt()
        .json()
        .flatten_event(true)
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
    let presence_thresholds = meshlet_domain::PresenceThresholds {
        agent_window: std::time::Duration::from_secs(config.presence_agent_window_secs),
        handshake_window: std::time::Duration::from_secs(config.presence_handshake_window_secs),
    };
    // §17.3 故障恢复：启动从 DB 重建期望状态（网络/设备/路由/邀请/修订），
    // 停在 applying 的修订收敛为 failed（§10.3 不假装成功）。
    let boot = meshlet_server::persist::load(&pool, presence_thresholds)
        .await
        .unwrap_or_else(|e| panic!("rebuild mesh state from {}: {e}", config.database_path));
    info!(
        networks = boot.summary.networks,
        devices = boot.summary.devices,
        routes = boot.summary.routes,
        invites = boot.summary.invites,
        revisions = boot.summary.revisions,
        interrupted_applying = boot.interrupted.len(),
        "mesh state rebuilt from database"
    );
    let state = std::sync::Arc::new(meshlet_server::auth::AppState::new(
        std::sync::Arc::new(std::sync::Mutex::new(boot.mesh)),
        meshlet_server::auth::AuthStore::new(pool.clone()),
        meshlet_server::agent::AgentTokenStore::new(pool.clone()),
        meshlet_server::api_token::ApiTokenStore::new(pool),
        config.cookie_secure,
    ));
    let app = match config.console_dir.as_deref() {
        Some(dir) => {
            info!(console_dir = dir, "serving console static files");
            meshlet_server::router_with_console(state, dir)
        }
        None => meshlet_server::router(state),
    };
    axum::serve(listener, app).await.expect("server error");
}
