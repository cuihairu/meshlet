//! meshlet-server：控制平面服务。
//!
//! 暴露状态/网络/邀请/设备加入/控制台认证路由（契约见
//! [api-contract.md](../../docs/architecture/api-contract.md)）。
//! 状态：Mesh 数据运行期存于内存（`MeshState`），每次变更镜像 SQLite，
//! 启动时从 DB 重建（§17.3 故障恢复）；用户/会话持久化 SQLite。
//!
//! 用法：
//! - `meshlet-server [config.toml]`：常驻服务；
//! - `meshlet-server restore <backup.db> [config.toml]`：从一致性备份离线
//!   恢复活动库（§17.4；先停服务再恢复），留痕 `system.restore` 审计事件
//!   并按 §17.3 语义收敛，随后正常启动即恢复到期望状态。

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

    // 参数：`restore <backup.db> [config.toml]` 或 `[config.toml]`。
    let mut args = std::env::args().skip(1).peekable();
    let config = if args.peek().map(String::as_str) == Some("restore") {
        args.next();
        let backup = args.next().unwrap_or_else(|| {
            eprintln!("usage: meshlet-server restore <backup.db> [config.toml]");
            std::process::exit(2);
        });
        let config = load_config(args.next());
        restore_command(&backup, &config).await;
        return;
    } else {
        load_config(args.next())
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
    let state = std::sync::Arc::new(
        meshlet_server::auth::AppState::new(
            std::sync::Arc::new(std::sync::Mutex::new(boot.mesh)),
            meshlet_server::auth::AuthStore::new(pool.clone()),
            meshlet_server::agent::AgentTokenStore::new(pool.clone()),
            meshlet_server::api_token::ApiTokenStore::new(pool.clone()),
            config.cookie_secure,
        )
        .with_backup_dir(config.backup.dir.clone().map(std::path::PathBuf::from))
        .with_tunnel_mtu(config.tunnel_mtu),
    );
    // 定时自动备份（§17.4）：显式 `[backup] auto = true` 才开启；只写本地
    // `[backup] dir`，无任何外发。到期写一份 + 审计留痕，失败只记日志。
    if config.backup.auto {
        if let Some(dir) = config.backup.dir.clone() {
            let pool = pool.clone();
            let interval = std::time::Duration::from_secs(config.backup.interval_secs);
            tokio::spawn(async move {
                let mut ticker = tokio::time::interval(interval);
                ticker.tick().await; // 首拍立即：启动即有一份备份。
                loop {
                    ticker.tick().await;
                    match meshlet_server::persist::backup_once(
                        &pool,
                        std::path::Path::new(&dir),
                        None,
                    )
                    .await
                    {
                        Ok(report) => tracing::info!(
                            path = %report.path,
                            bytes = report.bytes,
                            "scheduled backup written"
                        ),
                        Err(e) => tracing::error!(error = %e, "scheduled backup failed"),
                    }
                }
            });
        } else {
            tracing::warn!(
                "backup.auto = true but backup.dir is unset; scheduled backups disabled"
            );
        }
    }
    let app = match config.console_dir.as_deref() {
        Some(dir) => {
            info!(console_dir = dir, "serving console static files");
            meshlet_server::router_with_console(state, dir)
        }
        None => meshlet_server::router(state),
    };
    axum::serve(listener, app).await.expect("server error");
}

fn load_config(path: Option<String>) -> ServerConfig {
    match path {
        Some(path) => {
            let raw = std::fs::read_to_string(&path)
                .unwrap_or_else(|e| panic!("read config {path}: {e}"));
            ServerConfig::from_toml(&raw).unwrap_or_else(|e| panic!("invalid config {path}: {e}"))
        }
        None => ServerConfig::default(),
    }
}

/// §17.4 离线恢复：校验 → 原子换名 → 审计留痕 → §17.3 收敛；任何失败都
/// 不触碰活动库。完成后正常启动服务即恢复到期望状态。
async fn restore_command(backup: &str, config: &ServerConfig) {
    let database = config.database_path.trim_start_matches("sqlite:");
    println!("restoring {backup} -> {database}");
    let thresholds = meshlet_domain::PresenceThresholds {
        agent_window: std::time::Duration::from_secs(config.presence_agent_window_secs),
        handshake_window: std::time::Duration::from_secs(config.presence_handshake_window_secs),
    };
    let report = match meshlet_server::persist::restore_from_backup(
        std::path::Path::new(backup),
        std::path::Path::new(database),
        thresholds,
    )
    .await
    {
        Ok(report) => report,
        Err(e) => {
            eprintln!("restore failed (live database untouched): {e}");
            std::process::exit(1);
        }
    };
    println!(
        "restore ok: networks={} devices={} routes={} invites={} revisions={}",
        report.summary.networks,
        report.summary.devices,
        report.summary.routes,
        report.summary.invites,
        report.summary.revisions,
    );
    if !report.interrupted.is_empty() {
        println!(
            "interrupted applying converged to failed (10.3): {} revision(s)",
            report.interrupted.len()
        );
    }
    println!("audit: system.restore recorded; start meshlet-server to serve");
}
