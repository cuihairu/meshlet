//! meshlet-server: the control-plane service.
//!
//! Exposes status/network/invitation/device-enrollment/console-auth routes
//! (contract in [api-contract.md](../../docs/architecture/api-contract.md)).
//! State: Mesh data lives in memory at runtime (`MeshState`), every change is
//! mirrored to SQLite, and startup rebuilds from the DB (§17.3 failure
//! recovery); users/sessions persist in SQLite.
//!
//! Usage:
//! - `meshlet-server [config.toml]`: the resident service;
//! - `meshlet-server restore <backup.db> [config.toml]`: offline restore of the
//!   live database from a consistent backup (§17.4; stop the service before
//!   restoring), leaving a `system.restore` audit event and converging under
//!   §17.3 semantics, after which a normal start reaches the desired state.
//!
//! The two subcommands are mutually exclusive over the same database file: the
//! resident process holds the live database lock for its whole lifetime
//! ([instance_lock](meshlet_server::instance_lock)), and the restore command
//! refuses outright when it cannot get the lock.

use meshlet_config::ServerConfig;
use tracing::info;

#[tokio::main]
async fn main() {
    // Structured logging (§17.1): JSON line output, with the eight fields
    // (time/component/operation/network_id/device_id/config_revision/
    // error_category/result) as top-level keys, emitted uniformly by the
    // telemetry module's op_log! and the request_log middleware.
    tracing_subscriber::fmt()
        .json()
        .flatten_event(true)
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "meshlet_server=info,tower_http=info".into()),
        )
        .init();

    // Arguments: `restore <backup.db> [config.toml]` or `[config.toml]`;
    // `--version`/`--help` must be handled up front — otherwise they are treated
    // as a config file path, and `load_config` panics when it cannot read it
    // (caught by real-device acceptance NIGHTLY-MSI-1: `meshlet-server
    // --version` once exited 101).
    let mut args = std::env::args().skip(1).peekable();
    if let Some(flag) = args.peek().map(String::as_str) {
        match flag {
            "--version" | "-V" => {
                println!("meshlet-server {}", env!("CARGO_PKG_VERSION"));
                return;
            }
            "--help" | "-h" => {
                println!("meshlet-server {}", env!("CARGO_PKG_VERSION"));
                println!();
                println!("Usage: meshlet-server [config.toml]");
                println!("       meshlet-server restore <backup.db> [config.toml]");
                return;
            }
            _ => {}
        }
    }
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
    let listener = match tokio::net::TcpListener::bind(&config.bind).await {
        Ok(listener) => listener,
        Err(error) => startup_failure("bind", &config.bind, error),
    };

    let database_url = if config.database_path.starts_with("sqlite:") {
        config.database_path.clone()
    } else {
        format!("sqlite:{}", config.database_path)
    };
    // §17.4 restore guard: the process holds the live database lock throughout.
    // The `restore` subcommand takes that same lock before touching any file, and
    // refuses as a whole when it cannot get it — restoring while running would
    // send writes into a unlinked inode (the old database is overwritten by the
    // rename), while `systemctl` keeps showing active the whole time.
    let _instance_lock = match meshlet_server::instance_lock::try_acquire(std::path::Path::new(
        config.database_path.trim_start_matches("sqlite:"),
    )) {
        Ok(lock) => lock,
        Err(error) => startup_failure(
            "database lock",
            &config.database_path,
            format!("{error}; another meshlet-server is likely already running"),
        ),
    };
    let pool = match meshlet_server::store::connect(&database_url).await {
        Ok(pool) => pool,
        Err(error) => startup_failure("database", &config.database_path, error),
    };
    let presence_thresholds = meshlet_domain::PresenceThresholds {
        agent_window: std::time::Duration::from_secs(config.presence_agent_window_secs),
        handshake_window: std::time::Duration::from_secs(config.presence_handshake_window_secs),
    };
    // §17.3 failure recovery: startup rebuilds the desired state from the DB
    // (networks/devices/routes/invitations/revisions), and revisions stuck in
    // `applying` converge to `failed` (§10.3 — never pretend success).
    let boot = match meshlet_server::persist::load(&pool, presence_thresholds).await {
        Ok(boot) => boot,
        Err(error) => startup_failure("mesh state rebuild", &config.database_path, error),
    };
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
        .with_tunnel_mtu(config.tunnel_mtu)
        .with_dataplane(config.dataplane.clone())
        .with_ssh_config(config.ssh_config.clone())
        .with_trusted_proxies(config.trusted_proxies.clone())
        .with_apply_backend(if config.dataplane.enabled {
            // ADR-007 wiring: real local WireGuard/route execution (requires NET_ADMIN).
            meshlet_server::revision::hub_backend_factory(
                config.dataplane.clone(),
                config.tunnel_mtu,
            )
        } else {
            meshlet_server::revision::unconfigured_backend_factory()
        }),
    );
    meshlet_server::convergence::start_recovery(state.clone());
    // MT-005: periodically reclaim stuck tasks (assigned/acked past the window
    // with no receipt → failed + redispatch within budget). Does not depend on
    // dataplane.enabled — a pure control-plane deployment should reclaim too.
    meshlet_server::task::start_task_recovery(state.clone(), 30);
    // Disconnection observability (P1, nailed down on 2026-11-12: the imac went
    // offline as a fact while the server log held 0 disconnect records): log
    // presence state transitions. Does not depend on dataplane.enabled — a pure
    // control-plane deployment must still show every device's offline timeline.
    meshlet_server::presence_watch::start(state.clone());
    // Scheduled automatic backup (§17.4): enabled only with explicit
    // `[backup] auto = true`; it writes to the local `[backup] dir` only,
    // nothing is sent out. When due it writes a copy + leaves an audit trail;
    // failures are only logged.
    if config.backup.auto {
        if let Some(dir) = config.backup.dir.clone() {
            let pool = pool.clone();
            let interval = std::time::Duration::from_secs(config.backup.interval_secs);
            tokio::spawn(async move {
                let mut ticker = tokio::time::interval(interval);
                ticker.tick().await; // First tick is immediate: a backup exists right at startup.
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
    // ConnectInfo<SocketAddr>: agent heartbeats use this to observe the source
    // address of direct-connect candidates (§12).
    if let Err(error) = axum::serve(
        listener,
        app.into_make_service_with_connect_info::<std::net::SocketAddr>(),
    )
    .await
    {
        startup_failure("serve", &config.bind, error);
    }
}

fn load_config(path: Option<String>) -> ServerConfig {
    match path {
        Some(path) => {
            let raw = match std::fs::read_to_string(&path) {
                Ok(raw) => raw,
                Err(error) => startup_failure("read config", &path, error),
            };
            match ServerConfig::from_toml(&raw) {
                Ok(config) => config,
                Err(error) => startup_failure("invalid config", &path, error),
            }
        }
        None => ServerConfig::default(),
    }
}

/// Single exit for fatal resource acquisition failures during startup
/// (bind / database lock / connection / rebuild / serve / config read): first
/// log one error carrying the resource and the root cause (§17.1 — the JSON
/// surface is reachable), then state the same sentence plainly on stderr, and
/// finally exit non-zero as a whole. No panic — a crash backtrace is noise for
/// operators; both behave the same under systemd Restart, but an exit(1) log is
/// grep-able and the exit code is semantically clean. The partially initialized
/// surfaces from before (database lock / connection pool) are reclaimed by the
/// kernel when the process exits.
fn startup_failure(resource: &str, target: &str, error: impl std::fmt::Display) -> ! {
    let message = startup_failure_message(resource, target, &error.to_string());
    tracing::error!(resource, target, error = %error, "{message}");
    eprintln!("meshlet-server: {message}");
    std::process::exit(1);
}

/// Pure function (testable): `{resource} {target}: {error}` — the message
/// always carries the target and the root cause.
fn startup_failure_message(resource: &str, target: &str, error: &str) -> String {
    format!("{resource} {target}: {error}")
}

/// §17.4 offline restore: verify → atomic rename → audit trail → §17.3
/// convergence; any failure leaves the live database untouched. Afterwards a
/// normal service start reaches the desired state.
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

#[cfg(test)]
mod tests {
    use super::*;

    /// Failure message pin: must carry the resource, the target (address/path)
    /// and the root cause (os error).
    #[test]
    fn startup_failure_message_carries_target_and_root_cause() {
        let message = startup_failure_message(
            "bind",
            "0.0.0.0:8080",
            "Address already in use (os error 98)",
        );
        assert!(message.starts_with("bind "), "{message}");
        assert!(message.contains("0.0.0.0:8080"), "{message}");
        assert!(message.contains("os error 98"), "{message}");
    }

    /// Real port conflict (runs locally): after holding a concrete port, binding
    /// the same address must Err, and the wrapped message carries both the bind
    /// address and the os error root cause; the :0 ephemeral port succeeds
    /// normally.
    #[tokio::test]
    async fn bind_conflict_message_carries_address_and_cause() {
        let probe = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = probe.local_addr().unwrap().to_string();
        let error = tokio::net::TcpListener::bind(&addr)
            .await
            .expect_err("re-binding a held concrete address must fail");
        let message = startup_failure_message("bind", &addr, &error.to_string());
        assert!(message.contains(&addr), "{message}");
        assert!(message.contains("os error"), "{message}");
    }
}
