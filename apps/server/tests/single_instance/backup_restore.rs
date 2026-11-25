//! Backup restore must reconstruct a converged kernel state from persisted plans.
#![cfg(target_os = "linux")]
use super::boot::*;
use super::single_instance_support::*;
use axum::http::StatusCode;
use meshlet_network::SystemBackend;
use serde_json::{json, Value};

#[tokio::test(flavor = "multi_thread")]
async fn restoring_a_backup_reconverges_the_kernel() {
    let Some(sandbox) = setup() else {
        return;
    };
    let boot = boot_network(&sandbox, "restore.key").await;
    let route = admin(
        &boot.app,
        &boot.cookie,
        &format!("/api/v1/networks/{}/routes", boot.network),
        json!({"gateway_device_id":boot.device_ids[0],"destination_cidr":"192.168.60.0/24","route_mode":"direct","return_path_mode":"controlled_snat"}),
    )
    .await;
    assert_eq!(
        apply(&boot.app, &boot.cookie, &boot.network).await["apply_status"],
        "applied"
    );
    converge_device(&sandbox, &boot, 0).await;
    converge_device(&sandbox, &boot, 1).await;
    assert!(reconnects(&sandbox.names[2], "192.168.60.5"));

    // Kernel evidence at backup time: both the hub routes and the gateway NAT are present.
    let hub_routes = sorted_lines(&sandbox, 0, &["ip", "-4", "route", "show", "dev", "wg0"]);
    let nat = meshlet_nat_lines(&sandbox, 1);
    assert!(
        hub_routes.iter().any(|l| l.contains("192.168.60.0/24")),
        "hub must route the LAN prefix: {hub_routes:?}"
    );
    assert!(
        !nat.is_empty(),
        "the gateway must carry meshlet NAT before backup"
    );

    let backup_dir = sandbox.dir.join("backups");
    let backup = meshlet_server::persist::backup_once(&boot.pool, &backup_dir, Some("acceptance"))
        .await
        .unwrap();
    let backup_path = std::path::PathBuf::from(&backup.path);
    assert!(
        backup_path.is_file(),
        "backup file must exist: {}",
        backup.path
    );

    // A change lands after the backup: delete the LAN route and apply — the kernel then loses those managed objects.
    let (status, body) = request(
        &boot.app,
        "DELETE",
        &format!(
            "/api/v1/networks/{}/routes/{}",
            boot.network,
            route["id"].as_str().unwrap()
        ),
        Value::Null,
        Some(&boot.cookie),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT, "{body}");
    assert_eq!(
        apply(&boot.app, &boot.cookie, &boot.network).await["apply_status"],
        "applied"
    );
    let plan = desired_plan(&boot.app, &boot.tokens[0]).await;
    let state_dir = sandbox.dir.join("agent-restore");
    let config = meshlet_config::AgentConfig {
        server_url: "http://127.0.0.1:1".into(),
        state_dir: state_dir.to_string_lossy().into_owned(),
        device_token: Some(boot.tokens[0].clone()),
        bootstrap_token: None,
        device_name: None,
        tray: meshlet_config::TrayConfig::OFF,
        upgrade: meshlet_config::AgentConfig::default().upgrade,
        dataplane: meshlet_config::DataplaneConfig {
            enabled: true,
            hub_endpoint: Some("172.31.1.1:51820".into()),
            ..Default::default()
        },
        ssh_config_sync: meshlet_config::SshConfigSyncConfig::OFF,
        mcp: meshlet_config::McpConfig::OFF,
    };
    let mut agent = meshlet_agent::agent::Agent::with_backend(
        config,
        Some(boot.keys[0].clone()),
        SystemBackend::new()
            .with_netns(sandbox.names[1].clone())
            .with_sudo(),
    );
    agent.reconcile(&plan).unwrap();
    assert!(
        meshlet_nat_lines(&sandbox, 1)
            .iter()
            .all(|l| !l.contains("192.168.60.0/24")),
        "post-backup deletion must reach the gateway kernel"
    );

    // Restore: close the DB first (restore needs the exclusive lock), then swap back the backup content atomically.
    boot.pool.close().await;
    let database = sandbox.dir.join("state.db");
    let report = meshlet_server::persist::restore_from_backup(
        &backup_path,
        &database,
        meshlet_domain::PresenceThresholds::default(),
    )
    .await
    .unwrap();
    assert_eq!(
        report.summary.routes, 1,
        "restored view: {:?}",
        report.summary
    );
    assert_eq!(report.summary.aliases, 0);
    assert!(
        report.interrupted.is_empty(),
        "no applying revision should survive in the backup: {:?}",
        report.interrupted
    );

    // Restart the service on the restored DB. Device tokens / private keys are part of the backup,
    // so they stay valid after restart with no re-enrollment; the hub restart keeps the same key file (ADR-010).
    let hub_key = std::fs::read_to_string(sandbox.dir.join("restore.key")).unwrap();
    let network = boot.network.clone();
    let tokens = boot.tokens.clone();
    let keys = boot.keys.clone();
    let device_ids = boot.device_ids.clone();
    let mut boot = boot_app(&sandbox, "restore.key").await;
    std::fs::write(sandbox.dir.join("restore.key"), hub_key).unwrap();
    boot.network = network;
    boot.tokens = tokens;
    boot.keys = keys;
    boot.device_ids = device_ids;

    let (_, body) = request(
        &boot.app,
        "GET",
        &format!("/api/v1/networks/{}/routes", boot.network),
        Value::Null,
        Some(&boot.cookie),
        None,
    )
    .await;
    assert!(
        body.to_string().contains("192.168.60.0/24"),
        "the LAN route must be back in the control plane: {body}"
    );

    // "Clicking apply once" does not restore the kernel: an already-applied revision is an idempotent
    // no-op in the ledger (config_state.rs:230), and revisions added after the backup no longer exist
    // in the restored DB. What actually brings the kernel back to backup time is the production startup
    // recovery (the synchronous form of main.rs:98 start_recovery) — it diffs the restored desired plan against the kernel and fills whatever is missing.
    meshlet_server::convergence::recover_once(boot.state.clone())
        .await
        .unwrap();
    let restored_routes = sorted_lines(&sandbox, 0, &["ip", "-4", "route", "show", "dev", "wg0"]);
    assert_eq!(
        restored_routes, hub_routes,
        "hub routes must reconverge to the backup-time plan"
    );

    // Gateway side: the restored desired plan carries NAT again, and the device reconverges to its own desired plan.
    converge_device(&sandbox, &boot, 0).await;
    converge_device(&sandbox, &boot, 1).await;
    assert_eq!(
        meshlet_nat_lines(&sandbox, 1),
        nat,
        "gateway NAT must reconverge to the backup-time plan"
    );
    assert!(reconnects(&sandbox.names[2], "192.168.60.5"));
}
