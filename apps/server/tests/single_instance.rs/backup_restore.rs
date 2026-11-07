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

    // 备份时刻的内核证据：hub 路由与网关 NAT 都在场。
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

    // 备份之后发生变更：删掉 LAN 路由并应用——内核随之失去这些受管对象。
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

    // 恢复：先关库（restore 要独占锁），再原子换回备份内容。
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

    // 用恢复后的库重启服务。设备 token / 私钥都是备份内容的一部分，重启后
    // 照旧有效，不需要重新入网；hub 重启沿用同一个私钥文件（ADR-010）。
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

    // 「点一次 apply」并不能恢复内核：已 applied 的修订在账本里是幂等空操作
    // （config_state.rs:230），而备份后新增的修订在恢复出的库里已不存在。
    // 真正把内核带回备份时刻的是生产启动恢复（main.rs:98 start_recovery 的
    // 同步形态）——它拿恢复出的期望计划比对内核，缺什么补什么。
    meshlet_server::convergence::recover_once(boot.state.clone())
        .await
        .unwrap();
    let restored_routes = sorted_lines(&sandbox, 0, &["ip", "-4", "route", "show", "dev", "wg0"]);
    assert_eq!(
        restored_routes, hub_routes,
        "hub routes must reconverge to the backup-time plan"
    );

    // 网关侧：恢复出的期望又带上了 NAT，设备按自己的期望计划重新收敛。
    converge_device(&sandbox, &boot, 0).await;
    converge_device(&sandbox, &boot, 1).await;
    assert_eq!(
        meshlet_nat_lines(&sandbox, 1),
        nat,
        "gateway NAT must reconverge to the backup-time plan"
    );
    assert!(reconnects(&sandbox.names[2], "192.168.60.5"));
}
