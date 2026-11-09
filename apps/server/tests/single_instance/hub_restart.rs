//! Hub restart tests that rebuild managed WireGuard and firewall state by identity.
#![cfg(target_os = "linux")]
use super::boot::*;
use super::single_instance_support::*;
use serde_json::json;

/// 场景 1：Hub 重启后必须按**身份**重建受管状态，而不是只看条数。
#[tokio::test(flavor = "multi_thread")]
async fn hub_reboot_rebuilds_managed_kernel_state_by_identity() {
    let Some(sandbox) = setup() else {
        return;
    };
    let boot = boot_network(&sandbox, "reboot-hub.key").await;
    // 造出 hub 侧路由 + 网关侧 NAT，让「受管状态」有可逐字段比对的实体。
    admin(
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
    let hub_key = wg_own_public_key(&sandbox, 0);
    let peers = wg_identity_lines(&sandbox, 0);
    let routes = sorted_lines(&sandbox, 0, &["ip", "-4", "route", "show", "dev", "wg0"]);
    let nat = meshlet_nat_lines(&sandbox, 1);
    assert!(!peers.is_empty(), "hub must have peers");
    assert!(!routes.is_empty(), "hub must have managed routes");
    assert!(!nat.is_empty(), "the gateway must carry meshlet NAT");

    // 重启：内核全丢，库还在。
    net(&sandbox.names[0], &["ip", "link", "del", "wg0"]);
    assert!(
        !ns(&sandbox.names[0], &["wg", "show", "wg0"])
            .status
            .success(),
        "the kernel interface must be gone before recovery"
    );
    let loaded = meshlet_server::persist::load(&boot.pool, Default::default())
        .await
        .unwrap();
    *boot.shared.lock().unwrap() = loaded.mesh;
    meshlet_server::convergence::recover_once(boot.state.clone())
        .await
        .unwrap();

    assert_eq!(
        wg_own_public_key(&sandbox, 0),
        hub_key,
        "a reboot must not rotate the hub key"
    );
    assert_eq!(
        wg_identity_lines(&sandbox, 0),
        peers,
        "peer identities must be rebuilt by identity, not by count"
    );
    assert_eq!(
        sorted_lines(&sandbox, 0, &["ip", "-4", "route", "show", "dev", "wg0"]),
        routes,
        "hub routes must be rebuilt from the persisted plan"
    );
    assert_eq!(
        meshlet_nat_lines(&sandbox, 1),
        nat,
        "the gateway NAT must be untouched by the hub reboot"
    );
    // 重建后的 wg0 不带会话密钥：设备仍用旧会话（REJECT_AFTER_TIME 内有效）发
    // keepalive，hub 无法解密也就学不到对端 endpoint，静默丢包是 WireGuard 的
    // 标准行为，最多 180 秒后设备会话过期自动重握手。设备侧按自己的收敛步骤
    // 重新应用期望计划（`wg set peer` 会重置会话）可立即恢复，这里用它验证
    // 恢复后的数据面。
    for index in 0..2 {
        converge_device(&sandbox, &boot, index).await;
    }
    assert!(reconnects(&sandbox.names[1], "10.240.0.3"));
    assert!(reconnects(&sandbox.names[2], "192.168.60.5"));
}

/// 场景 8：Hub 公钥轮换。轮换发生在密钥文件，Hub 重启后必须用新密钥重建隧道，
/// 设备的期望与内核随之收敛，旧公钥不得残留。
#[tokio::test(flavor = "multi_thread")]
async fn hub_key_rotation_converges_devices_after_restart() {
    let Some(sandbox) = setup() else {
        return;
    };
    let boot = boot_network(&sandbox, "rotate-hub.key").await;
    let key_file = sandbox.dir.join("rotate-hub.key");
    let before = wg_own_public_key(&sandbox, 0);
    let peers_before = wg_identity_lines(&sandbox, 0);

    let (new_private, _) = meshlet_network::keys::generate_keypair().unwrap();
    std::fs::write(&key_file, new_private).unwrap();
    net(&sandbox.names[0], &["ip", "link", "del", "wg0"]);
    let loaded = meshlet_server::persist::load(&boot.pool, Default::default())
        .await
        .unwrap();
    *boot.shared.lock().unwrap() = loaded.mesh;
    meshlet_server::convergence::recover_once(boot.state.clone())
        .await
        .unwrap();

    let after = wg_own_public_key(&sandbox, 0);
    assert_ne!(
        before, after,
        "the hub must come back up on the rotated key"
    );
    assert_eq!(
        wg_identity_lines(&sandbox, 0),
        peers_before,
        "rotation must only change the hub's own key"
    );

    for index in 0..2 {
        let plan = converge_device(&sandbox, &boot, index).await;
        assert!(
            plan.tunnel.peers.iter().any(|p| p.public_key == after),
            "device {index} plan must carry the rotated key"
        );
        let peers = wg_identity_lines(&sandbox, index + 1);
        assert!(
            peers.iter().any(|line| line.contains(&after)),
            "device {index} kernel must hold the rotated key: {peers:?}"
        );
        assert!(
            !peers.iter().any(|line| line.contains(&before)),
            "the old key must be gone from device {index}: {peers:?}"
        );
    }
    assert!(reconnects(&sandbox.names[1], "10.240.0.3"));
}
