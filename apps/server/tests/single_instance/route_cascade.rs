//! Deleting a LAN route must cascade managed routes, peers, aliases, and NAT.
#![cfg(target_os = "linux")]
use super::boot::*;
use super::single_instance_support::*;
use axum::http::StatusCode;
use meshlet_network::SystemBackend;
use serde_json::{json, Value};

/// Scenario 4: deleting a LAN route = deleting the complete unit of "route + its dependent aliases".
/// Managed objects must be cleaned up by identity: hub routes and hub AllowedIPs converge by re-applying on
/// the hub side, and gateway NAT converges by the gateway agent's ownership sweep — neither side may leave orphans.
#[tokio::test(flavor = "multi_thread")]
async fn deleting_a_lan_route_cascades_managed_kernel_objects() {
    let Some(sandbox) = setup() else {
        return;
    };
    let boot = boot_network(&sandbox, "del-route.key").await;
    let route = admin(
        &boot.app,
        &boot.cookie,
        &format!("/api/v1/networks/{}/routes", boot.network),
        json!({"gateway_device_id":boot.device_ids[0],"destination_cidr":"192.168.61.0/24","route_mode":"alias","return_path_mode":"dual_route"}),
    )
    .await;
    let alias = admin(
        &boot.app,
        &boot.cookie,
        &format!("/api/v1/networks/{}/aliases", boot.network),
        json!({"lan_route_id":route["id"],"alias_cidr":"10.243.61.0/24","translation_mode":"dnat_only"}),
    )
    .await;
    let owner = format!("meshlet alias {}", alias["id"].as_str().unwrap());
    assert_eq!(
        apply(&boot.app, &boot.cookie, &boot.network).await["apply_status"],
        "applied"
    );
    converge_device(&sandbox, &boot, 0).await;
    converge_device(&sandbox, &boot, 1).await;

    // Capture the three managed pieces of evidence first: hub routes, gateway NAT, hub AllowedIPs.
    let hub_routes = sorted_lines(&sandbox, 0, &["ip", "-4", "route", "show", "dev", "wg0"]);
    let nat = meshlet_nat_lines(&sandbox, 1);
    let allowed = wg_identity_lines(&sandbox, 0);
    assert!(
        hub_routes.iter().any(|l| l.contains("10.243.61.0/24")),
        "hub must route the alias prefix: {hub_routes:?}"
    );
    assert!(
        nat.iter().any(|l| l.contains(&owner)),
        "gateway must carry the alias NAT: {nat:?}"
    );
    assert!(
        allowed.iter().any(|l| l.contains("10.243.61.0/24")),
        "hub AllowedIPs must carry the alias prefix: {allowed:?}"
    );

    // Delete the LAN route: the alias is its dependent unit and must disappear along with it (control plane).
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
    let (status, body) = request(
        &boot.app,
        "GET",
        &format!("/api/v1/networks/{}/aliases", boot.network),
        Value::Null,
        Some(&boot.cookie),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert!(
        body.as_array().unwrap().is_empty(),
        "the alias must be cascade-deleted: {body}"
    );

    // The hub side converges via apply: both the route and the alias prefix in AllowedIPs should be gone.
    assert_eq!(
        apply(&boot.app, &boot.cookie, &boot.network).await["apply_status"],
        "applied"
    );
    let hub_routes = sorted_lines(&sandbox, 0, &["ip", "-4", "route", "show", "dev", "wg0"]);
    assert!(
        !hub_routes.iter().any(|l| l.contains("10.243.61.0/24")),
        "hub route must go: {hub_routes:?}"
    );
    assert!(
        !wg_identity_lines(&sandbox, 0)
            .iter()
            .any(|l| l.contains("10.243.61.0/24")),
        "hub AllowedIPs must shrink back to the overlay /32"
    );

    // The gateway side converges via the agent: the new plan has empty nat_rules, and apply_device_plan_sync
    // returns early on empty NAT, so Agent::reconcile's ownership sweep must be the path taken.
    let plan = desired_plan(&boot.app, &boot.tokens[0]).await;
    assert!(
        plan.nat_rules.is_empty(),
        "the gateway plan must no longer carry NAT: {:?}",
        plan.nat_rules
    );
    let state_dir = sandbox.dir.join("agent-cascade");
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
    let decision = agent.reconcile(&plan).unwrap();
    assert_eq!(
        decision.reason,
        meshlet_agent::reconcile::Reason::NoLocalLedger
    );
    let nat = meshlet_nat_lines(&sandbox, 1);
    assert!(
        nat.iter().all(|l| !l.contains(&owner)),
        "the alias NAT owner must be swept from the gateway: {nat:?}"
    );
    assert!(
        reconnects(&sandbox.names[1], "10.240.0.3"),
        "overlay connectivity must survive the cascade"
    );
}
