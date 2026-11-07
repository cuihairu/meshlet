//! Control-plane restart recovery and exact kernel-state restore.

#![cfg(target_os = "linux")]

use super::context::*;
use super::support::*;
use serde_json::json;
use std::time::Duration;

#[test]
fn restart_restores_remaining_site_from_persisted_state() {
    let _guard = lock();
    let Some(mut ctx) = Context::setup() else {
        return;
    };
    let routes_uri = format!("/api/v1/networks/{}/routes", ctx.network_id);
    let aliases_uri = format!("/api/v1/networks/{}/aliases", ctx.network_id);
    for (name, gateway, alias_cidr) in [
        ("gw1", ctx.g1_id.as_str(), "10.241.1.0/24"),
        ("gw2", ctx.g2_id.as_str(), "10.241.2.0/24"),
    ] {
        let (code, route) = http_json(
            "POST",
            &format!("{}{routes_uri}", ctx.base),
            Some(&ctx.cookie),
            None,
            Some(json!({
                "gateway_device_id": gateway,
                "destination_cidr": "192.168.1.0/24",
                "return_path_mode": "controlled_snat",
                "route_mode": "alias",
            })),
        );
        assert_eq!(code, 201, "route for {name}: {route}");
        let route_id = route["id"].as_str().unwrap().to_string();
        let (code, alias) = http_json(
            "POST",
            &format!("{}{aliases_uri}", ctx.base),
            Some(&ctx.cookie),
            None,
            Some(json!({
                "lan_route_id": route_id,
                "alias_cidr": alias_cidr,
                "translation_mode": "dnat_snat",
            })),
        );
        assert_eq!(code, 201, "alias for {name}: {alias}");
        ctx.alias_ids
            .push(alias["id"].as_str().unwrap().to_string());
        ctx.route_ids.push(route_id);
    }
    ctx.apply_latest(&ctx.base_b, &ctx.network_b_id);
    ctx.apply_latest(&ctx.base, &ctx.network_id);
    for (node, token, name) in [
        (&ctx.topo.g1, ctx.g1_token.as_str(), "g1"),
        (&ctx.topo.g2, ctx.g2_token.as_str(), "g2"),
        (&ctx.topo.a, ctx.a_token.as_str(), "a"),
    ] {
        tick_agent(
            &ctx.dir,
            &ctx.base,
            name,
            node,
            token,
            Some(&ctx.hub_endpoint),
        );
    }
    tick_agent(
        &ctx.dir,
        &ctx.base_b,
        "laptop-b",
        &ctx.topo.b,
        ctx.b_token.as_str(),
        Some(&ctx.hub_b_endpoint),
    );
    for ns in [
        &ctx.topo.g1.netns,
        &ctx.topo.g2.netns,
        &ctx.topo.a.netns,
        &ctx.topo.hub2.netns,
        &ctx.topo.b.netns,
    ] {
        assert!(
            ctx.topo.wait_handshake(ns),
            "handshake did not complete in {ns}"
        );
    }
    let (code, _) = http_json(
        "DELETE",
        &format!("{}{routes_uri}/{}", ctx.base, ctx.route_ids[0]),
        Some(&ctx.cookie),
        None,
        None,
    );
    assert_eq!(code, 204, "delete site1 route");
    ctx.apply_latest(&ctx.base, &ctx.network_id);
    for (node, token, name) in [
        (&ctx.topo.g1, ctx.g1_token.as_str(), "g1"),
        (&ctx.topo.g2, ctx.g2_token.as_str(), "g2"),
        (&ctx.topo.a, ctx.a_token.as_str(), "a"),
    ] {
        tick_agent(
            &ctx.dir,
            &ctx.base,
            name,
            node,
            token,
            Some(&ctx.hub_endpoint),
        );
    }
    let expected_client_routes = kernel_routes(&ctx.topo.a.netns)
        .lines()
        .filter(|route| !route.contains("10.241.1.0/24"))
        .map(|route| route.to_string())
        .collect::<Vec<_>>()
        .join("\n");
    let site1_unreachable =
        ctx.topo
            .ping_within(&ctx.topo.a.netns, "10.241.1.5", Duration::from_secs(4));
    assert!(
        !site1_unreachable,
        "deleted site1 alias must remain unreachable before restart"
    );
    let g2_kernel_before_restart = managed_iptables(&ctx.topo.g2.netns);
    let local_kernel_before_restart = iptables_save(&ctx.topo.local_lan);
    ctx.server.stop();
    ctx.server_b.stop();
    std::fs::remove_file(ctx.dir.join("agent-a/applied.json")).unwrap();
    require_ok(
        &netns_exec(&ctx.topo.a.netns, &["ip", "link", "del", "wg0"]),
        "simulate agent restart",
    );
    let (base_restarted, restarted_handle) = start_stoppable_server(
        ctx.dir.join("db.sqlite3"),
        ctx.dir.join("hub.key"),
        ctx.topo.hub.netns.clone(),
    );
    wait_server_up(&base_restarted);
    let (base_b_restarted, base_b_restarted_handle) = start_stoppable_server(
        ctx.dir.join("db.sqlite3"),
        ctx.dir.join("hub-b.key"),
        ctx.topo.hub2.netns.clone(),
    );
    wait_server_up(&base_b_restarted);
    for (node, token, name) in [
        (&ctx.topo.g1, ctx.g1_token.as_str(), "g1"),
        (&ctx.topo.g2, ctx.g2_token.as_str(), "g2"),
        (&ctx.topo.a, ctx.a_token.as_str(), "a"),
    ] {
        tick_agent(
            &ctx.dir,
            &base_restarted,
            name,
            node,
            token,
            Some(&ctx.hub_endpoint),
        );
    }
    tick_agent(
        &ctx.dir,
        &base_b_restarted,
        "laptop-b",
        &ctx.topo.b,
        ctx.b_token.as_str(),
        Some(&format!("{HUB_B_UNDERLAY_IP}:{HUB_LISTEN_PORT}")),
    );
    assert_eq!(
        managed_iptables(&ctx.topo.g2.netns),
        g2_kernel_before_restart,
        "remaining gateway NAT must be rebuilt exactly after restart"
    );
    assert_eq!(
        kernel_routes(&ctx.topo.a.netns),
        expected_client_routes,
        "client routes must be rebuilt exactly after restart"
    );
    assert_eq!(
        iptables_save(&ctx.topo.local_lan),
        local_kernel_before_restart,
        "local LAN must remain untouched by restore"
    );
    let restored_local = tcp_echo(
        &ctx.topo,
        &ctx.dir,
        &ctx.topo.local_lan,
        "192.168.1.5",
        "local",
        7808,
    );
    let restored_site2 = tcp_echo(
        &ctx.topo,
        &ctx.dir,
        &ctx.topo.lan2,
        "10.241.2.5",
        "site2",
        7809,
    );
    assert!(restored_local.contains("local"), "{restored_local}");
    assert!(restored_site2.contains("site2"), "{restored_site2}");
    base_b_restarted_handle.stop();
    restarted_handle.stop();
    let _ = std::fs::remove_dir_all(&ctx.dir);
}
