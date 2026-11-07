//! Route deletion convergence and cross-network isolation.

#![cfg(target_os = "linux")]

use super::context::*;
use super::support::*;
use serde_json::{json, Value};
use std::time::Duration;

#[test]
fn deleting_one_site_converges_the_other_site_and_isolates_networks() {
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
    let rules_before_delete = (
        iptables_save(&ctx.topo.g1.netns),
        iptables_save(&ctx.topo.g2.netns),
        policy_rules(&ctx.topo.g1.netns),
        policy_rules(&ctx.topo.g2.netns),
    );
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
    let g1_after = iptables_save(&ctx.topo.g1.netns);
    let g2_after = iptables_save(&ctx.topo.g2.netns);
    assert_eq!(policy_rules(&ctx.topo.g1.netns), rules_before_delete.2);
    assert_eq!(policy_rules(&ctx.topo.g2.netns), rules_before_delete.3);
    assert!(
        !g1_after.contains("10.241.1.0/24"),
        "site1 alias rules must be absent after deletion: {g1_after}"
    );
    assert!(
        !g1_after.contains(&format!("meshlet alias {}", ctx.alias_ids[0])),
        "deleted alias owner must be absent after deletion: {g1_after}"
    );
    assert!(
        g2_after.contains("10.241.2.0/24"),
        "site2 NAT must remain after deleting site1: {g2_after}"
    );
    assert!(
        !g2_after.contains("10.241.1.0/24"),
        "site2 must not gain site1 rules: {g2_after}"
    );
    let tcp_after_delete = tcp_echo(
        &ctx.topo,
        &ctx.dir,
        &ctx.topo.local_lan,
        "192.168.1.5",
        "local",
        7806,
    );
    let tcp_site2_after_delete = tcp_echo(
        &ctx.topo,
        &ctx.dir,
        &ctx.topo.lan2,
        "10.241.2.5",
        "site2",
        7807,
    );
    assert!(tcp_after_delete.contains("local"), "{tcp_after_delete}");
    assert!(
        tcp_site2_after_delete.contains("site2"),
        "{tcp_site2_after_delete}"
    );
    assert!(
        ctx.topo
            .ping_within(&ctx.topo.b.netns, HUB_B_VIP, HANDSHAKE_TIMEOUT),
        "net-b must be alive: laptop-b -> net-b hub"
    );
    assert!(
        !ctx.topo
            .ping_within(&ctx.topo.a.netns, &ctx.b_vip, Duration::from_secs(10)),
        "net-a device must not reach net-b device (isolation)"
    );
    let plan_of = |base: &str, token: &str| -> Value {
        let (code, v) = http_json(
            "GET",
            &format!("{base}/api/v1/agent/device/desired"),
            None,
            Some(token),
            None,
        );
        assert!(code < 300, "desired plan fetch -> {code}: {v}");
        v
    };
    let a_plan = plan_of(&ctx.base, &ctx.a_token);
    let b_plan = plan_of(&ctx.base_b, &ctx.b_token);
    assert!(
        a_plan.to_string().contains("10.240.0.0/16"),
        "net-a plan carries its own overlay: {a_plan}"
    );
    assert!(
        b_plan.to_string().contains("10.242.0.0/16"),
        "net-b plan carries its own overlay: {b_plan}"
    );
    assert!(
        !a_plan.to_string().contains("10.242"),
        "net-a plan must not carry net-b's overlay: {a_plan}"
    );
    assert!(
        !b_plan.to_string().contains("10.240"),
        "net-b plan must not carry net-a's overlay: {b_plan}"
    );
    assert!(
        kernel_routes(&ctx.topo.a.netns).contains("10.240.0.0/16"),
        "net-a kernel route carries its own overlay: {}",
        kernel_routes(&ctx.topo.a.netns)
    );
    assert!(
        kernel_routes(&ctx.topo.b.netns).contains("10.242.0.0/16"),
        "net-b kernel route carries its own overlay: {}",
        kernel_routes(&ctx.topo.b.netns)
    );
    assert!(
        !kernel_routes(&ctx.topo.a.netns).contains("10.242"),
        "net-a kernel routes must not reach net-b: {}",
        kernel_routes(&ctx.topo.a.netns)
    );
    assert!(
        !kernel_routes(&ctx.topo.b.netns).contains("10.240"),
        "net-b kernel routes must not reach net-a: {}",
        kernel_routes(&ctx.topo.b.netns)
    );
}
