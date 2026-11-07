//! Kernel NAT, forwarding, packet placement, and evidence assertions.

#![cfg(target_os = "linux")]

use super::context::*;
use super::support::*;
use serde_json::json;

#[test]
fn overlapping_lans_forward_without_cross_wiring_and_report_kernel_evidence() {
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
    let local_route_after = kernel_routes(&ctx.topo.a.netns);
    assert!(
        local_route_after
            .lines()
            .any(|route| route.starts_with("192.168.1.0/24 ") && !route.contains("dev wg0")),
        "managed Alias routes must preserve the client's same-prefix local route: {local_route_after}"
    );
    assert!(
        !local_route_after.contains("192.168.1.0/24 dev wg0"),
        "the repeated real LAN prefix must not enter the tunnel routes: {local_route_after}"
    );
    let reply1 = udp_echo(
        &ctx.topo,
        &ctx.dir,
        &ctx.topo.lan1,
        "site1",
        "10.241.1.5",
        7701,
    );
    let reply2 = udp_echo(
        &ctx.topo,
        &ctx.dir,
        &ctx.topo.lan2,
        "site2",
        "10.241.2.5",
        7702,
    );
    let local_reply = local_udp_echo(&ctx.topo, &ctx.dir, "192.168.1.5", 7700);
    assert!(
        reply1.contains("site1"),
        "alias1 must land at site1 (overlap must not cross-wire): {reply1}"
    );
    assert!(
        reply2.contains("site2"),
        "alias2 must land at site2: {reply2}"
    );
    assert!(
        local_reply.contains("local"),
        "same-prefix local destination must keep using its existing route: {local_reply}"
    );
    assert!(
        reply1.contains("seen=192.168.1.1"),
        "controlled snat rewrites the source to the gateway lan addr: {reply1}"
    );
    assert!(
        reply2.contains("seen=192.168.1.1"),
        "site2 gateway lan addr expected: {reply2}"
    );
    let tcp_site1 = tcp_echo(
        &ctx.topo,
        &ctx.dir,
        &ctx.topo.lan1,
        "10.241.1.5",
        "site1",
        7801,
    );
    let tcp_site2 = tcp_echo(
        &ctx.topo,
        &ctx.dir,
        &ctx.topo.lan2,
        "10.241.2.5",
        "site2",
        7802,
    );
    let tcp_local = tcp_echo(
        &ctx.topo,
        &ctx.dir,
        &ctx.topo.local_lan,
        "192.168.1.5",
        "local",
        7800,
    );
    for (name, identity) in [
        ("site1", tcp_site1.as_str()),
        ("site2", tcp_site2.as_str()),
        ("local", tcp_local.as_str()),
    ] {
        assert!(
            identity.contains(name) && identity.contains(" tcp"),
            "TCP path must identify {name} with a tuple: {identity}"
        );
    }
    let packet1 = capture_packet(
        &ctx.topo,
        &ctx.dir,
        &ctx.topo.a.netns,
        "wg0",
        "tcp port 7803 and host 10.241.1.5",
        "10.241.1.5",
        7803,
    );
    let packet2 = capture_packet(
        &ctx.topo,
        &ctx.dir,
        &ctx.topo.a.netns,
        "wg0",
        "tcp port 7804 and host 10.241.2.5",
        "10.241.2.5",
        7804,
    );
    let local_packet = capture_packet(
        &ctx.topo,
        &ctx.dir,
        &ctx.topo.a.netns,
        "any",
        "tcp port 7805 and host 192.168.1.5",
        "192.168.1.5",
        7805,
    );
    assert!(packet1.contains("10.241.1.5.7803"), "wire tuple: {packet1}");
    assert!(packet2.contains("10.241.2.5.7804"), "wire tuple: {packet2}");
    assert!(
        local_packet.contains("192.168.1.5.7805"),
        "wire tuple: {local_packet}"
    );
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
    let devices = ctx.devices();
    let devices = devices.as_array().unwrap();
    let evidence_of = |name: &str| {
        devices
            .iter()
            .find(|d| d["name"] == name)
            .unwrap_or_else(|| panic!("device {name} in view: {devices:?}"))["dataplane_evidence"]
            .clone()
    };
    for name in ["gw1", "gw2"] {
        let ev = evidence_of(name);
        assert_eq!(
            ev["nat_rules_present"], true,
            "gateway {name} must report its meshlet nat rules: {ev}"
        );
        assert_eq!(
            ev["nat_snat_rules_present"], true,
            "gateway {name} runs dnat_snat: controlled snat rule kernel-verified: {ev}"
        );
    }
    let ev = evidence_of("laptop-a");
    assert_eq!(
        ev["mtu_probe_payload"], 1392,
        "client must report the large-packet probe (1420 default mtu - 28): {ev}"
    );
    assert_eq!(ev["tunnel_mtu"], 1420, "kernel mtu reading: {ev}");
}
