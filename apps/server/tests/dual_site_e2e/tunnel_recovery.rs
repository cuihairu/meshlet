//! Full self-healing chain after a disconnect (P2, 2026-11-12 task list; precondition gate for the R-07 soak).
//!
//! Scenario: the tunnel interface is killed (`ip link del wg0`, the netns equivalent of a Windows
//! WireGuardNT crash / driver reset) -> the agent notices and rebuilds within one tick -> re-handshakes
//! with the hub -> the device timeline advances on the server side and presence converges back to `online`
//! — the whole chain in <=60s (task budget). The data plane really runs: it needs sudo -n + wireguard-tools,
//! otherwise SKIP (the same guard as the other dual_site cases).

#![cfg(target_os = "linux")]

use super::context::*;
use super::support::*;
use serde_json::{json, Value};
use std::time::{Duration, Instant};

/// Pull one device out of the device list (matched by the device_name given at enroll time).
fn device_of<'a>(devices: &'a Value, name: &str) -> &'a Value {
    devices
        .as_array()
        .unwrap()
        .iter()
        .find(|d| d["name"] == json!(name))
        .unwrap_or_else(|| panic!("device {name} not in list: {devices}"))
}

#[test]
fn killed_tunnel_is_rebuilt_within_sixty_seconds_and_the_server_sees_it() {
    let _guard = lock();
    let Some(ctx) = Context::setup() else {
        return;
    };
    // Same groundwork as recovery.rs: one real business route + an alias, so site 2 (lan2, behind g2)
    // is reachable through the tunnel — "10.241.2.x = site 2's 192.168.1.x".
    let routes_uri = format!("/api/v1/networks/{}/routes", ctx.network_id);
    let aliases_uri = format!("/api/v1/networks/{}/aliases", ctx.network_id);
    let (code, route) = http_json(
        "POST",
        &format!("{}{routes_uri}", ctx.base),
        Some(&ctx.cookie),
        None,
        Some(json!({
            "gateway_device_id": ctx.g2_id,
            "destination_cidr": "192.168.1.0/24",
            "return_path_mode": "controlled_snat",
            "route_mode": "alias",
        })),
    );
    assert_eq!(code, 201, "route: {route}");
    let route_id = route["id"].as_str().unwrap().to_string();
    let (code, alias) = http_json(
        "POST",
        &format!("{}{aliases_uri}", ctx.base),
        Some(&ctx.cookie),
        None,
        Some(json!({
            "lan_route_id": route_id,
            "alias_cidr": "10.241.2.0/24",
            "translation_mode": "dnat_snat",
        })),
    );
    assert_eq!(code, 201, "alias: {alias}");
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
        assert!(ctx.topo.wait_handshake(ns), "baseline handshake in {ns}");
    }

    // Baseline: site 2's alias is reachable across the tunnel, and the server already judges laptop-a online.
    let devices_before = ctx.devices();
    let baseline = device_of(&devices_before, "laptop-a");
    assert_eq!(
        baseline["online_state"], "online",
        "laptop-a must be online before the tunnel is killed: {baseline}"
    );
    let seen_before = baseline["last_seen_at"]
        .as_str()
        .expect("baseline last_seen_at")
        .to_string();
    let before = tcp_echo(
        &ctx.topo,
        &ctx.dir,
        &ctx.topo.lan2,
        "10.241.2.5",
        "site2",
        7812,
    );
    assert!(
        before.contains("site2"),
        "baseline cross-tunnel echo: {before}"
    );

    // Kill the tunnel: delete the interface outright (the netns equivalent of a data-plane incident).
    // The control plane (HTTPS over the underlay) is unaffected — matching the real-machine disconnect case.
    require_ok(
        &netns_exec(&ctx.topo.a.netns, &["ip", "link", "del", "wg0"]),
        "kill the tunnel interface",
    );
    // now() has second-level precision: leave a second so the post-rebuild heartbeat timestamp strictly advances.
    std::thread::sleep(Duration::from_secs(1));

    // Full-chain timing (task budget <=60s): from "self-healing starts" to "the server observes convergence".
    let started = Instant::now();
    let deadline = started + Duration::from_secs(60);

    // The agent notices and rebuilds: one tick of reconciliation (the ledger survives, kernel drift is converged away).
    tick_agent(
        &ctx.dir,
        &ctx.base,
        "a",
        &ctx.topo.a,
        ctx.a_token.as_str(),
        Some(&ctx.hub_endpoint),
    );
    assert!(
        ctx.topo.wait_handshake(&ctx.topo.a.netns),
        "handshake must re-establish after rebuild"
    );

    // Server state converges: laptop-a's timeline advances (a fresh heartbeat arrives), presence returns to
    // `online` and the source is an agent report (the complete definition of presence convergence).
    let mut view = device_of(&ctx.devices(), "laptop-a").clone();
    while view["last_seen_at"] == json!(seen_before) {
        assert!(
            Instant::now() < deadline,
            "server view did not converge within 60s: last_seen_at stuck at {seen_before}"
        );
        std::thread::sleep(Duration::from_millis(200));
        view = device_of(&ctx.devices(), "laptop-a").clone();
    }
    assert!(
        view["last_seen_at"].as_str().unwrap() > seen_before.as_str(),
        "device timeline must advance after the rebuild: {} -> {}",
        seen_before,
        view["last_seen_at"]
    );
    assert_eq!(
        view["online_state"], "online",
        "presence must converge back to online: {view}"
    );
    assert_eq!(
        view["presence_source"], "agent_report",
        "converged state must come from a fresh agent report: {view}"
    );
    // Nothing is left stuck on the revision side: no revision parks in applying (§10.3 — an interrupted
    // applying is only legal once converged to failed; pending/applied are normal history, and a
    // superseded older revision staying pending is expected).
    let revisions = admin(
        &ctx.base,
        &ctx.cookie,
        "GET",
        &format!("/api/v1/networks/{}/config-revisions", ctx.network_id),
        None,
    );
    for revision in revisions.as_array().unwrap() {
        assert_ne!(
            revision["apply_status"], "applying",
            "no revision may be stuck mid-apply after self-healing: {revision}"
        );
    }
    // Data-plane recovery: the cross-tunnel echo is reachable again.
    let after = tcp_echo(
        &ctx.topo,
        &ctx.dir,
        &ctx.topo.lan2,
        "10.241.2.5",
        "site2",
        7813,
    );
    assert!(
        after.contains("site2"),
        "recovered cross-tunnel echo: {after}"
    );

    assert!(
        started.elapsed() <= Duration::from_secs(60),
        "full self-healing chain took {:?} (budget 60s)",
        started.elapsed()
    );
    println!(
        "self-healing chain (kill -> rebuild -> handshake -> server view -> echo): {:?}",
        started.elapsed()
    );
    let _ = std::fs::remove_dir_all(&ctx.dir);
}
