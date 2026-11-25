use std::collections::BTreeSet;

use meshlet_network::RouteConfig;

use crate::common::{
    alias_mapping, hub_routes, hub_tunnel, leaf_tunnel, netns_exec, peer_identities,
    planned_peer_identities, require_ok, snapshot_has_snat, sorted_signatures, Topology,
    ALIAS_OWNER, NETNS_PREFIX_LOCK,
};

#[test]
fn tunnel_routes_nat_connectivity_and_idempotence() {
    let _guard = NETNS_PREFIX_LOCK.lock().unwrap();
    let topo = match Topology::setup() {
        Some(t) => t,
        None => return, // Already printed SKIP:
    };

    // ---- All dataplane configuration is handed down through LinuxNetworkBackend ------------------------
    let mut hub_backend = topo.hub.backend();
    let mut a_backend = topo.a.backend();
    let mut b_backend = topo.b.backend();
    let mut gw_backend = topo.gw.backend();

    // Hub: tunnel (peers A/B/G) + the forwarding routes for the alias prefixes.
    hub_backend
        .apply_tunnel_sync(
            &hub_tunnel(&topo.hub, &topo.a, &topo.b, &topo.gw, true),
            &BTreeSet::new(),
        )
        .expect("hub apply_tunnel");
    hub_backend
        .apply_routes_sync(&hub_routes())
        .expect("hub apply_routes");

    // Clients A/B: tunnel + the routes sending the alias range into the tunnel.
    for (node, backend) in [(&topo.a, &mut a_backend), (&topo.b, &mut b_backend)] {
        backend
            .apply_tunnel_sync(
                &leaf_tunnel(node, &topo.hub, &["10.240.0.0/16", "10.241.0.0/16"]),
                &BTreeSet::new(),
            )
            .unwrap_or_else(|e| panic!("{} apply_tunnel: {e}", node.netns));
        backend
            .apply_routes_sync(&[RouteConfig {
                destination: "10.241.0.0/16".parse().unwrap(),
                interface: "wg0".into(),
                gateway: None,
            }])
            .unwrap_or_else(|e| panic!("{} apply_routes: {e}", node.netns));
    }

    // Gateway G: tunnel + the return route + alias NAT (rendered and executed by the planning layer).
    gw_backend
        .apply_tunnel_sync(
            &leaf_tunnel(&topo.gw, &topo.hub, &["10.240.0.0/16", "10.241.0.0/16"]),
            &BTreeSet::new(),
        )
        .expect("gw apply_tunnel");
    gw_backend
        .apply_routes_sync(&[RouteConfig {
            destination: "10.241.0.0/16".parse().unwrap(),
            interface: "wg0".into(),
            gateway: None,
        }])
        .expect("gw apply_routes");
    let alias = alias_mapping();
    let rules = meshlet_network::nat::alias_nat_rules(&alias);
    gw_backend
        .apply_nat_sync(&rules, "192.168.1.1".parse().unwrap())
        .expect("gw apply_nat");

    // ---- 1. Handshake complete + inspect snapshot ---------------------------------------
    for ns in [&topo.a.netns, &topo.b.netns, &topo.gw.netns] {
        assert!(
            topo.wait_handshake(ns),
            "handshake did not complete in {ns}"
        );
    }
    let snap = hub_backend.inspect_sync().expect("hub inspect");
    assert!(snap.tunnel_exists);
    assert_eq!(snap.peers.len(), 3, "hub peers: A + B + G");
    // Identity level (M2): beyond the count, the public-key + allowed-ips identities must be read out faithfully.
    assert_eq!(
        peer_identities(&snap),
        planned_peer_identities(&topo.a, &topo.b, &topo.gw),
        "hub peers must be read by identity, not just by count"
    );
    assert_eq!(snap.forwarding_enabled, Some(true));
    assert!(
        snap.installed_routes
            .contains(&"10.241.1.0/24".parse().unwrap()),
        "hub must route the alias prefix: {:?}",
        snap.installed_routes
    );
    assert!(
        snap.nat_rules.is_empty(),
        "hub carries no NAT rules: {:?}",
        snap.nat_rules
    );

    // Gateway G's snapshot: the rule is present + a reading of the controlled SNAT is present
    // (dnat_snat mode, the evidence source for §8.2's "the mode the kernel actually uses").
    let gw_snap = gw_backend.inspect_sync().expect("gw inspect");
    assert!(
        !gw_snap.nat_rules.is_empty(),
        "gw carries meshlet NAT rules: {:?}",
        gw_snap.nat_rules
    );
    // The planning side and the kernel side match byte for byte (M2: the same plan produces the same
    // fingerprint before and after an upgrade, so an existing ledger is not invalidated).
    assert_eq!(
        gw_snap.nat_rules,
        sorted_signatures(
            &rules
                .iter()
                .map(|rule| rule.signature())
                .collect::<Vec<_>>()
        ),
        "kernel fingerprints must equal plan fingerprints"
    );
    assert!(
        snapshot_has_snat(&gw_snap),
        "dnat_snat mode: controlled SNAT rule kernel-verified"
    );

    // ---- 2. A -> B is reachable forwarded through the hub (both directions) --------------------------------
    assert!(topo.ping(&topo.a.netns, &topo.b.overlay), "A -> B via hub");
    assert!(topo.ping(&topo.b.netns, &topo.a.overlay), "B -> A via hub");

    // ---- 3. Alias path: A reaches G's real LAN behind G via hub + G + NAT --------------
    assert!(
        topo.ping(&topo.a.netns, "10.241.1.5"),
        "A -> alias 10.241.1.5 (real LAN 192.168.1.5 behind G)"
    );

    // ---- 4. Idempotence: applying the same configuration repeatedly gives the same result (§10.3) ------------------------
    hub_backend
        .apply_tunnel_sync(
            &hub_tunnel(&topo.hub, &topo.a, &topo.b, &topo.gw, true),
            &BTreeSet::new(),
        )
        .expect("hub apply_tunnel (re-apply)");
    gw_backend
        .apply_nat_sync(&rules, "192.168.1.1".parse().unwrap())
        .expect("gw apply_nat (re-apply)");
    assert!(
        topo.ping(&topo.a.netns, &topo.b.overlay),
        "A -> B after re-apply"
    );
    assert!(
        topo.ping(&topo.a.netns, "10.241.1.5"),
        "alias after re-apply"
    );

    // ---- 5. Overlay source preservation (§7.4): with the NAT present, the A -> B source is still the original address ----------
    // G's NAT rule is present at this point -- if an indiscriminate SNAT existed, the source B sees would be rewritten.
    let expected_source = format!("src={}", topo.a.overlay);
    let observed = topo.overlay_source_seen_by_b();
    assert_eq!(
        observed.as_deref(),
        Some(expected_source.as_str()),
        "overlay A->B must keep the original source address (7.4)"
    );

    // ---- 6. remove_nat removes only Meshlet rules and never touches user rules (§12.6) ----------
    // Plant one non-Meshlet rule (a foreign rule from the user's viewpoint).
    require_ok(
        &netns_exec(
            &topo.gw.netns,
            &[
                "iptables",
                "-t",
                "nat",
                "-A",
                "PREROUTING",
                "-d",
                "203.0.113.0/24",
                "-j",
                "ACCEPT",
                "-m",
                "comment",
                "--comment",
                "user rule",
            ],
        ),
        "plant foreign nat rule",
    );
    gw_backend
        .remove_nat_sync(ALIAS_OWNER)
        .expect("gw remove_nat");
    let prerouting = topo.nat_rules(&topo.gw.netns, "PREROUTING");
    assert!(
        !prerouting.contains(ALIAS_OWNER),
        "meshlet alias rules must be gone:\n{prerouting}"
    );
    assert!(
        prerouting.contains("user rule"),
        "foreign rule must survive remove_nat:\n{prerouting}"
    );
    assert!(
        !topo.ping(&topo.a.netns, "10.241.1.5"),
        "alias path must fail after remove_nat"
    );
    assert!(
        topo.ping(&topo.a.netns, &topo.b.overlay),
        "overlay must be unaffected by remove_nat"
    );
}
