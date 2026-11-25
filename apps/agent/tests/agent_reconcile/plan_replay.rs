use std::collections::BTreeSet;

use meshlet_agent::Reason;
use meshlet_network::linux::LinuxNetworkBackend;
use meshlet_network::nat::alias_nat_rules;

use crate::common::{
    agent_in, alias_mapping, count_prefix_lines, hub_plan, leaf_plan, netns_exec, require_ok, sudo,
    tag, temp_state_dir, wg_genkey, wg_pubkey, Topology, ALIAS_OWNER, HANDSHAKE_TIMEOUT,
};

#[test]
fn agent_applies_the_plan_and_replays_after_a_reboot() {
    let topo = match Topology::setup("r") {
        Some(t) => t,
        None => return, // printed SKIP already:
    };

    // ---- hub side first (server data plane, unrelated to the agent) ----
    let mut hub_backend = LinuxNetworkBackend::new()
        .with_netns(&topo.hub.netns)
        .with_sudo()
        .with_interface("wg0");
    hub_backend
        .apply_device_plan_sync(
            &hub_plan(&topo),
            Some(topo.hub.private_key.clone()),
            None,
            &BTreeSet::new(),
        )
        .expect("hub applies its own plan");
    // Kernel-level MTU assertion (#51(1)): the plan's MTU really landed on the interface.
    assert_eq!(
        hub_backend.inspect_sync().expect("hub snapshot").tunnel_mtu,
        Some(1380),
        "hub tunnel MTU must match the plan in the kernel"
    );

    // ---- 1. the agent applies the device plan (tunnel + other gateways' prefix routes) ----
    // The client plan's routes = the LAN/Alias prefixes published by other gateways, via each gateway's
    // virtual IP; AllowedIPs covers exactly that same set of prefixes + Overlay (isomorphic to the
    // server's `build_device_plan`, §7.2). The two must agree: when a destination prefix is not inside
    // AllowedIPs WireGuard sends nothing (the route alone never carries traffic), so "AllowedIPs matches the destination routes" is a testable constraint.
    let a_dir = temp_state_dir("state-a");
    let mut a_agent = agent_in(&topo.a, &a_dir);
    let a_plan = leaf_plan(
        &topo.a,
        &topo.hub,
        &["10.240.0.0/16", "192.168.1.0/24", "10.241.1.0/24"],
        &[
            ("10.241.1.0/24", &topo.gw.overlay),
            ("192.168.1.0/24", &topo.gw.overlay),
        ],
        Vec::new(),
        "hash-a1",
    );

    // First install: no ledger -> must apply (NoLocalLedger).
    let decision = a_agent.reconcile(&a_plan).expect("agent applies plan");
    assert!(decision.needs_apply);
    assert_eq!(decision.reason, Reason::NoLocalLedger);
    assert!(a_agent.state_path().exists(), "ledger written after apply");

    // The B side applies the same way (another agent instance).
    let b_dir = temp_state_dir("state-b");
    let mut b_agent = agent_in(&topo.b, &b_dir);
    let b_plan = leaf_plan(
        &topo.b,
        &topo.hub,
        &["10.240.0.0/16", "192.168.1.0/24", "10.241.1.0/24"],
        &[
            ("10.241.1.0/24", &topo.gw.overlay),
            ("192.168.1.0/24", &topo.gw.overlay),
        ],
        Vec::new(),
        "hash-b1",
    );
    b_agent.reconcile(&b_plan).expect("agent B applies plan");

    for (label, ns) in [("A", &topo.a.netns), ("B", &topo.b.netns)] {
        assert!(
            topo.wait_handshake(ns),
            "{label} handshake did not complete"
        );
    }
    assert!(
        topo.ping_within(&topo.a.netns, &topo.b.overlay, HANDSHAKE_TIMEOUT),
        "A -> B via hub"
    );
    assert!(
        topo.ping_within(&topo.b.netns, &topo.a.overlay, HANDSHAKE_TIMEOUT),
        "B -> A via hub"
    );

    // No replay when nothing changed (§10.1: replay only on change).
    let decision = a_agent.reconcile(&a_plan).expect("second reconcile");
    assert!(!decision.needs_apply, "unchanged plan must not be replayed");
    assert_eq!(decision.reason, Reason::UpToDate);

    // ---- 2. a new server revision -> replay ----
    let a_plan_v2 = leaf_plan(
        &topo.a,
        &topo.hub,
        &[
            "10.240.0.0/16",
            "192.168.1.0/24",
            "192.168.2.0/24",
            "10.241.1.0/24",
        ],
        &[
            ("10.241.1.0/24", &topo.gw.overlay),
            ("192.168.1.0/24", &topo.gw.overlay),
            ("192.168.2.0/24", &topo.gw.overlay),
        ],
        Vec::new(),
        "hash-a2",
    );
    let decision = a_agent.reconcile(&a_plan_v2).expect("replay new revision");
    assert!(decision.needs_apply);
    assert_eq!(decision.reason, Reason::DesiredConfigChanged);
    assert!(
        topo.ping_within(&topo.a.netns, &topo.b.overlay, HANDSHAKE_TIMEOUT),
        "data path survives replay"
    );

    // ---- 3. host reboot: the ledger says applied but the kernel interface is gone -> drift verdict + replay (#32) ----
    require_ok(
        &netns_exec(&topo.a.netns, &["ip", "link", "del", "wg0"]),
        "simulate host reboot losing the tunnel",
    );
    assert!(
        !topo.ping(&topo.a.netns, &topo.b.overlay),
        "tunnel is gone after the simulated reboot"
    );
    // The ledger still records hash-a2 — exactly the "ledger says applied after reboot" scene.
    let decision = a_agent.reconcile(&a_plan_v2).expect("replay after reboot");
    assert!(decision.needs_apply, "lost tunnel must be replayed");
    assert_eq!(decision.reason, Reason::KernelDrift);
    assert!(
        topo.wait_handshake(&topo.a.netns),
        "A handshake after replay"
    );
    assert!(
        topo.ping_within(&topo.a.netns, &topo.b.overlay, HANDSHAKE_TIMEOUT),
        "A -> B recovered after replay"
    );

    // Reconcile again after the replay: no drift -> no replay.
    assert!(!a_agent.reconcile(&a_plan_v2).unwrap().needs_apply);

    // ---- 3.5 MTU: plan value lands in the kernel; a mismatching kernel reading -> drift verdict + correction (#51) ----
    let a_backend = LinuxNetworkBackend::new()
        .with_netns(&topo.a.netns)
        .with_sudo()
        .with_interface("wg0");
    let mut mtu_plan = a_plan_v2.clone();
    mtu_plan.tunnel.mtu = Some(1380);
    // MTU is part of the plan: the server hash covers the whole plan, so an MTU change is a new revision.
    mtu_plan.desired_config_hash = "hash-a3".into();
    let decision = a_agent.reconcile(&mtu_plan).expect("apply mtu plan");
    assert!(decision.needs_apply);
    assert_eq!(decision.reason, Reason::DesiredConfigChanged);
    assert_eq!(
        a_backend.inspect_sync().expect("A snapshot").tunnel_mtu,
        Some(1380),
        "planned MTU must land in the kernel"
    );

    // The kernel reading gets knocked off (manual change / partial failure) -> reconcile judges drift, replay corrects it.
    require_ok(
        &netns_exec(&topo.a.netns, &["ip", "link", "set", "wg0", "mtu", "1420"]),
        "sabotage tunnel mtu",
    );
    let decision = a_agent
        .reconcile(&mtu_plan)
        .expect("reconcile after mtu sabotage");
    assert!(decision.needs_apply, "mtu mismatch must be replayed");
    assert_eq!(decision.reason, Reason::KernelDrift);
    assert_eq!(
        a_backend.inspect_sync().expect("A snapshot").tunnel_mtu,
        Some(1380),
        "replay restores the planned MTU"
    );

    // Device-side measured evidence (#51(2)): kernel readings plus a big-packet probe (`ping -M do`,
    // payload = plan MTU − 28) ride the heartbeat back — probe target = the hub overlay address, over the real tunnel.
    let evidence = a_agent.collect_evidence(Some(&mtu_plan));
    assert_eq!(evidence.tunnel_mtu, Some(1380), "kernel reading reported");
    assert_eq!(
        evidence.mtu_probe_payload,
        Some(1352),
        "large-packet probe must pass at planned MTU - 28 via the tunnel"
    );

    // ---- 4. gateway side: Alias NAT comes down with the plan; deleting the mapping cleans up the whole unit (§12.6) ----
    let gw_dir = temp_state_dir("state-gw");
    let mut gw_agent = agent_in(&topo.gw, &gw_dir);
    let gw_plan = leaf_plan(
        &topo.gw,
        &topo.hub,
        &["10.240.0.0/16"],
        &[],
        alias_nat_rules(&alias_mapping()),
        "hash-gw1",
    );
    gw_agent
        .reconcile(&gw_plan)
        .expect("gateway applies nat rules");
    assert!(topo.wait_handshake(&topo.gw.netns), "G handshake");
    // Gateway evidence (#57(2)): the NAT reading carried back by the heartbeat reflects kernel reality (rules present -> true).
    let gw_evidence = gw_agent.collect_evidence(Some(&gw_plan));
    assert_eq!(
        gw_evidence.nat_rules_present,
        Some(true),
        "gateway must report its meshlet NAT rules as present"
    );
    // Direct-mode (non-Alias) route: the plan's `192.168.1.0/24 via gateway` makes the remote
    // real LAN directly reachable (§8.1 acceptance: "once the CIDR is published the remote side can reach it").
    assert!(
        topo.ping_within(&topo.a.netns, "192.168.1.5", HANDSHAKE_TIMEOUT),
        "A -> remote LAN via the gateway (direct route from the plan)"
    );
    // Alias path: the plan's Alias prefix plus the gateway-side DNAT/SNAT rules connect the same segment.
    assert!(
        topo.ping_within(&topo.a.netns, "10.241.1.5", HANDSHAKE_TIMEOUT),
        "A -> alias prefix reaches the real LAN behind G"
    );

    // Plant a non-Meshlet rule (a foreign rule from the user's point of view).
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

    // The mapping is deleted (new revision, NAT rules emptied) -> the agent cleans up precisely, keyed by the ownership comment.
    let gw_plan_v2 = leaf_plan(
        &topo.gw,
        &topo.hub,
        &["10.240.0.0/16"],
        &[],
        Vec::new(),
        "hash-gw2",
    );
    let decision = gw_agent.reconcile(&gw_plan_v2).expect("gateway drops nat");
    assert!(decision.needs_apply);
    assert_eq!(decision.reason, Reason::DesiredConfigChanged);
    let prerouting = topo.nat_rules(&topo.gw.netns, "PREROUTING");
    assert!(
        !prerouting.contains(ALIAS_OWNER),
        "meshlet alias rules must be gone:\n{prerouting}"
    );
    assert!(
        prerouting.contains("user rule"),
        "foreign rule must survive:\n{prerouting}"
    );
    assert!(
        !topo.ping(&topo.a.netns, "10.241.1.5"),
        "alias path must fail after the mapping is deleted"
    );
    assert!(
        topo.ping_within(&topo.a.netns, &topo.b.overlay, HANDSHAKE_TIMEOUT),
        "overlay must stay unaffected by the mapping removal"
    );
    // After cleanup the evidence flips honestly (#57(2)): the kernel really has no Meshlet NAT rules -> false.
    let gw_evidence = gw_agent.collect_evidence(Some(&gw_plan_v2));
    assert_eq!(
        gw_evidence.nat_rules_present,
        Some(false),
        "evidence must report the kernel after the ownership cleanup"
    );

    // ---- 4.5 identity-level drift end to end (M2): Reason attribution + non-meshlet resources are never touched ----
    // (a) a foreign peer shows up on the tunnel (identity not in the plan) -> KernelDrift and it gets removed.
    let stranger_private = wg_genkey().expect("generate a stranger key");
    let stranger_public = wg_pubkey(&stranger_private).expect("derive the stranger key");
    require_ok(
        &netns_exec(
            &topo.a.netns,
            &[
                "wg",
                "set",
                "wg0",
                "peer",
                &stranger_public,
                "allowed-ips",
                "10.244.0.0/24",
            ],
        ),
        "plant a foreign peer on A's tunnel",
    );
    let decision = a_agent
        .reconcile(&mtu_plan)
        .expect("reconcile after peer injection");
    assert!(decision.needs_apply, "an extra peer is kernel drift");
    assert_eq!(decision.reason, Reason::KernelDrift);
    let peers = a_backend
        .inspect_sync()
        .expect("A snapshot after repair")
        .peers;
    assert!(
        !peers.iter().any(|p| p.public_key == stranger_public),
        "the foreign peer must be removed: {peers:?}"
    );
    assert_eq!(
        peers
            .iter()
            .map(|p| p.public_key.clone())
            .collect::<Vec<_>>(),
        vec![topo.hub.public_key.clone()],
        "A's planned peer must survive the repair"
    );
    assert!(
        topo.ping_within(&topo.a.netns, &topo.b.overlay, HANDSHAKE_TIMEOUT),
        "data path must survive the peer repair"
    );

    // (b) a route without the Meshlet marker on the tunnel interface -> not drift (UpToDate),
    // and that route is kept untouched: resources outside this meshlet are never touched.
    require_ok(
        &netns_exec(
            &topo.a.netns,
            &["ip", "route", "add", "10.245.0.0/24", "dev", "wg0"],
        ),
        "plant an unmarked route on A's tunnel",
    );
    let decision = a_agent
        .reconcile(&mtu_plan)
        .expect("reconcile with a foreign route");
    assert!(
        !decision.needs_apply,
        "a foreign route is not drift: {:?}",
        decision.reason
    );
    let shown = String::from_utf8_lossy(
        &netns_exec(
            &topo.a.netns,
            &["ip", "route", "show", "exact", "10.245.0.0/24"],
        )
        .stdout,
    )
    .to_string();
    assert!(
        shown.contains("wg0"),
        "the foreign route must survive untouched: {shown}"
    );

    // (c) a NAT rule on the gateway carrying a Meshlet ownership comment but not in the plan (an
    // extra self-owned object) -> KernelDrift, cleaned up by fingerprint; foreign rules are kept.
    gw_agent
        .reconcile(&gw_plan)
        .expect("gateway re-applies nat plan");
    require_ok(
        &netns_exec(
            &topo.gw.netns,
            &[
                "iptables",
                "-t",
                "nat",
                "-A",
                "POSTROUTING",
                "-d",
                "203.0.113.0/24",
                "-j",
                "SNAT",
                "--to-source",
                "192.168.1.1",
                "-m",
                "comment",
                "--comment",
                ALIAS_OWNER,
            ],
        ),
        "plant an extra meshlet-owned nat rule",
    );
    let decision = gw_agent
        .reconcile(&gw_plan)
        .expect("reconcile after nat injection");
    assert!(decision.needs_apply, "an extra meshlet-owned rule is drift");
    assert_eq!(decision.reason, Reason::KernelDrift);
    let postrouting = topo.nat_rules(&topo.gw.netns, "POSTROUTING");
    assert!(
        !postrouting.contains("203.0.113.0/24"),
        "the extra meshlet-owned rule must be removed:\n{postrouting}"
    );
    assert!(
        postrouting.contains(ALIAS_OWNER),
        "the planned snat rule must survive:\n{postrouting}"
    );
    let prerouting = topo.nat_rules(&topo.gw.netns, "PREROUTING");
    assert!(
        prerouting.contains("user rule"),
        "the foreign rule must survive the fingerprint cleanup:\n{prerouting}"
    );
    assert!(
        !a_agent.reconcile(&mtu_plan).unwrap().needs_apply,
        "no drift left on A"
    );

    // Teardown and assert "nothing is left behind after the run" (counted by this process's tag;
    // historical leftovers are `preflight_cleanup`'s job).
    drop(topo);
    let tag = tag("r");
    let netns_text = String::from_utf8_lossy(&sudo(&["ip", "netns", "list"]).stdout).to_string();
    let links_text = String::from_utf8_lossy(&sudo(&["ip", "-br", "link"]).stdout).to_string();
    assert_eq!(
        count_prefix_lines(&netns_text, &tag),
        0,
        "leftover netns after teardown:\n{netns_text}"
    );
    assert_eq!(
        count_prefix_lines(&links_text, &tag),
        0,
        "leftover links after teardown:\n{links_text}"
    );
    for dir in [a_dir, b_dir, gw_dir] {
        std::fs::remove_dir_all(dir).ok();
    }
}
