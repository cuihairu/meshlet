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
        None => return, // 已打印 SKIP:
    };

    // ---- 全部数据面配置经 LinuxNetworkBackend 下发 ------------------------
    let mut hub_backend = topo.hub.backend();
    let mut a_backend = topo.a.backend();
    let mut b_backend = topo.b.backend();
    let mut gw_backend = topo.gw.backend();

    // hub：tunnel（peer A/B/G）+ Alias 前缀转发路由。
    hub_backend
        .apply_tunnel_sync(
            &hub_tunnel(&topo.hub, &topo.a, &topo.b, &topo.gw, true),
            &BTreeSet::new(),
        )
        .expect("hub apply_tunnel");
    hub_backend
        .apply_routes_sync(&hub_routes())
        .expect("hub apply_routes");

    // 客户端 A/B：tunnel + Alias 段进隧道的路由。
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

    // 网关 G：tunnel + 回程路由 + Alias NAT（计划层渲染执行）。
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

    // ---- 1. 握手完成 + inspect 快照 ---------------------------------------
    for ns in [&topo.a.netns, &topo.b.netns, &topo.gw.netns] {
        assert!(
            topo.wait_handshake(ns),
            "handshake did not complete in {ns}"
        );
    }
    let snap = hub_backend.inspect_sync().expect("hub inspect");
    assert!(snap.tunnel_exists);
    assert_eq!(snap.peers.len(), 3, "hub peers: A + B + G");
    // 身份级（M2）：条数之外的公钥 + allowed-ips 身份必须如实读出。
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

    // 网关 G 的快照：规则在场 + 受控 SNAT 读数在场（dnat_snat 模式，
    // §8.2「内核实测所采用模式」的证据源）。
    let gw_snap = gw_backend.inspect_sync().expect("gw inspect");
    assert!(
        !gw_snap.nat_rules.is_empty(),
        "gw carries meshlet NAT rules: {:?}",
        gw_snap.nat_rules
    );
    // 计划侧与内核侧指纹逐字节一致（M2：同一计划升级前后产出同一指纹，
    // 存量账本不作废）。
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

    // ---- 2. A -> B 经 hub 转发可达（双向） --------------------------------
    assert!(topo.ping(&topo.a.netns, &topo.b.overlay), "A -> B via hub");
    assert!(topo.ping(&topo.b.netns, &topo.a.overlay), "B -> A via hub");

    // ---- 3. Alias 路径：A 经 hub + G + NAT 打到 G 后真实 LAN --------------
    assert!(
        topo.ping(&topo.a.netns, "10.241.1.5"),
        "A -> alias 10.241.1.5 (real LAN 192.168.1.5 behind G)"
    );

    // ---- 4. 幂等：同一配置重复应用结果一致（§10.3） ------------------------
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

    // ---- 5. Overlay 源保留（§7.4）：NAT 在场，A→B 源仍是原始地址 ----------
    // G 的 NAT 规则此刻在场——若存在无差别 SNAT，B 看到的源就会被改写。
    let expected_source = format!("src={}", topo.a.overlay);
    let observed = topo.overlay_source_seen_by_b();
    assert_eq!(
        observed.as_deref(),
        Some(expected_source.as_str()),
        "overlay A->B must keep the original source address (7.4)"
    );

    // ---- 6. remove_nat 只删 Meshlet 规则，不触碰用户规则（§12.6） ----------
    // 预埋一条非 Meshlet 规则（用户视角的外来规则）。
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
