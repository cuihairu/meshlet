use std::collections::BTreeSet;

use meshlet_network::RouteConfig;

use crate::common::{
    alias_mapping, hub_routes, hub_tunnel, leaf_tunnel, netns_exec, peer_identities,
    planned_peer_identities, require_ok, sorted_signatures, wg_genkey, wg_pubkey, Topology,
    NETNS_PREFIX_LOCK,
};

#[test]
fn nat_mode_selection_and_identity_isolation() {
    let _guard = NETNS_PREFIX_LOCK.lock().unwrap();
    let topo = match Topology::setup() {
        Some(t) => t,
        None => return, // 已打印 SKIP:
    };
    let mut hub_backend = topo.hub.backend();
    let mut a_backend = topo.a.backend();
    let mut b_backend = topo.b.backend();
    let mut gw_backend = topo.gw.backend();

    hub_backend
        .apply_tunnel_sync(
            &hub_tunnel(&topo.hub, &topo.a, &topo.b, &topo.gw, true),
            &BTreeSet::new(),
        )
        .expect("hub baseline apply_tunnel");
    hub_backend
        .apply_routes_sync(&hub_routes())
        .expect("hub baseline apply_routes");
    for (node, backend) in [(&topo.a, &mut a_backend), (&topo.b, &mut b_backend)] {
        backend
            .apply_tunnel_sync(
                &leaf_tunnel(node, &topo.hub, &["10.240.0.0/16", "10.241.0.0/16"]),
                &BTreeSet::new(),
            )
            .unwrap_or_else(|e| panic!("{} baseline apply_tunnel: {e}", node.netns));
        backend
            .apply_routes_sync(&[RouteConfig {
                destination: "10.241.0.0/16".parse().unwrap(),
                interface: "wg0".into(),
                gateway: None,
            }])
            .unwrap_or_else(|e| panic!("{} baseline apply_routes: {e}", node.netns));
    }
    gw_backend
        .apply_tunnel_sync(
            &leaf_tunnel(&topo.gw, &topo.hub, &["10.240.0.0/16", "10.241.0.0/16"]),
            &BTreeSet::new(),
        )
        .expect("gw baseline apply_tunnel");
    gw_backend
        .apply_routes_sync(&[RouteConfig {
            destination: "10.241.0.0/16".parse().unwrap(),
            interface: "wg0".into(),
            gateway: None,
        }])
        .expect("gw baseline apply_routes");

    // ---- 11. 身份级漂移注入（M2）：观测层如实报出身份，外来资源不入集合
    // 本文件只允许一个 netns 前缀，故并入本测试末尾而非另开 #[test]。
    let alias = alias_mapping();
    let rules = meshlet_network::nat::alias_nat_rules(&alias);
    hub_backend
        .apply_tunnel_sync(
            &hub_tunnel(&topo.hub, &topo.a, &topo.b, &topo.gw, true),
            &BTreeSet::new(),
        )
        .expect("hub re-apply for drift injection");
    gw_backend
        .apply_nat_sync(&rules, "192.168.1.1".parse().unwrap())
        .expect("gw re-apply nat for drift injection");
    assert!(
        topo.wait_handshake(&topo.hub.netns),
        "hub handshake after re-apply"
    );

    // (a) peer 身份：条数相同、身份被换 → 快照必须报出新身份（旧条数检查看不见）。
    let stranger_private = wg_genkey().expect("generate a stranger key");
    let stranger_public = wg_pubkey(&stranger_private).expect("derive the stranger key");
    require_ok(
        &netns_exec(
            &topo.hub.netns,
            &["wg", "set", "wg0", "peer", &topo.b.public_key, "remove"],
        ),
        "drop B's peer from the hub",
    );
    require_ok(
        &netns_exec(
            &topo.hub.netns,
            &[
                "wg",
                "set",
                "wg0",
                "peer",
                &stranger_public,
                "allowed-ips",
                &format!("{}/32", topo.b.overlay),
            ],
        ),
        "plant a stranger peer at B's address",
    );
    let snap = hub_backend
        .inspect_sync()
        .expect("hub inspect after peer substitution");
    assert_eq!(
        snap.peers.len(),
        3,
        "count is still 3 — the blind spot of a count check"
    );
    let ids = peer_identities(&snap);
    assert!(
        !ids.iter().any(|id| id.starts_with(&topo.b.public_key)),
        "B's identity must be gone after substitution: {ids:?}"
    );
    assert!(
        ids.iter()
            .any(|id| id == &format!("{stranger_public}:{}/32", topo.b.overlay)),
        "the stranger's identity and its allowed-ips must be read out: {ids:?}"
    );

    // (b) 身份未变但 allowed-ips 被改宽 → 快照按身份报出改动。
    require_ok(
        &netns_exec(
            &topo.hub.netns,
            &[
                "wg",
                "set",
                "wg0",
                "peer",
                &topo.a.public_key,
                "allowed-ips",
                "0.0.0.0/0",
            ],
        ),
        "widen A's allowed-ips",
    );
    let widened_snap = hub_backend
        .inspect_sync()
        .expect("hub inspect after widening");
    let widened = widened_snap
        .peers
        .iter()
        .find(|p| p.public_key == topo.a.public_key)
        .expect("A's peer is still there");
    assert_eq!(
        widened.allowed_ips,
        vec!["0.0.0.0/0".parse().unwrap()],
        "widened allowed-ips must be read back by identity"
    );

    // (c) 路由所有权：未打 Meshlet 标记的路由不入观测集合；打了标记的残留
    // 会被看到（因此能被 reconcile 按所有权清理）。
    require_ok(
        &netns_exec(
            &topo.hub.netns,
            &["ip", "route", "add", "10.245.0.0/24", "dev", "wg0"],
        ),
        "plant an unmarked route on the managed interface",
    );
    require_ok(
        &netns_exec(
            &topo.hub.netns,
            &[
                "ip",
                "route",
                "add",
                "10.246.0.0/24",
                "dev",
                "wg0",
                "proto",
                "198",
            ],
        ),
        "plant a meshlet-marked stale route",
    );
    let snap = hub_backend
        .inspect_sync()
        .expect("hub inspect after route injection");
    assert!(
        !snap
            .installed_routes
            .contains(&"10.245.0.0/24".parse().unwrap()),
        "an unmarked route is foreign and must stay out of the owned set: {:?}",
        snap.installed_routes
    );
    assert!(
        snap.installed_routes
            .contains(&"10.246.0.0/24".parse().unwrap()),
        "a meshlet-marked stale route must be visible so it can be cleaned: {:?}",
        snap.installed_routes
    );

    // (d) NAT 指纹：非 Meshlet 所有权注释的规则不入集合，自有指纹与计划侧
    // 逐字节一致。
    let planned = sorted_signatures(
        &rules
            .iter()
            .map(|rule| rule.signature())
            .collect::<Vec<_>>(),
    );
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
                "MASQUERADE",
                "-m",
                "comment",
                "--comment",
                "user rule",
            ],
        ),
        "plant a foreign nat rule on the gateway",
    );
    let gw_snap = gw_backend
        .inspect_sync()
        .expect("gw inspect after nat injection");
    assert_eq!(
        gw_snap.nat_rules, planned,
        "a foreign rule must not enter the meshlet-owned signature set"
    );

    // 修复：再 apply 一次清掉 Meshlet 自有的注入，外来路由与外来规则保留。
    hub_backend
        .apply_tunnel_sync(
            &hub_tunnel(&topo.hub, &topo.a, &topo.b, &topo.gw, true),
            &BTreeSet::new(),
        )
        .expect("hub apply clears the meshlet-owned peers");
    hub_backend
        .apply_routes_sync(&hub_routes())
        .expect("hub apply clears the meshlet-owned stale route");
    let snap = hub_backend
        .inspect_sync()
        .expect("hub inspect after repair");
    let ids = peer_identities(&snap);
    assert_eq!(
        ids,
        planned_peer_identities(&topo.a, &topo.b, &topo.gw),
        "re-apply restores the exact planned peer identities"
    );
    assert!(
        !ids.iter().any(|id| id.starts_with(&stranger_public)),
        "the substituted stranger must be gone: {ids:?}"
    );
    assert!(
        !snap
            .installed_routes
            .contains(&"10.246.0.0/24".parse().unwrap()),
        "the meshlet-owned stale route must be removed: {:?}",
        snap.installed_routes
    );
    let shown = String::from_utf8_lossy(
        &netns_exec(
            &topo.hub.netns,
            &["ip", "route", "show", "exact", "10.245.0.0/24"],
        )
        .stdout,
    )
    .to_string();
    assert_eq!(
        shown.trim(),
        "10.245.0.0/24 dev wg0 scope link",
        "the foreign route must survive the repair untouched: {shown:?}"
    );
    let gw_snap = gw_backend.inspect_sync().expect("gw inspect after repair");
    assert_eq!(
        gw_snap.nat_rules, planned,
        "a foreign nat rule must survive the repair"
    );
}
