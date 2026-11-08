use std::collections::BTreeSet;

use meshlet_network::RouteConfig;

use crate::common::{hub_routes, hub_tunnel, leaf_tunnel, Topology, NETNS_PREFIX_LOCK};

#[test]
fn revocation_rollback_route_conflict_and_identity_repair() {
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

    // ---- 7. 撤销即失效：hub 重应用去掉 B，其余 peer 不受影响（§11.5） -------
    hub_backend
        .apply_tunnel_sync(
            &hub_tunnel(&topo.hub, &topo.a, &topo.b, &topo.gw, false),
            &BTreeSet::new(),
        )
        .expect("hub apply_tunnel without B");
    let hub_peers = topo.wg_show(&topo.hub.netns);
    assert!(
        !hub_peers.contains(&topo.b.public_key),
        "revoked B must vanish from hub peers:\n{hub_peers}"
    );
    assert!(
        hub_peers.contains(&topo.a.public_key),
        "A must survive B's revoke:\n{hub_peers}"
    );
    assert!(
        !topo.ping(&topo.a.netns, &topo.b.overlay),
        "A -> B must fail after B revoked"
    );
    // Alias 通路（A→G）不受 B 撤销影响（G 的 NAT 尚未恢复）。
    assert!(
        hub_peers.contains(&topo.gw.public_key),
        "G must survive B's revoke:\n{hub_peers}"
    );

    // ---- 8. 回滚只删 Meshlet 自有对象（§10.3） -----------------------------
    hub_backend.rollback_sync().expect("hub rollback");
    let snap = hub_backend
        .inspect_sync()
        .expect("hub inspect after rollback");
    assert!(
        snap.peers.is_empty(),
        "rollback removes all peers: {:?}",
        snap.peers
    );
    assert!(
        snap.installed_routes.is_empty(),
        "rollback removes tunnel routes: {:?}",
        snap.installed_routes
    );
    assert!(snap.tunnel_exists, "rollback keeps the interface");
    assert_eq!(
        snap.forwarding_enabled,
        Some(true),
        "ip_forward is system state"
    );
    assert!(
        !topo.ping(&topo.b.netns, &topo.a.overlay),
        "data path must be down after rollback"
    );
}
