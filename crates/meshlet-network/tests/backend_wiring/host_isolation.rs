use std::collections::BTreeSet;

use meshlet_network::linux::LinuxNetworkBackend;
use meshlet_network::{PeerConfig, RouteConfig, TunnelConfig};

use crate::common::{
    alias_mapping, count_prefix_lines, host_rule_line, hub_routes, hub_tunnel, leaf_tunnel,
    require_ok, root_route_exact, sudo, sudo_ok, wg_genkey, wg_pubkey, RootGuard, Topology,
    ALIAS_OWNER, NETNS_PREFIX_LOCK,
};

#[test]
fn host_namespace_foreign_objects_survive_managed_lifecycle() {
    let _guard = NETNS_PREFIX_LOCK.lock().unwrap();
    let topo = match Topology::setup() {
        Some(t) => t,
        None => return, // Already printed SKIP:
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

    // ---- 12. Host rules are not deleted by mistake (M3 scenario 6): the managed apply runs straight in the **root namespace**
    // (the production shape: the agent runs on the host, alongside somebody else's routes/NAT/FORWARD rules).
    // Plant three foreign objects first, then run the full apply (tunnel + routes + NAT) and the reclamation
    // (remove_nat + rollback), requiring the foreign objects on the host side to survive verbatim and the
    // ip_forward baseline to be untouched. RootGuard is the safety net for cleanup -- no failed assertion leaves test objects on the host.
    if !sudo_ok(&["ip", "link", "show", "wg0"]) && !root_route_exact("198.51.101.0/24").is_some() {
        let _guard = RootGuard;
        let forward_before = sudo(&["sysctl", "-n", "net.ipv4.ip_forward"])
            .stdout
            .to_vec();
        require_ok(
            &sudo(&["ip", "route", "add", "198.51.101.0/24", "dev", "lo"]),
            "seed host route",
        );
        require_ok(
            &sudo(&[
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
                "host rule",
            ]),
            "seed host nat rule",
        );
        require_ok(
            &sudo(&[
                "iptables",
                "-t",
                "filter",
                "-A",
                "FORWARD",
                "-i",
                "lo",
                "-j",
                "ACCEPT",
                "-m",
                "comment",
                "--comment",
                "host rule",
            ]),
            "seed host forward rule",
        );

        // Root-namespace backend: no with_netns.
        let mut host = LinuxNetworkBackend::new().with_sudo().with_interface("wg0");
        let own_key = wg_genkey().expect("host private key");
        let peer_key = wg_genkey().expect("host peer key");
        let peer_pub = wg_pubkey(&peer_key).expect("host peer public key");
        let host_tunnel = TunnelConfig {
            name: "wg0".into(),
            address: "10.249.0.1".parse().unwrap(),
            address_prefix: 24,
            listen_port: None,
            peers: vec![PeerConfig {
                public_key: peer_pub,
                allowed_ips: vec!["10.249.0.2/32".parse().unwrap()],
                endpoint: None,
                persistent_keepalive_secs: None,
            }],
            mtu: None,
            private_key: Some(own_key),
        };
        host.apply_tunnel_sync(&host_tunnel, &BTreeSet::new())
            .expect("root apply_tunnel");
        host.apply_routes_sync(&[RouteConfig {
            destination: "10.249.1.0/24".parse().unwrap(),
            interface: "wg0".into(),
            gateway: None,
        }])
        .expect("root apply_routes");
        let rules = meshlet_network::nat::alias_nat_rules(&alias_mapping());
        host.apply_nat_sync(&rules, "192.168.1.1".parse().unwrap())
            .expect("root apply_nat");

        // The apply really landed on the host: the objects are present.
        let snap = host.inspect_sync().expect("root inspect");
        assert!(
            snap.tunnel_exists,
            "managed tunnel must exist in the host namespace"
        );
        assert_eq!(
            snap.peers.len(),
            1,
            "managed peer must exist in the host namespace"
        );
        assert!(
            snap.installed_routes
                .contains(&"10.249.1.0/24".parse().unwrap()),
            "managed route must exist in the host namespace: {:?}",
            snap.installed_routes
        );
        assert!(
            !snap.nat_rules.is_empty(),
            "managed NAT rules must exist in the host namespace: {:?}",
            snap.nat_rules
        );

        // The host's foreign objects survive verbatim.
        assert_eq!(
            root_route_exact("198.51.101.0/24").as_deref(),
            Some("198.51.101.0/24 dev lo scope link"),
            "the host route must survive a managed apply"
        );
        let nat_after_apply = sudo(&["iptables", "-t", "nat", "-S", "PREROUTING"]);
        let filter_after_apply = sudo(&["iptables", "-t", "filter", "-S", "FORWARD"]);
        assert!(
            host_rule_line(&nat_after_apply.stdout, "-d 203.0.113.0/24").is_some(),
            "the host NAT rule must survive a managed apply:\n{}",
            String::from_utf8_lossy(&nat_after_apply.stdout)
        );
        assert!(
            host_rule_line(&filter_after_apply.stdout, "-i lo").is_some(),
            "the host FORWARD rule must survive a managed apply:\n{}",
            String::from_utf8_lossy(&filter_after_apply.stdout)
        );
        let forward_after_apply = sudo(&["sysctl", "-n", "net.ipv4.ip_forward"]).stdout;
        assert_eq!(
            forward_before, forward_after_apply,
            "the host ip_forward must not be changed by a host apply"
        );

        // Reclamation: only Meshlet-owned objects are taken away.
        host.remove_nat_sync(ALIAS_OWNER).expect("root remove_nat");
        host.rollback_sync().expect("root rollback");
        let snap = host.inspect_sync().expect("root inspect after rollback");
        assert!(
            snap.peers.is_empty(),
            "managed peers must be gone after rollback: {:?}",
            snap.peers
        );
        assert!(
            snap.installed_routes.is_empty(),
            "managed routes must be gone after rollback: {:?}",
            snap.installed_routes
        );
        assert!(
            snap.nat_rules.is_empty(),
            "managed NAT must be gone after rollback: {:?}",
            snap.nat_rules
        );
        assert!(
            snap.tunnel_exists,
            "the managed interface is system state and must remain"
        );
        // The foreign objects are still present after the reclamation.
        assert_eq!(
            root_route_exact("198.51.101.0/24").as_deref(),
            Some("198.51.101.0/24 dev lo scope link"),
            "the host route must survive the managed rollback"
        );
        let nat_after_rollback = sudo(&["iptables", "-t", "nat", "-S", "PREROUTING"]);
        let filter_after_rollback = sudo(&["iptables", "-t", "filter", "-S", "FORWARD"]);
        assert!(
            host_rule_line(&nat_after_rollback.stdout, "-d 203.0.113.0/24").is_some(),
            "the host NAT rule must survive the managed rollback:\n{}",
            String::from_utf8_lossy(&nat_after_rollback.stdout)
        );
        assert!(
            host_rule_line(&filter_after_rollback.stdout, "-i lo").is_some(),
            "the host FORWARD rule must survive the managed rollback:\n{}",
            String::from_utf8_lossy(&filter_after_rollback.stdout)
        );
        let nat_text = String::from_utf8_lossy(&nat_after_rollback.stdout);
        assert!(
            !nat_text.contains(ALIAS_OWNER),
            "managed alias rules must be gone from the host namespace:\n{nat_text}"
        );
        assert_eq!(
            forward_before,
            sudo(&["sysctl", "-n", "net.ipv4.ip_forward"]).stdout,
            "the host ip_forward must not be changed by the managed rollback"
        );
    } else {
        eprintln!("SKIP: the host namespace already holds wg0 or 198.51.101.0/24");
    }

    // Teardown and assert that "nothing is left behind after the run".
    drop(topo);
    let netns_left = sudo(&["ip", "netns", "list"]);
    let links_left = sudo(&["ip", "-br", "link"]);
    let netns_text = String::from_utf8_lossy(&netns_left.stdout).to_string();
    let links_text = String::from_utf8_lossy(&links_left.stdout).to_string();
    assert_eq!(
        count_prefix_lines(&netns_text),
        0,
        "leftover netns after teardown:\n{netns_text}"
    );
    assert_eq!(
        count_prefix_lines(&links_text),
        0,
        "leftover links after teardown:\n{links_text}"
    );
}
