use std::net::Ipv4Addr;

use meshlet_domain::Ipv4Cidr;
use meshlet_net_linux::{
    compile::HubPlan,
    drift::{HubObserved, LinkObserved},
    model::{HubState, NetworkState},
    reconciler::{decide, RecoveryAction},
};

fn network(id: &str) -> NetworkState {
    NetworkState {
        network_id: id.into(),
        interface: format!("wg-{id}"),
        listen_port: 51820,
        hub_address: Ipv4Addr::new(10, 240, 0, 0),
        prefix_len: 24,
        private_key_file: "/run/meshlet/hub.key".into(),
        mtu: None,
        peers: vec![],
        routes: vec![],
        revoked_peers: vec![],
    }
}

#[test]
fn in_sync_observation_requires_no_action() {
    let state = HubState {
        revision: 1,
        networks: vec![network("net-a")],
    };
    let plan = HubPlan::compile(&state).unwrap();
    let observed = HubObserved {
        ipv4_forwarding: true,
        links: [(
            "wg-net-a".to_string(),
            LinkObserved {
                interface: "wg-net-a".to_string(),
                addresses: vec![Ipv4Cidr::new(Ipv4Addr::new(10, 240, 0, 0), 24).unwrap()],
                mtu: None,
            },
        )]
        .into(),
        wireguard: [(
            "wg-net-a".to_string(),
            meshlet_net_linux::drift::WgDeviceObserved {
                interface: "wg-net-a".to_string(),
                listen_port: 51820,
                peers: vec![],
            },
        )]
        .into(),
        routes: [("wg-net-a".to_string(), vec![])].into(),
        firewall: meshlet_net_linux::drift::FirewallObserved {
            table_present: true,
            chain_present: true,
            comments: plan
                .firewall
                .rules
                .iter()
                .map(|rule| rule.comment.clone())
                .collect(),
        },
    };

    assert_eq!(
        decide(&state, None, &plan, &observed).unwrap().action,
        RecoveryAction::AlreadyGood
    );
}
