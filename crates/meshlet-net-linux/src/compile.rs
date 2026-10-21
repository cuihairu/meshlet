//! Deterministic compiler from desired hub state to typed dataplane plans.

use std::collections::BTreeSet;
use std::net::Ipv4Addr;

use meshlet_domain::Ipv4Cidr;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::model::{HubState, NetworkState, ValidationError};

pub const NFT_TABLE: &str = "meshlet";
pub const NFT_FORWARD_CHAIN: &str = "meshlet-forward";
pub const ROUTE_PROTOCOL: u8 = 198;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HubPlan {
    pub revision: u64,
    pub networks: Vec<NetworkPlan>,
    pub firewall: FirewallPlan,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NetworkPlan {
    pub network_id: String,
    pub link: LinkPlan,
    pub wireguard: WireGuardPlan,
    pub routes: Vec<Ipv4Cidr>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LinkPlan {
    pub interface: String,
    pub address: Ipv4Addr,
    pub prefix_len: u8,
    pub mtu: Option<u32>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WireGuardPlan {
    pub interface: String,
    pub listen_port: u16,
    pub private_key_file: String,
    pub peers: Vec<WgPeerPlan>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WgPeerPlan {
    pub public_key: String,
    pub allowed_ips: Vec<Ipv4Cidr>,
    pub persistent_keepalive_secs: Option<u16>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FirewallPlan {
    pub table: String,
    pub chain: String,
    pub rules: Vec<FirewallRule>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FirewallRule {
    pub comment: String,
    pub matches: Vec<FirewallMatch>,
    pub verdict: FirewallVerdict,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum FirewallMatch {
    InputInterface(String),
    OutputInterface(String),
    SourceIpv4(Ipv4Addr),
    DestinationIpv4(Ipv4Addr),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum FirewallVerdict {
    Accept,
    Drop,
}

impl HubPlan {
    /// Compile and validate in one step. The output order is stable and is the
    /// only input used by the executor, so retries apply the same plan.
    pub fn compile(state: &HubState) -> Result<Self, ValidationError> {
        state.validate()?;

        let mut networks = state.networks.iter().collect::<Vec<_>>();
        networks.sort_by(|a, b| a.network_id.cmp(&b.network_id));

        let mut network_plans = Vec::with_capacity(networks.len());
        for network in networks {
            network_plans.push(compile_network(network));
        }

        Ok(Self {
            revision: state.revision,
            networks: network_plans,
            firewall: compile_firewall(&state.networks),
        })
    }
}

fn compile_network(network: &NetworkState) -> NetworkPlan {
    let mut peers = network
        .effective_peers()
        .into_iter()
        .map(|peer| WgPeerPlan {
            public_key: peer.public_key.clone(),
            allowed_ips: NetworkState::effective_allowed_ips(peer),
            persistent_keepalive_secs: peer.persistent_keepalive_secs,
        })
        .collect::<Vec<_>>();
    peers.sort_by(|a, b| a.public_key.cmp(&b.public_key));

    NetworkPlan {
        network_id: network.network_id.clone(),
        link: LinkPlan {
            interface: network.interface.clone(),
            address: network.hub_address,
            prefix_len: network.prefix_len,
            mtu: network.mtu,
        },
        wireguard: WireGuardPlan {
            interface: network.interface.clone(),
            listen_port: network.listen_port,
            private_key_file: network.private_key_file.clone(),
            peers,
        },
        routes: network.effective_routes(),
    }
}

fn compile_firewall(networks: &[NetworkState]) -> FirewallPlan {
    let mut networks = networks.iter().collect::<Vec<_>>();
    networks.sort_by(|a, b| a.network_id.cmp(&b.network_id));

    let mut rules = Vec::new();
    let mut revocations = networks
        .iter()
        .flat_map(|network| {
            network
                .revoked_peers
                .iter()
                .map(move |revoked| (network, revoked))
        })
        .collect::<Vec<_>>();
    revocations.sort_by_key(|(network, revoked)| (network.network_id.clone(), revoked.overlay_ip));
    for (network, revoked) in revocations {
        let subject = format!("{}:{}", network.network_id, revoked.overlay_ip);
        rules.push(rule(
            "revoked-source",
            &subject,
            vec![FirewallMatch::SourceIpv4(revoked.overlay_ip)],
            FirewallVerdict::Drop,
        ));
        rules.push(rule(
            "revoked-destination",
            &subject,
            vec![FirewallMatch::DestinationIpv4(revoked.overlay_ip)],
            FirewallVerdict::Drop,
        ));
    }

    for network in &networks {
        rules.push(rule(
            "same-network",
            &network.network_id,
            vec![
                FirewallMatch::InputInterface(network.interface.clone()),
                FirewallMatch::OutputInterface(network.interface.clone()),
            ],
            FirewallVerdict::Accept,
        ));
    }

    for left in &networks {
        for right in &networks {
            if left.network_id == right.network_id {
                continue;
            }
            rules.push(rule(
                "isolate",
                &format!("{}->{}", left.network_id, right.network_id),
                vec![
                    FirewallMatch::InputInterface(left.interface.clone()),
                    FirewallMatch::OutputInterface(right.interface.clone()),
                ],
                FirewallVerdict::Drop,
            ));
        }
    }

    FirewallPlan {
        table: NFT_TABLE.into(),
        chain: NFT_FORWARD_CHAIN.into(),
        rules,
    }
}

fn rule(
    kind: &str,
    subject: &str,
    matches: Vec<FirewallMatch>,
    verdict: FirewallVerdict,
) -> FirewallRule {
    let payload = serde_json::to_vec(&(&matches, verdict)).expect("rule spec is serializable");
    let digest = Sha256::digest(payload);
    let hash = digest
        .iter()
        .take(6)
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    let subject = subject.replace(char::is_whitespace, "_");
    FirewallRule {
        comment: format!("meshlet:{kind}:{subject}:{hash}"),
        matches,
        verdict,
    }
}

impl FirewallPlan {
    pub fn comments(&self) -> Vec<String> {
        self.rules.iter().map(|rule| rule.comment.clone()).collect()
    }

    pub fn comment_set(&self) -> BTreeSet<String> {
        self.comments().into_iter().collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{PeerState, RevokedPeer};

    fn key(seed: char) -> String {
        let mut value: String = std::iter::repeat_n(seed, 43).collect();
        value.push('=');
        value
    }

    fn network(id: &str, interface: &str, port: u16, hub: &str) -> NetworkState {
        NetworkState {
            network_id: id.into(),
            interface: interface.into(),
            listen_port: port,
            hub_address: hub.parse().unwrap(),
            prefix_len: 24,
            private_key_file: "/run/meshlet/hub.key".into(),
            mtu: Some(1420),
            peers: vec![],
            routes: vec![],
            revoked_peers: vec![],
        }
    }

    fn peer(device: &str, key_seed: char, ip: &str, allowed: &[&str]) -> PeerState {
        PeerState {
            device_id: device.into(),
            public_key: key(key_seed),
            overlay_ip: ip.parse().unwrap(),
            allowed_ips: allowed.iter().map(|cidr| cidr.parse().unwrap()).collect(),
            persistent_keepalive_secs: Some(25),
        }
    }

    #[test]
    fn plan_is_deterministic_and_sorted() {
        let mut a = network("net-a", "wg-a", 51820, "10.240.0.1");
        a.peers = vec![
            peer("dev-b", 'B', "10.240.0.3", &["192.168.2.0/24"]),
            peer("dev-a", 'A', "10.240.0.2", &["192.168.1.0/24"]),
        ];
        a.routes.push(crate::model::RouteState {
            destination: "192.168.1.0/24".parse().unwrap(),
        });
        let first = HubState {
            revision: 7,
            networks: vec![a.clone()],
        };
        let mut reversed = a;
        reversed.peers.reverse();
        let second = HubState {
            revision: 7,
            networks: vec![reversed],
        };
        assert_eq!(
            HubPlan::compile(&first).unwrap(),
            HubPlan::compile(&second).unwrap()
        );
        let plan = HubPlan::compile(&first).unwrap();
        assert_eq!(plan.networks[0].wireguard.peers[0].public_key, key('A'));
        assert!(plan.networks[0]
            .routes
            .contains(&"10.240.0.2/32".parse().unwrap()));
        assert!(plan.networks[0]
            .routes
            .contains(&"192.168.1.0/24".parse().unwrap()));
    }

    #[test]
    fn two_networks_get_same_network_accept_and_cross_network_drop() {
        let mut a = network("net-a", "wg-a", 51820, "10.240.0.1");
        a.peers.push(peer("dev-a", 'A', "10.240.0.2", &[]));
        let mut b = network("net-b", "wg-b", 51821, "10.241.0.1");
        b.peers.push(peer("dev-b", 'B', "10.241.0.2", &[]));
        let plan = HubPlan::compile(&HubState {
            revision: 1,
            networks: vec![a, b],
        })
        .unwrap();

        let accepts = plan
            .firewall
            .rules
            .iter()
            .filter(|rule| rule.verdict == FirewallVerdict::Accept)
            .count();
        let drops = plan
            .firewall
            .rules
            .iter()
            .filter(|rule| rule.verdict == FirewallVerdict::Drop)
            .count();
        assert_eq!(accepts, 2);
        assert_eq!(drops, 2, "one drop for each ordered cross-network pair");
        assert!(plan.firewall.rules.iter().any(|rule| {
            rule.comment.contains("isolate") && rule.verdict == FirewallVerdict::Drop
        }));
    }

    #[test]
    fn revoked_peer_is_absent_from_wireguard_and_present_in_firewall() {
        let mut a = network("net-a", "wg-a", 51820, "10.240.0.1");
        let revoked = peer("dev-a", 'A', "10.240.0.2", &["192.168.1.0/24"]);
        a.revoked_peers.push(RevokedPeer {
            public_key: revoked.public_key.clone(),
            overlay_ip: revoked.overlay_ip,
            reason: Some("lost device".into()),
        });
        a.peers.push(revoked);
        let plan = HubPlan::compile(&HubState {
            revision: 2,
            networks: vec![a],
        })
        .unwrap();

        assert!(plan.networks[0].wireguard.peers.is_empty());
        assert!(plan.networks[0].routes.is_empty());
        assert_eq!(
            plan.firewall
                .rules
                .iter()
                .filter(|rule| rule.comment.contains("revoked-"))
                .count(),
            2
        );
    }
}
