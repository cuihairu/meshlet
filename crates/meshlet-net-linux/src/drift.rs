//! Observed kernel state and drift classification.

use std::collections::{BTreeMap, BTreeSet};

use meshlet_domain::Ipv4Cidr;
use serde::{Deserialize, Serialize};

use crate::compile::{FirewallPlan, HubPlan, NetworkPlan};

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct HubObserved {
    pub links: BTreeMap<String, LinkObserved>,
    pub wireguard: BTreeMap<String, WgDeviceObserved>,
    pub routes: BTreeMap<String, Vec<Ipv4Cidr>>,
    pub firewall: FirewallObserved,
    pub ipv4_forwarding: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LinkObserved {
    pub interface: String,
    pub addresses: Vec<Ipv4Cidr>,
    pub mtu: Option<u32>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WgDeviceObserved {
    pub interface: String,
    pub listen_port: u16,
    pub peers: Vec<WgPeerObserved>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WgPeerObserved {
    pub public_key: String,
    pub allowed_ips: Vec<Ipv4Cidr>,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct FirewallObserved {
    pub table_present: bool,
    pub chain_present: bool,
    pub comments: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum DriftIssue {
    Ipv4ForwardingDisabled,
    MissingLink {
        interface: String,
    },
    LinkAddressMismatch {
        interface: String,
        expected: String,
        actual: Vec<String>,
    },
    LinkMtuMismatch {
        interface: String,
        expected: u32,
        actual: Option<u32>,
    },
    MissingWireGuard {
        interface: String,
    },
    ListenPortMismatch {
        interface: String,
        expected: u16,
        actual: u16,
    },
    MissingPeer {
        interface: String,
        public_key: String,
    },
    UnexpectedPeer {
        interface: String,
        public_key: String,
    },
    PeerAllowedIpsMismatch {
        interface: String,
        public_key: String,
    },
    MissingRoute {
        interface: String,
        destination: String,
    },
    UnexpectedRoute {
        interface: String,
        destination: String,
    },
    MissingFirewallTable,
    MissingFirewallChain,
    MissingFirewallRule {
        comment: String,
    },
    UnexpectedFirewallRule {
        comment: String,
    },
}

impl DriftIssue {
    pub fn code(&self) -> &'static str {
        match self {
            Self::Ipv4ForwardingDisabled => "ipv4_forwarding_disabled",
            Self::MissingLink { .. } => "missing_link",
            Self::LinkAddressMismatch { .. } => "link_address_mismatch",
            Self::LinkMtuMismatch { .. } => "link_mtu_mismatch",
            Self::MissingWireGuard { .. } => "missing_wireguard",
            Self::ListenPortMismatch { .. } => "listen_port_mismatch",
            Self::MissingPeer { .. } => "missing_peer",
            Self::UnexpectedPeer { .. } => "unexpected_peer",
            Self::PeerAllowedIpsMismatch { .. } => "peer_allowed_ips_mismatch",
            Self::MissingRoute { .. } => "missing_route",
            Self::UnexpectedRoute { .. } => "unexpected_route",
            Self::MissingFirewallTable => "missing_firewall_table",
            Self::MissingFirewallChain => "missing_firewall_chain",
            Self::MissingFirewallRule { .. } => "missing_firewall_rule",
            Self::UnexpectedFirewallRule { .. } => "unexpected_firewall_rule",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct DriftReport {
    pub issues: Vec<DriftIssue>,
}

impl DriftReport {
    pub fn in_sync(&self) -> bool {
        self.issues.is_empty()
    }
}

pub fn detect(plan: &HubPlan, observed: &HubObserved) -> DriftReport {
    let mut issues = Vec::new();
    if !observed.ipv4_forwarding {
        issues.push(DriftIssue::Ipv4ForwardingDisabled);
    }
    for network in &plan.networks {
        detect_link(network, observed, &mut issues);
        detect_wireguard(network, observed, &mut issues);
        detect_routes(network, observed, &mut issues);
    }
    detect_firewall(&plan.firewall, &observed.firewall, &mut issues);
    DriftReport { issues }
}

fn detect_link(network: &NetworkPlan, observed: &HubObserved, issues: &mut Vec<DriftIssue>) {
    let interface = &network.link.interface;
    let Some(link) = observed.links.get(interface) else {
        issues.push(DriftIssue::MissingLink {
            interface: interface.clone(),
        });
        return;
    };

    let expected = format!("{}/{}", network.link.address, network.link.prefix_len);
    let actual = link
        .addresses
        .iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>();
    if !link.addresses.iter().any(|address| {
        address.prefix_len() == network.link.prefix_len && address.contains(network.link.address)
    }) {
        issues.push(DriftIssue::LinkAddressMismatch {
            interface: interface.clone(),
            expected,
            actual,
        });
    }
    if let Some(mtu) = network.link.mtu {
        if link.mtu != Some(mtu) {
            issues.push(DriftIssue::LinkMtuMismatch {
                interface: interface.clone(),
                expected: mtu,
                actual: link.mtu,
            });
        }
    }
}

fn detect_wireguard(network: &NetworkPlan, observed: &HubObserved, issues: &mut Vec<DriftIssue>) {
    let interface = &network.wireguard.interface;
    let Some(device) = observed.wireguard.get(interface) else {
        issues.push(DriftIssue::MissingWireGuard {
            interface: interface.clone(),
        });
        return;
    };
    if device.listen_port != network.wireguard.listen_port {
        issues.push(DriftIssue::ListenPortMismatch {
            interface: interface.clone(),
            expected: network.wireguard.listen_port,
            actual: device.listen_port,
        });
    }

    let desired: BTreeMap<&str, Vec<Ipv4Cidr>> = network
        .wireguard
        .peers
        .iter()
        .map(|peer| (peer.public_key.as_str(), sorted(&peer.allowed_ips)))
        .collect();
    let actual: BTreeMap<&str, Vec<Ipv4Cidr>> = device
        .peers
        .iter()
        .map(|peer| (peer.public_key.as_str(), sorted(&peer.allowed_ips)))
        .collect();

    for (public_key, allowed_ips) in &desired {
        match actual.get(public_key) {
            None => issues.push(DriftIssue::MissingPeer {
                interface: interface.clone(),
                public_key: (*public_key).into(),
            }),
            Some(actual_allowed) if actual_allowed != allowed_ips => {
                issues.push(DriftIssue::PeerAllowedIpsMismatch {
                    interface: interface.clone(),
                    public_key: (*public_key).into(),
                });
            }
            Some(_) => {}
        }
    }
    for public_key in actual.keys() {
        if !desired.contains_key(public_key) {
            issues.push(DriftIssue::UnexpectedPeer {
                interface: interface.clone(),
                public_key: (*public_key).into(),
            });
        }
    }
}

fn detect_routes(network: &NetworkPlan, observed: &HubObserved, issues: &mut Vec<DriftIssue>) {
    let interface = &network.link.interface;
    let desired: BTreeSet<Ipv4Cidr> = network.routes.iter().copied().collect();
    let actual: BTreeSet<Ipv4Cidr> = observed
        .routes
        .get(interface)
        .cloned()
        .unwrap_or_default()
        .into_iter()
        .collect();
    for destination in desired.difference(&actual) {
        issues.push(DriftIssue::MissingRoute {
            interface: interface.clone(),
            destination: destination.to_string(),
        });
    }
    for destination in actual.difference(&desired) {
        issues.push(DriftIssue::UnexpectedRoute {
            interface: interface.clone(),
            destination: destination.to_string(),
        });
    }
}

fn detect_firewall(plan: &FirewallPlan, observed: &FirewallObserved, issues: &mut Vec<DriftIssue>) {
    if !observed.table_present {
        issues.push(DriftIssue::MissingFirewallTable);
        return;
    }
    if !observed.chain_present {
        issues.push(DriftIssue::MissingFirewallChain);
        return;
    }
    let desired = plan.comment_set();
    let actual: BTreeSet<String> = observed.comments.iter().cloned().collect();
    for comment in desired.difference(&actual) {
        issues.push(DriftIssue::MissingFirewallRule {
            comment: comment.clone(),
        });
    }
    for comment in actual.difference(&desired) {
        issues.push(DriftIssue::UnexpectedFirewallRule {
            comment: comment.clone(),
        });
    }
}

fn sorted(cidrs: &[Ipv4Cidr]) -> Vec<Ipv4Cidr> {
    let mut values = cidrs.to_vec();
    values.sort_by_key(|cidr| (u32::from(cidr.network()), cidr.prefix_len()));
    values.dedup();
    values
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::compile::HubPlan;
    use crate::model::{HubState, NetworkState, PeerState};
    use std::net::Ipv4Addr;

    fn key(seed: char) -> String {
        let mut value: String = std::iter::repeat_n(seed, 43).collect();
        value.push('=');
        value
    }

    fn plan() -> HubPlan {
        let network = NetworkState {
            network_id: "net-a".into(),
            interface: "wg-a".into(),
            listen_port: 51820,
            hub_address: "10.240.0.1".parse().unwrap(),
            prefix_len: 24,
            private_key_file: "/run/meshlet/hub.key".into(),
            mtu: Some(1420),
            peers: vec![PeerState {
                device_id: "dev-a".into(),
                public_key: key('A'),
                overlay_ip: "10.240.0.2".parse().unwrap(),
                allowed_ips: vec!["192.168.1.0/24".parse().unwrap()],
                persistent_keepalive_secs: None,
            }],
            routes: vec![],
            revoked_peers: vec![],
        };
        HubPlan::compile(&HubState {
            revision: 3,
            networks: vec![network],
        })
        .unwrap()
    }

    fn matching_observed(plan: &HubPlan) -> HubObserved {
        let network = &plan.networks[0];
        let mut observed = HubObserved {
            ipv4_forwarding: true,
            ..HubObserved::default()
        };
        observed.links.insert(
            network.link.interface.clone(),
            LinkObserved {
                interface: network.link.interface.clone(),
                addresses: vec![Ipv4Cidr::new(
                    Ipv4Addr::from(
                        u32::from(network.link.address)
                            & if network.link.prefix_len == 0 {
                                0
                            } else {
                                u32::MAX << (32 - network.link.prefix_len as u32)
                            },
                    ),
                    network.link.prefix_len,
                )
                .unwrap()],
                mtu: network.link.mtu,
            },
        );
        observed.wireguard.insert(
            network.wireguard.interface.clone(),
            WgDeviceObserved {
                interface: network.wireguard.interface.clone(),
                listen_port: network.wireguard.listen_port,
                peers: network
                    .wireguard
                    .peers
                    .iter()
                    .map(|peer| WgPeerObserved {
                        public_key: peer.public_key.clone(),
                        allowed_ips: peer.allowed_ips.clone(),
                    })
                    .collect(),
            },
        );
        observed
            .routes
            .insert(network.link.interface.clone(), network.routes.clone());
        observed.firewall = FirewallObserved {
            table_present: true,
            chain_present: true,
            comments: plan.firewall.comments(),
        };
        observed
    }

    #[test]
    fn matching_observation_is_in_sync() {
        let plan = plan();
        assert!(detect(&plan, &matching_observed(&plan)).in_sync());
    }

    #[test]
    fn peer_route_firewall_and_forwarding_drift_are_reported() {
        let plan = plan();
        let mut observed = matching_observed(&plan);
        observed.ipv4_forwarding = false;
        observed.wireguard.get_mut("wg-a").unwrap().peers.clear();
        observed.routes.get_mut("wg-a").unwrap().clear();
        observed.firewall.comments.clear();

        let report = detect(&plan, &observed);
        assert!(report
            .issues
            .iter()
            .any(|issue| matches!(issue, DriftIssue::Ipv4ForwardingDisabled)));
        assert!(report
            .issues
            .iter()
            .any(|issue| matches!(issue, DriftIssue::MissingPeer { .. })));
        assert!(report
            .issues
            .iter()
            .any(|issue| matches!(issue, DriftIssue::MissingRoute { .. })));
        assert!(!report.in_sync());
    }
}
