//! Observe Linux state through WireGuard/netlink and nftables transactions.

use std::{io, net::Ipv4Addr, str::FromStr};

use defguard_wireguard_rs::{
    host::Host, key::Key, net::IpAddrMask, peer::Peer, InterfaceConfiguration, Kernel, WGApi,
    WireguardInterfaceApi,
};
use nftables::{
    batch::Batch,
    expr::{Expression, NamedExpression, Payload, PayloadField},
    helper,
    schema::{Chain, NfListObject, NfObject, Rule, Table},
    stmt::{Match, Operator, Statement},
    types::{NfChainPolicy, NfChainType, NfFamily, NfHook},
};

use crate::{
    compile::{FirewallMatch, FirewallPlan, FirewallRule, FirewallVerdict, HubPlan, NetworkPlan},
    drift::{FirewallObserved, HubObserved, LinkObserved, WgDeviceObserved, WgPeerObserved},
};

use meshlet_domain::Ipv4Cidr;

#[derive(Debug, thiserror::Error)]
pub enum KernelError {
    #[error("WireGuard: {0}")]
    WireGuard(#[from] defguard_wireguard_rs::error::WireguardInterfaceError),
    #[error("nftables: {0}")]
    Nftables(#[from] nftables::helper::NftablesError),
    #[error("invalid key: {0}")]
    InvalidKey(String),
    #[error("io: {0}")]
    Io(#[from] io::Error),
    #[error("invalid state: {0}")]
    InvalidState(String),
}

pub fn nftables_transaction(plan: &FirewallPlan) -> Vec<NfObject<'static>> {
    let mut batch = Batch::new();
    batch.add_cmd(nftables::schema::NfCmd::Delete(NfListObject::Table(
        Table {
            family: NfFamily::INet,
            name: plan.table.clone().into(),
            handle: None,
        },
    )));
    append_owned_table(&mut batch, plan);
    batch.to_nftables().objects.into_owned().to_vec()
}

pub fn nftables_bootstrap_transaction(plan: &FirewallPlan) -> Vec<NfObject<'static>> {
    let mut batch = Batch::new();
    append_owned_table(&mut batch, plan);
    batch.to_nftables().objects.into_owned().to_vec()
}

fn append_owned_table(batch: &mut Batch<'static>, plan: &FirewallPlan) {
    batch.add(NfListObject::Table(Table {
        family: NfFamily::INet,
        name: plan.table.clone().into(),
        ..Default::default()
    }));
    batch.add(NfListObject::Chain(Chain {
        family: NfFamily::INet,
        table: plan.table.clone().into(),
        name: plan.chain.clone().into(),
        _type: Some(NfChainType::Filter),
        hook: Some(NfHook::Forward),
        prio: Some(10),
        policy: Some(NfChainPolicy::Drop),
        ..Default::default()
    }));
    for rule in &plan.rules {
        batch.add(NfListObject::Rule(build_rule(plan, rule)));
    }
}

fn build_rule(plan: &FirewallPlan, plan_rule: &FirewallRule) -> Rule<'static> {
    let mut expressions = Vec::new();
    for matched in &plan_rule.matches {
        let expression = match matched {
            FirewallMatch::InputInterface(interface) => interface_match(interface, true),
            FirewallMatch::OutputInterface(interface) => interface_match(interface, false),
            FirewallMatch::SourceIpv4(address) => address_match(*address, true),
            FirewallMatch::DestinationIpv4(address) => address_match(*address, false),
        };
        expressions.push(expression);
    }
    expressions.push(match plan_rule.verdict {
        FirewallVerdict::Accept => Statement::Accept(None),
        FirewallVerdict::Drop => Statement::Drop(None),
    });

    Rule {
        family: NfFamily::INet,
        table: plan.table.clone().into(),
        chain: plan.chain.clone().into(),
        expr: expressions.into(),
        comment: Some(plan_rule.comment.clone().into()),
        ..Default::default()
    }
}

fn interface_match(interface: &str, input: bool) -> Statement<'static> {
    Statement::Match(Match {
        left: named_payload("meta", if input { "iifname" } else { "oifname" }),
        right: Expression::String(interface.to_string().into()),
        op: Operator::EQ,
    })
}

fn address_match(address: Ipv4Addr, source: bool) -> Statement<'static> {
    Statement::Match(Match {
        left: named_payload("ip", if source { "saddr" } else { "daddr" }),
        right: Expression::String(address.to_string().into()),
        op: Operator::EQ,
    })
}

fn named_payload(protocol: &'static str, field: &'static str) -> Expression<'static> {
    Expression::Named(NamedExpression::Payload(Payload::PayloadField(
        PayloadField {
            protocol: protocol.into(),
            field: field.into(),
        },
    )))
}

pub struct LinuxDataplane {
    wireguard: WGApi<Kernel>,
}

impl LinuxDataplane {
    pub fn new(interface: impl Into<String>) -> Result<Self, KernelError> {
        Ok(Self {
            wireguard: WGApi::<Kernel>::new(interface.into())?,
        })
    }

    pub fn observe(&mut self, interfaces: &[String]) -> Result<HubObserved, KernelError> {
        let mut observed = HubObserved::default();
        for interface in interfaces {
            let Ok(device) = self.wireguard.read_interface_data() else {
                continue;
            };
            let device = observe_wireguard(device, interface)?;
            let mtu = read_mtu(interface)?;
            observed.wireguard.insert(device.interface.clone(), device);
            observed.links.insert(
                interface.clone(),
                LinkObserved {
                    interface: interface.clone(),
                    addresses: read_addresses(interface)?,
                    mtu,
                },
            );
        }
        observed.ipv4_forwarding = read_ipv4_forwarding()?;
        observed.firewall = observe_firewall(&helper::get_current_ruleset()?);
        Ok(observed)
    }

    pub fn prepare(&mut self, plan: &HubPlan) -> Result<(), KernelError> {
        std::fs::write("/proc/sys/net/ipv4/ip_forward", "1\n")
            .map_err(|error| KernelError::InvalidKey(format!("enable forwarding: {error}")))?;
        for network in &plan.networks {
            self.prepare_wireguard(network)?;
        }
        let nftables::schema::Nftables { objects } = helper::get_current_ruleset()?;
        let table_exists = objects.iter().any(|object| {
            matches!(
                object,
                nftables::schema::NfObject::ListObject(NfListObject::Table(table))
                    if table.family == NfFamily::INet && table.name == plan.firewall.table
            )
        });
        let transaction = if table_exists {
            nftables_transaction(&plan.firewall)
        } else {
            nftables_bootstrap_transaction(&plan.firewall)
        };
        helper::apply_ruleset(&nftables::schema::Nftables {
            objects: transaction.into(),
        })?;
        Ok(())
    }

    fn prepare_wireguard(&mut self, network: &NetworkPlan) -> Result<(), KernelError> {
        let interface = network.wireguard.interface.clone();
        let private_key = read_private_key(&network.wireguard.private_key_file)?;
        let mut wireguard = WGApi::<Kernel>::new(interface.clone())?;
        if wireguard.read_interface_data().is_err() {
            wireguard.create_interface()?;
        }
        let peers = network
            .wireguard
            .peers
            .iter()
            .map(|peer| {
                let mut kernel_peer = Peer::new(
                    Key::from_str(&peer.public_key)
                        .map_err(|error| KernelError::InvalidKey(error.to_string()))?,
                );
                kernel_peer.allowed_ips = peer
                    .allowed_ips
                    .iter()
                    .map(|cidr| {
                        IpAddrMask::new(std::net::IpAddr::V4(cidr.network()), cidr.prefix_len())
                    })
                    .collect();
                kernel_peer.persistent_keepalive_interval = peer.persistent_keepalive_secs;
                Ok(kernel_peer)
            })
            .collect::<Result<Vec<_>, KernelError>>()?;
        wireguard.configure_interface(&InterfaceConfiguration {
            name: interface,
            prvkey: private_key.to_string(),
            addresses: vec![IpAddrMask::new(
                std::net::IpAddr::V4(network.link.address),
                network.link.prefix_len,
            )],
            port: network.wireguard.listen_port,
            peers,
            mtu: network.link.mtu,
            fwmark: None,
        })?;
        Ok(())
    }
}

fn observe_wireguard(host: Host, interface: &str) -> Result<WgDeviceObserved, KernelError> {
    Ok(WgDeviceObserved {
        interface: interface.to_string(),
        listen_port: host.listen_port,
        peers: host
            .peers
            .values()
            .map(|peer| {
                Ok(WgPeerObserved {
                    public_key: peer.public_key.to_string(),
                    allowed_ips: peer
                        .allowed_ips
                        .iter()
                        .filter_map(|cidr| match cidr.address {
                            std::net::IpAddr::V4(address) => Ipv4Cidr::new(address, cidr.cidr).ok(),
                            std::net::IpAddr::V6(_) => None,
                        })
                        .collect(),
                })
            })
            .collect::<Result<Vec<_>, KernelError>>()?,
    })
}

fn read_addresses(interface: &str) -> Result<Vec<Ipv4Cidr>, KernelError> {
    let output = std::process::Command::new("ip")
        .args(["-4", "-j", "addr", "show", "dev", interface])
        .output()
        .map_err(|error| KernelError::InvalidKey(format!("run ip: {error}")))?;
    if !output.status.success() {
        return Ok(Vec::new());
    }
    let addresses = serde_json::from_slice::<Vec<IpAddress>>(&output.stdout)
        .map_err(|error| KernelError::InvalidKey(format!("parse ip output: {error}")))?;
    Ok(addresses
        .into_iter()
        .flat_map(|address| address.addr_info)
        .filter_map(|info| {
            let address = info.local?.parse().ok()?;
            Ipv4Cidr::new(address, info.prefixlen?.parse().ok()?).ok()
        })
        .collect())
}

fn read_mtu(interface: &str) -> Result<Option<u32>, KernelError> {
    let output = std::process::Command::new("ip")
        .args(["-j", "link", "show", "dev", interface])
        .output()
        .map_err(|error| KernelError::InvalidKey(format!("run ip: {error}")))?;
    if !output.status.success() {
        return Ok(None);
    }
    let links = serde_json::from_slice::<Vec<serde_json::Value>>(&output.stdout)
        .map_err(|error| KernelError::InvalidKey(format!("parse ip output: {error}")))?;
    Ok(links
        .first()
        .and_then(|link| link.get("mtu"))
        .and_then(|mtu| mtu.as_u64())
        .and_then(|mtu| u32::try_from(mtu).ok()))
}

#[derive(serde::Deserialize)]
struct IpAddress {
    addr_info: Vec<IpAddressInfo>,
}

#[derive(serde::Deserialize)]
struct IpAddressInfo {
    local: Option<String>,
    prefixlen: Option<String>,
}

fn read_ipv4_forwarding() -> Result<bool, KernelError> {
    let raw = std::fs::read_to_string("/proc/sys/net/ipv4/ip_forward")?;
    raw.trim()
        .parse()
        .map_err(|error: std::str::ParseBoolError| KernelError::InvalidState(error.to_string()))
}

fn read_private_key(path: &str) -> Result<Key, KernelError> {
    Key::from_str(std::fs::read_to_string(path)?.trim())
        .map_err(|error| KernelError::InvalidKey(error.to_string()))
}

fn observe_firewall(ruleset: &nftables::schema::Nftables<'_>) -> FirewallObserved {
    let mut observed = FirewallObserved::default();
    for object in ruleset.objects.iter() {
        let nftables::schema::NfObject::ListObject(object) = object else {
            continue;
        };
        match object {
            NfListObject::Table(table) if table.name == crate::compile::NFT_TABLE => {
                observed.table_present = true;
            }
            NfListObject::Chain(chain)
                if chain.table == crate::compile::NFT_TABLE
                    && chain.name == crate::compile::NFT_FORWARD_CHAIN =>
            {
                observed.chain_present = true;
            }
            NfListObject::Rule(rule) if rule.table == crate::compile::NFT_TABLE => {
                if let Some(comment) = &rule.comment {
                    observed.comments.push(comment.to_string());
                }
            }
            _ => {}
        }
    }
    observed
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn firewall_transactions_recreate_owned_table() {
        let plan = compile();
        let transaction = nftables_transaction(&plan.firewall);

        assert!(matches!(
            &transaction[0],
            NfObject::CmdObject(nftables::schema::NfCmd::Delete(_))
        ));
        assert_eq!(transaction.len(), plan.firewall.rules.len() + 3);

        let bootstrap = nftables_bootstrap_transaction(&plan.firewall);
        assert!(matches!(
            &bootstrap[0],
            NfObject::CmdObject(nftables::schema::NfCmd::Add(NfListObject::Table(_)))
        ));
        assert_eq!(bootstrap.len(), transaction.len() - 1);
    }

    #[test]
    fn firewall_transaction_puts_revocations_before_accepts() {
        let plan = compile_with_revocation();
        let revoked_index = plan
            .firewall
            .rules
            .iter()
            .position(|rule| rule.comment.contains("revoked-source"))
            .unwrap();
        let accept_index = plan
            .firewall
            .rules
            .iter()
            .position(|rule| rule.comment.contains("same-network"))
            .unwrap();
        assert!(revoked_index < accept_index);
    }

    fn compile() -> crate::HubPlan {
        crate::HubPlan::compile(&crate::model::HubState {
            revision: 1,
            networks: vec![crate::last_good::tests::network("net-a")],
        })
        .unwrap()
    }

    fn compile_with_revocation() -> crate::HubPlan {
        let mut network = crate::last_good::tests::network("net-a");
        network.revoked_peers.push(crate::model::RevokedPeer {
            public_key: "A".repeat(43) + "=",
            overlay_ip: Ipv4Addr::new(10, 240, 0, 2),
            reason: Some("test".into()),
        });
        crate::HubPlan::compile(&crate::model::HubState {
            revision: 1,
            networks: vec![network],
        })
        .unwrap()
    }
}
