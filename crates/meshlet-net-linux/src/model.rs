//! Desired state for the Linux hub dataplane.

use std::collections::{BTreeMap, BTreeSet};
use std::net::Ipv4Addr;

use meshlet_domain::Ipv4Cidr;
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// One immutable hub desired-state revision.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HubState {
    pub revision: u64,
    pub networks: Vec<NetworkState>,
}

/// The hub-side dataplane for one isolated Meshlet network.
///
/// Every network owns a distinct WireGuard interface, UDP port and overlay.
/// The firewall compiler turns this isolation into explicit nftables rules.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NetworkState {
    pub network_id: String,
    pub interface: String,
    pub listen_port: u16,
    pub hub_address: Ipv4Addr,
    pub prefix_len: u8,
    pub private_key_file: String,
    #[serde(default)]
    pub mtu: Option<u32>,
    pub peers: Vec<PeerState>,
    #[serde(default)]
    pub routes: Vec<RouteState>,
    #[serde(default)]
    pub revoked_peers: Vec<RevokedPeer>,
}

/// A hub peer. The hub never dials clients, so endpoint state is left to the
/// kernel and is deliberately not part of desired state.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PeerState {
    pub device_id: String,
    pub public_key: String,
    pub overlay_ip: Ipv4Addr,
    #[serde(default)]
    pub allowed_ips: Vec<Ipv4Cidr>,
    #[serde(default)]
    pub persistent_keepalive_secs: Option<u16>,
}

/// An explicitly published route. It must be covered by a peer AllowedIP so
/// the hub never installs a black-hole route.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RouteState {
    pub destination: Ipv4Cidr,
}

/// Revocation is sticky input to the compiler. A revoked peer is never put back
/// into WireGuard, and its overlay address receives an nftables drop rule before
/// peer cleanup happens.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RevokedPeer {
    pub public_key: String,
    pub overlay_ip: Ipv4Addr,
    #[serde(default)]
    pub reason: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum ValidationError {
    #[error("network id must not be empty")]
    EmptyNetworkId,
    #[error("invalid interface name {0:?}")]
    InvalidInterface(String),
    #[error("duplicate network id {0}")]
    DuplicateNetworkId(String),
    #[error("duplicate interface {0}")]
    DuplicateInterface(String),
    #[error("duplicate listen port {0}")]
    DuplicateListenPort(u16),
    #[error("invalid overlay prefix /{0} (expected /1..=/30)")]
    InvalidPrefix(u8),
    #[error("network {0} has an empty private key file")]
    EmptyPrivateKeyFile(String),
    #[error("overlay {0} overlaps another network")]
    OverlayOverlap(String),
    #[error("hub address {0} is outside overlay {1}")]
    HubOutsideOverlay(Ipv4Addr, Ipv4Cidr),
    #[error("network {0}: overlay addresses and listen ports are already used by another network")]
    DuplicateHubIdentity(String),
    #[error("duplicate device id {0} in network {1}")]
    DuplicateDeviceId(String, String),
    #[error("invalid WireGuard public key for device {0}")]
    InvalidPublicKey(String),
    #[error("duplicate peer public key in network {0}")]
    DuplicatePeerKey(String),
    #[error("duplicate peer overlay address {0}")]
    DuplicatePeerAddress(Ipv4Addr),
    #[error("peer {0} overlay address {1} is outside overlay {2}")]
    PeerOutsideOverlay(String, Ipv4Addr, Ipv4Cidr),
    #[error("peer {0} overlay address {1} collides with the hub address")]
    PeerCollidesWithHub(String, Ipv4Addr),
    #[error("peer {0} AllowedIP {1} contains the hub address {2}")]
    PeerAllowedIpContainsHub(String, Ipv4Cidr, Ipv4Addr),
    #[error("peer {0} AllowedIP {1} overlaps peer {2} AllowedIP {3}")]
    PeerAllowedIpOverlap(String, Ipv4Cidr, String, Ipv4Cidr),
    #[error("peer {0} uses 0.0.0.0/0, which would turn the hub into a default gateway")]
    DefaultRouteAllowedIp(String),
    #[error("network {0} publishes route {1} more than once")]
    DuplicateRoute(String, Ipv4Cidr),
    #[error("network {0} route {1} is not covered by any peer AllowedIP")]
    RouteNotCovered(String, Ipv4Cidr),
    #[error("route {0} overlaps route {1} published by network {2}")]
    CrossNetworkRouteOverlap(Ipv4Cidr, Ipv4Cidr, String),
    #[error("revoked peer {0} is still configured as an active peer")]
    RevokedPeerStillActive(String),
    #[error("revoked overlay address {0} is still assigned to an active peer")]
    RevokedAddressStillActive(Ipv4Addr),
    #[error("revoked peer {0} has an invalid public key")]
    InvalidRevokedKey(String),
    #[error("revoked peer {0} address {1} is outside overlay {2}")]
    RevokedOutsideOverlay(String, Ipv4Addr, Ipv4Cidr),
}

impl HubState {
    pub fn network(&self, network_id: &str) -> Option<&NetworkState> {
        self.networks.iter().find(|n| n.network_id == network_id)
    }

    pub fn validate(&self) -> Result<(), ValidationError> {
        if self.networks.is_empty() {
            return Ok(());
        }

        let mut ids = BTreeSet::new();
        let mut interfaces = BTreeSet::new();
        let mut ports = BTreeSet::new();
        let mut overlays: Vec<(String, Ipv4Cidr)> = Vec::new();
        let mut global_routes: Vec<(String, Ipv4Cidr)> = Vec::new();
        let mut global_peer_ips: BTreeSet<Ipv4Addr> = BTreeSet::new();

        for network in &self.networks {
            network.validate()?;
            if network.network_id.trim().is_empty() {
                return Err(ValidationError::EmptyNetworkId);
            }
            if !ids.insert(network.network_id.clone()) {
                return Err(ValidationError::DuplicateNetworkId(
                    network.network_id.clone(),
                ));
            }
            if !interfaces.insert(network.interface.clone()) {
                return Err(ValidationError::DuplicateInterface(
                    network.interface.clone(),
                ));
            }
            if !ports.insert(network.listen_port) {
                return Err(ValidationError::DuplicateListenPort(network.listen_port));
            }

            let overlay = network.overlay_cidr();
            if let Some((other, _)) = overlays.iter().find(|(_, cidr)| cidr.overlaps(&overlay)) {
                return Err(ValidationError::OverlayOverlap(format!(
                    "{} ({}) vs {other} ({overlay})",
                    network.network_id, overlay
                )));
            }
            overlays.push((network.network_id.clone(), overlay));

            for peer in network.effective_peers() {
                if !global_peer_ips.insert(peer.overlay_ip) {
                    return Err(ValidationError::DuplicatePeerAddress(peer.overlay_ip));
                }
            }

            for route in network.effective_routes() {
                if let Some((other_network, other_route)) = global_routes
                    .iter()
                    .find(|(_, existing)| existing.overlaps(&route))
                {
                    return Err(ValidationError::CrossNetworkRouteOverlap(
                        route,
                        *other_route,
                        other_network.clone(),
                    ));
                }
                global_routes.push((network.network_id.clone(), route));
            }
        }
        Ok(())
    }
}

impl NetworkState {
    pub fn overlay_cidr(&self) -> Ipv4Cidr {
        let mask = if self.prefix_len == 0 {
            0
        } else {
            u32::MAX << (32 - self.prefix_len as u32)
        };
        Ipv4Cidr::new(
            Ipv4Addr::from(u32::from(self.hub_address) & mask),
            self.prefix_len,
        )
        .expect("validated prefix length")
    }

    /// Peers that are still allowed by desired state. Revocation wins over a
    /// stale peer entry, so a rollback can never resurrect a revoked key.
    pub fn effective_peers(&self) -> Vec<&PeerState> {
        let revoked_keys: BTreeSet<&str> = self
            .revoked_peers
            .iter()
            .map(|peer| peer.public_key.as_str())
            .collect();
        let revoked_ips: BTreeSet<Ipv4Addr> = self
            .revoked_peers
            .iter()
            .map(|peer| peer.overlay_ip)
            .collect();
        let mut peers: Vec<&PeerState> = self
            .peers
            .iter()
            .filter(|peer| {
                !revoked_keys.contains(peer.public_key.as_str())
                    && !revoked_ips.contains(&peer.overlay_ip)
            })
            .collect();
        peers.sort_by(|a, b| a.public_key.cmp(&b.public_key));
        peers
    }

    /// AllowedIPs for one peer, always including its overlay /32.
    pub fn effective_allowed_ips(peer: &PeerState) -> Vec<Ipv4Cidr> {
        let mut ips = peer.allowed_ips.clone();
        ips.push(Ipv4Cidr::new(peer.overlay_ip, 32).expect("/32 is valid"));
        sort_cidrs(&mut ips);
        ips.dedup();
        ips
    }

    /// The complete route set the hub must own for this network: every
    /// AllowedIP plus explicitly published routes.
    pub fn effective_routes(&self) -> Vec<Ipv4Cidr> {
        let mut routes = Vec::new();
        for peer in self.effective_peers() {
            routes.extend(Self::effective_allowed_ips(peer));
        }
        routes.extend(self.routes.iter().map(|route| route.destination));
        sort_cidrs(&mut routes);
        routes.dedup();
        routes
    }

    fn validate(&self) -> Result<(), ValidationError> {
        if !valid_interface(&self.interface) {
            return Err(ValidationError::InvalidInterface(self.interface.clone()));
        }
        if self.listen_port == 0 {
            return Err(ValidationError::DuplicateListenPort(self.listen_port));
        }
        if !(1..=30).contains(&self.prefix_len) {
            return Err(ValidationError::InvalidPrefix(self.prefix_len));
        }
        if self.private_key_file.trim().is_empty() {
            return Err(ValidationError::EmptyPrivateKeyFile(
                self.network_id.clone(),
            ));
        }
        let overlay = self.overlay_cidr();
        if !overlay.contains(self.hub_address) {
            return Err(ValidationError::HubOutsideOverlay(
                self.hub_address,
                overlay,
            ));
        }

        let mut device_ids = BTreeSet::new();
        let mut public_keys = BTreeSet::new();
        let mut peer_ips = BTreeSet::new();
        for peer in self.effective_peers() {
            if peer.device_id.trim().is_empty() || !device_ids.insert(peer.device_id.clone()) {
                return Err(ValidationError::DuplicateDeviceId(
                    peer.device_id.clone(),
                    self.network_id.clone(),
                ));
            }
            if !is_wireguard_key(&peer.public_key) {
                return Err(ValidationError::InvalidPublicKey(peer.device_id.clone()));
            }
            if !public_keys.insert(peer.public_key.clone()) {
                return Err(ValidationError::DuplicatePeerKey(self.network_id.clone()));
            }
            if !peer_ips.insert(peer.overlay_ip) {
                return Err(ValidationError::DuplicatePeerAddress(peer.overlay_ip));
            }
            if !overlay.contains(peer.overlay_ip)
                || peer.overlay_ip == overlay.network()
                || peer.overlay_ip == overlay.broadcast()
            {
                return Err(ValidationError::PeerOutsideOverlay(
                    peer.device_id.clone(),
                    peer.overlay_ip,
                    overlay,
                ));
            }
            if peer.overlay_ip == self.hub_address {
                return Err(ValidationError::PeerCollidesWithHub(
                    peer.device_id.clone(),
                    peer.overlay_ip,
                ));
            }
            let allowed = Self::effective_allowed_ips(peer);
            for cidr in &allowed {
                if cidr.contains_cidr(&Ipv4Cidr::new(self.hub_address, 32).expect("/32 is valid")) {
                    return Err(ValidationError::PeerAllowedIpContainsHub(
                        peer.device_id.clone(),
                        *cidr,
                        self.hub_address,
                    ));
                }
                if cidr.prefix_len() == 0 {
                    return Err(ValidationError::DefaultRouteAllowedIp(
                        peer.device_id.clone(),
                    ));
                }
            }
        }

        let peers = self.effective_peers();
        for (i, left) in peers.iter().enumerate() {
            let left_ips = Self::effective_allowed_ips(left);
            for right in peers.iter().skip(i + 1) {
                for left_ip in &left_ips {
                    for right_ip in Self::effective_allowed_ips(right) {
                        if left_ip.overlaps(&right_ip) {
                            return Err(ValidationError::PeerAllowedIpOverlap(
                                left.device_id.clone(),
                                *left_ip,
                                right.device_id.clone(),
                                right_ip,
                            ));
                        }
                    }
                }
            }
        }

        let mut seen_routes = BTreeSet::new();
        let effective_ips: Vec<Ipv4Cidr> = peers
            .iter()
            .flat_map(|peer| Self::effective_allowed_ips(peer))
            .collect();
        for route in &self.routes {
            if !seen_routes.insert(route.destination) {
                return Err(ValidationError::DuplicateRoute(
                    self.network_id.clone(),
                    route.destination,
                ));
            }
            if !effective_ips
                .iter()
                .any(|allowed| allowed.contains_cidr(&route.destination))
            {
                return Err(ValidationError::RouteNotCovered(
                    self.network_id.clone(),
                    route.destination,
                ));
            }
        }

        let active_keys: BTreeSet<&str> =
            peers.iter().map(|peer| peer.public_key.as_str()).collect();
        for revoked in &self.revoked_peers {
            if !is_wireguard_key(&revoked.public_key) {
                return Err(ValidationError::InvalidRevokedKey(
                    revoked.public_key.clone(),
                ));
            }
            if active_keys.contains(revoked.public_key.as_str()) {
                return Err(ValidationError::RevokedPeerStillActive(
                    revoked.public_key.clone(),
                ));
            }
            if !overlay.contains(revoked.overlay_ip) {
                return Err(ValidationError::RevokedOutsideOverlay(
                    revoked.public_key.clone(),
                    revoked.overlay_ip,
                    overlay,
                ));
            }
            if peer_ips.contains(&revoked.overlay_ip) {
                return Err(ValidationError::RevokedAddressStillActive(
                    revoked.overlay_ip,
                ));
            }
        }
        Ok(())
    }
}

fn valid_interface(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 15
        && name != "."
        && name != ".."
        && name != "lo"
        && name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.'))
}

fn is_wireguard_key(key: &str) -> bool {
    key.len() == 44
        && key.ends_with('=')
        && key
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'+' | b'/' | b'='))
}

fn sort_cidrs(cidrs: &mut [Ipv4Cidr]) {
    cidrs.sort_by_key(|cidr| (u32::from(cidr.network()), cidr.prefix_len()));
}

pub fn group_by_interface(networks: &[NetworkState]) -> BTreeMap<String, &NetworkState> {
    let mut map = BTreeMap::new();
    for network in networks {
        map.insert(network.interface.clone(), network);
    }
    map
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(seed: char) -> String {
        let mut value: String = std::iter::repeat_n(seed, 43).collect();
        value.push('=');
        value
    }

    fn network(id: &str, interface: &str, port: u16) -> NetworkState {
        NetworkState {
            network_id: id.into(),
            interface: interface.into(),
            listen_port: port,
            hub_address: "10.240.0.1".parse().unwrap(),
            prefix_len: 24,
            private_key_file: "/run/meshlet/hub.key".into(),
            mtu: None,
            peers: vec![],
            routes: vec![],
            revoked_peers: vec![],
        }
    }

    fn peer(device: &str, key_seed: char, ip: &str) -> PeerState {
        PeerState {
            device_id: device.into(),
            public_key: key(key_seed),
            overlay_ip: ip.parse().unwrap(),
            allowed_ips: vec![],
            persistent_keepalive_secs: None,
        }
    }

    #[test]
    fn valid_state_accepts_two_isolated_networks() {
        let mut a = network("net-a", "wg-a", 51820);
        a.peers.push(peer("dev-a", 'A', "10.240.0.2"));
        let mut b = network("net-b", "wg-b", 51821);
        b.hub_address = "10.241.0.1".parse().unwrap();
        b.peers.push(peer("dev-b", 'B', "10.241.0.2"));
        let state = HubState {
            revision: 1,
            networks: vec![a, b],
        };
        state.validate().unwrap();
    }

    #[test]
    fn revocation_filters_peers_before_compilation() {
        let mut a = network("net-a", "wg-a", 51820);
        let mut revoked = peer("dev-a", 'A', "10.240.0.2");
        revoked.allowed_ips.push("192.168.1.0/24".parse().unwrap());
        a.revoked_peers.push(RevokedPeer {
            public_key: revoked.public_key.clone(),
            overlay_ip: revoked.overlay_ip,
            reason: Some("stolen".into()),
        });
        a.peers.push(revoked);
        assert!(a.effective_peers().is_empty());
        assert!(a.effective_routes().is_empty());
    }

    #[test]
    fn overlapping_allowed_ips_are_rejected() {
        let mut a = network("net-a", "wg-a", 51820);
        let mut first = peer("dev-a", 'A', "10.240.0.2");
        first.allowed_ips.push("192.168.1.0/24".parse().unwrap());
        let mut second = peer("dev-b", 'B', "10.240.0.3");
        second.allowed_ips.push("192.168.1.128/25".parse().unwrap());
        a.peers = vec![first, second];
        assert!(matches!(
            HubState {
                revision: 1,
                networks: vec![a]
            }
            .validate(),
            Err(ValidationError::PeerAllowedIpOverlap(_, _, _, _))
        ));
    }

    #[test]
    fn cross_network_route_overlap_is_rejected() {
        let mut a = network("net-a", "wg-a", 51820);
        let mut pa = peer("dev-a", 'A', "10.240.0.2");
        pa.allowed_ips.push("192.168.1.0/24".parse().unwrap());
        a.peers.push(pa);
        let mut b = network("net-b", "wg-b", 51821);
        b.hub_address = "10.241.0.1".parse().unwrap();
        let mut pb = peer("dev-b", 'B', "10.241.0.2");
        pb.allowed_ips.push("192.168.1.0/25".parse().unwrap());
        b.peers.push(pb);
        assert!(matches!(
            HubState {
                revision: 1,
                networks: vec![a, b]
            }
            .validate(),
            Err(ValidationError::CrossNetworkRouteOverlap(_, _, _))
        ));
    }

    #[test]
    fn duplicate_hub_identity_is_rejected() {
        let a = network("net-a", "wg-a", 51820);
        let b = network("net-b", "wg-b", 51820);
        assert!(matches!(
            HubState {
                revision: 1,
                networks: vec![a, b]
            }
            .validate(),
            Err(ValidationError::DuplicateListenPort(51820))
        ));
    }
}
