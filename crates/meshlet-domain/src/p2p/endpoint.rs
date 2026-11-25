//! Candidate endpoints and direct-path decisions: public / LAN candidate
//! classification, plus the deterministic choice between same-LAN direct, public hole-punch, or keeping hub relay.

use std::net::{Ipv4Addr, SocketAddrV4};

use crate::cidr::Ipv4Cidr;

/// Candidate endpoint classification (spec: two kinds, public ip:port and LAN ip:port).
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, serde::Serialize, serde::Deserialize,
)]
#[serde(rename_all = "snake_case")]
pub enum EndpointKind {
    /// RFC1918 private address (used for same-subnet direct connect).
    Lan,
    /// Public address (agent source address + UDP port as observed by the hub; used for hole punching).
    Public,
}

impl EndpointKind {
    /// Lowercase snake_case identifier for API display (contract field `kind`).
    pub fn as_str(self) -> &'static str {
        match self {
            EndpointKind::Lan => "lan",
            EndpointKind::Public => "public",
        }
    }
}

/// One candidate direct-connect endpoint (ip:port + classification).
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, serde::Serialize, serde::Deserialize,
)]
pub struct EndpointCandidate {
    pub ip: Ipv4Addr,
    pub port: u16,
    pub kind: EndpointKind,
}

impl EndpointCandidate {
    pub fn lan(ip: Ipv4Addr, port: u16) -> Self {
        Self {
            ip,
            port,
            kind: EndpointKind::Lan,
        }
    }

    pub fn public(ip: Ipv4Addr, port: u16) -> Self {
        Self {
            ip,
            port,
            kind: EndpointKind::Public,
        }
    }

    /// Socket address used for hole punching / `wg set peer endpoint`.
    pub fn socket(&self) -> SocketAddrV4 {
        SocketAddrV4::new(self.ip, self.port)
    }
}

/// Whether the IP is an RFC1918 private address (the basis for LAN candidate
/// classification; link-local 169.254/16 does not count, as it is not routable across hosts).
pub fn is_private_ip(ip: Ipv4Addr) -> bool {
    match ip.octets() {
        [10, ..] => true,
        [172, b, ..] => (16..=31).contains(&b),
        [192, 168, ..] => true,
        _ => false,
    }
}

/// Whether the peer candidate falls inside any of this host's LAN subnets (same-subnet check).
pub fn is_lan_reachable(my_lan_subnets: &[Ipv4Cidr], candidate: &EndpointCandidate) -> bool {
    candidate.kind == EndpointKind::Lan && my_lan_subnets.iter().any(|c| c.contains(candidate.ip))
}

/// Outcome of the direct-path decision.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DirectDecision {
    /// No direct path - keep hub relay (current behaviour, not an error).
    Relay,
    /// Same LAN: use the peer's private endpoint directly (no NAT, handshake at once).
    SameLan(EndpointCandidate),
    /// Public hole punch: use the peer's public endpoint; both sides send packets to open their NAT mappings, then handshake.
    HolePunch(EndpointCandidate),
}

/// Decide the direct path (pure function, no IO):
/// 1. a peer LAN candidate falls inside my subnets -> [DirectDecision::SameLan]
///    (with several candidates, the smallest address wins, deterministically);
/// 2. otherwise the peer has a public candidate -> [DirectDecision::HolePunch] (smallest again);
/// 3. neither -> [DirectDecision::Relay].
pub fn decide_direct_path(
    my_lan_subnets: &[Ipv4Cidr],
    peer_candidates: &[EndpointCandidate],
) -> DirectDecision {
    let mut lan: Vec<_> = peer_candidates
        .iter()
        .copied()
        .filter(|c| is_lan_reachable(my_lan_subnets, c))
        .collect();
    lan.sort_by_key(|c| (c.ip, c.port));
    if let Some(c) = lan.first() {
        return DirectDecision::SameLan(*c);
    }
    let mut public: Vec<_> = peer_candidates
        .iter()
        .copied()
        .filter(|c| c.kind == EndpointKind::Public)
        .collect();
    public.sort_by_key(|c| (c.ip, c.port));
    if let Some(c) = public.first() {
        return DirectDecision::HolePunch(*c);
    }
    DirectDecision::Relay
}

#[cfg(test)]
mod tests {
    use super::{decide_direct_path, is_private_ip, DirectDecision};
    use crate::p2p::test_support::{cidr, lan, public, HOME};
    use std::net::Ipv4Addr;

    // ------------------------------------------------------- path decision ----

    #[test]
    fn same_lan_wins_over_public() {
        let my = [cidr(HOME)];
        let cands = vec![public("203.0.113.5", 51820), lan("192.168.1.50", 51821)];
        assert_eq!(
            decide_direct_path(&my, &cands),
            DirectDecision::SameLan(lan("192.168.1.50", 51821))
        );
    }

    #[test]
    fn public_candidate_punches_when_lan_is_outside_my_subnets() {
        let my = [cidr(HOME)];
        let cands = vec![
            lan("10.0.0.9", 51820), // peer is private but on a different subnet than me
            public("203.0.113.5", 51820),
        ];
        assert_eq!(
            decide_direct_path(&my, &cands),
            DirectDecision::HolePunch(public("203.0.113.5", 51820))
        );
    }

    #[test]
    fn no_candidates_means_relay() {
        assert_eq!(
            decide_direct_path(&[cidr(HOME)], &[]),
            DirectDecision::Relay
        );
    }

    #[test]
    fn peer_lan_without_reach_and_without_public_stays_relay() {
        let my = [cidr(HOME)];
        let cands = vec![lan("10.0.0.9", 51820)];
        assert_eq!(decide_direct_path(&my, &cands), DirectDecision::Relay);
    }

    #[test]
    fn empty_lan_subnets_never_pick_peer_lan() {
        let cands = vec![lan("192.168.1.50", 51820)];
        assert_eq!(decide_direct_path(&[], &cands), DirectDecision::Relay);
    }

    #[test]
    fn multiple_lan_candidates_pick_lowest_ip_deterministically() {
        let my = [cidr("192.168.0.0/16")];
        let cands = vec![lan("192.168.1.9", 51820), lan("192.168.1.2", 51820)];
        assert_eq!(
            decide_direct_path(&my, &cands),
            DirectDecision::SameLan(lan("192.168.1.2", 51820))
        );
    }

    // ------------------------------------------------------- private check ----

    #[test]
    fn rfc1918_classification() {
        let p = |s: &str| s.parse::<Ipv4Addr>().unwrap();
        assert!(is_private_ip(p("10.0.0.1")));
        assert!(is_private_ip(p("172.16.0.1")));
        assert!(is_private_ip(p("172.31.255.255")));
        assert!(is_private_ip(p("192.168.1.1")));
        assert!(!is_private_ip(p("172.32.0.1")));
        assert!(!is_private_ip(p("8.8.8.8")));
        assert!(!is_private_ip(p("169.254.1.1")));
        assert!(!is_private_ip(p("127.0.0.1")));
    }
}
