//! 候选 endpoint 与直连路径决策：公网 / 局域网候选分类，以及
//! 「同 LAN 直连 / 公网打洞 / 保持 hub 中继」的确定性决策。纯逻辑，无 IO。

use std::net::{Ipv4Addr, SocketAddrV4};

use crate::cidr::Ipv4Cidr;

/// 候选 endpoint 分类（任务书：公网 ip:port 与局域网 ip:port 两类）。
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, serde::Serialize, serde::Deserialize,
)]
#[serde(rename_all = "snake_case")]
pub enum EndpointKind {
    /// RFC1918 内网地址（同网段直连用）。
    Lan,
    /// 公网地址（hub 观测到的 agent 源地址 + UDP 端口，打洞用）。
    Public,
}

impl EndpointKind {
    /// API 展示用小写蛇形标识（契约字段 `kind`）。
    pub fn as_str(self) -> &'static str {
        match self {
            EndpointKind::Lan => "lan",
            EndpointKind::Public => "public",
        }
    }
}

/// 一个候选直连 endpoint（ip:port + 分类）。
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

    /// 打洞 / `wg set peer endpoint` 用的 socket 地址。
    pub fn socket(&self) -> SocketAddrV4 {
        SocketAddrV4::new(self.ip, self.port)
    }
}

/// IP 是否为 RFC1918 私网地址（LAN 候选判定基准；链路本地 169.254/16
/// 不算——跨主机不可路由）。
pub fn is_private_ip(ip: Ipv4Addr) -> bool {
    match ip.octets() {
        [10, ..] => true,
        [172, b, ..] => (16..=31).contains(&b),
        [192, 168, ..] => true,
        _ => false,
    }
}

/// 对端候选是否落在本机任一局域网子网内（同网段判定）。
pub fn is_lan_reachable(my_lan_subnets: &[Ipv4Cidr], candidate: &EndpointCandidate) -> bool {
    candidate.kind == EndpointKind::Lan && my_lan_subnets.iter().any(|c| c.contains(candidate.ip))
}

/// 直连路径决策结果。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DirectDecision {
    /// 不可直连——保持 hub 中继（现状行为，不报错）。
    Relay,
    /// 同 LAN：直接用对端内网 endpoint（无 NAT，立即可握手）。
    SameLan(EndpointCandidate),
    /// 公网打洞：用对端公网 endpoint，双方各自发包开启 NAT 映射后握手。
    HolePunch(EndpointCandidate),
}

/// 决策直连路径（无 IO 纯函数）：
/// 1. 对端 LAN 候选落在本机子网内 → [DirectDecision::SameLan]（多个候选取
///    地址最小者，确定性）；
/// 2. 否则对端有公网候选 → [DirectDecision::HolePunch]（同样取最小者）；
/// 3. 都没有 → [DirectDecision::Relay]。
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

    // ------------------------------------------------------- 路径决策 ----

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
            lan("10.0.0.9", 51820), // 对端内网但与我不同段
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

    // ------------------------------------------------------- 私网判定 ----

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
