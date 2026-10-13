//! Overlay IPAM（[ADR-004](../../docs/decisions/adr-004-overlay-ipam.md)）：
//! hub 保留第一个可用地址；客户端顺序分配、全局唯一、耗尽报错不复用。

use crate::cidr::Ipv4Cidr;
use std::collections::HashSet;
use std::net::Ipv4Addr;

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum IpamError {
    #[error("hub address {0} is not a usable address of {1}")]
    HubNotUsable(Ipv4Addr, Ipv4Cidr),
    #[error("address {0} is outside pool {1}")]
    OutsidePool(Ipv4Addr, Ipv4Cidr),
    #[error("address {0} already allocated or reserved")]
    AlreadyTaken(Ipv4Addr),
    #[error("pool {0} exhausted ({1} usable)")]
    Exhausted(Ipv4Cidr, u64),
}

#[derive(Debug, Clone)]
pub struct Ipam {
    pool: Ipv4Cidr,
    used: HashSet<u32>,
    /// 下一个候选地址（含）；顺序前进不复用已释放地址，保证可预测。
    cursor: u32,
    hub: Ipv4Addr,
}

impl Ipam {
    /// 以 `hub` 作为中继地址建立分配器（保留，不分配给客户端）。
    pub fn new(pool: Ipv4Cidr, hub: Ipv4Addr) -> Result<Self, IpamError> {
        if !pool.contains(hub) || !pool.iter_usable().any(|a| a == hub) {
            return Err(IpamError::HubNotUsable(hub, pool));
        }
        Ok(Self {
            used: HashSet::from([u32::from(hub)]),
            cursor: u32::from(pool.first_usable()),
            pool,
            hub,
        })
    }

    pub fn pool(&self) -> Ipv4Cidr {
        self.pool
    }

    pub fn hub_address(&self) -> Ipv4Addr {
        self.hub
    }

    /// 顺序分配下一个可用地址。
    pub fn allocate(&mut self) -> Result<Ipv4Addr, IpamError> {
        let last = u32::from(self.pool.last_usable());
        while self.cursor <= last {
            let candidate = self.cursor;
            self.cursor += 1;
            if self.used.insert(candidate) {
                return Ok(Ipv4Addr::from(candidate));
            }
        }
        Err(IpamError::Exhausted(
            self.pool,
            self.pool.usable_addresses(),
        ))
    }

    /// 分配指定地址（固定 IP 场景）。
    pub fn allocate_specific(&mut self, ip: Ipv4Addr) -> Result<(), IpamError> {
        if !self.pool.contains(ip) || !self.pool.iter_usable().any(|a| a == ip) {
            return Err(IpamError::OutsidePool(ip, self.pool));
        }
        if !self.used.insert(u32::from(ip)) {
            return Err(IpamError::AlreadyTaken(ip));
        }
        Ok(())
    }

    pub fn reserve(&mut self, ip: Ipv4Addr) -> Result<(), IpamError> {
        self.allocate_specific(ip)
    }

    pub fn release(&mut self, ip: Ipv4Addr) {
        self.used.remove(&u32::from(ip));
    }

    pub fn is_taken(&self, ip: Ipv4Addr) -> bool {
        self.used.contains(&u32::from(ip))
    }

    pub fn allocated_count(&self) -> usize {
        self.used.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn first_client_gets_second_usable_address() {
        // ADR-004：hub=10.240.0.1，第一个客户端=10.240.0.2。
        let mut ipam = Ipam::new(
            "10.240.0.0/16".parse().unwrap(),
            "10.240.0.1".parse().unwrap(),
        )
        .unwrap();
        assert_eq!(
            ipam.allocate().unwrap(),
            "10.240.0.2".parse::<Ipv4Addr>().unwrap()
        );
        assert_eq!(
            ipam.allocate().unwrap(),
            "10.240.0.3".parse::<Ipv4Addr>().unwrap()
        );
    }

    #[test]
    fn hub_never_allocated() {
        let hub: Ipv4Addr = "10.240.0.1".parse().unwrap();
        let mut ipam = Ipam::new("10.240.0.0/24".parse().unwrap(), hub).unwrap();
        assert!(ipam.is_taken(hub));
        assert!(matches!(
            ipam.allocate_specific(hub),
            Err(IpamError::AlreadyTaken(_))
        ));
    }

    #[test]
    fn allocation_never_duplicates() {
        let mut ipam = Ipam::new(
            "10.240.0.0/24".parse().unwrap(),
            "10.240.0.1".parse().unwrap(),
        )
        .unwrap();
        let mut seen = HashSet::new();
        for _ in 0..253 {
            let ip = ipam.allocate().unwrap();
            assert!(seen.insert(ip), "duplicate allocation: {ip}");
        }
        assert!(matches!(ipam.allocate(), Err(IpamError::Exhausted(_, 254))));
    }

    #[test]
    fn exhaustion_reports_pool() {
        // /30：2 个可用，hub 占 1，仅剩 1 个可分配。
        let mut ipam =
            Ipam::new("10.0.0.0/30".parse().unwrap(), "10.0.0.1".parse().unwrap()).unwrap();
        assert_eq!(
            ipam.allocate().unwrap(),
            "10.0.0.2".parse::<Ipv4Addr>().unwrap()
        );
        assert!(matches!(ipam.allocate(), Err(IpamError::Exhausted(_, 2))));
    }

    #[test]
    fn hub_must_be_usable_member_of_pool() {
        // 网络地址不可作 hub。
        assert!(matches!(
            Ipam::new("10.0.0.0/24".parse().unwrap(), "10.0.0.0".parse().unwrap()),
            Err(IpamError::HubNotUsable(_, _))
        ));
        // 池外地址不可作 hub。
        assert!(matches!(
            Ipam::new("10.0.0.0/24".parse().unwrap(), "10.1.0.1".parse().unwrap()),
            Err(IpamError::HubNotUsable(_, _))
        ));
    }

    #[test]
    fn specific_allocation_bounds() {
        let mut ipam =
            Ipam::new("10.0.0.0/24".parse().unwrap(), "10.0.0.1".parse().unwrap()).unwrap();
        ipam.allocate_specific("10.0.0.50".parse().unwrap())
            .unwrap();
        assert!(matches!(
            ipam.allocate_specific("10.0.0.50".parse().unwrap()),
            Err(IpamError::AlreadyTaken(_))
        ));
        assert!(matches!(
            ipam.allocate_specific("10.0.1.50".parse().unwrap()),
            Err(IpamError::OutsidePool(_, _))
        ));
        assert!(matches!(
            ipam.allocate_specific("10.0.0.0".parse().unwrap()), // 网络地址
            Err(IpamError::OutsidePool(_, _))
        ));
        assert!(matches!(
            ipam.allocate_specific("10.0.0.255".parse().unwrap()), // 广播地址
            Err(IpamError::OutsidePool(_, _))
        ));
    }

    #[test]
    fn release_allows_specific_reuse() {
        let mut ipam = Ipam::new(
            "10.240.0.0/24".parse().unwrap(),
            "10.240.0.1".parse().unwrap(),
        )
        .unwrap();
        let a = ipam.allocate().unwrap(); // .2
        ipam.release(a);
        assert!(!ipam.is_taken(a));
        ipam.allocate_specific(a).unwrap(); // 显式重用允许
    }
}
