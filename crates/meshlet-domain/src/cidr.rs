//! IPv4 CIDR type: parsing, validation, containment and overlap checks.
//!
//! Constraints ([ADR-004](../../docs/decisions/adr-004-overlay-ipam.md)):
//! - construction requires zero host bits (canonical form), rejecting non-network addresses such as `10.240.0.1/16`;
//! - prefix length 0..=32;
//! - `/30` and wider: usable hosts exclude the network and broadcast addresses; `/31`, `/32`: all addresses are usable.

use std::fmt;
use std::net::Ipv4Addr;
use std::str::FromStr;

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum CidrError {
    #[error("invalid CIDR notation: {0:?} (expected a.b.c.d/p)")]
    Notation(String),
    #[error("prefix length out of range: {0} (expected 0..=32)")]
    PrefixOutOfRange(u8),
    #[error("host bits set: {addr} is not the network address of /{prefix}")]
    HostBitsSet { addr: Ipv4Addr, prefix: u8 },
}

fn mask_of(prefix: u8) -> u32 {
    debug_assert!(prefix <= 32);
    if prefix == 0 {
        0
    } else {
        u32::MAX << (32 - prefix as u32)
    }
}

/// Normalized IPv4 CIDR (host bits always zero).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Ipv4Cidr {
    network: u32,
    prefix: u8,
}

impl Ipv4Cidr {
    pub fn new(addr: Ipv4Addr, prefix: u8) -> Result<Self, CidrError> {
        if prefix > 32 {
            return Err(CidrError::PrefixOutOfRange(prefix));
        }
        let raw = u32::from(addr);
        let masked = raw & mask_of(prefix);
        if raw != masked {
            return Err(CidrError::HostBitsSet { addr, prefix });
        }
        Ok(Self {
            network: masked,
            prefix,
        })
    }

    /// Build the containing network from an "interface address + prefix": host bits are masked off. An
    /// interface address such as `10.98.0.20/24` is not a network address ([Self::new] rejects it), but the
    /// **LAN** it sits in is `10.98.0.0/24` — `ip -o addr show` reports exactly this kind of address, so LAN
    /// enumeration must use it to build the network.
    pub fn from_host_address(addr: Ipv4Addr, prefix: u8) -> Result<Self, CidrError> {
        if prefix > 32 {
            return Err(CidrError::PrefixOutOfRange(prefix));
        }
        Ok(Self {
            network: u32::from(addr) & mask_of(prefix),
            prefix,
        })
    }

    pub fn network(&self) -> Ipv4Addr {
        Ipv4Addr::from(self.network)
    }

    pub fn broadcast(&self) -> Ipv4Addr {
        Ipv4Addr::from(self.network | !mask_of(self.prefix))
    }

    pub fn prefix_len(&self) -> u8 {
        self.prefix
    }

    pub fn mask(&self) -> Ipv4Addr {
        Ipv4Addr::from(mask_of(self.prefix))
    }

    pub fn contains(&self, ip: Ipv4Addr) -> bool {
        u32::from(ip) & mask_of(self.prefix) == self.network
    }

    /// Whether this CIDR wholly contains `other` (an equal CIDR also contains
    /// itself). This is stricter than overlap, which cannot prove containment.
    pub fn contains_cidr(&self, other: &Self) -> bool {
        self.prefix <= other.prefix
            && self.contains(other.network())
            && self.contains(other.broadcast())
    }

    /// Whether the ranges overlap (one being a subnet of the other also counts as overlap).
    pub fn overlaps(&self, other: &Self) -> bool {
        let min_prefix = self.prefix.min(other.prefix);
        let mask = mask_of(min_prefix);
        self.network & mask == other.network & mask
    }

    /// Total address count in the mathematical sense (including network/broadcast addresses).
    pub fn total_addresses(&self) -> u64 {
        1u64 << (32 - self.prefix as u32)
    }

    /// Number of allocatable addresses.
    pub fn usable_addresses(&self) -> u64 {
        match self.prefix {
            31 | 32 => self.total_addresses(),
            _ => self.total_addresses() - 2,
        }
    }

    /// First usable address (`/30` and wider = network address +1; `/31`, `/32` = the network address itself).
    pub fn first_usable(&self) -> Ipv4Addr {
        match self.prefix {
            31 | 32 => self.network(),
            _ => Ipv4Addr::from(self.network + 1),
        }
    }

    /// Last usable address (`/30` and wider = broadcast address -1; `/31`, `/32` = the broadcast address itself).
    pub fn last_usable(&self) -> Ipv4Addr {
        match self.prefix {
            31 | 32 => self.broadcast(),
            _ => Ipv4Addr::from(u32::from(self.broadcast()) - 1),
        }
    }

    /// Iterate all usable addresses (exclusion rules in the module docs).
    pub fn iter_usable(&self) -> impl Iterator<Item = Ipv4Addr> {
        let start = u32::from(self.first_usable());
        let count = self.usable_addresses();
        (0..count).map(move |i| Ipv4Addr::from(start + i as u32))
    }
}

impl FromStr for Ipv4Cidr {
    type Err = CidrError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let (addr, prefix) = s
            .split_once('/')
            .ok_or_else(|| CidrError::Notation(s.to_string()))?;
        let addr: Ipv4Addr = addr
            .parse()
            .map_err(|_| CidrError::Notation(s.to_string()))?;
        let prefix: u8 = prefix
            .parse()
            .map_err(|_| CidrError::Notation(s.to_string()))?;
        Self::new(addr, prefix)
    }
}

impl fmt::Display for Ipv4Cidr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}", self.network(), self.prefix)
    }
}

/// The serialized form is an `a.b.c.d/p` string (same syntax as [FromStr](std::str::FromStr),
/// which likewise rejects nonzero host bits): the device data-plane plan (§16.4
/// structured configuration object) travels across the server/agent boundary in this form.
impl serde::Serialize for Ipv4Cidr {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.to_string())
    }
}

impl<'de> serde::Deserialize<'de> for Ipv4Cidr {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        String::deserialize(deserializer)?
            .parse()
            .map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cidr(s: &str) -> Ipv4Cidr {
        s.parse().expect("valid cidr")
    }

    #[test]
    fn parse_and_display_roundtrip() {
        for s in ["10.240.0.0/16", "192.168.1.0/24", "0.0.0.0/0", "10.0.0.0/8"] {
            assert_eq!(cidr(s).to_string(), s);
        }
    }

    #[test]
    fn rejects_bad_notation() {
        assert!(matches!(
            "10.240.0.0".parse::<Ipv4Cidr>(),
            Err(CidrError::Notation(_))
        ));
        assert!(matches!(
            "10.240.0/16".parse::<Ipv4Cidr>(),
            Err(CidrError::Notation(_))
        ));
        assert!(matches!(
            "10.240.0.0/x".parse::<Ipv4Cidr>(),
            Err(CidrError::Notation(_))
        ));
    }

    #[test]
    fn rejects_prefix_out_of_range() {
        assert!(matches!(
            "10.0.0.0/33".parse::<Ipv4Cidr>(),
            Err(CidrError::PrefixOutOfRange(33))
        ));
    }

    #[test]
    fn rejects_host_bits_set() {
        let err = "10.240.0.1/16".parse::<Ipv4Cidr>().unwrap_err();
        assert!(matches!(err, CidrError::HostBitsSet { prefix: 16, .. }));
    }

    #[test]
    fn network_broadcast_and_masks() {
        let c = cidr("192.168.1.0/24");
        assert_eq!(c.network(), "192.168.1.0".parse::<Ipv4Addr>().unwrap());
        assert_eq!(c.broadcast(), "192.168.1.255".parse::<Ipv4Addr>().unwrap());
        assert_eq!(c.mask(), "255.255.255.0".parse::<Ipv4Addr>().unwrap());
        let zero = cidr("0.0.0.0/0");
        assert_eq!(zero.mask(), "0.0.0.0".parse::<Ipv4Addr>().unwrap());
        assert_eq!(
            zero.broadcast(),
            "255.255.255.255".parse::<Ipv4Addr>().unwrap()
        );
    }

    #[test]
    fn contains_boundary() {
        let c = cidr("10.240.0.0/16");
        let parse = |s: &str| s.parse::<Ipv4Addr>().unwrap();
        assert!(c.contains(parse("10.240.0.0")));
        assert!(c.contains(parse("10.240.255.255")));
        assert!(c.contains(parse("10.240.12.34")));
        assert!(!c.contains(parse("10.241.0.0")));
        assert!(!c.contains(parse("10.239.255.255")));
    }

    #[test]
    fn overlap_detection() {
        let a = cidr("10.240.0.0/16");
        assert!(a.overlaps(&cidr("10.240.1.0/24"))); // subnet
        assert!(a.overlaps(&cidr("10.0.0.0/8"))); // parent
        assert!(a.overlaps(&cidr("10.240.0.0/16"))); // self
        assert!(!a.overlaps(&cidr("10.241.0.0/16")));
        assert!(!a.overlaps(&cidr("192.168.0.0/16")));
    }

    #[test]
    fn contains_cidr_requires_the_whole_prefix() {
        let overlay = cidr("10.240.0.0/16");
        assert!(overlay.contains_cidr(&cidr("10.240.0.0/16")));
        assert!(overlay.contains_cidr(&cidr("10.240.255.0/24")));
        assert!(!overlay.contains_cidr(&cidr("10.0.0.0/8")));
        assert!(!overlay.contains_cidr(&cidr("10.240.0.0/15")));
        assert!(!overlay.contains_cidr(&cidr("10.241.0.0/24")));
    }

    #[test]
    fn usable_counts() {
        assert_eq!(cidr("10.240.0.0/16").usable_addresses(), 65_534);
        assert_eq!(cidr("192.168.1.0/24").usable_addresses(), 254);
        assert_eq!(cidr("10.0.0.0/30").usable_addresses(), 2);
        assert_eq!(cidr("10.0.0.0/31").usable_addresses(), 2);
        assert_eq!(cidr("10.0.0.0/32").usable_addresses(), 1);
    }

    #[test]
    fn iter_usable_excludes_net_and_broadcast() {
        let hosts: Vec<_> = cidr("10.0.0.0/30").iter_usable().collect();
        let parse = |s: &str| s.parse::<Ipv4Addr>().unwrap();
        assert_eq!(hosts, vec![parse("10.0.0.1"), parse("10.0.0.2")]);

        let p2p: Vec<_> = cidr("10.0.0.0/31").iter_usable().collect();
        assert_eq!(p2p, vec![parse("10.0.0.0"), parse("10.0.0.1")]);
    }

    #[test]
    fn default_overlay_first_usable_is_hub_candidate() {
        // ADR-004: hub takes the first usable address (10.240.0.1), clients start at 10.240.0.2.
        let c = cidr("10.240.0.0/16");
        let parse = |s: &str| s.parse::<Ipv4Addr>().unwrap();
        assert_eq!(c.first_usable(), parse("10.240.0.1"));
    }
}
