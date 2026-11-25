//! Trusted reverse-proxy sources (TODO-116): `X-Forwarded-For`/`X-Real-IP` are honored only when the request comes **directly from**
//! a trusted proxy; untrusted sources ignore the headers entirely (forgery resistance).
//!
//! Loopback only by default (`127.0.0.1` and `::1`) — the typical shape of a same-host nginx/Caddy reverse proxy;
//! CIDRs or single addresses (IPv4/IPv6) are configurable, e.g. `10.0.0.0/8`, `192.168.1.0/24`,
//! `203.0.113.10`. Notation with host bits is accepted (e.g. `192.168.1.5/24`) and folded to its enclosing network.

use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::str::FromStr;

use meshlet_domain::Ipv4Cidr;

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum TrustedProxyParseError {
    #[error("invalid trusted proxy entry {0:?} (expected an IP address or a CIDR)")]
    Invalid(String),
}

/// A single trusted proxy source: an address or a network.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrustedProxySource {
    Addr(IpAddr),
    V4(Ipv4Cidr),
    V6(Ipv6Cidr),
}

impl TrustedProxySource {
    pub fn contains(&self, ip: IpAddr) -> bool {
        match (self, ip) {
            (Self::Addr(a), ip) => *a == ip,
            (Self::V4(c), IpAddr::V4(ip)) => c.contains(ip),
            (Self::V6(c), IpAddr::V6(ip)) => c.contains(ip),
            _ => false,
        }
    }
}

impl FromStr for TrustedProxySource {
    type Err = TrustedProxyParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let s = s.trim();
        if let Ok(ip) = s.parse::<IpAddr>() {
            return Ok(Self::Addr(ip));
        }
        if let Some((addr, prefix)) = s.split_once('/') {
            if let (Ok(addr), Ok(prefix)) = (addr.parse::<Ipv4Addr>(), prefix.parse::<u8>()) {
                if let Ok(c) = Ipv4Cidr::from_host_address(addr, prefix) {
                    return Ok(Self::V4(c));
                }
            }
        }
        if let Ok(c) = s.parse::<Ipv6Cidr>() {
            return Ok(Self::V6(c));
        }
        Err(TrustedProxyParseError::Invalid(s.to_string()))
    }
}

impl fmt::Display for TrustedProxySource {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Addr(ip) => write!(f, "{ip}"),
            Self::V4(c) => write!(f, "{c}"),
            Self::V6(c) => write!(f, "{c}"),
        }
    }
}

/// IPv6 CIDR (`meshlet-domain` only has IPv4 CIDRs; proxy sources need v6 shapes such as `::1`,
/// so this is a minimal implementation — host bits are folded to the enclosing network, same
/// convention as [Ipv4Cidr::from_host_address]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Ipv6Cidr {
    network: u128,
    prefix: u8,
}

impl Ipv6Cidr {
    /// Builds the enclosing network from "address + prefix" (host bits are masked off).
    pub fn from_host_address(addr: Ipv6Addr, prefix: u8) -> Result<Self, TrustedProxyParseError> {
        if prefix > 128 {
            return Err(TrustedProxyParseError::Invalid(format!("{addr}/{prefix}")));
        }
        let raw = u128::from(addr);
        Ok(Self {
            network: raw & mask_of_v6(prefix),
            prefix,
        })
    }

    pub fn contains(&self, ip: Ipv6Addr) -> bool {
        u128::from(ip) & mask_of_v6(self.prefix) == self.network
    }
}

fn mask_of_v6(prefix: u8) -> u128 {
    if prefix == 0 {
        0
    } else {
        u128::MAX << (128 - prefix as u32)
    }
}

impl FromStr for Ipv6Cidr {
    type Err = TrustedProxyParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let (addr, prefix) = s
            .split_once('/')
            .ok_or_else(|| TrustedProxyParseError::Invalid(s.to_string()))?;
        let addr: Ipv6Addr = addr
            .parse()
            .map_err(|_| TrustedProxyParseError::Invalid(s.to_string()))?;
        let prefix: u8 = prefix
            .parse()
            .map_err(|_| TrustedProxyParseError::Invalid(s.to_string()))?;
        Self::from_host_address(addr, prefix)
    }
}

impl fmt::Display for Ipv6Cidr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}", Ipv6Addr::from(self.network), self.prefix)
    }
}

/// Set of trusted reverse-proxy sources (server config key `trusted_proxies`). Defaults to loopback only,
/// `127.0.0.1` and `::1` (the nginx same-host proxy shape).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrustedProxyConfig {
    pub sources: Vec<TrustedProxySource>,
}

impl Default for TrustedProxyConfig {
    fn default() -> Self {
        Self {
            sources: vec![
                TrustedProxySource::Addr(IpAddr::V4(Ipv4Addr::LOCALHOST)),
                TrustedProxySource::Addr(IpAddr::V6(Ipv6Addr::LOCALHOST)),
            ],
        }
    }
}

impl TrustedProxyConfig {
    pub fn is_trusted(&self, ip: IpAddr) -> bool {
        self.sources.iter().any(|s| s.contains(ip))
    }

    /// Builds from a list of strings (each entry must be an address or a CIDR).
    pub fn from_strings<I, S>(entries: I) -> Result<Self, TrustedProxyParseError>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        let sources = entries
            .into_iter()
            .map(|s| s.as_ref().parse::<TrustedProxySource>())
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Self { sources })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(s: &str) -> TrustedProxySource {
        s.parse().unwrap()
    }

    #[test]
    fn default_is_loopback_only() {
        let c = TrustedProxyConfig::default();
        assert!(c.is_trusted("127.0.0.1".parse().unwrap()));
        assert!(c.is_trusted("::1".parse().unwrap()));
        assert!(!c.is_trusted("203.0.113.9".parse().unwrap()));
        assert!(!c.is_trusted("192.168.1.11".parse().unwrap()));
    }

    #[test]
    fn parses_address_and_cidr() {
        let c = TrustedProxyConfig::from_strings([
            "203.0.113.10",
            "192.168.1.0/24",
            "2001:db8::/32",
            "::1",
        ])
        .unwrap();
        assert!(c.is_trusted("203.0.113.10".parse().unwrap()));
        assert!(c.is_trusted("192.168.1.99".parse().unwrap()));
        assert!(c.is_trusted("2001:db8::1234".parse().unwrap()));
        assert!(c.is_trusted("::1".parse().unwrap()));
        assert!(!c.is_trusted("192.168.2.1".parse().unwrap()));
        assert!(!c.is_trusted("2001:db9::1".parse().unwrap()));
    }

    #[test]
    fn cidr_host_bits_are_masked() {
        // Host-bit notation is folded to the enclosing network (same as Ipv4Cidr::from_host_address).
        let c = TrustedProxyConfig::from_strings(["192.168.1.5/24"]).unwrap();
        assert!(c.is_trusted("192.168.1.99".parse().unwrap()));
        assert!(!c.is_trusted("192.168.2.1".parse().unwrap()));
        // IPv6 follows the same convention.
        let c = TrustedProxyConfig::from_strings(["2001:db8::1/64"]).unwrap();
        assert!(c.is_trusted("2001:db8::ffff".parse().unwrap()));
    }

    #[test]
    fn rejects_invalid_entries() {
        assert!(TrustedProxyConfig::from_strings(["not-an-ip"]).is_err());
        assert!(TrustedProxyConfig::from_strings(["10.0.0.0/33"]).is_err());
        assert!(TrustedProxyConfig::from_strings(["2001:db8::/129"]).is_err());
    }

    #[test]
    fn display_roundtrip() {
        for s in ["203.0.113.10", "192.168.1.0/24", "2001:db8::/32"] {
            let src = parse(s);
            assert_eq!(src.to_string(), s);
        }
    }
}
