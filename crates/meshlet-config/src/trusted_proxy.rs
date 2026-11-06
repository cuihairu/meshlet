//! 可信反代来源（TODO-116）：`X-Forwarded-For`/`X-Real-IP` 只在请求**直接来自**
//! 可信代理时才被采信；不可信来源完全忽略头部（防伪造）。
//!
//! 默认仅回环（`127.0.0.1` 与 `::1`）——nginx/Caddy 反代同主机部署的典型形态；
//! 可配 CIDR 或单个地址（IPv4/IPv6），如 `10.0.0.0/8`、`192.168.1.0/24`、
//! `203.0.113.10`。网段写法接受主机位（如 `192.168.1.5/24`），按「所在网段」归并。

use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::str::FromStr;

use meshlet_domain::Ipv4Cidr;

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum TrustedProxyParseError {
    #[error("invalid trusted proxy entry {0:?} (expected an IP address or a CIDR)")]
    Invalid(String),
}

/// 单个可信代理来源：地址或网段。
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

/// IPv6 CIDR（`meshlet-domain` 只有 IPv4 CIDR；反代来源需要 `::1` 等 v6 形态，
/// 这里做最小实现——主机位按「所在网段」归并，与 [Ipv4Cidr::from_host_address]
/// 同口径）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Ipv6Cidr {
    network: u128,
    prefix: u8,
}

impl Ipv6Cidr {
    /// 由「地址 + 前缀」构造所在网段（主机位被掩掉）。
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

/// 可信反代来源集合（server 配置项 `trusted_proxies`）。默认仅回环
/// `127.0.0.1` 与 `::1`（nginx 同主机反代形态）。
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

    /// 从字符串列表构造（每个条目必须是地址或 CIDR）。
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
        // 主机位写法按「所在网段」归并（同 Ipv4Cidr::from_host_address）。
        let c = TrustedProxyConfig::from_strings(["192.168.1.5/24"]).unwrap();
        assert!(c.is_trusted("192.168.1.99".parse().unwrap()));
        assert!(!c.is_trusted("192.168.2.1".parse().unwrap()));
        // IPv6 同口径。
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
