use crate::{WgPeerDiagnostic, DEFAULT_TUNNEL_MTU};
use meshlet_domain::Ipv4Cidr;
use std::net::Ipv4Addr;
use std::process::{Command, Stdio};

/// Parse the actual MTU reading out of `ip link show <if>` output (the first
/// line looks like `3: wg0: <...> mtu 1420 qdisc noqueue ...`). Returns
/// `None` when no `mtu` field can be read or parsed — the caller treats that
/// as "reading unavailable" rather than assuming a default value.
pub(crate) fn parse_link_mtu(link_show: &str) -> Option<u32> {
    let mut tokens = link_show.split_whitespace();
    while let Some(token) = tokens.next() {
        if token == "mtu" {
            return tokens.next().and_then(|v| v.parse().ok());
        }
    }
    None
}

/// Parse the default route's outgoing interface out of `ip -4 route show
/// default` (the first line looks like `default via 10.0.0.1 dev ens18
/// proto dhcp ...`). Returns `None` when no `dev` can be parsed — the caller
/// treats that as "reading unavailable" rather than guessing an interface name.
pub(crate) fn parse_default_route_interface(route_show: &str) -> Option<String> {
    let line = route_show.lines().next()?;
    let mut tokens = line.split_whitespace();
    while let Some(token) = tokens.next() {
        if token == "dev" {
            return tokens.next().map(str::to_string);
        }
    }
    None
}

/// Parse `(interface, IPv4 address)` pairs out of `ip -4 -o addr show`
/// output (only `inet` lines). Lines look like
/// `2: eth0    inet 192.168.1.50/24 ...` (`-o` puts one address per line).
pub(crate) fn parse_ip_octet_addrs(output: &str) -> Vec<(String, Ipv4Addr)> {
    output
        .lines()
        .filter_map(|line| {
            let fields: Vec<&str> = line.split_whitespace().collect();
            if fields.len() < 4 || fields[2] != "inet" {
                return None;
            }
            let ifname = fields[1].to_string();
            let addr: Ipv4Addr = fields[3].split('/').next()?.parse().ok()?;
            Some((ifname, addr))
        })
        .collect()
}

/// Same as [`parse_ip_octet_addrs`], but keeps the prefix length
/// (`192.168.1.50/24` -> the subnet). Only valid subnets are parsed
/// (prefix 0-32); lines that fail to parse are skipped (the caller treats
/// that as "this subnet is unknown" rather than inventing one).
pub(crate) fn parse_ip_octet_subnets(output: &str) -> Vec<(String, Ipv4Cidr)> {
    output
        .lines()
        .filter_map(|line| {
            let fields: Vec<&str> = line.split_whitespace().collect();
            if fields.len() < 4 || fields[2] != "inet" {
                return None;
            }
            let ifname = fields[1].to_string();
            // An interface address looks like `10.98.0.20/24` — the host bits are
            // never zero, so `Ipv4Cidr::from_str` (which requires a canonical
            // network address) cannot be used; mask out the containing network
            // from "address + prefix" instead (`10.98.0.0/24`).
            let (addr, prefix) = fields[3].split_once('/')?;
            let addr: std::net::Ipv4Addr = addr.parse().ok()?;
            let prefix: u8 = prefix.parse().ok()?;
            let subnet = meshlet_domain::Ipv4Cidr::from_host_address(addr, prefix).ok()?;
            Some((ifname, subnet))
        })
        .collect()
}

/// Candidate LAN interfaces: exclude loopback, the managed tunnel, and
/// virtual interfaces from containers/virtualization/VPN that would never
/// carry a peer's direct connection (`docker*`/`br-*`/`veth*`/`virbr*`/
/// `vmbr*`/`tailscale*`/`wg*`).
///
/// **Foreign overlays are out too** (`zt*` = ZeroTier, which on Linux is
/// always `zt` plus a random suffix): treating its subnet as the local LAN
/// would classify the peer's ZeroTier address as "same-subnet direct", and
/// the WG endpoint would then point into the other tunnel — with the two
/// tunnels serving as each other's path they encapsulate each other into a
/// loop (2026-11-23 real-machine incident: inner/physical 185:1). ADR-014's
/// "mutual backup, no route contention" also requires the two to take their
/// own paths rather than transit through each other.
pub(crate) fn is_lan_interface(ifname: &str, wg_interface: &str) -> bool {
    if ifname == "lo" || ifname == wg_interface {
        return false;
    }
    for prefix in [
        "docker",
        "br-",
        "veth",
        "virbr",
        "vmbr",
        "tailscale",
        "wg",
        "zt",
    ] {
        if ifname.starts_with(prefix) {
            return false;
        }
    }
    true
}

/// The MTU the agent enforces. An unset plan value means the WireGuard default
/// ([`DEFAULT_TUNNEL_MTU`]), not "leave the interface alone" — see
/// [`mtu_matches_planned`].
pub(crate) fn enforced_tunnel_mtu(planned: Option<u32>) -> u32 {
    planned.unwrap_or(DEFAULT_TUNNEL_MTU)
}

/// Readback half of MTU convergence: true only when the interface carries the
/// MTU the plan intends. The default is enforced like an explicit value, so an
/// interface left at a higher MTU (by an older plan or a manual `ip link set`)
/// is seen as drifted on the next reconcile instead of matching the plan.
pub(crate) fn mtu_matches_planned(link_show: &str, planned: Option<u32>) -> bool {
    parse_link_mtu(link_show) == Some(enforced_tunnel_mtu(planned))
}

/// ISO-8601 string of the current UTC time (second precision, `Z` suffix) —
/// the diagnostic collection timestamp. chrono is deliberately not pulled in
/// (meshlet-network is a pure command-execution layer); the local UTC time is
/// read with the `date` command, falling back to formatting `SystemTime`
/// epoch seconds on failure (displayed only as the collection timestamp).
pub(crate) fn chrono_now_iso() -> String {
    if let Ok(out) = std::process::Command::new("date")
        .args(["-u", "+%Y-%m-%dT%H:%M:%SZ"])
        .output()
    {
        if out.status.success() {
            let text = String::from_utf8_lossy(&out.stdout);
            let text = text.trim();
            if !text.is_empty() {
                return text.to_string();
            }
        }
    }
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    format!("{secs}")
}

/// Parse the first RTT (milliseconds) out of `ping` output. Supports both
/// `time=12.3 ms` and `time<1 ms` (iputils on Linux expresses sub-millisecond
/// latency this way); returns `None` when there is no reading.
///
/// `pub` (not `pub(crate)`): both the probe layer ([`crate::probe`]) and the
/// netns integration tests (`tests/probe_netns.rs`) reuse this parser directly.
pub fn parse_ping_rtt_ms(text: &str) -> Option<u128> {
    let start = text.find("time")?;
    let rest = &text[start + 4..];
    let digit_start = rest.find(|c: char| c.is_ascii_digit())?;
    let value = &rest[digit_start..];
    let end = value
        .find(|c: char| !c.is_ascii_digit() && c != '.')
        .unwrap_or(value.len());
    value[..end].parse::<f64>().ok().map(|v| v.round() as u128)
}

/// SEL-001 probe-layer transport: measures ICMP RTT (milliseconds) with a
/// direct `ping -c 1 -W 1`, bypassing the backend (no sudo / netns prefix).
/// The agent's probe thread uses this function to probe candidate endpoint
/// IPs (a candidate is an ordinary unicast address — reachable from the
/// agent process is enough; the wg interface is not needed). The timeout is
/// 1s — probing is a high-frequency lightweight operation, and a 2s
/// diagnostics-grade wait would slow the probe thread down.
pub fn run_ping_rtt(target: Ipv4Addr) -> Option<u128> {
    let out = Command::new("ping")
        .args(["-c", "1", "-W", "1", &target.to_string()])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .ok()?;
    parse_ping_rtt_ms(&String::from_utf8_lossy(&out.stdout))
}

/// Parse a peer line of `wg show <if> dump` into diagnostic readings (pure
/// function, testable on a Linux host). Whitespace separated:
/// `pubkey preshared endpoint allowed-ips latest-handshake rx tx keepalive`;
/// the same public-key criterion as the existing Linux peer dump parser, with
/// missing columns filled in as 0/empty.
pub(crate) fn parse_wg_dump_diag_line(line: &str) -> Option<WgPeerDiagnostic> {
    let fields: Vec<&str> = line.split_whitespace().collect();
    let public_key = fields.first()?;
    if public_key.len() != 44 || !public_key.ends_with('=') {
        return None;
    }
    let endpoint = fields.get(2).unwrap_or(&"").to_string();
    let allowed_ips = fields.get(3).unwrap_or(&"").to_string();
    let last_handshake: u64 = fields.get(4).and_then(|v| v.parse().ok()).unwrap_or(0);
    let rx_bytes: u64 = fields.get(5).and_then(|v| v.parse().ok()).unwrap_or(0);
    let tx_bytes: u64 = fields.get(6).and_then(|v| v.parse().ok()).unwrap_or(0);
    Some(WgPeerDiagnostic {
        public_key: public_key.to_string(),
        endpoint,
        allowed_ips,
        last_handshake,
        rx_bytes,
        tx_bytes,
    })
}

/// Kernel-selected source for the actual destination, not an address inside its prefix.
pub(crate) fn route_source(route_get: &str, tunnel: &str) -> Option<Ipv4Addr> {
    let fields: Vec<_> = route_get.split_whitespace().collect();
    if matches!(
        fields.first().copied(),
        Some("local" | "broadcast" | "unreachable" | "blackhole" | "prohibit")
    ) {
        return None;
    }
    let dev = fields.windows(2).find(|p| p[0] == "dev")?[1];
    if dev == tunnel || dev == "lo" {
        return None;
    }
    let source: Ipv4Addr = fields.windows(2).find(|p| p[0] == "src")?[1].parse().ok()?;
    (!source.is_unspecified() && !source.is_loopback()).then_some(source)
}

/// §18.3: decide whether one line of `ip route show exact <dst>` is a "foreign
/// route not going through the managed interface". Returns `Some(raw line)`
/// for a conflict — the target prefix is already pointed at a different path,
/// and `ip route replace` would silently take it over, so the operation must
/// be refused explicitly; `None` means an existing route through the managed
/// interface (a Meshlet-owned object, where rewriting it idempotently is a
/// normal plan change). Lines whose `dev` cannot be parsed (blackhole /
/// changed output format) are treated as conflicts — fail closed, never let an
/// unknown object through.
pub(crate) fn foreign_route_line(line: &str, interface: &str) -> Option<String> {
    let tokens: Vec<&str> = line.split_whitespace().collect();
    match tokens
        .iter()
        .position(|t| *t == "dev")
        .and_then(|i| tokens.get(i + 1))
    {
        Some(dev) if *dev == interface => None,
        _ => Some(line.trim().to_string()),
    }
}
