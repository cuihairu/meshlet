//! The Linux data-plane implementation ([ADR-007](../../docs/decisions/adr-007-linux-network-backend.md)):
//! controlled execution of the `ip` / `wg` / `iptables` system commands (the
//! controlled downgrade path of ADR-007; the move to Netlink/nftables is left
//! until its re-evaluation condition fires).
//!
//! Every command runs through [LinuxNetworkBackend::run] as an argument array
//! (no shell concatenation, the §4.3 prohibition); every writable operation is
//! idempotent (`replace` / a `-C` probe / `peer remove` reconciliation), so
//! applying the same revision repeatedly yields the same result (§10.3).
//!
//! Command-surface pitfalls (verified on real machines by the netns
//! integration tests, see the header note of `tests/wg_forwarding.rs`):
//! - The private key and the peers of `wg set` must be issued in **two
//!   separate** calls (a merged call silently drops the peer);
//! - `wg setconf` triggers fopen EPERM in this environment, so only `wg set`
//!   is used;
//! - A peer's endpoint points at the peer's **netns-side** address (a host-side
//!   veth address would handshake on the wrong port);
//! - Rollback only removes Meshlet's own objects: ownership is marked by
//!   iptables comments (`meshlet alias {id}` / `meshlet tunnel`) and by "objects
//!   on this backend's tunnel interface" — system routes and the user's existing
//!   rules are never touched (§10.3, ADR-007).
//!
//! The two fields `netns` / `sudo` are test hooks: in production a privileged
//! process talks to the host network stack directly
//! (`netns=None, sudo=false`); the integration tests run on an unprivileged
//! runner and use `sudo -n` to work inside a netns
//! (`with_netns(..).with_sudo()`).

mod backend;
mod operations;
mod parser;

/// The iptables ownership comment prefix: nat rules carry `meshlet alias {id}`
/// (§12.6) and the filter FORWARD allowance rules carry `meshlet tunnel` —
/// rollback/cleanup locate the target precisely by the comment only.
pub const MESHLET_NAT_COMMENT_PREFIX: &str = "meshlet alias";
pub const MESHLET_FILTER_COMMENT: &str = "meshlet tunnel";
/// Routing-protocol number used as Meshlet's route ownership marker.
pub const MESHLET_ROUTE_PROTO: &str = "198";

/// A host firewall allowance action (AGENT-FW-2).
///
/// Background: when a Linux host has ufw/firewalld enabled, its default INPUT
/// policy can block the mesh interface's ICMP/application traffic (the same
/// root as Windows's Public profile blocking ICMP). When a manager is detected
/// as active, the mesh interface traffic is allowed automatically, idempotently.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HostFirewallAction {
    /// `ufw allow in on <if>`: allow inbound on the interface.
    UfwAllowInOn { interface: String },
    /// `firewall-cmd --zone=trusted --add-interface=<if>`: put the interface
    /// into the trusted zone (allow everything). This is runtime configuration;
    /// the agent re-probes on every apply, and the reconcile restores it after a
    /// reboot.
    FirewalldTrustedInterface { interface: String },
    /// `ufw allow in proto udp to any port <p>`: allow the direct-connect UDP
    /// port (§12.4).
    /// A direct-connect peer reaches this host's wg listen port through a LAN or
    /// public interface, which the interface-level allowance (wg0) does not
    /// cover, so it must be opened by port.
    UfwAllowPort { port: u16 },
    /// `firewall-cmd --zone=trusted --add-port=<p>/udp`: the same as above
    /// (firewalld).
    FirewalldAllowPort { port: u16 },
}

/// Pure planning (AGENT-FW-2, unit-tested cross-platform): given the
/// ufw/firewalld active states and the current rule state, produce the allowance
/// actions. Fully idempotent — already allowed -> an empty plan; no manager
/// active -> no action.
pub fn host_firewall_allow_actions(
    ufw_active: bool,
    ufw_interface_allowed: bool,
    firewalld_active: bool,
    firewalld_interface_allowed: bool,
    interface: &str,
) -> Vec<HostFirewallAction> {
    let mut actions = Vec::new();
    if ufw_active && !ufw_interface_allowed {
        actions.push(HostFirewallAction::UfwAllowInOn {
            interface: interface.into(),
        });
    }
    if firewalld_active && !firewalld_interface_allowed {
        actions.push(HostFirewallAction::FirewalldTrustedInterface {
            interface: interface.into(),
        });
    }
    actions
}

/// Pure planning (the §12.4 firewall linkage, unit-tested cross-platform): the
/// host allowance plan for the direct-connect UDP port.
/// Fully idempotent — already allowed -> an empty plan; no manager active -> no
/// action. A direct-connect peer's inbound traffic arrives through a LAN or
/// public interface, which the interface-level allowance does not cover, so it
/// must be opened by port.
pub fn direct_udp_firewall_allow_actions(
    ufw_active: bool,
    ufw_port_allowed: bool,
    firewalld_active: bool,
    firewalld_port_allowed: bool,
    port: u16,
) -> Vec<HostFirewallAction> {
    let mut actions = Vec::new();
    if ufw_active && !ufw_port_allowed {
        actions.push(HostFirewallAction::UfwAllowPort { port });
    }
    if firewalld_active && !firewalld_port_allowed {
        actions.push(HostFirewallAction::FirewalldAllowPort { port });
    }
    actions
}

/// The iptables ownership comment of the foreign overlay isolation rules
/// (AGENT-ISO-1): rollback/cleanup locate the target precisely by the comment,
/// the same discipline as [MESHLET_FILTER_COMMENT] (§10.3).
pub const MESHLET_ISOLATION_COMMENT: &str = "meshlet foreign-overlay isolation";

/// The daemon user name of the foreign overlay (the object `id -u` reads the
/// uid for).
pub const FOREIGN_OVERLAY_USER: &str = "zerotier-one";

/// The well-known source port of the foreign overlay's primary protocol
/// (9993 for ZeroTier).
pub const FOREIGN_OVERLAY_WELLKNOWN_PORT: u16 = 9993;

/// A foreign overlay isolation rule (AGENT-ISO-1).
///
/// One rule = the target chain plus the rule body; `-C` (the probe) and `-I`
/// (the insert) share the `spec`, so the execution side only swaps the verb.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OverlayIsolationRule {
    /// The target chain (`OUTPUT` / `INPUT`).
    pub chain: String,
    /// The rule body (excluding `iptables`, `-t`, the chain name, and the insert
    /// position).
    pub spec: Vec<String>,
}

/// The identity input of the foreign overlay (ZeroTier-like) (AGENT-ISO-1).
///
/// Fields that cannot be read are `None` / empty — **never guessed** (§7.5):
/// when there is no such peer, no uid or port is invented, and the matching
/// rule is simply absent.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ForeignOverlay {
    /// The uid of the peer's daemon (`id -u <user>`). `None` = the user does not
    /// exist / the read failed.
    pub uid: Option<u32>,
    /// The local UDP listen ports of the peer's primary socket (they change on a
    /// ZeroTier restart, so they must be read live every time).
    pub local_ports: Vec<u16>,
    /// The well-known source port of the peer's primary protocol (9993 for
    /// ZeroTier).
    pub wellknown_port: u16,
}

/// Pure planning (AGENT-ISO-1, unit-tested cross-platform): produce the
/// expected rules for "the foreign overlay must not ride the meshlet tunnel".
///
/// Recursive encapsulation happens because the two tunnels **serve as each
/// other's path**: meshlet's WG endpoint lands in the ZeroTier segment
/// (outbound borrowing), while ZeroTier learns the meshlet overlay as a peer
/// path (inbound borrowing). Cutting either direction prevents the loop, and
/// this function emits rules in both directions:
///
/// 1. `OUTPUT -o <if> -m owner --uid-owner <uid>`: the peer's processes may not
///    send packets into the meshlet tunnel (cutting the outbound direction, a
///    hard guarantee);
/// 2. `INPUT -i <if> -p udp --dport <port>`: the peer's sockets may not receive
///    packets from the meshlet tunnel (its overlay paths then expire and fall
///    back to the public paths);
/// 3. `INPUT -i <if> -p udp --sport <wellknown>`: the peer's protocol may not
///    enter this host from the meshlet tunnel (blocking the same kind of packet
///    that the peer borrows in).
///
/// An empty `interface`, or a `foreign` that supplies no identity at all -> an
/// empty plan (no guessing).
/// Every rule carries the [MESHLET_ISOLATION_COMMENT] ownership marker.
pub fn overlay_isolation_rules(
    interface: &str,
    foreign: &ForeignOverlay,
) -> Vec<OverlayIsolationRule> {
    if interface.is_empty() {
        return Vec::new();
    }
    let mut rules = Vec::new();
    if let Some(uid) = foreign.uid {
        rules.push(OverlayIsolationRule {
            chain: "OUTPUT".into(),
            spec: vec![
                "-o".into(),
                interface.into(),
                "-m".into(),
                "owner".into(),
                "--uid-owner".into(),
                uid.to_string(),
                "-m".into(),
                "comment".into(),
                "--comment".into(),
                MESHLET_ISOLATION_COMMENT.into(),
                "-j".into(),
                "DROP".into(),
            ],
        });
    }
    for port in &foreign.local_ports {
        rules.push(OverlayIsolationRule {
            chain: "INPUT".into(),
            spec: vec![
                "-i".into(),
                interface.into(),
                "-p".into(),
                "udp".into(),
                "--dport".into(),
                port.to_string(),
                "-m".into(),
                "comment".into(),
                "--comment".into(),
                MESHLET_ISOLATION_COMMENT.into(),
                "-j".into(),
                "DROP".into(),
            ],
        });
    }
    if foreign.wellknown_port > 0 {
        rules.push(OverlayIsolationRule {
            chain: "INPUT".into(),
            spec: vec![
                "-i".into(),
                interface.into(),
                "-p".into(),
                "udp".into(),
                "--sport".into(),
                foreign.wellknown_port.to_string(),
                "-m".into(),
                "comment".into(),
                "--comment".into(),
                MESHLET_ISOLATION_COMMENT.into(),
                "-j".into(),
                "DROP".into(),
            ],
        });
    }
    rules
}

/// `ss -H -ulnp` -> the local UDP listen ports of a given process name (deduped
/// and ascending, pure parsing).
///
/// Lines look like (column order: State Recv-Q Send-Q **Local** Peer
/// Process):
/// `UNCONN 0 0 10.240.0.4%wg-mlt:63614 0.0.0.0:* users:(("zerotier-one",pid=1579,fd=25))`
///
/// Take the port at the end of the **4th column** (the local address) — the
/// address may carry an `%interface` scope suffix, and taking the last segment
/// with `rsplit(':')` strips it. Only lines containing `needle` (the process
/// name) are taken; the `users:` column requires permission to read other
/// processes (root only), and its absence does not affect the per-line process
/// name filter.
pub fn parse_ss_udp_listen_ports(output: &str, needle: &str) -> Vec<u16> {
    let mut ports: Vec<u16> = output
        .lines()
        .filter(|line| line.contains(needle))
        .filter_map(|line| {
            let local = line.split_whitespace().nth(3)?;
            let port = local.rsplit(':').next()?;
            port.parse::<u16>().ok()
        })
        .collect();
    ports.sort_unstable();
    ports.dedup();
    ports
}

pub(crate) use parser::{
    chrono_now_iso, enforced_tunnel_mtu, foreign_route_line, is_lan_interface, mtu_matches_planned,
    parse_default_route_interface, parse_ip_octet_addrs, parse_ip_octet_subnets, parse_link_mtu,
    parse_wg_dump_diag_line, route_source,
};

pub use backend::LinuxNetworkBackend;
pub use parser::{parse_ping_rtt_ms, run_ping_rtt};

#[cfg(test)]
mod tests;
