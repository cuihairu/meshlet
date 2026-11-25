//! Planning-layer types (split out from lib.rs): the structured configuration object from server
//! to agent, the snapshot carriers and the apply result; pure data + derivation, no IO.

use crate::nat;
use meshlet_domain::Ipv4Cidr;

/// Peer configuration: AllowedIPs must line up with the target routes (§7.2) and must never point
/// everything at the tunnel.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct PeerConfig {
    pub public_key: String,
    pub allowed_ips: Vec<Ipv4Cidr>,
    pub endpoint: Option<String>,
    pub persistent_keepalive_secs: Option<u32>,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct TunnelConfig {
    /// The interface name (Linux) or the tunnel name (Windows).
    pub name: String,
    pub address: std::net::Ipv4Addr,
    /// The prefix length of the interface address (on Linux, `ip address replace <addr>/<prefix>`).
    pub address_prefix: u8,
    pub listen_port: Option<u16>,
    pub peers: Vec<PeerConfig>,
    pub mtu: Option<u32>,
    /// The private key (base64). `None` = keep the interface's current private key (an idempotent
    /// re-apply); `Some` = set it explicitly via `wg set <if> private-key`.
    pub private_key: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct RouteConfig {
    pub destination: Ipv4Cidr,
    /// The next-hop interface name.
    pub interface: String,
    /// The next-hop gateway address (the peer device's virtual IP); `None` = a direct route.
    pub gateway: Option<std::net::Ipv4Addr>,
}

/// One host of the SSH alias sync (the SSH config distribution section `ssh_config` pushed by the hub).
///
/// One entry per Active node in the network; the agent renders the `Host <alias>` blocks of
/// `~/.ssh/meshlet.conf` from it. The alias has three source tiers: an explicit hub override > the
/// node's real hostname > the meshlet peer name (`alias_source` states the source as-is; the
/// panel/docs use the same convention).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct SshHostConfig {
    /// The meshlet peer name (matches the console device name; the anchor for logs/troubleshooting).
    pub name: String,
    /// The SSH Host alias (already sanitized into legal Host characters).
    pub alias: String,
    /// The peer's overlay VIP (the `HostName`).
    pub address: std::net::Ipv4Addr,
    /// The SSH port; `None` = the agent uses the default 22.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub port: Option<u16>,
    /// The SSH login user; `None` = not distributed (the local ssh default is used).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub user: Option<String>,
    /// Where the alias came from (`hub-config` / `hostname` / `peer-name`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub alias_source: Option<String>,
}

/// The SSH config distribution section (appears in the plan only when the hub turns it on
/// explicitly): the alias table for all Active nodes in the network. Absent (old servers / hub not
/// enabled) means the hub pushed nothing — the agent self-generates a single entry from the local
/// defaults (hostname + its own overlay VIP + 22).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct SshConfigPlan {
    pub hosts: Vec<SshHostConfig>,
}

/// The device dataplane plan: the **structured configuration object** the server pushes to the agent
/// (§16.4: the agent only executes typed objects and never runs arbitrary shell commands handed down
/// by the server).
///
/// - `tunnel`: this device's tunnel (the private key is injected locally by the agent and never
///   carried by the server — the private key never leaves the client, ADR-010);
/// - `routes`: the destination subnets this device forwards over the tunnel (the overlay + LANs/Aliases
///   published by others; its own local subnet is not fed back);
/// - `nat_rules`: the NAT rules this device should push when acting as a gateway (planning-layer
///   rendering, ownership comment `meshlet alias {id}`); empty = not a gateway or the mapping was deleted;
/// - `hub_address`: the hub's overlay address (allocated by the server IPAM) — used only for agent-local
///   diagnostics (the target of the planned-MTU large-packet probe), not part of the kernel configuration;
/// - `publish`: the service publishing plan (R-06, [`meshlet_publish::PublishPlan`]): the L4 forwarding /
///   HTTP routes / DNS sockets and probe schedule this device should bind; absent (`None`, old servers)
///   means this device has no publishing configuration;
/// - `desired_config_hash`: the desired configuration hash this plan corresponds to — the agent uses it
///   to decide "replay only when something changed" (§10.1).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct DevicePlan {
    #[serde(default)]
    pub desired_revision: u64,
    #[serde(default)]
    pub hub_port: Option<u16>,
    pub tunnel: TunnelConfig,
    pub routes: Vec<RouteConfig>,
    pub nat_rules: Vec<nat::NatRule>,
    /// The hub overlay address; absent (old servers) means unknown — probing is skipped accordingly.
    #[serde(default)]
    pub hub_address: Option<std::net::Ipv4Addr>,
    /// The service publishing plan; absent (old servers / this device has nothing to publish) means `None`.
    #[serde(default)]
    pub publish: Option<meshlet_publish::PublishPlan>,
    /// The SSH alias distribution section (`ssh_config`): carried only when the hub turns it on
    /// explicitly. Omitted from serialization when absent (`skip_serializing_if`) — so the hash of
    /// plans from old servers is unchanged and an upgrade triggers no needless network-wide replay.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ssh_config: Option<SshConfigPlan>,
    pub desired_config_hash: String,
}

/// Default tunnel MTU (the WireGuard default): the effective plan value when the plan sets no MTU
/// explicitly, and one of the size sources for the large-packet probe (1420 − 28 = 1392).
pub const DEFAULT_TUNNEL_MTU: u32 = 1420;

/// WireGuard tunnel IPv4 encapsulation overhead over the underlay (bytes): outer IPv4 header 20B +
/// UDP header 8B + WireGuard data channel header/tag 52B ≈ 80B (an IPv6 outer header is 80B + 20B,
/// and the more conservative 80B is used to stay consistent with WireGuard documentation convention).
pub const WG_TUNNEL_OVERHEAD_BYTES: u32 = 80;

/// SEL-003 hub backstop: the hub peer's persistent-keepalive (seconds). The hub is the relay's
/// lifeline; if keepalive drops, the hub side loses sight of this device (the NAT mapping expires)
/// and there is nowhere to fall back to after a direct-connect demotion. The agent forces
/// max(plan value, this value) for the hub peer during reconcile, guaranteeing it "never drops".
pub const HUB_KEEPALIVE_SECS: u32 = 25;

/// Derive the tunnel MTU from the underlay interface MTU (lane/dataplane-speed): `underlay − 80`,
/// floored at 1280 (the IPv6 minimum MTU — below it IPv6-in-tunnel and common TLS paths break
/// outright, the same source as `MIN_TUNNEL_MTU` in meshlet-config).
///
/// - underlay 1500 (standard Ethernet) → 1420, identical to [`DEFAULT_TUNNEL_MTU`] — default
///   behavior is unchanged; this is **not a conservative value**, it is the correct one for a 1500
///   underlay;
/// - underlay 9000 (jumbo) → 8920; measured (netns baseline, see docs/guide/performance) single-flow
///   throughput 1.5 → 8.5 Gbps;
/// - underlay 1492 (PPPoE) → 1412, closer to the real path than the default 1420.
///
/// This is a **derivation aid**, not automatic distribution: the server's `tunnel_mtu` plan remains
/// the sole kernel authority (drift correction runs per plan). The agent only uses it for the
/// large-packet probe payload (§7.5 evidence), and ops pin an explicit `tunnel_mtu` in the server
/// configuration based on it.
pub fn derive_tunnel_mtu(underlay_mtu: u32) -> u32 {
    underlay_mtu
        .saturating_sub(WG_TUNNEL_OVERHEAD_BYTES)
        .max(1280)
}

/// Apply result: **when applied=false an error explanation must be carried** — never pretend success (§10.3).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApplyResult {
    pub applied: bool,
    pub error: Option<String>,
}

impl ApplyResult {
    pub fn ok() -> Self {
        Self {
            applied: true,
            error: None,
        }
    }

    pub fn failed(message: impl Into<String>) -> Self {
        Self {
            applied: false,
            error: Some(message.into()),
        }
    }
}

/// A configuration revision reference (the rollback target, ADR-009).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfigRevisionRef {
    pub network_id: String,
    pub revision: u64,
}

/// The inspect snapshot: the source of truth for diagnostics and configuration reconciliation (§12.7, §17.3).
///
/// Every field is collected by **identity**, not by **count**: peers form a public-key set, routes a
/// destination set carrying ownership marks, and NAT a rule-fingerprint set under the ownership
/// comment. Drift verdicts can therefore distinguish "installed too little" from "installed things
/// that should not be there", and only Meshlet-owned objects are looked at — resources outside this
/// meshlet are never touched.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct NetworkSnapshot {
    pub tunnel_exists: bool,
    pub forwarding_enabled: Option<bool>,
    /// The WireGuard peers actually present on the managed interface (public key + allowed-ips read as-is).
    pub peers: Vec<PeerObserved>,
    /// Route destinations carrying the Meshlet ownership mark (the backend only enumerates marked objects).
    pub installed_routes: Vec<Ipv4Cidr>,
    /// Fingerprints of the kernel's NAT rules under the Meshlet ownership comment (the same shape
    /// as `NatRule::signature`); the plan side and the kernel side do exact set comparison by it.
    pub nat_rules: Vec<String>,
    /// The tunnel interface's actual MTU reading (parsed from `ip link show`; used for drift
    /// verdicts when the plan configures an MTU explicitly: a kernel reading that disagrees with
    /// the plan triggers a replay to correct).
    pub tunnel_mtu: Option<u32>,
    /// The local public-key fingerprint of the managed interface (`wg show dump` interface line,
    /// column 2, 44 characters of base64). Drift verdicts use it to recognize a hand-made tunnel
    /// where "peers happen to match the plan but the local private key was swapped" (the second
    /// finding of the todo.md Windows deployment); unreadable → `None` (missing evidence is not
    /// judged, no replay loop).
    pub local_public_key: Option<String>,
    /// The managed interface adapter's actual IPv4 address. Drift verdicts compare it against the
    /// planned address — even a hand-made tunnel that changed its address must be replay-corrected;
    /// unreadable → `None` (missing evidence is not judged).
    pub tunnel_address: Option<std::net::Ipv4Addr>,
    /// The managed interface's actual WireGuard listening port (`wg show dump` interface line,
    /// column 3). When direct connect is on, the plan pins a fixed port (`plan.tunnel.listen_port`)
    /// — an actual port that disagrees with the plan must read as not matching (otherwise the peer
    /// sends to the reported port, this machine never receives, and hole punching fails silently);
    /// unreadable → `None` (missing evidence is not judged, no replay loop).
    pub tunnel_listen_port: Option<u16>,
    /// Route-provenance semantics (declared by the backend): `true` = this backend's kernel routes
    /// are assembled entirely from peer allowed-ips (wireguard-nt's adapter `set_default_route`;
    /// `plan.routes` is never pushed through an independent path on this backend, and netsh route
    /// apply is explicitly rejected). Drift verdicts accordingly stop judging "missing route /
    /// out-of-plan route" against `plan.routes` — routes are already fully determined by the
    /// peer identity-level comparison (public key → allowed-ips, item by item); otherwise the hub's
    /// `/16` on a leaf node with `routes=[]` always reads as "out-of-plan route" → a KernelDrift
    /// replay loop every round (confirmed on a real imac on 2026-11-22: the old binary hit the
    /// pre boundary 185 times).
    pub routes_from_peers: bool,
}

/// One WireGuard peer read off the managed interface (an identity-level fact: public key + allowed-ips).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct PeerObserved {
    pub public_key: String,
    pub allowed_ips: Vec<Ipv4Cidr>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn derived_tunnel_mtu_tracks_the_underlay_with_floor() {
        assert_eq!(derive_tunnel_mtu(1500), 1420); // Ethernet: the default is the correct value
        assert_eq!(derive_tunnel_mtu(9000), 8920); // jumbo underlay
        assert_eq!(derive_tunnel_mtu(1492), 1412); // PPPoE
        assert_eq!(derive_tunnel_mtu(1300), 1280); // floor clamped
        assert_eq!(derive_tunnel_mtu(0), 1280); // a bad reading still yields no 0/underflow
    }

    #[test]
    fn apply_result_failure_carries_error() {
        let ok = ApplyResult::ok();
        assert!(ok.applied && ok.error.is_none());
        let bad = ApplyResult::failed("route install rejected");
        assert!(!bad.applied);
        assert_eq!(bad.error.as_deref(), Some("route install rejected"));
    }

    #[test]
    fn peer_allowed_ips_explicit() {
        // §7.2: AllowedIPs must line up with the target routes — the types force listing them explicitly.
        let peer = PeerConfig {
            public_key: "hub-pub".into(),
            allowed_ips: vec![
                "10.240.0.0/16".parse().unwrap(),
                "10.241.1.0/24".parse().unwrap(), // the alias of a published LAN
            ],
            endpoint: Some("203.0.113.10:51820".into()),
            persistent_keepalive_secs: Some(25),
        };
        assert_eq!(peer.allowed_ips.len(), 2);
    }

    #[test]
    fn device_plan_round_trips_as_a_structured_object() {
        // §16.4: server→agent transfers typed objects (a CIDR serializes to an a.b.c.d/p string).
        let plan = DevicePlan {
            desired_revision: 0,
            hub_port: None,
            tunnel: TunnelConfig {
                name: "wg0".into(),
                address: "10.240.0.3".parse().unwrap(),
                address_prefix: 16,
                listen_port: None,
                peers: vec![PeerConfig {
                    public_key: "hub-pub".into(),
                    allowed_ips: vec!["10.240.0.0/16".parse().unwrap()],
                    endpoint: Some("203.0.113.10:51820".into()),
                    persistent_keepalive_secs: Some(25),
                }],
                mtu: None,
                private_key: None,
            },
            routes: vec![RouteConfig {
                destination: "10.241.1.0/24".parse().unwrap(),
                interface: "wg0".into(),
                gateway: None,
            }],
            nat_rules: vec![],
            hub_address: Some("10.240.0.1".parse().unwrap()),
            publish: None,
            ssh_config: None,
            desired_config_hash: "meshlet-desired-v3:ab".into(),
        };
        let value = serde_json::to_value(&plan).unwrap();
        assert_eq!(value["tunnel"]["address_prefix"], 16);
        assert_eq!(
            value["tunnel"]["peers"][0]["allowed_ips"][0],
            "10.240.0.0/16"
        );
        assert_eq!(value["routes"][0]["destination"], "10.241.1.0/24");
        // Absent (old servers / hub not enabled) means no ssh_config is carried: the plan's serialization
        // adds no field and the hash pushed by old servers is unchanged — an upgrade triggers no
        // needless network-wide replay.
        assert!(value.get("ssh_config").is_none());
        let round = serde_json::from_value::<DevicePlan>(value).unwrap();
        assert_eq!(round, plan);

        // A plan without hub_address still parses (forward compatibility with plans from old servers).
        let without_hub = serde_json::json!({
            "tunnel": plan.tunnel,
            "routes": [],
            "nat_rules": [],
            "desired_config_hash": "h",
        });
        let old: DevicePlan = serde_json::from_value(without_hub).unwrap();
        assert_eq!(old.hub_address, None);
    }

    #[test]
    fn device_plan_rejects_a_non_canonical_cidr() {
        // Deserialization runs the same validation: a subnet with host bits set is not legal plan input (§6.1).
        let plan = DevicePlan {
            desired_revision: 0,
            hub_port: None,
            tunnel: TunnelConfig {
                name: "wg0".into(),
                address: "10.240.0.3".parse().unwrap(),
                address_prefix: 16,
                listen_port: None,
                peers: vec![],
                mtu: None,
                private_key: None,
            },
            routes: vec![RouteConfig {
                destination: "10.240.0.0/16".parse().unwrap(),
                interface: "wg0".into(),
                gateway: None,
            }],
            nat_rules: vec![],
            hub_address: None,
            publish: None,
            ssh_config: None,
            desired_config_hash: "h".into(),
        };
        let mut value = serde_json::to_value(&plan).unwrap();
        value["routes"][0]["destination"] = serde_json::Value::String("10.240.0.1/16".into());
        assert!(
            serde_json::from_value::<DevicePlan>(value).is_err(),
            "host bits set must be rejected"
        );
    }
}
