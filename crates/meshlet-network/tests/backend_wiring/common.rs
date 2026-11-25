//! Shared fixtures for the backend-driven Linux integration scenarios.
//!
//! All kernel objects use one `mltb` prefix. The process-local lock keeps the
//! split scenario tests from racing on that shared host-side underlay.

use std::collections::BTreeSet;
use std::path::Path;
use std::process::{Command, Output, Stdio};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use meshlet_domain::{AliasMapping, AliasMappingId, LanRouteId, NetworkId, TranslationMode};
use meshlet_network::linux::LinuxNetworkBackend;
use meshlet_network::{NetworkSnapshot, PeerConfig, RouteConfig, TunnelConfig};

/// Prefix for the object names (to tell these apart from the other netns tests).
pub(crate) const PREFIX: &str = "mltb";
/// Upper bound for waiting on the handshake.
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(25);

/// The §7.4 source-observation script: a UDP echo on B that exits after a single receive (it also
/// exits itself after 10s without a packet, leaving no orphan process), whose reply body is the
/// source address of the packet received. The @BIND@ placeholder is replaced with B's overlay address.
const ECHO_SERVER_PY: &str = r#"
import socket
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.bind(("@BIND@", 15900))
s.settimeout(10)
try:
    _, addr = s.recvfrom(2048)
    s.sendto(("src=" + addr[0]).encode(), addr)
except Exception:
    pass
"#;

/// The echo client: hit @PEER@ once and print the reply body. The @PEER@ placeholder is replaced with B's overlay address.
const ECHO_CLIENT_PY: &str = r#"
import socket
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.settimeout(5)
s.sendto(b"hi", ("@PEER@", 15900))
print(s.recvfrom(2048)[0].decode().strip())
"#;

// ---------------------------------------------------------------- process helpers

pub(crate) fn sudo(args: &[&str]) -> Output {
    Command::new("sudo")
        .arg("-n")
        .args(args)
        .output()
        .expect("spawn sudo")
}

pub(crate) fn sudo_ok(args: &[&str]) -> bool {
    sudo(args).status.success()
}

pub(crate) fn netns_exec(ns: &str, args: &[&str]) -> Output {
    let mut full = vec!["ip", "netns", "exec", ns];
    full.extend_from_slice(args);
    sudo(&full)
}

/// A failed command during topology setup panics outright (with the environment right, a failing command is a real bug).
pub(crate) fn require_ok(out: &Output, what: &str) {
    if !out.status.success() {
        panic!(
            "{what} failed (rc={:?}): {}",
            out.status.code(),
            String::from_utf8_lossy(&out.stderr)
        );
    }
}

pub(crate) fn count_prefix_lines(text: &str) -> usize {
    text.lines().filter(|l| l.starts_with(PREFIX)).count()
}

// ---------------------------------------------------------------- prerequisites

pub(crate) fn prerequisites() -> Option<()> {
    if !sudo_ok(&["true"]) {
        assert!(
            std::env::var_os("MESHLET_REQUIRE_DATAPLANE").is_none(),
            "required dataplane prerequisite failed"
        );
        eprintln!("SKIP: passwordless sudo (sudo -n) unavailable");
        return None;
    }
    match Command::new("wg").arg("--version").output() {
        Ok(o) if o.status.success() => {}
        _ => {
            assert!(
                std::env::var_os("MESHLET_REQUIRE_DATAPLANE").is_none(),
                "required dataplane prerequisite failed"
            );
            eprintln!("SKIP: wireguard-tools (wg) not installed");
            return None;
        }
    }
    if !sudo_ok(&["modprobe", "wireguard"]) && !Path::new("/sys/module/wireguard").exists() {
        assert!(
            std::env::var_os("MESHLET_REQUIRE_DATAPLANE").is_none(),
            "required dataplane prerequisite failed"
        );
        eprintln!("SKIP: wireguard kernel module unavailable");
        return None;
    }
    match Command::new("python3").arg("--version").output() {
        Ok(o) if o.status.success() => {}
        _ => {
            assert!(
                std::env::var_os("MESHLET_REQUIRE_DATAPLANE").is_none(),
                "required dataplane prerequisite failed"
            );
            eprintln!("SKIP: python3 not installed (udp echo probe)");
            return None;
        }
    }
    Some(())
}

pub(crate) fn preflight_cleanup() {
    let out = sudo(&["ip", "netns", "list"]);
    let text = String::from_utf8_lossy(&out.stdout);
    for line in text.lines() {
        if let Some(name) = line.split_whitespace().next() {
            if name.starts_with(PREFIX) {
                let _ = sudo(&["ip", "netns", "del", name]);
            }
        }
    }
    let out = sudo(&["ip", "-br", "link"]);
    let text = String::from_utf8_lossy(&out.stdout);
    for line in text.lines() {
        if let Some(name) = line.split_whitespace().next() {
            if name.starts_with(PREFIX) {
                let _ = sudo(&["ip", "link", "del", name]);
            }
        }
    }
}

// ---------------------------------------------------------------- keys

pub(crate) fn wg_genkey() -> Option<String> {
    let out = Command::new("wg").arg("genkey").output().ok()?;
    if !out.status.success() {
        return None;
    }
    Some(String::from_utf8_lossy(&out.stdout).trim().to_string())
}

pub(crate) fn wg_pubkey(private: &str) -> Option<String> {
    use std::io::Write;
    use std::process::Stdio;
    let mut child = Command::new("wg")
        .arg("pubkey")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .ok()?;
    child
        .stdin
        .take()
        .expect("piped stdin")
        .write_all(private.as_bytes())
        .ok()?;
    let out = child.wait_with_output().ok()?;
    if !out.status.success() {
        return None;
    }
    Some(String::from_utf8_lossy(&out.stdout).trim().to_string())
}

// ---------------------------------------------------------------- topology

pub(crate) struct Node {
    pub(crate) netns: String,
    pub(crate) veth_host: String,
    pub(crate) veth_ns: String,
    pub(crate) underlay: String,
    pub(crate) overlay: String,
    pub(crate) public_key: String,
    pub(crate) private_key: String,
}

impl Node {
    pub(crate) fn backend(&self) -> LinuxNetworkBackend {
        LinuxNetworkBackend::new()
            .with_netns(&self.netns)
            .with_sudo()
            .with_interface("wg0")
    }
}

pub(crate) struct Guard {
    netns: Vec<String>,
    veth: Vec<String>,
    bridge: Option<String>,
}

impl Drop for Guard {
    fn drop(&mut self) {
        for ns in &self.netns {
            let _ = sudo(&["ip", "netns", "del", ns]);
        }
        for link in &self.veth {
            let _ = sudo(&["ip", "link", "del", link]);
        }
        if let Some(bridge) = &self.bridge {
            let _ = sudo(&["ip", "link", "del", bridge]);
        }
    }
}

/// The fallback cleanup for scenario 12 (the host): the test plants foreign objects in the **root
/// namespace** and configures wg0, and no assertion failure may leave those objects on the host.
pub(crate) struct RootGuard;

impl Drop for RootGuard {
    fn drop(&mut self) {
        // First peel off the managed NAT by ownership, then delete the managed interface (taking its routes and peers along with it).
        let cleanup = LinuxNetworkBackend::new().with_sudo().with_interface("wg0");
        let _ = cleanup.remove_nat_sync(ALIAS_OWNER);
        let _ = sudo(&["ip", "link", "del", "wg0"]);
        let _ = sudo(&["ip", "route", "del", "198.51.101.0/24", "dev", "lo"]);
        let _ = sudo(&[
            "iptables",
            "-t",
            "nat",
            "-D",
            "PREROUTING",
            "-d",
            "203.0.113.0/24",
            "-j",
            "ACCEPT",
            "-m",
            "comment",
            "--comment",
            "host rule",
        ]);
        let _ = sudo(&[
            "iptables",
            "-t",
            "filter",
            "-D",
            "FORWARD",
            "-i",
            "lo",
            "-j",
            "ACCEPT",
            "-m",
            "comment",
            "--comment",
            "host rule",
        ]);
    }
}

/// The exact rendered line of a route in the root namespace (`None` when it does not exist) -- the comparison criterion for whether a foreign object survived.
pub(crate) fn root_route_exact(destination: &str) -> Option<String> {
    let out = sudo(&["ip", "-4", "route", "show", "exact", destination]);
    if !out.status.success() {
        return None;
    }
    let text = String::from_utf8_lossy(&out.stdout).trim().to_string();
    (!text.is_empty()).then_some(text)
}

/// Find a line in the `iptables -S` output that matches both `needle` and the ownership comment.
pub(crate) fn host_rule_line(stdout: &[u8], needle: &str) -> Option<String> {
    String::from_utf8_lossy(stdout)
        .lines()
        .find(|line| line.contains(needle) && line.contains("host rule"))
        .map(str::to_string)
}

pub(crate) struct Topology {
    #[allow(dead_code)] // The field is only ever used for Drop-based cleanup
    guard: Guard,
    pub(crate) hub: Node,
    pub(crate) a: Node,
    pub(crate) b: Node,
    pub(crate) gw: Node,
    /// The LAN host netns (192.168.1.5 behind the gateway).
    #[allow(dead_code)]
    lan: String,
}

impl Topology {
    pub(crate) fn setup() -> Option<Topology> {
        prerequisites()?;
        preflight_cleanup();

        let mut guard = Guard {
            netns: Vec::new(),
            veth: Vec::new(),
            bridge: None,
        };

        // --- Keys (one pair per node)
        let mut keys = Vec::new();
        for _ in 0..4 {
            let private = match wg_genkey() {
                Some(k) => k,
                None => {
                    assert!(
                        std::env::var_os("MESHLET_REQUIRE_DATAPLANE").is_none(),
                        "required dataplane prerequisite failed"
                    );
                    eprintln!("SKIP: key generation failed");
                    return None;
                }
            };
            let public = match wg_pubkey(&private) {
                Some(k) => k,
                None => {
                    assert!(
                        std::env::var_os("MESHLET_REQUIRE_DATAPLANE").is_none(),
                        "required dataplane prerequisite failed"
                    );
                    eprintln!("SKIP: key derivation failed");
                    return None;
                }
            };
            keys.push((private, public));
        }

        // --- Node identities (H/A/B/G hang off the bridge; G also carries a LAN segment)
        let defs = [
            ("H", "10.99.0.10", "10.240.0.1"),
            ("A", "10.99.0.20", "10.240.0.2"),
            ("B", "10.99.0.30", "10.240.0.3"),
            ("G", "10.99.0.40", "10.240.0.4"),
        ];
        let mut nodes = Vec::new();
        for ((name, underlay, overlay), (private, public)) in defs.iter().zip(keys.iter()) {
            nodes.push(Node {
                netns: format!("{PREFIX}{name}"),
                veth_host: format!("{PREFIX}{name}0"),
                veth_ns: format!("{PREFIX}{name}1"),
                underlay: underlay.to_string(),
                overlay: overlay.to_string(),
                public_key: public.clone(),
                private_key: private.clone(),
            });
        }

        // --- Bridge + netns + veth + turning off offload (the same pitfall handling as wg_forwarding.rs)
        let bridge = format!("{PREFIX}br0");
        guard.bridge = Some(bridge.clone());
        require_ok(
            &sudo(&["ip", "link", "add", &bridge, "type", "bridge"]),
            "create bridge",
        );
        require_ok(&sudo(&["ip", "link", "set", &bridge, "up"]), "bridge up");

        for n in &nodes {
            guard.netns.push(n.netns.clone());
            guard.veth.push(n.veth_host.clone());
            require_ok(&sudo(&["ip", "netns", "add", &n.netns]), "netns add");
            require_ok(
                &sudo(&[
                    "ip",
                    "link",
                    "add",
                    &n.veth_host,
                    "type",
                    "veth",
                    "peer",
                    "name",
                    &n.veth_ns,
                ]),
                "veth add",
            );
            require_ok(
                &sudo(&["ip", "link", "set", &n.veth_ns, "netns", &n.netns]),
                "veth into netns",
            );
            require_ok(
                &sudo(&["ip", "link", "set", &n.veth_host, "master", &bridge]),
                "veth onto bridge",
            );
            require_ok(
                &netns_exec(
                    &n.netns,
                    &[
                        "ip",
                        "addr",
                        "add",
                        &format!("{}/24", n.underlay),
                        "dev",
                        &n.veth_ns,
                    ],
                ),
                "underlay addr",
            );
            require_ok(
                &sudo(&["ip", "link", "set", &n.veth_host, "up"]),
                "veth host up",
            );
            require_ok(
                &netns_exec(&n.netns, &["ip", "link", "set", &n.veth_ns, "up"]),
                "veth ns up",
            );
            require_ok(
                &netns_exec(&n.netns, &["ip", "link", "set", "lo", "up"]),
                "lo up",
            );
            // GRO/GSO/TSO make a wg-over-veth handshake fail silently; turn them off on both ends.
            for dev in [&n.veth_host, &n.veth_ns] {
                let _ = sudo(&[
                    "ethtool", "-K", dev, "gro", "off", "gso", "off", "tso", "off", "rx", "off",
                    "tx", "off", "sg", "off",
                ]);
            }
        }

        // --- Gateway LAN segment (G's second interface + the LAN host netns)
        let lan = format!("{PREFIX}L");
        let (lan0, lan1) = (format!("{PREFIX}X0"), format!("{PREFIX}X1"));
        guard.netns.push(lan.clone());
        guard.veth.push(lan0.clone());
        require_ok(&sudo(&["ip", "netns", "add", &lan]), "lan netns add");
        require_ok(
            &sudo(&[
                "ip", "link", "add", &lan0, "type", "veth", "peer", "name", &lan1,
            ]),
            "lan veth add",
        );
        let gw_netns = nodes[3].netns.clone();
        require_ok(
            &sudo(&["ip", "link", "set", &lan0, "netns", &gw_netns]),
            "lan0 -> G",
        );
        require_ok(
            &sudo(&["ip", "link", "set", &lan1, "netns", &lan]),
            "lan1 -> L",
        );
        require_ok(
            &netns_exec(
                &gw_netns,
                &["ip", "addr", "add", "192.168.1.1/24", "dev", &lan0],
            ),
            "gateway lan addr",
        );
        require_ok(
            &netns_exec(&lan, &["ip", "addr", "add", "192.168.1.5/24", "dev", &lan1]),
            "lan host addr",
        );
        require_ok(
            &netns_exec(&gw_netns, &["ip", "link", "set", &lan0, "up"]),
            "lan0 up",
        );
        require_ok(
            &netns_exec(&lan, &["ip", "link", "set", &lan1, "up"]),
            "lan1 up",
        );
        require_ok(
            &netns_exec(&lan, &["ip", "link", "set", "lo", "up"]),
            "lan lo up",
        );
        for dev in [&lan0, &lan1] {
            let _ = sudo(&[
                "ethtool", "-K", dev, "gro", "off", "gso", "off", "tso", "off", "rx", "off", "tx",
                "off", "sg", "off",
            ]);
        }

        let [hub, a, b, gw] = nodes.try_into().ok()?;
        Some(Topology {
            guard,
            hub,
            a,
            b,
            gw,
            lan,
        })
    }

    pub(crate) fn wait_handshake(&self, ns: &str) -> bool {
        let start = Instant::now();
        while start.elapsed() < HANDSHAKE_TIMEOUT {
            let out = netns_exec(ns, &["wg", "show", "wg0"]);
            if String::from_utf8_lossy(&out.stdout).contains("latest handshake") {
                return true;
            }
            std::thread::sleep(Duration::from_millis(500));
        }
        false
    }

    pub(crate) fn ping(&self, from: &str, to: &str) -> bool {
        netns_exec(from, &["ping", "-c", "3", "-W", "2", to])
            .status
            .success()
    }

    pub(crate) fn wg_show(&self, ns: &str) -> String {
        String::from_utf8_lossy(&netns_exec(ns, &["wg", "show", "wg0"]).stdout).to_string()
    }

    pub(crate) fn nat_rules(&self, ns: &str, chain: &str) -> String {
        String::from_utf8_lossy(&netns_exec(ns, &["iptables", "-t", "nat", "-S", chain]).stdout)
            .to_string()
    }

    /// The §7.4 source-preservation probe: B starts a one-shot UDP echo (reply body = the packet's source
    /// address) and A sends once. Returns the reply body (`Some("src=<source address>")`) to assert that
    /// the A -> B source was not rewritten.
    pub(crate) fn overlay_source_seen_by_b(&self) -> Option<String> {
        let server = ECHO_SERVER_PY.replace("@BIND@", &self.b.overlay);
        let mut child = Command::new("sudo")
            .arg("-n")
            .args([
                "ip",
                "netns",
                "exec",
                &self.b.netns,
                "python3",
                "-c",
                &server,
            ])
            .stdout(Stdio::null())
            .spawn()
            .ok()?;
        std::thread::sleep(Duration::from_millis(700)); // give the echo server time to be ready
        let client = ECHO_CLIENT_PY.replace("@PEER@", &self.b.overlay);
        let mut answer = None;
        for _ in 0..3 {
            let out = netns_exec(&self.a.netns, &["python3", "-c", &client]);
            if out.status.success() {
                answer = Some(String::from_utf8_lossy(&out.stdout).trim().to_string());
                break;
            }
            std::thread::sleep(Duration::from_millis(500));
        }
        let _ = child.wait();
        answer
    }
}

// ---------------------------------------------------------------- config builders

/// The hub-side tunnel config (isomorphic to the server adapter's `hub_plan`: a peer's allowed-ips =
/// its virtual IP /32 plus the alias prefixes forwarded through that device).
pub(crate) fn hub_tunnel(hub: &Node, a: &Node, b: &Node, gw: &Node, with_b: bool) -> TunnelConfig {
    let mut peers = vec![
        PeerConfig {
            public_key: a.public_key.clone(),
            allowed_ips: vec!["10.240.0.2/32".parse().unwrap()],
            endpoint: None,
            persistent_keepalive_secs: None,
        },
        PeerConfig {
            public_key: gw.public_key.clone(),
            allowed_ips: vec![
                "10.240.0.4/32".parse().unwrap(),
                "10.241.1.0/24".parse().unwrap(),
            ],
            endpoint: None,
            persistent_keepalive_secs: None,
        },
    ];
    if with_b {
        peers.insert(
            1,
            PeerConfig {
                public_key: b.public_key.clone(),
                allowed_ips: vec!["10.240.0.3/32".parse().unwrap()],
                endpoint: None,
                persistent_keepalive_secs: None,
            },
        );
    }
    TunnelConfig {
        name: "wg0".into(),
        address: hub.overlay.parse().unwrap(),
        address_prefix: 24,
        listen_port: Some(16190),
        peers,
        mtu: None,
        private_key: Some(hub.private_key.clone()),
    }
}

/// The hub's alias forwarding routes (what the server adapter's `hub_plan` produces for alias routes).
pub(crate) fn hub_routes() -> Vec<RouteConfig> {
    vec![RouteConfig {
        destination: "10.241.1.0/24".parse().unwrap(),
        interface: "wg0".into(),
        gateway: Some("10.240.0.4".parse().unwrap()),
    }]
}

/// The client/gateway-side tunnel config (peer = hub, endpoint pointing at the hub netns address on the bridge).
pub(crate) fn leaf_tunnel(node: &Node, hub: &Node, allowed_ips: &[&str]) -> TunnelConfig {
    TunnelConfig {
        name: "wg0".into(),
        address: node.overlay.parse().unwrap(),
        address_prefix: 24,
        listen_port: None,
        peers: vec![PeerConfig {
            public_key: hub.public_key.clone(),
            allowed_ips: allowed_ips.iter().map(|s| s.parse().unwrap()).collect(),
            endpoint: Some(format!("{}:16190", hub.underlay)),
            persistent_keepalive_secs: Some(2),
        }],
        mtu: None,
        private_key: Some(node.private_key.clone()),
    }
}

/// The alias mapping in dnat_snat mode (§9.4-§9.5, the same shape as alias_nat.rs).
pub(crate) fn alias_mapping() -> AliasMapping {
    AliasMapping::new(
        AliasMappingId("al-1".into()),
        NetworkId("net-1".into()),
        LanRouteId("rt-1".into()),
        "10.241.1.0/24".parse().unwrap(),
        "192.168.1.0/24".parse().unwrap(),
        TranslationMode::DnatSnat,
    )
    .unwrap()
}

pub(crate) const ALIAS_OWNER: &str = "meshlet alias al-1";

/// Whether the snapshot's fingerprint set contains a controlled SNAT action (read from the fingerprint
/// content, not by separately enumerating the POSTROUTING chain -- the same criterion as `collect_evidence`).
pub(crate) fn snapshot_has_snat(snap: &NetworkSnapshot) -> bool {
    snap.nat_rules
        .iter()
        .any(|sig| sig.contains("|snat_to_gateway_lan|"))
}

/// For fingerprint-set comparison: sort both sides. The observed side comes from a `BTreeSet`
/// (already sorted); the planned side comes from a `Vec` (plan order) -- rule order is not part
/// of the identity.
pub(crate) fn sorted_signatures(signatures: &[String]) -> Vec<String> {
    let mut out = signatures.to_vec();
    out.sort();
    out
}

/// Render the snapshot's peer identities into a set (`public key:allowed-ips,...`). Set comparison is
/// order-insensitive by nature, so an assertion built on it checks "identities" rather than "counts":
/// that is how the case of an equal count with a swapped identity becomes visible.
pub(crate) fn peer_identities(snap: &NetworkSnapshot) -> BTreeSet<String> {
    snap.peers
        .iter()
        .map(|p| {
            format!(
                "{}:{}",
                p.public_key,
                p.allowed_ips
                    .iter()
                    .map(|c| c.to_string())
                    .collect::<Vec<_>>()
                    .join(",")
            )
        })
        .collect()
}

/// The expected set of peer identities (rendered the same way as `peer_identities`).
pub(crate) fn planned_peer_identities(a: &Node, b: &Node, gw: &Node) -> BTreeSet<String> {
    [
        format!("{}:10.240.0.2/32", a.public_key),
        format!("{}:10.240.0.3/32", b.public_key),
        format!("{}:10.240.0.4/32,10.241.1.0/24", gw.public_key),
    ]
    .into_iter()
    .collect()
}

/// The shared netns prefix also shows up on the host's underlay; this in-process serialization lock
/// keeps the multi-scenario tests of this binary from trampling each other concurrently. Isolation
/// across test binaries remains the job of distinct prefixes.
pub(crate) static NETNS_PREFIX_LOCK: Mutex<()> = Mutex::new(());
