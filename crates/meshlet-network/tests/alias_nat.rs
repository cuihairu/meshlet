//! Real-network integration tests for the Alias DNAT/SNAT prototype
//! ([archive §9.2–§9.5](../../../docs/review/chatgpt-2026-10-13.md),
//! [ADR-006](../../../docs/decisions/adr-006-alias-prefix-nat.md)).
//!
//! Six network namespaces build the topology of "VPS hub + two site gateways + two **same-prefix**
//! real LANs + an overlay client" -- both sites' real LANs are `192.168.1.0/24` (overlapping
//! addresses), distinguishable only by their alias prefixes:
//!
//! - **site1**: alias `10.241.1.0/24` -> gw1, `dnat_snat` mode (the default-compatible mode, a
//!   controlled SNAT for the return path, §9.5 mode B);
//! - **site2**: alias `10.241.2.0/24` -> gw2, `dnat_only` mode (source address preserved, requiring
//!   the LAN to hold a return route pointing at the gateway, §9.5 mode A).
//!
//! The NAT rules are handed down with `iptables NETMAP`/`SNAT`, shaped the same as the rendering of
//! [NatRule::iptables_args] (plan and execution share one shape, no drift).
//!
//! Four acceptance items:
//!
//! 1. **The two 192.168.1.0/24 LANs reach each other through different aliases**: the client's ping
//!    to both `10.241.1.5` and `10.241.2.5` works (the real subnets overlap entirely; the alias
//!    prefixes are the only distinction);
//! 2. **Site identities do not cross wires**: the UDP echo reply body carries the site name -- the
//!    alias1 reply comes from `site1`, the alias2 reply from `site2` (the overlapping subnets really
//!    do land at two different sites);
//! 3. **The controlled SNAT is observable (site1)**: the source address the LAN host sees is the
//!    gateway's own LAN address `192.168.1.1` (the limitation §9.5 spells out), and the reply's
//!    source address is reverse-translated by conntrack back to the alias address `10.241.1.5`;
//! 4. **Source preservation is observable (site2)**: the LAN host sees the client's real overlay
//!    source `10.240.0.3` (§9.5 mode A), and the reply's source is `10.241.2.5`.
//!
//! Topology essentials (all pinned down by hands-on hits):
//!
//! - `ip netns add` first, then move the veth end into the netns -- in the reversed order the
//!   command fails silently, the LAN-side address never gets configured, and it shows up as ARP
//!   failing on the gateway side (`Destination Host Unreachable`, sourced from the
//!   reverse-translated alias address);
//! - the VPS hub forwards by prefix only: `ip route add 10.241.1.0/24 via <gw1 wg addr> dev wg0`,
//!   and the hub itself performs no NAT at all (§9.4);
//! - the client needs a `10.241.0.0/16 dev wg0` route (`wg set` does not add routes automatically);
//! - the translation happens at the **destination LAN gateway** (NETMAP on gw1/gw2), not on the hub;
//! - NETMAP is conntrack-based: the reverse translation in the reply direction (real address ->
//!   alias address) needs no extra rules.
//!
//! Prerequisites and the skip discipline are the same as [wg_forwarding]; cleanup goes through
//! `Drop` + a final assertion that nothing is left behind.

#![cfg(target_os = "linux")]

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

/// The name prefix shared by every object this test creates.
const PREFIX: &str = "mlta";
/// The overlay range that client routes traverse via the hub.
const OVERLAY_CIDR: &str = "10.240.0.0/16";
/// The alias supernet shared by the two sites (the client-side route).
const ALIAS_CIDR: &str = "10.241.0.0/16";
/// The two sites' **fully overlapping** real LAN prefix.
const REAL_LAN: &str = "192.168.1.0/24";
/// The LAN host address (identical at both sites).
const LAN_HOST: &str = "192.168.1.5";
/// The gateway's address within the real LAN (the SNAT target of the controlled SNAT).
const LAN_GW: &str = "192.168.1.1";
/// Upper bound for waiting on the handshake.
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(25);

// ---------------------------------------------------------------- process helpers

fn sudo(args: &[&str]) -> Output {
    Command::new("sudo")
        .arg("-n")
        .args(args)
        .output()
        .expect("spawn sudo")
}

fn sudo_ok(args: &[&str]) -> bool {
    sudo(args).status.success()
}

fn netns_exec(ns: &str, args: &[&str]) -> Output {
    let mut full = vec!["ip", "netns", "exec", ns];
    full.extend_from_slice(args);
    sudo(&full)
}

fn netns_bash(ns: &str, script: &str) -> Output {
    netns_exec(ns, &["bash", "-c", script])
}

fn require_ok(out: &Output, what: &str) {
    if !out.status.success() {
        panic!(
            "{what} failed (rc={:?}): {}",
            out.status.code(),
            String::from_utf8_lossy(&out.stderr)
        );
    }
}

fn count_prefix_lines(text: &str) -> usize {
    text.lines().filter(|l| l.starts_with(PREFIX)).count()
}

/// Prerequisites (the same as [wg_forwarding]: passwordless sudo + wg + the kernel module; this
/// test additionally needs python3 for the UDP echo and iptables NETMAP support).
fn prerequisites() -> Option<()> {
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
            eprintln!("SKIP: python3 not installed");
            return None;
        }
    }
    Some(())
}

/// Idempotent pre-cleanup (crash recovery).
fn preflight_cleanup() {
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

// ---------------------------------------------------------------- topology

/// An overlay-side node (hanging off the bridge, with a wg0).
struct Node {
    netns: String,
    underlay: String,
    overlay: String,
    port: u16,
    public_key: String,
    private_key: String,
}

impl Node {
    fn netns_exec(&self, args: &[&str]) -> Output {
        netns_exec(&self.netns, args)
    }
    fn netns_bash(&self, script: &str) -> Output {
        netns_bash(&self.netns, script)
    }
}

/// Tracks the objects built so far so that a panic partway through setup can still clean everything up.
struct Guard {
    netns: Vec<String>,
    veth: Vec<String>,
    bridge: Option<String>,
    scripts_dir: Option<PathBuf>,
}

impl Guard {
    fn new() -> Self {
        Guard {
            netns: Vec::new(),
            veth: Vec::new(),
            bridge: None,
            scripts_dir: None,
        }
    }
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
        if let Some(dir) = &self.scripts_dir {
            let _ = std::fs::remove_dir_all(dir);
        }
    }
}

struct Topology {
    #[allow(dead_code)]
    guard: Guard,
    hub: Node,
    gw1: Node,
    gw2: Node,
    client: Node,
    keys_dir: PathBuf,
}

/// Bridge-attached nodes (netns + veth + underlay addresses + offload off).
fn bridge_node(guard: &mut Guard, bridge: &str, name: &str, underlay: &str) -> (String, String) {
    let netns = format!("{PREFIX}{name}");
    let veth_host = format!("{PREFIX}{name}0");
    let veth_ns = format!("{PREFIX}{name}1");
    guard.netns.push(netns.clone());
    guard.veth.push(veth_host.clone());
    require_ok(&sudo(&["ip", "netns", "add", &netns]), "netns add");
    require_ok(
        &sudo(&[
            "ip", "link", "add", &veth_host, "type", "veth", "peer", "name", &veth_ns,
        ]),
        "veth add",
    );
    require_ok(
        &sudo(&["ip", "link", "set", &veth_ns, "netns", &netns]),
        "veth into netns",
    );
    require_ok(
        &sudo(&["ip", "link", "set", &veth_host, "master", bridge]),
        "veth onto bridge",
    );
    require_ok(
        &netns_exec(
            &netns,
            &[
                "ip",
                "addr",
                "add",
                &format!("{underlay}/24"),
                "dev",
                &veth_ns,
            ],
        ),
        "underlay addr",
    );
    require_ok(
        &sudo(&["ip", "link", "set", &veth_host, "up"]),
        "veth host up",
    );
    require_ok(
        &netns_exec(&netns, &["ip", "link", "set", &veth_ns, "up"]),
        "veth ns up",
    );
    require_ok(
        &netns_exec(&netns, &["ip", "link", "set", "lo", "up"]),
        "lo up",
    );
    // GRO/GSO/TSO make a wg-over-veth handshake fail silently; turn them off on both ends.
    let offload = [
        "gro", "off", "gso", "off", "tso", "off", "rx", "off", "tx", "off", "sg", "off",
    ];
    let mut host_offload = vec!["ethtool", "-K", &veth_host];
    host_offload.extend_from_slice(&offload);
    let mut ns_offload = vec!["ethtool", "-K", &veth_ns];
    ns_offload.extend_from_slice(&offload);
    let _ = sudo(&host_offload);
    let _ = netns_exec(&netns, &ns_offload);
    (netns, veth_ns)
}

/// The LAN segment behind a gateway: one veth end goes into the gateway, the other into the LAN
/// host's netns. The `lan_veth` names use the site letters (X/Y) to avoid clashing with the
/// bridge-attached veth.
fn lan_segment(guard: &mut Guard, gw_netns: &str, letter: &str, gw_addr: &str, host_addr: &str) {
    let lan_netns = format!("{PREFIX}L{letter}");
    let veth_gw = format!("{PREFIX}{letter}0");
    let veth_host = format!("{PREFIX}{letter}1");
    guard.netns.push(lan_netns.clone());
    guard.veth.push(veth_gw.clone());
    require_ok(&sudo(&["ip", "netns", "add", &lan_netns]), "lan netns add");
    require_ok(
        &sudo(&[
            "ip", "link", "add", &veth_gw, "type", "veth", "peer", "name", &veth_host,
        ]),
        "lan veth add",
    );
    require_ok(
        &sudo(&["ip", "link", "set", &veth_gw, "netns", gw_netns]),
        "lan veth into gw",
    );
    require_ok(
        &sudo(&["ip", "link", "set", &veth_host, "netns", &lan_netns]),
        "lan veth into host",
    );
    require_ok(
        &netns_exec(
            gw_netns,
            &[
                "ip",
                "addr",
                "add",
                &format!("{gw_addr}/24"),
                "dev",
                &veth_gw,
            ],
        ),
        "gw lan addr",
    );
    require_ok(
        &netns_exec(
            &lan_netns,
            &[
                "ip",
                "addr",
                "add",
                &format!("{host_addr}/24"),
                "dev",
                &veth_host,
            ],
        ),
        "lan host addr",
    );
    require_ok(
        &netns_exec(gw_netns, &["ip", "link", "set", &veth_gw, "up"]),
        "gw lan up",
    );
    require_ok(
        &netns_exec(&lan_netns, &["ip", "link", "set", &veth_host, "up"]),
        "lan host up",
    );
    require_ok(
        &netns_exec(gw_netns, &["ip", "link", "set", "lo", "up"]),
        "gw lo up",
    );
    require_ok(
        &netns_exec(&lan_netns, &["ip", "link", "set", "lo", "up"]),
        "lan lo up",
    );
    // The LAN host uses the gateway as its default route (the return path for §9.5 mode A).
    require_ok(
        &netns_exec(
            &lan_netns,
            &["ip", "route", "add", "default", "via", gw_addr],
        ),
        "lan default route",
    );
}

/// wg0 + addresses + (optionally) ip_forward; the private key and peers go in two separate `wg set` calls.
fn wg_iface(node: &Node, forward: bool) {
    let fwd = if forward {
        " && sysctl -w net.ipv4.ip_forward=1"
    } else {
        ""
    };
    let script = format!(
        "ip link add wg0 type wireguard && ip address add {}/24 dev wg0 && ip link set wg0 up{fwd}",
        node.overlay
    );
    require_ok(&node.netns_bash(&script), "wg interface");
    let script = format!(
        "wg set wg0 listen-port {} private-key <(echo {})",
        node.port, node.private_key
    );
    require_ok(&node.netns_bash(&script), "private key");
}

impl Topology {
    fn setup() -> Option<Topology> {
        prerequisites()?;
        preflight_cleanup();

        let keys_dir = std::env::temp_dir().join(format!(
            "{PREFIX}-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .ok()?
                .as_nanos(),
        ));
        if std::fs::create_dir_all(&keys_dir).is_err() {
            return None;
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(&keys_dir, std::fs::Permissions::from_mode(0o700));
        }
        let mut guard = Guard::new();
        guard.scripts_dir = Some(keys_dir.clone());

        // --- Keys
        let mut keys = Vec::new();
        for name in ["H", "G1", "G2", "CL"] {
            let private = match wg_genkey() {
                Ok(k) => k,
                Err(e) => {
                    assert!(
                        std::env::var_os("MESHLET_REQUIRE_DATAPLANE").is_none(),
                        "required dataplane prerequisite failed"
                    );
                    eprintln!("SKIP: key generation failed: {e}");
                    return None;
                }
            };
            let public = match wg_pubkey(&private) {
                Ok(k) => k,
                Err(e) => {
                    assert!(
                        std::env::var_os("MESHLET_REQUIRE_DATAPLANE").is_none(),
                        "required dataplane prerequisite failed"
                    );
                    eprintln!("SKIP: key derivation failed: {e}");
                    return None;
                }
            };
            keys.push((name, private, public));
        }

        // --- Underlay: the bridge + bridge-attached nodes
        let bridge = format!("{PREFIX}br0");
        guard.bridge = Some(bridge.clone());
        require_ok(
            &sudo(&["ip", "link", "add", &bridge, "type", "bridge"]),
            "create bridge",
        );
        require_ok(&sudo(&["ip", "link", "set", &bridge, "up"]), "bridge up");

        let mk = |guard: &mut Guard, name: &str, underlay: &str, overlay: &str, port: u16| {
            let (netns, _) = bridge_node(guard, &bridge, name, underlay);
            let private = keys
                .iter()
                .find(|(n, _, _)| *n == name)
                .expect("key")
                .1
                .clone();
            let public = keys
                .iter()
                .find(|(n, _, _)| *n == name)
                .expect("key")
                .2
                .clone();
            Node {
                netns,
                underlay: underlay.to_string(),
                overlay: overlay.to_string(),
                port,
                public_key: public,
                private_key: private,
            }
        };
        let hub = mk(&mut guard, "H", "10.99.0.10", "10.240.0.1", 16180);
        let gw1 = mk(&mut guard, "G1", "10.99.0.20", "10.240.0.2", 16181);
        let gw2 = mk(&mut guard, "G2", "10.99.0.30", "10.240.0.4", 16182);
        let client = mk(&mut guard, "CL", "10.99.0.40", "10.240.0.3", 16183);

        // --- The LAN segment behind the gateways (both sites' real prefixes fully overlap)
        lan_segment(&mut guard, &gw1.netns, "X", LAN_GW, LAN_HOST);
        lan_segment(&mut guard, &gw2.netns, "Y", LAN_GW, LAN_HOST);

        // --- wg interfaces (forwarding on for the hub/gateways)
        wg_iface(&hub, true);
        wg_iface(&gw1, true);
        wg_iface(&gw2, true);
        wg_iface(&client, false);

        // --- Hub peers: each gateway carries its own alias prefix (the VPS forwards by prefix only)
        require_ok(
            &hub.netns_bash(&format!(
                "wg set wg0 peer {} allowed-ips 10.240.0.2/32,10.241.1.0/24",
                gw1.public_key
            )),
            "hub peer gw1",
        );
        require_ok(
            &hub.netns_bash(&format!(
                "wg set wg0 peer {} allowed-ips 10.240.0.4/32,10.241.2.0/24",
                gw2.public_key
            )),
            "hub peer gw2",
        );
        require_ok(
            &hub.netns_bash(&format!(
                "wg set wg0 peer {} allowed-ips 10.240.0.3/32",
                client.public_key
            )),
            "hub peer client",
        );
        // --- Gateway/client peers (all point at the hub, covering overlay + alias space)
        for n in [&gw1, &gw2] {
            require_ok(
                &n.netns_bash(&format!(
                    "wg set wg0 peer {} allowed-ips {OVERLAY_CIDR},{ALIAS_CIDR} endpoint {}:{} persistent-keepalive 2",
                    hub.public_key, hub.underlay, hub.port
                )),
                "gateway peer",
            );
        }
        require_ok(
            &client.netns_bash(&format!(
                "wg set wg0 peer {} allowed-ips {OVERLAY_CIDR},{ALIAS_CIDR} endpoint {}:{} persistent-keepalive 2",
                hub.public_key, hub.underlay, hub.port
            )),
            "client peer",
        );

        // --- Hub: the alias prefix routes to the matching site gateway (§9.4: the VPS does no NAT)
        require_ok(
            &hub.netns_exec(&[
                "ip",
                "route",
                "add",
                "10.241.1.0/24",
                "via",
                &gw1.overlay,
                "dev",
                "wg0",
            ]),
            "hub alias1 route",
        );
        require_ok(
            &hub.netns_exec(&[
                "ip",
                "route",
                "add",
                "10.241.2.0/24",
                "via",
                &gw2.overlay,
                "dev",
                "wg0",
            ]),
            "hub alias2 route",
        );
        // --- Client: the alias space enters the tunnel (wg set does not add routes automatically)
        require_ok(
            &client.netns_exec(&["ip", "route", "add", ALIAS_CIDR, "dev", "wg0"]),
            "client alias route",
        );

        // --- Gateway NAT rules (shaped the same as NatRule::iptables_args renders)
        // site1 (dnat_snat): DNAT always + a controlled SNAT (§9.5 mode B)
        require_ok(
            &gw1.netns_exec(&[
                "iptables",
                "-t",
                "nat",
                "-A",
                "PREROUTING",
                "-d",
                "10.241.1.0/24",
                "-j",
                "NETMAP",
                "--to",
                REAL_LAN,
            ]),
            "gw1 netmap",
        );
        require_ok(
            &gw1.netns_exec(&[
                "iptables",
                "-t",
                "nat",
                "-A",
                "POSTROUTING",
                "-d",
                REAL_LAN,
                "-j",
                "SNAT",
                "--to-source",
                LAN_GW,
            ]),
            "gw1 controlled snat",
        );
        // site2 (dnat_only): DNAT only, preserving the original source address (§9.5 mode A)
        require_ok(
            &gw2.netns_exec(&[
                "iptables",
                "-t",
                "nat",
                "-A",
                "PREROUTING",
                "-d",
                "10.241.2.0/24",
                "-j",
                "NETMAP",
                "--to",
                REAL_LAN,
            ]),
            "gw2 netmap",
        );

        // --- Echo/send scripts
        let echo_py = keys_dir.join("echo.py");
        std::fs::write(&echo_py, ECHO_PY).expect("write echo.py");
        let send_py = keys_dir.join("send.py");
        std::fs::write(&send_py, SEND_PY).expect("write send.py");

        Some(Topology {
            guard,
            hub,
            gw1,
            gw2,
            client,
            keys_dir,
        })
    }

    fn wait_handshake(&self, ns: &str) -> bool {
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

    fn ping(&self, from: &str, to: &str) -> bool {
        netns_exec(from, &["ping", "-c", "3", "-W", "2", to])
            .status
            .success()
    }

    /// Start a one-shot UDP echo server in `site` (an L1/L2 netns), with the client hitting `alias`.
    /// Returns the reply body (shaped like `site1 seen=192.168.1.1`) and the reply's source address.
    fn udp_echo(
        &self,
        site_netns: &str,
        site_name: &str,
        port: u16,
        alias: &str,
    ) -> (String, String) {
        let echo_py = self.keys_dir.join("echo.py");
        let send_py = self.keys_dir.join("send.py");
        let mut server = Command::new("sudo")
            .arg("-n")
            .args(["ip", "netns", "exec", site_netns, "python3"])
            .arg(&echo_py)
            .arg(port.to_string())
            .arg(site_name)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn echo server");
        // The client retries: packets sent before the echo server is up get dropped, so just resend.
        let out = netns_exec(
            &self.client.netns,
            &[
                "python3",
                &send_py.to_string_lossy(),
                alias,
                &port.to_string(),
            ],
        );
        let client_line = String::from_utf8_lossy(&out.stdout).trim().to_string();
        let _ = server.wait();
        if !out.status.success() {
            return (client_line, String::new());
        }
        // send.py's output is shaped like `reply_from=<ip> body=<...>`.
        let mut reply_from = String::new();
        for part in client_line.split_whitespace() {
            if let Some(v) = part.strip_prefix("reply_from=") {
                reply_from = v.to_string();
            }
        }
        let body = client_line
            .split_once("body=")
            .map(|(_, b)| b.to_string())
            .unwrap_or_default();
        (body, reply_from)
    }

    fn dump_all(&self) {
        for n in [&self.hub, &self.gw1, &self.gw2, &self.client] {
            eprintln!("--- wg show wg0 in {} ---", n.netns);
            let out = n.netns_exec(&["wg", "show", "wg0"]);
            eprintln!("{}", String::from_utf8_lossy(&out.stdout));
        }
    }
}

/// One-shot UDP echo server: receives one packet, replies `site seen=<src>`, then exits.
const ECHO_PY: &str = "\
import socket, sys
port, site = int(sys.argv[1]), sys.argv[2]
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.bind(('0.0.0.0', port))
s.settimeout(15)
data, addr = s.recvfrom(2048)
s.sendto(f'{site} seen={addr[0]}'.encode(), addr)
";

/// The UDP sender: retries (waiting for the echo server to come up), prints the reply source and reply body.
const SEND_PY: &str = "\
import socket, sys, time
target, port = sys.argv[1], int(sys.argv[2])
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.settimeout(1.5)
for i in range(12):
    try:
        s.sendto(b'probe', (target, port))
        data, addr = s.recvfrom(2048)
        print(f'reply_from={addr[0]} body={data.decode()}')
        sys.exit(0)
    except socket.timeout:
        pass
print('no_reply')
sys.exit(1)
";

fn wg_genkey() -> std::io::Result<String> {
    let out = Command::new("wg").arg("genkey").output()?;
    if !out.status.success() {
        return Err(std::io::Error::other("wg genkey failed"));
    }
    Ok(String::from_utf8_lossy(&out.stdout).trim().to_string())
}

fn wg_pubkey(private: &str) -> std::io::Result<String> {
    let mut child = Command::new("wg")
        .arg("pubkey")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()?;
    child
        .stdin
        .take()
        .expect("piped stdin")
        .write_all(private.as_bytes())?;
    let out = child.wait_with_output()?;
    if !out.status.success() {
        return Err(std::io::Error::other("wg pubkey failed"));
    }
    Ok(String::from_utf8_lossy(&out.stdout).trim().to_string())
}

#[test]
fn alias_nat_forwarding() {
    let topo = match Topology::setup() {
        Some(t) => t,
        None => return, // Already printed SKIP:
    };

    for ns in [&topo.gw1.netns, &topo.gw2.netns, &topo.client.netns] {
        if !topo.wait_handshake(ns) {
            topo.dump_all();
            panic!("wireguard handshake did not complete within {HANDSHAKE_TIMEOUT:?}");
        }
    }

    // 1. The two 192.168.1.0/24 LANs reach each other through different aliases (the real prefixes fully overlap).
    assert!(
        topo.ping(&topo.client.netns, LAN_HOST_ALIAS1),
        "alias 10.241.1.0/24 must reach site1's 192.168.1.5"
    );
    assert!(
        topo.ping(&topo.client.netns, LAN_HOST_ALIAS2),
        "alias 10.241.2.0/24 must reach site2's 192.168.1.5"
    );

    // 2+3. site1 (dnat_snat): the site identity is right + the LAN sees the gateway's LAN address (a
    // controlled SNAT, §9.5 mode B) + the reply source is reverse-translated back to the alias address.
    let (body, reply_from) = topo.udp_echo("mltaLX", "site1", 45701, LAN_HOST_ALIAS1);
    assert_eq!(
        reply_from, LAN_HOST_ALIAS1,
        "echo reply must come from the alias address"
    );
    assert!(
        body.starts_with("site1 "),
        "alias1 traffic must land on site1, got: {body}"
    );
    assert_eq!(
        body, "site1 seen=192.168.1.1",
        "dnat_snat mode: LAN host must see the gateway's own LAN address (controlled SNAT)"
    );

    // 2+4. site2 (dnat_only): the site identity is right + the LAN sees the real overlay source
    // address (§9.5 mode A, source preserved) + the reply source is the alias address.
    let (body, reply_from) = topo.udp_echo("mltaLY", "site2", 45702, LAN_HOST_ALIAS2);
    assert_eq!(
        reply_from, LAN_HOST_ALIAS2,
        "echo reply must come from the alias address"
    );
    assert!(
        body.starts_with("site2 "),
        "alias2 traffic must land on site2, got: {body}"
    );
    assert_eq!(
        body, "site2 seen=10.240.0.3",
        "dnat_only mode: LAN host must see the client's real overlay source (preserved)"
    );

    // Teardown and assert that nothing is left behind.
    let keys_dir = topo.keys_dir.clone();
    drop(topo);
    let netns_left = sudo(&["ip", "netns", "list"]);
    let links_left = sudo(&["ip", "-br", "link"]);
    let netns_text = String::from_utf8_lossy(&netns_left.stdout);
    let links_text = String::from_utf8_lossy(&links_left.stdout);
    assert_eq!(
        count_prefix_lines(&netns_text),
        0,
        "leftover netns after teardown:\n{netns_text}"
    );
    assert_eq!(
        count_prefix_lines(&links_text),
        0,
        "leftover links after teardown:\n{links_text}"
    );
    assert!(!keys_dir.exists(), "keys dir {keys_dir:?} not removed");
}

const LAN_HOST_ALIAS1: &str = "10.241.1.5";
const LAN_HOST_ALIAS2: &str = "10.241.2.5";
